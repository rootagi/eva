"""Interactive Chat REPL workflow with dynamic context budgeting, slash commands, and transcript encryption."""

from __future__ import annotations

import re
import urllib.request
from pathlib import Path

from eva.config import AppConfig, get_config_dir
from eva.indexing.tokenizer import trim_context
from eva.indexing.tree import generate_tree
from eva.prompts import CHAT_SYSTEM_PROMPT
from eva.providers import dispatch, get_context_budget
from eva.ui.formatter import is_ai_error, print_error, print_info, print_markdown, print_success
from eva.ui.streaming import stream_response
from eva.workspace.session import record_command_history

SLASH_COMMANDS: dict[str, str] = {
    "/file": "Attach file content to context: /file <path>",
    "/tree": "Show directory tree of current workspace",
    "/model": "Switch active model: /model <name>",
    "/provider": "Switch active provider: /provider <name>",
    "/url": "Fetch URL content and attach to context: /url <url>",
    "/web": "Search web and attach results: /web <query>",
    "/clear": "Clear conversation history",
    "/save": "Save session transcript: /save [path]",
    "/multiline": "Toggle multi-line input mode",
    "/help": "Show available slash commands",
    "/exit": "Exit chat session",
    "/quit": "Exit chat session",
}


def handle_url_command(url: str) -> str:
    """Fetch content from a URL to attach to conversation context."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Eva-CLI/4.4.1 (Defensive Security REPL)"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        raw_bytes = resp.read()
        text = raw_bytes.decode(charset, errors="replace")

    clean_text = re.sub(r"<[^>]+>", " ", text)
    clean_text = re.sub(r"\s+", " ", clean_text).strip()
    return clean_text


def save_session_transcript(
    path: Path | str,
    content: str,
    encrypt: bool = True,
) -> Path:
    """Save session transcript to disk, encrypting with Fernet at rest by default."""
    from eva.security.redaction import redact_secrets

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = content.encode("utf-8")
    if encrypt:
        from eva.replay.crypto import get_fernet

        fernet = get_fernet()
        blob = fernet.encrypt(raw)
        p.write_bytes(blob)
    else:
        # Sanitize clear-text transcripts before persisting to disk
        p.write_text(redact_secrets(content), encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return p


def load_session_transcript(path: Path | str) -> str:
    """Load transcript with transparent decryption for Fernet-encrypted files or plaintext fallback."""
    p = Path(path)
    if not p.exists():
        if p.with_suffix(".eva_chat").exists():
            p = p.with_suffix(".eva_chat")
        elif p.with_suffix(".md").exists():
            p = p.with_suffix(".md")
        else:
            cand_enc = get_config_dir() / "sessions" / f"{p.name}.eva_chat"
            cand_md = get_config_dir() / "sessions" / f"{p.name}.md"
            if cand_enc.exists():
                p = cand_enc
            elif cand_md.exists():
                p = cand_md
            else:
                raise FileNotFoundError(f"Transcript not found: {path}")

    raw = p.read_bytes()
    if raw.startswith(b"gAAAA"):
        try:
            from cryptography.fernet import InvalidToken

            from eva.replay.crypto import get_fernet

            return get_fernet().decrypt(raw).decode("utf-8").replace("\r\n", "\n")
        except (InvalidToken, ValueError, TypeError, OSError):
            pass
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n")


def dispatch_slash_command(session: ChatSession, command_line: str) -> bool:
    """Dispatch interactive REPL slash commands. Returns True if handled."""
    parts = command_line.strip().split(maxsplit=1)
    if not parts:
        return False

    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd in ("/exit", "/quit"):
        session.running = False
        return True

    if cmd == "/file":
        if not arg:
            print_error("Usage: /file <path>")
            return True
        fpath = Path(arg)
        if not fpath.exists():
            print_error(f"File not found: {arg}")
            return True
        if fpath.is_dir():
            print_error(f"Cannot load directory: {arg}")
            return True
        from eva.security.sensitive_files import is_sensitive_file

        if is_sensitive_file(fpath):
            print_error(f"Access denied: '{arg}' is a sensitive or protected file.")
            return True
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            lines_count = len(content.splitlines())
            session.context_history += (
                f"\nUser: /file {arg}\nAssistant: Loaded {lines_count} lines from {arg}\n\n```{arg}\n{content}\n```\n"
            )
            print_info(f"Loaded {lines_count} lines from {arg}")
        except OSError as exc:
            print_error(f"Failed to read file {arg}: {exc}")
        return True

    if cmd == "/tree":
        tree_str = generate_tree(".")
        session.context_history += (
            f"\nUser: /tree\nAssistant: Current workspace directory structure:\n```\n{tree_str}\n```\n"
        )
        print_info("Workspace Tree:\n" + tree_str[:1500] + ("\n..." if len(tree_str) > 1500 else ""))
        return True

    if cmd == "/model":
        if arg:
            session.set_model(arg)
            print_success(f"Switched model to: {arg}")
        else:
            print_info(f"Active model: {session.get_current_model()}")
        return True

    if cmd == "/provider":
        if arg:
            session.provider = arg
            print_success(f"Switched provider to: {arg}")
        else:
            active_prov = session.provider or session.config.general.default_provider
            print_info(f"Active provider: {active_prov}")
        return True

    if cmd == "/url":
        if not arg:
            print_error("Usage: /url <url>")
            return True
        try:
            fetched = handle_url_command(arg)
            snippet = fetched[:3000]
            session.context_history += f"\nUser: /url {arg}\nAssistant: Attached content from {arg}:\n{snippet}\n"
            print_success(f"Fetched and attached {len(fetched)} characters from {arg}")
        except (OSError, ValueError, urllib.error.URLError) as exc:
            print_error(f"Failed to fetch {arg}: {exc}")
        return True

    if cmd == "/web":
        if not arg:
            print_error("Usage: /web <query>")
            return True
        try:
            import importlib

            searxng = importlib.import_module("eva.web.searxng")
            results = searxng.search(arg)
            session.context_history += f"\nUser: /web {arg}\nAssistant: Web search results for '{arg}':\n{results}\n"
            print_success(f"Attached web search results for: {arg}")
        except (ImportError, OSError, ValueError, KeyError):
            session.context_history += f"\nUser: /web {arg}\nAssistant: Web search query: {arg}\n"
            print_info(f"Attached web search query: {arg}")
        return True

    if cmd == "/clear":
        session.context_history = ""
        session.turns_count = 0
        print_info("Conversation history cleared.")
        return True

    if cmd == "/save":
        target = Path(arg) if arg else session.session_path
        if not target:
            target = get_config_dir() / "sessions" / "session_transcript.md"
        saved = session.save_to(target)
        print_success(f"Session transcript saved to: {saved}")
        return True

    if cmd == "/multiline":
        session.multiline_mode = not session.multiline_mode
        state = "enabled (submit with empty line or /send)" if session.multiline_mode else "disabled"
        print_info(f"Multiline mode {state}.")
        return True

    if cmd == "/help":
        print_info("Available slash commands:")
        for name, desc in SLASH_COMMANDS.items():
            print_info(f"  {name:12} : {desc}")
        return True

    print_error(f"Unknown slash command: {cmd}. Type /help for available commands.")
    return True


class ChatSession:
    """Interactive chat REPL session managing history, context budgeting, and slash commands."""

    def __init__(
        self,
        config: AppConfig,
        provider: str | None = None,
        session: str | None = None,
        resume: bool = False,
        no_project_context: bool = False,
    ):
        self.config = config
        self.provider = provider
        self.session = session
        self.resume = resume
        self.no_project_context = no_project_context
        self.turns_count = 0
        self.context_history = ""
        self.multiline_mode = False
        self.running = True
        self.history_file = get_config_dir() / "sessions" / ".history"

        self.session_path: Path | None = None
        if self.session:
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.session).strip("._") or "session"
            self.session_path = get_config_dir() / "sessions" / f"{safe_name}.md"
            self.session_path.parent.mkdir(parents=True, exist_ok=True)
            if self.resume:
                candidate = self.session_path
                if not candidate.exists() and candidate.with_suffix(".eva_chat").exists():
                    candidate = candidate.with_suffix(".eva_chat")
                if candidate.exists():
                    self.context_history = load_session_transcript(candidate)
                    print_info(f"Resumed chat session: {candidate}")

        self.project_context = ""
        if not self.no_project_context:
            proj_ctx_path = Path.cwd() / ".eva" / "context.md"
            if proj_ctx_path.exists():
                try:
                    self.project_context = proj_ctx_path.read_text(encoding="utf-8", errors="replace").strip()
                    if self.project_context:
                        print_info(f"Loaded project context from {proj_ctx_path}")
                except OSError:
                    pass

    def get_current_model(self) -> str:
        if self.provider and self.provider in self.config.providers:
            return self.config.providers[self.provider].model
        default_prov = self.config.general.default_provider
        if default_prov in self.config.providers:
            return self.config.providers[default_prov].model
        return "default"

    def set_model(self, model_name: str) -> None:
        prov = self.provider or self.config.general.default_provider
        if prov in self.config.providers:
            self.config.providers[prov].model = model_name

    def get_system_prompt(self) -> str:
        prompt = CHAT_SYSTEM_PROMPT
        if self.project_context:
            prompt = f"{prompt}\n\n# Project Context\n{self.project_context}"
        return prompt

    def get_budget(self) -> int:
        return get_context_budget(self.provider, self.config)

    def save_to(self, path: Path | str) -> Path:
        p = Path(path)
        encrypt = getattr(self.config.general, "encrypt_sessions", True) and p.suffix != ".md"
        return save_session_transcript(p, self.context_history, encrypt=encrypt)

    def persist_session(self) -> None:
        if self.session_path:
            if getattr(self.config.general, "encrypt_sessions", True):
                enc_path = self.session_path.with_suffix(".eva_chat")
                save_session_transcript(enc_path, self.context_history, encrypt=True)
                if self.session_path.exists() and self.session_path != enc_path:
                    try:
                        self.session_path.unlink()
                    except OSError:
                        pass
            else:
                save_session_transcript(self.session_path, self.context_history, encrypt=False)

    def _init_history(self) -> None:
        try:
            import readline

            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            if self.history_file.exists():
                readline.read_history_file(str(self.history_file))
        except (ImportError, OSError):
            pass

    def _save_history(self) -> None:
        try:
            import readline

            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            readline.write_history_file(str(self.history_file))
            try:
                self.history_file.chmod(0o600)
            except OSError:
                pass
        except (ImportError, OSError):
            pass

    def read_user_input(self) -> str:
        if self.multiline_mode:
            lines = []
            while True:
                try:
                    line = input("... " if lines else ">>> ")
                except EOFError:
                    if lines:
                        break
                    raise
                if line == "/send" or (not line and lines):
                    break
                lines.append(line)
            return "\n".join(lines)

        query = input("\n> ")
        if query.startswith(('"""', "'''")):
            delim = query[:3]
            rest = query[3:]
            if rest.endswith(delim) and len(rest) >= 3:
                return rest[:-3]
            lines = [rest]
            while True:
                try:
                    line = input("... ")
                except EOFError:
                    break
                if line.endswith(delim):
                    lines.append(line[:-3])
                    break
                lines.append(line)
            return "\n".join(lines)
        return query

    def run(self) -> None:
        print_info("Starting Eva Chat. Type 'exit' or 'quit' to stop, or '/help' for commands.")
        self._init_history()

        try:
            while self.running:
                try:
                    query = self.read_user_input()
                except (KeyboardInterrupt, EOFError):
                    break

                if not query or not query.strip():
                    continue

                stripped = query.strip()
                if stripped.lower() in ("exit", "quit"):
                    break

                if stripped.startswith("/"):
                    handled = dispatch_slash_command(self, stripped)
                    if handled:
                        continue

                self.turns_count += 1
                budget = self.get_budget()
                trimmed_history = (
                    trim_context(self.context_history, max_tokens=budget, keep="tail") if self.context_history else ""
                )
                system_prompt = self.get_system_prompt()

                stream = dispatch(
                    system_prompt,
                    query,
                    trimmed_history,
                    self.config,
                    pinned_provider=self.provider,
                )
                result = stream_response(stream)

                if is_ai_error(result):
                    print_error(result.strip())
                    continue

                print_markdown(result)
                self.context_history += f"\nUser: {query}\nEva: {result}\n"
                self.persist_session()
        finally:
            self._save_history()

        record_command_history(
            entry_type="chat",
            summary={"session": self.session or "interactive", "turns": self.turns_count},
            metadata={"provider": self.provider},
        )


def run_chat_session(
    config: AppConfig,
    provider: str | None = None,
    session: str | None = None,
    resume: bool = False,
    no_project_context: bool = False,
) -> None:
    chat_sess = ChatSession(
        config=config,
        provider=provider,
        session=session,
        resume=resume,
        no_project_context=no_project_context,
    )
    chat_sess.run()
