import re
from pathlib import Path

from eva.config import get_config_dir
from eva.indexing.tokenizer import trim_context
from eva.prompts import CHAT_SYSTEM_PROMPT
from eva.providers import dispatch
from eva.ui.formatter import is_ai_error, print_error, print_info, print_markdown
from eva.ui.streaming import stream_response


def run_chat_session(
    config,
    provider: str | None = None,
    session: str | None = None,
    resume: bool = False,
) -> None:
    print_info("Starting Eva Chat. Type 'exit' or 'quit' to stop.")



    context_history = ""
    session_path: Path | None = None
    if session:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", session).strip("._") or "session"
        session_path = get_config_dir() / "sessions" / f"{safe_name}.md"
        session_path.parent.mkdir(parents=True, exist_ok=True)
        if resume and session_path.exists():
            context_history = session_path.read_text(encoding="utf-8", errors="replace")
            print_info(f"Resumed chat session: {session_path}")

    while True:
        try:
            query = input("\n> ")
            if query.lower() in ("exit", "quit"):
                break
            if not query.strip():
                continue

            trimmed_history = trim_context(context_history, max_tokens=6000, keep="tail") if context_history else ""
            stream = dispatch(CHAT_SYSTEM_PROMPT, query, trimmed_history, config, pinned_provider=provider)
            result = stream_response(stream)

            if is_ai_error(result):
                print_error(result.strip())
                continue

            print_markdown(result)

            # Simple rolling context (just appending for now)
            context_history += f"\nUser: {query}\nEva: {result}\n"
            if session_path:
                session_path.write_text(context_history, encoding="utf-8")

        except (KeyboardInterrupt, EOFError):
            break
