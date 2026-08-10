
# Eva CLI


<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/rootagi/eva?style=for-the-badge"></a>
  <a href="https://github.com/rootagi/eva/actions"><img src="https://img.shields.io/github/actions/workflow/status/rootagi/eva/ci.yaml?style=for-the-badge&label=Build"></a>
  <a href="#usage"><img src="https://img.shields.io/badge/CLI-Terminal-111827?style=for-the-badge&logo=gnubash&logoColor=white"></a>
  <a href="https://docs.astral.sh/ruff/"><img src="https://img.shields.io/badge/Code%20Style-Ruff-D7FF64?style=for-the-badge&logo=ruff&logoColor=black"></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/Status-Active%20Development-F59E0B?style=for-the-badge"></a>
</p>

<img src="assets/eva.png" alt="Eva Logo" align="left" width="160" />

Eva is a command line intelligence assistant. It uses deterministic local tools for file discovery, tree generation, search, configuration, caching, and quota tracking, while reserving LLM calls for natural-language reasoning, summarization, code review, command generation, and patch generation.

The design goal is practical: keep routine terminal work fast and local, "Can't remember the right command... Don't leave CLI just for a single command and simple work insted ask eva directly from your CLI"


<br clear="left"/>

<h2 align="center">Quick Demo</h2>

<p align="center">
    <img src="assets/demo.gif" alt="Eva CLI Demo" width="900">
  </a>
</p>
<h3 align="center">"Forgot a command?". Ask eva </h3>
<p align="center">
    <img src="assets/demo2.gif" alt="Eva CLI Demo" width="900">
  </a>
</p>
<h3 align="center">"Need help understanding any command output?". Ask eva </h3>
<p align="center">
    <img src="assets/demo3.gif" alt="Eva CLI Demo" width="900">
  </a>
</p>
<h3 align="center">"Want to patch a script?". Ask eva </h3>
<p align="center">
    <img src="assets/demo4.gif" alt="Eva CLI Demo" width="900">
  </a>
</p>
<h3 align="center">"Need a chatbot?". Just eva </h3>
<p align="center">
    <img src="assets/demo5.gif" alt="Eva CLI Demo" width="900">
  </a>
</p>


## Highlights

- Provider abstraction with fallback routing across OpenRouter, Groq, Gemini, and OpenCode Zen.
- Streaming responses with disk-backed caching.
- Local RPM/RPD budget tracking to avoid unexpectedly exhausting free-tier provider quotas.
- `.gitignore`-aware context collection with common heavy directories pruned automatically.
- Safe file-context reads with missing-file, binary-file, large-file, and invalid-UTF-8 handling.
- Hardened command generation via `eva work`: strict parsing, risk checks, no `shell=True`, dry-run mode, and audit logging.
- Git-aware workflows for explaining diffs and generating commit messages.
- Reviewable patch generation with `eva edit`.
- Health checks through `eva config doctor`.
- Persistent chat sessions with `eva chat --session`.

## Installation

Eva requires Python 3.10 or newer.

**Quick install:**

```bash
curl -fsSL https://raw.githubusercontent.com/rootagi/eva/main/install.sh | sh
```

**Or with a package manager, once published to PyPI:**

```bash
uv tool install eva-cli    # or: pipx install eva-cli / pip install --user eva-cli
```

For the Rust-accelerated file walker, once published:
```bash
uv tool install "eva-cli[fast]"
```


**Shell completion setup (bash, zsh, fish):**

```bash
eva --install-completion
```

**Or with Docker (no Python required):**

```bash
docker run --rm -it -v "$(pwd):/workspace" -e EVA_OPENAI_API_KEY="$OPENAI_API_KEY" \
  ghcr.io/rootagi/eva chat
```

**From a local checkout (for contributing):**

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Configuration

Set the default provider:

```bash
eva use groq
```

Store an API key using the OS keyring:

```bash
eva config set-key groq
```

Headless environments such as containers, CI runners, and SSH-only servers may not have a usable OS keyring backend. In that case, use provider-specific environment variables:

```bash
export EVA_GROQ_API_KEY="..."
export EVA_OPENROUTER_API_KEY="..."
export EVA_GEMINI_API_KEY="..."
export EVA_OPENCODE_ZEN_API_KEY="..."
```

Check the local setup:

```bash
eva config doctor
```

## Usage

Ask a one-shot question:

```bash
eva ask "Explain the difference between a process and a thread"
```

Include a file as context:

```bash
eva ask "What does this module do?" --file src/eva/cli.py
```

Include a directory tree as context:

```bash
eva ask "Where should I add a new provider?" --dir src/eva
```

Explain a file or directory:

```bash
eva explain src/eva/router
```

Analyze piped output:

```bash
pytest -q | eva analyse "Summarize the failures"
```

Start an interactive chat session:

```bash
eva chat --session refactor-router
eva chat --session refactor-router --resume
```

Generate a safe command from natural language:

```bash
eva work "list the largest files in this repository" --dry-run
```

Explain current git changes:

```bash
eva changes
eva changes --staged
```

Generate a commit message:

```bash
eva commit-message
```

Generate a reviewable patch:

```bash
eva edit "add validation for empty provider names" --file src/eva/cli.py
```

Apply the generated patch after confirmation:

```bash
eva edit "add validation for empty provider names" --file src/eva/cli.py --apply
```

Local utility commands do not use LLM quota:

```bash
eva find "*.py"
eva tree src/eva

```

## Command reference

| Command | Purpose |
| --- | --- |
| `eva ask` | Ask a one-shot question, optionally with file or directory context. |
| `eva explain` | Explain a file, concept, or repository (with stack detection & module dependency graph). |
| `eva analyse` / `eva analyze` | Analyze piped terminal output. |
| `eva chat` | Run an interactive chat session, optionally saved and resumed. |
| `eva work` | Generate and optionally execute a single safe local command. |
| `eva edit` | Generate a unified diff for one or more files. |
| `eva workflow run` | Walk through a declarative multi-step YAML workflow with human approval gates. |
| `eva workflow list` | List available built-in and user-defined workflows. |
| `eva workflow show` | Display workflow steps and commands without executing them. |
| `eva workspace` | Manage isolated session workspaces, notes, and bookmarks. |
| `eva workspace create` | Create a new named session workspace. |
| `eva workspace switch` | Switch to a named session workspace. |
| `eva workspace list` | List all session workspaces. |
| `eva workspace note` | Add a note to the active workspace (secrets redacted automatically). |
| `eva workspace bookmark` | Bookmark a file path or URL in the active workspace. |
| `eva workspace show` | Display notes, bookmarks, and activity history for a workspace. |
| `eva replay` | Replay recorded terminal execution sessions (`eva replay <session>` or `eva replay --list`). |
| `eva changes` | Explain unstaged or staged git changes. |
| `eva commit-message` | Generate a concise commit message from a git diff. |
| `eva find` | Find files locally without AI usage. |
| `eva tree` | Print a `.gitignore`-aware directory tree. |
| `eva usage` | Show normalized local provider usage counters. |


| `eva config set-key <provider>` | Store an API key in the OS keyring. |
| `eva config remove-key <provider>` | Delete a stored API key from the OS keyring. |
| `eva config set-model <provider> <model>` | Set active model for a provider. |
| `eva config` | Manage provider, model, and API-key configuration. |
| `eva cache clear` | Clear cached AI responses. |


Global options:

```bash
eva --version
eva --verbose ask "Why did this fail?"
```

Verbose mode writes diagnostics to stderr and to Eva’s log file.

## Safety model & Production Hardening

`eva work` and `eva workflow` are intentionally conservative:

- model output must resolve to exactly one command line;
- malformed Markdown fences and trailing explanations are rejected;
- shell operators such as pipes, redirects, command substitution, and chained commands are rejected;
- high-risk patterns such as `sudo`, `rm -rf`, `curl | bash`, `dd`, `mkfs`, recursive ownership changes, and system-path redirects are blocked;
- secrets, API keys, tokens, and high-entropy strings are redacted before any network request and before writing to local disk;
- every generated, blocked, declined, or executed command is recorded in a **cryptographic hash-chained audit log** with SHA-256 tamper verification;
- optional **sandboxed execution** (`sandbox_risky_commands = true` in config) runs commands in a stripped subprocess environment with environment variable isolation and strict timeouts.

See [`SECURITY.md`](SECURITY.md) for full security documentation.

## Opt-in Telemetry

Eva collects **zero** data by default (`telemetry_enabled = false`). When explicitly opted-in via configuration, Eva records only anonymized provider response latency, error types, and success status. Prompt text, code snippets, file contents, and terminal commands are **never** collected. An optional self-hosted export endpoint is supported via `telemetry_export_endpoint`.

## Cross-platform support & limitations

Eva is tested across Linux (`ubuntu-latest`), macOS (`macos-latest`), and Windows (`windows-latest`):

- **Path Handling**: Eva normalizes file paths to POSIX format internally for `.gitignore` pattern matching and diff operations across all operating systems.
- **Credential Storage**: On Linux/macOS/Windows desktops with a native keyring backend (macOS Keychain, Windows Credential Manager, D-Bus SecretService), `eva config set-key` stores secrets securely in the OS keyring. In headless Linux/CI runners without a D-Bus secret service, keyring access degrades gracefully to provider environment variables (e.g. `EVA_GROQ_API_KEY`).
- **Shell Execution & Command Safety**:
  - `eva work` and sandboxed subprocess execution adjust argument splitting (`shlex`) for Windows command semantics.
  - POSIX-specific blast-radius protection patterns (e.g. `rm -rf /`, `chmod/chown`, `curl | bash`, `/dev/*` writes) are tailored for Unix shells (`sh`, `bash`, `zsh`). On Windows (`cmd.exe` / `powershell.exe`), equivalent high-risk command prevention relies on interactive confirmation gates and sandbox execution.
- **Performance Accelerators**: The optional `eva_fastwalk` C/Rust extension accelerates directory tree generation and file discovery when compiled binaries exist for the platform; on platforms without binary wheels, Eva seamlessly falls back to Python standard library directory traversal (`os.walk` / `Path.iterdir`).



## Provider behavior

Eva tries the configured default provider first. If fallback is enabled, it then tries providers in the configured fallback order. Provider failures are logged instead of being silently discarded, and final provider failure messages include a concise summary of what failed.

Configured providers:

- OpenRouter
- Groq
- Gemini
- OpenCode Zen
- Ollama (offline local backend)
- llama.cpp (offline GGUF backend)

## Plugins

Eva CLI features an extensible plugin system. Third-party packages can register CLI commands, contribute custom AI providers, or register workflow step hooks by creating standard Python packages with entry points.

### Writing a Plugin

1. Subclass `EvaPlugin` from `eva.plugins`:

```python
import typer
from eva.plugins import EvaPlugin


class MyPlugin(EvaPlugin):
    name = "my-plugin"
    version = "0.1.0"

    def register_commands(self, app: typer.Typer) -> None:
        @app.command("my-command")
        def my_command():
            """Custom command contributed by plugin."""
            typer.echo("Hello from my plugin!")

    def register_providers(self) -> None:
        # Register custom LLM provider implementations here
        pass
```

2. Expose the plugin in your package's `pyproject.toml` under `[project.entry-points."eva.plugins"]`:

```toml
[project.entry-points."eva.plugins"]
my_plugin = "my_package.module:MyPlugin"
```

3. Install your package into the environment (`pip install .` or `pip install -e .`). Eva automatically discovers installed plugins via `importlib.metadata.entry_points` on startup.

### Fail-Soft Safety

If an installed plugin fails to load or raises an exception during initialization, Eva logs a warning and skips the broken plugin without interrupting CLI operation.

See [`examples/eva-plugin-hello`](examples/eva-plugin-hello) for a complete example plugin package.

## Development

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

Run the same checks in CI by pushing to a branch or opening a pull request. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Project files

- [`pyproject.toml`](pyproject.toml) — package metadata, dependencies, and tooling.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.
- [`LICENSE`](LICENSE) — MIT license.
- [`src/eva`](src/eva) — CLI implementation.
- [`tests`](tests) — regression tests.

## License

Eva CLI is released under the [MIT License](LICENSE).
