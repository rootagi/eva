# Changelog

All notable changes to Eva CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [4.0.0] - 2026-08-10

### Added
- **PyPI Packaging & Release Workflow for `eva_fastwalk` Extension (`rust/eva_fastwalk/`, `.github/workflows/fastwalk-release.yml`):**
  - Added `rust/eva_fastwalk/pyproject.toml` configured with `maturin` build backend for PyPI distribution package `eva-fastwalk`.
  - Added `license = "MIT"` to `[package]` in `rust/eva_fastwalk/Cargo.toml`.
  - Created `.github/workflows/fastwalk-release.yml` for building multi-platform wheel matrix (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x64, sdist) and publishing to PyPI via OIDC trusted publishing on `fastwalk-v*` tags.
  - Added `fast` opt-in extra (`eva-fastwalk>=0.1.0,<0.2.0`) under `[project.optional-dependencies]` in `pyproject.toml` to maintain zero-dependency `eva-cli` installs.
  - Updated `install.sh` and `README.md` to document `eva-cli[fast]` installation.



### Added

- **Shell Completion (`src/eva/cli/app.py`):**
  - Turned shell completion on in Typer CLI app (`add_completion=True`), enabling `--install-completion` and `--show-completion`.
  - Added support and verification for `bash`, `zsh`, and `fish` shell completion.
  - Documented shell completion installation (`eva --install-completion`) in `README.md`.
  - Added unit test suite covering shell completion output generation in `tests/unit/cli/test_cli.py`.
- **Cross-Platform CI & OS Compatibility (`.github/workflows/ci.yaml`, `src/eva/`):**
  - Extended CI matrix to test across `ubuntu-latest`, `windows-latest`, and `macos-latest` on Python 3.10, 3.11, and 3.12.
  - Fixed cross-platform path handling in `src/eva/workspace/gitignore.py` using `.as_posix()` for `pathspec` pattern matching.
  - Hardened sandboxed subprocess execution in `src/eva/security/sandbox.py` and `src/eva/security/work_safety.py` for Windows system environment variables and `shlex` argument splitting (`posix=(sys.platform != "win32")`).
  - Updated `keyring_backend_available()` in `src/eva/config/config.py` to handle zero-priority backends (`fail.Keyring`) and degrade to `EVA_*_API_KEY` environment variables on headless CI runners.
  - Added explicit unit tests for keyring backend fallback in `tests/unit/config/test_config_keys.py`.
  - Documented cross-platform support and OS limitations in `README.md`.



### Fixed
- **Offline tokenization (`src/eva/indexing/tokenizer.py`):**
  - `count_tokens()` and `trim_context()` no longer crash on restricted-network machines
    (corporate proxy, air-gapped box, CI runner) when tiktoken cannot download
    `cl100k_base.tiktoken` from `openaipublic.blob.core.windows.net`.
  - Broadened exception handling from a narrow set (`ValueError, KeyError, RuntimeError,
    TypeError`) to `Exception`, covering `HTTPError`, `ConnectionError`, `OSError`, and
    any other network or SSL failure that tiktoken may raise.
  - The encoding is now loaded once and cached at module level; degradation logs a single
    `WARNING` message instead of repeating on every call.
  - Graceful fallback: when the encoding cannot be loaded, token counting approximates via
    `len(text) // 4` and trimming approximates via character count × 4 — matching the
    existing fallback logic that was previously unreachable for network errors.

### Added
- **`EVA_TIKTOKEN_ENCODING_PATH` config/env var (`src/eva/config/config.py`):**
  - New `tiktoken_encoding_path` field in `GeneralConfig` (readable from the
    `EVA_TIKTOKEN_ENCODING_PATH` environment variable or `config.toml`).
  - When set, the tokenizer loads the BPE vocabulary from that local file path
    instead of attempting a network download, enabling fully air-gapped deployments.
- **Offline tokenizer tests (`tests/unit/indexing/test_tokenizer_offline.py`):**
  - 8 new tests covering: approximation fallback for `count_tokens` and `trim_context`,
    all exception types handled without crash, warning logged exactly once, custom
    encoding path bypasses download, and bad custom path degrades gracefully.



### Added
- **Opt-In Command Allowlist (`allowed_command_prefixes`):**
  - Configured via `allowed_command_prefixes` in `GeneralConfig` (`config.toml`). Empty list defaults to off (denylist-only).
  - CLI management commands: `eva config allow-command <prefix>`, `eva config disallow-command <prefix>`, and `eva config import-allowlist <path>`.
  - Extended `eva config show` to display active allowlist state.
- **Argv-Based Default Subprocess Execution:**
  - Commands executed in sandbox (and `eva work`) default to `shlex.split` / `shell=False`, preventing shell metacharacter injection.
  - Added `--allow-shell-features` flag to `eva work` for opting into shell features (pipes and redirection).
- **Safety Check Transparency (`--dry-run-explain`):**
  - Added `--dry-run-explain` flag to `eva work` that generates and prints a full summary table of all safety check results (extraction, blast-radius scan, allowlist check, shlex syntax parsing) before execution.
- **Security Hardening Documentation:**
  - Updated `SECURITY.md` Section 3 ("Command Execution Hardening & Defense in Depth") detailing the multi-layered safety framework, argv execution trade-offs, and explicit security limitations.



### Breaking
- **Removed `eva.router` and `eva.context` compatibility shim packages.**
  These re-exported names from the canonical modules and have been superseded since v2.2.0.
  - `eva.router` → use `eva.providers`
  - `eva.context` → use `eva.indexing` / `eva.workspace`



### Added
- **Plugin Architecture Subsystem (`src/eva/plugins/`):**
  - Abstract base class `EvaPlugin` (`src/eva/plugins/protocol.py`) defining lifecycle hooks for registering CLI commands (`register_commands`), contributing custom LLM providers (`register_providers`), and registering workflow step hooks (`register_workflow_hooks`).
  - Automatic discovery mechanism (`src/eva/plugins/loader.py`) using Python standard `importlib.metadata.entry_points` (`[project.entry-points."eva.plugins"]`).
  - Fail-soft error handling: broken plugins log warnings and are safely skipped without crashing CLI startup.
  - Included a reference example plugin (`examples/eva-plugin-hello/`) adding a `hello` command.

## [3.0.1] - 2026-08-06
### Fixed
- Added support for custom focus prompts in `eva analyze`.
- Added `-y`/`--yes` auto-approve flag to `eva workflow run` to prevent piping stalls.

## [3.0.0] - 2026-08-05

### Added
- **Security Hardening Framework (`src/eva/security/`):**
  - Centralized secret and API-key redaction (`src/eva/security/redaction.py`) combining regex pattern matching for API keys, tokens, and private key blocks with Shannon entropy threshold checks ($H(S) > 3.5$). Redaction is executed **before** any provider network request and before writing to local disk.
  - Cryptographic hash-chained audit log (`src/eva/security/audit.py`) with sequential SHA-256 signatures for tamper detection (`verify_audit_chain()`).
  - Sandboxed execution (`src/eva/security/sandbox.py`) providing a restricted subprocess environment with environment variable stripping, stdin isolation, and execution timeouts. Opt-in via `sandbox_risky_commands = true` in config.
- **Terminal Replay Subsystem (`eva replay`):**
  - Session execution recorder and player (`src/eva/replay/`). Captures command, output, exit code, duration, and working directory with automatic secret redaction at write time.
  - New commands: `eva replay <session>` and `eva replay --list`.
- **Opt-In Telemetry (`src/eva/telemetry/`):**
  - Local-only telemetry collector (`src/eva/telemetry/metrics.py`) tracking provider response latency, error rates, and success status only. Zero prompt text or file content collected. Disabled by default; opt-in via `telemetry_enabled = true`. Optional self-hosted HTTP POST export endpoint supported.
- **Documentation:**
  - Created `SECURITY.md` detailing security mechanisms, redaction patterns, audit chain format, sandbox controls, and vulnerability reporting.

## [2.3.0] - 2026-08-05


### Added
- **Declarative Workflow Engine (`eva workflow`):** YAML workflow definitions with approval gates reusing Phase 1 work safety policy (`eva workflow run`, `eva workflow list`, `eva workflow show`). Shipped 3 built-in workflows: `repo_health`, `dependency_audit`, and `security_scan`.
- **Offline Model Support (`ollama` & `llamacpp`):** Added Ollama and llama.cpp GGUF backends with automatic local fallback when cloud providers are unreachable or quota-exhausted.
- **Project Understanding (`src/eva/indexing/repo_index.py`):** Automated project stack detection (languages, frameworks, package managers, test frameworks, CI configs) and module-level dependency graph feeding `eva explain` at repo roots.
- **Session Workspaces (`eva workspace`):** Named session contexts (`eva workspace create`, `switch`, `list`, `note`, `bookmark`, `show`) with secret redaction before writing to disk and strict isolation between workspace names.

## [2.2.0] - 2026-08-05

### Fixed
- **CRITICAL:** `eva changes` and `eva commit-message` no longer crash when git output contains bracket characters (Rich MarkupError).
- **BROKEN:** `eva tree <path>`, `eva grep <pattern> <path>`, and `eva find <pattern> <path>` now correctly accept path arguments.
- `eva doctor` now shows ⚠ for providers with missing API keys instead of a misleading ✔.
- `eva config status` no longer shows doubled emoji prefixes.
- Cache keys now include the model name, preventing stale responses when switching models within a provider.
- Option injection vulnerability in `eva grep` fixed by adding `--` separator before user arguments.

### Changed
- Streaming responses now show real-time progress (`Receiving... (N chars)`) instead of a static spinner.
- Provider code refactored: OpenRouter, Groq, and OpenCode Zen now share an `OpenAICompatibleProvider` base class, eliminating ~90% code duplication.
- `cli.py` split into focused modules: `git_ops.py` for git operations and `chat_session.py` for the interactive REPL.
- Work safety blocklist hardened against absolute path bypasses, `env`/`command` prefix attacks, `xargs rm`, and interpreter code execution.

### Added
- Multi-file context support: `eva ask --file a.py --file b.py` now accepts multiple `--file` flags.
- `--no-cache` flag for `eva ask` to bypass the response cache.
- `CONTRIBUTING.md` with development setup, architecture overview, and suggested contributions including local model integration.
- Explicit `__init__.py` for the `context` package.

### Removed
- Stale `test_gemini.py` scratchpad file that was breaking pytest collection.

## [2.1.0] - 2025-07-01

### Added
- Provider abstraction with fallback routing across OpenRouter, Groq, Gemini, and OpenCode Zen.
- Streaming responses with disk-backed caching.
- Local RPM/RPD budget tracking.
- `.gitignore`-aware context collection.
- Safe file-context reads with binary-file and large-file handling.
- Hardened command generation via `eva work`.
- Git-aware workflows (`eva changes`, `eva commit-message`).
- Reviewable patch generation with `eva edit`.
- Health checks through `eva doctor`.
- Persistent chat sessions with `eva chat --session`.

## [2.0.0] - 2025-06-01

### Changed
- Complete rewrite with provider routing and safety model.

## [1.0.0] - 2025-05-01

### Added
- Initial release with basic AI-powered terminal assistant functionality.
