# Changelog

All notable changes to Eva CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
