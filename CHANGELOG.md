# Changelog

All notable changes to Eva CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - Unreleased

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
