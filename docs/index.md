# Eva Documentation

Welcome to the official documentation for **Eva**, a local-first command-line intelligence assistant.

Eva uses deterministic local tools for file discovery, directory tree generation, search, configuration, response caching, and quota tracking, while reserving LLM calls for natural-language reasoning, summarization, code review, command generation, and patch generation.

---

## Core Philosophy

Modern terminal workflows often require quick assistance — looking up complex flags, explaining terminal output errors, or generating precision git patches. Eva keeps routine terminal tasks fast and local without forcing you to switch context to a web browser.

- **Local-First**: Search, find files, print git-aware trees, and inspect local configurations without using any LLM token quota.
- **Provider Fallback**: Automatic failover across multiple free-tier and paid providers (Groq, OpenRouter, Gemini, OpenCode Zen, and local offline backends).
- **Safety by Default**: Strict parsing, risk scanning, no `shell=True` default execution, opt-in allowlists, and cryptographic hash-chained audit logging.
- **Extensible Plugin System**: Third-party packages can register CLI commands, custom providers, and workflow hooks via standard Python entry points.

---

## Quick Installation

Eva requires Python 3.10 or newer.

### Quick Shell Install

```bash
curl -fsSL https://raw.githubusercontent.com/rootagi/eva/main/install.sh | sh
```

### Via Package Manager

```bash
uv tool install eva-cli
# or: pipx install eva-cli
# or: pip install --user eva-cli
```

### Rust-Accelerated File Walker (Optional)

For significantly faster directory traversal and file discovery, install the optional Rust extension:

```bash
uv tool install "eva-cli[fast]"
```

This installs `eva-fastwalk`, a Rust/PyO3 extension. On platforms without compiled binaries, Eva automatically falls back to Python standard library traversal.

### Container Execution (Docker)

```bash
docker run --rm -it -v "$(pwd):/workspace" \
  -e EVA_GROQ_API_KEY="$GROQ_API_KEY" \
  ghcr.io/rootagi/eva chat
```

### Local Development Setup

```bash
git clone https://github.com/rootagi/eva.git
cd eva
python -m pip install -e ".[dev]"
```

### Shell Completion Setup

Enable tab auto-completion for Bash, Zsh, or Fish:

```bash
eva --install-completion
```

---

## Key Features

1. **One-Shot Queries**: `eva ask "How do I untar a gz archive?"` (supports `--format json`).
2. **Context-Aware Analysis**: Pass `--file` or `--dir` context safely with `.gitignore` filtering.
3. **Repository Packing & Agentic Investigation**: `eva ask --repo .` and `eva investigate` for query-driven codebase exploration.
4. **Project Memory (`.eva/context.md`)**: Automatically injects repository-level instructions into `ask` and `work` prompts.
5. **Terminal Pipeline Analysis**: Pipe command output directly into `eva analyze`.
6. **Interactive Session Chat**: Persistent sessions with `eva chat --session <id>`.
7. **Safe Command Generation**: Natural language command generation via `eva work` with `--dry-run`, `--dry-run-explain`, and safety checks.
8. **Git & Patch Workflows**: Reviewable diff generation with `eva edit` and automated commit messages via `eva commit-message`.
9. **Fine-Grained Security Controls**: Path-aware secret redaction, configurable Shannon entropy thresholds, sensitive file allowlists, and SHA-256 hash-chained audit logging.
10. **Plugin Architecture**: Extend Eva with custom commands and providers via `EvaPlugin` subclasses and Python entry points.
11. **Rust Performance**: Optional `eva-fastwalk` extension for native-speed file discovery.

