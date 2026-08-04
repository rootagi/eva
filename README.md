# Eva CLI

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/interface-terminal-111827.svg)](#usage)
[![CI](https://img.shields.io/badge/ci-github%20actions-2088FF.svg)](.github/workflows/ci.yml)
[![Code style](https://img.shields.io/badge/code%20style-ruff-46A5F3.svg)](https://docs.astral.sh/ruff/)
[![Status](https://img.shields.io/badge/status-active%20development-orange.svg)](CHANGELOG.md)

<img src="assets/logo.png" alt="Eva Logo" align="left" width="160" />

Eva is a command line intelligence assistant. It uses deterministic local tools for file discovery, tree generation, search, configuration, caching, and quota tracking, while reserving LLM calls for natural-language reasoning, summarization, code review, command generation, and patch generation.

The design goal is practical: keep routine terminal work fast and local, "Can't remember the right command... Don't leave CLI just for a single command and simple work insted ask eva directly from your CLI"


<br clear="left"/>

<h2 align="center">Quick Demo</h2>

<p align="center">
  <a href="https://github.com/rootagi/eva/releases/download/v0.1.0/demo.mp4">
    <img src="assets/demo.gif" alt="Eva CLI Demo" width="900">
  </a>
</p>

<p align="center">
  <em>Click the preview to watch the full quick demo.</em>
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
- Health checks through `eva doctor`.
- Persistent chat sessions with `eva chat --session`.

## Installation

From a local checkout:

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

Eva requires Python 3.10 or newer.

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
eva doctor
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
eva grep "dispatch" src/eva
```

## Command reference

| Command | Purpose |
| --- | --- |
| `eva ask` | Ask a one-shot question, optionally with file or directory context. |
| `eva explain` | Explain a file or directory. |
| `eva analyse` / `eva analyze` | Analyze piped terminal output. |
| `eva chat` | Run an interactive chat session, optionally saved and resumed. |
| `eva work` | Generate and optionally execute a single safe local command. |
| `eva edit` | Generate a unified diff for one or more files. |
| `eva changes` | Explain unstaged or staged git changes. |
| `eva commit-message` | Generate a concise commit message from a git diff. |
| `eva find` | Find files locally without AI usage. |
| `eva tree` | Print a `.gitignore`-aware directory tree. |
| `eva grep` | Run `ripgrep` through Eva’s CLI. |
| `eva usage` | Show normalized local provider usage counters. |
| `eva providers` | Show provider configuration, model selection, and quotas. |
| `eva doctor` | Check keyring, config, provider registration, API keys, and local tools. |
| `eva config` | Manage provider, model, and API-key configuration. |
| `eva cache clear` | Clear cached AI responses. |

Global options:

```bash
eva --version
eva --verbose ask "Why did this fail?"
```

Verbose mode writes diagnostics to stderr and to Eva’s log file.

## Safety model

`eva work` is intentionally conservative:

- model output must resolve to exactly one command line;
- malformed Markdown fences and trailing explanations are rejected;
- shell operators such as pipes, redirects, command substitution, and chained commands are rejected;
- high-risk patterns such as `sudo`, `rm -rf`, `curl | bash`, `dd`, `mkfs`, recursive ownership changes, and system-path redirects are blocked;
- commands run with `subprocess.run(argv)` rather than `shell=True`;
- unattended execution requires both `--yes` and `EVA_WORK_ASSUME_YES=1`;
- every generated, blocked, declined, or executed command is recorded in an audit log.

This is not a sandbox. Review generated commands and patches before applying them.

## Provider behavior

Eva tries the configured default provider first. If fallback is enabled, it then tries providers in the configured fallback order. Provider failures are logged instead of being silently discarded, and final provider failure messages include a concise summary of what failed.

Configured providers:

- OpenRouter
- Groq
- Gemini
- OpenCode Zen

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
