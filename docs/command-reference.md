# Command Reference

Eva provides a suite of natural language and deterministic local commands. Below is the comprehensive command reference.

---

## AI Intelligence Commands

### `eva ask`
Ask a one-shot question to the LLM, optionally passing local files or directories as context.

```bash
# Basic question
eva ask "Explain the difference between a process and a thread"

# Include file context
eva ask "What does this module do?" --file src/eva/cli.py

# Include multiple file contexts
eva ask "Compare these modules" --file src/eva/cli.py --file src/eva/config.py

# Include directory context (respects .gitignore)
eva ask "Where should I add a new provider?" --dir src/eva

# Pack entire repository context up to provider budget (with dry-run summary)
eva ask "Explain codebase architecture" --repo . --dry-run

# Pack entire repository context and skip confirmation prompt
eva ask "Find architectural flaws" --repo . --yes

# Bypass response cache
eva ask "Why did this fail?" --no-cache
```

### `eva investigate`
Agentic, multi-turn, query-driven repository exploration (Codex/Claude Code-style). The LLM receives the question first and actively calls read-only tools (`list_directory`, `read_file`, `search_code`) to inspect relevant files before delivering a final answer.

```bash
# Agentic repo investigation
eva investigate "Find how CLI commands are registered and explain the app flow" . --yes

# Custom turn cap and provider
eva investigate "Trace where budget limits are checked" . --max-turns 10 --provider groq --yes
```

#### Comparison: `eva investigate` vs `eva ask --repo`
| Feature | `eva ask --repo` | `eva investigate` |
| :--- | :--- | :--- |
| **Execution Model** | Single-pass context dump | Multi-turn iterative tool calling |
| **Context Selection** | Query-blind (dependency centrality, file size) | Query-driven (model decides what to read) |
| **Tool Calling** | None | `list_directory`, `read_file`, `search_code` |
| **Token Usage** | Pre-packs files up to token budget | Reads only files needed for the query |
| **Supported Providers** | All providers | Tool-capable providers (`groq`, `openrouter`, `opencode_zen`, `gemini`) |

### `eva explain`
Explain a file, concept, or repository with automatic stack detection and module dependency graph extraction.

```bash
eva explain src/eva/router
```

### `eva analyze`
Analyze piped terminal output from stdin. Useful for diagnostic analysis of test failures or build logs.

```bash
pytest -q | eva analyze "Summarize the test failures and root cause"
```

### `eva chat`
Run an interactive session chat with persistent memory and session state.

```bash
# Start or attach to a named chat session
eva chat --session refactor-router

# Resume a previous session
eva chat --session refactor-router --resume
```

### `eva work`
Generate and optionally execute a single safe local command from natural language input.

```bash
# Dry run command generation with safety scan
eva work "list the largest files in this repository" --dry-run

# Full safety check transparency report
eva work "find all TODO comments" --dry-run-explain

# Re-enable shell feature evaluation (pipes / redirects)
eva work "find top memory using processes" --allow-shell-features
```

### `eva edit`
Generate a reviewable unified diff patch for one or more files based on desired modifications.

```bash
# Generate patch
eva edit "add validation for empty provider names" --file src/eva/cli.py

# Apply generated patch directly after confirmation
eva edit "add validation for empty provider names" --file src/eva/cli.py --apply
```

---

## Workflow & Workspace Management

### `eva workflow`
Declarative multi-step YAML workflow execution with human approval gates.

| Subcommand | Description |
| --- | --- |
| `eva workflow run <name>` | Execute a declarative multi-step workflow step-by-step. |
| `eva workflow run <name> -y` | Auto-approve all steps (useful for piping / CI). |
| `eva workflow list` | List available built-in and custom user workflows. |
| `eva workflow show <name>` | Display workflow steps and commands without running them. |

### `eva workspace`
Manage isolated session workspaces, notes, bookmarks, and activity tracking.

```bash
eva workspace create feature-auth   # Create isolated workspace
eva workspace switch feature-auth   # Switch active workspace
eva workspace list                 # List all session workspaces
eva workspace note "Check JWT key" # Add note (auto-redacts secrets)
eva workspace bookmark src/auth.py # Bookmark file or URL
eva workspace show                 # Show workspace history & notes
```

### `eva replay`
Replay recorded terminal execution sessions with step controls.

```bash
eva replay --list
eva replay session-2026-08-10
```

---

## Git Intelligence Commands

### `eva changes`
Explain unstaged or staged git diff changes.

```bash
eva changes
eva changes --staged
```

### `eva commit-message`
Generate a concise, conventional git commit message from staged changes.

```bash
git add .
eva commit-message
```

---

## Deterministic Local Commands (Zero Quota)

These utility commands run 100% locally and consume no LLM provider quota.

| Command | Purpose |
| --- | --- |
| `eva find "<pattern>"` | Fast local file matching. |
| `eva tree [dir]` | Print a `.gitignore`-aware directory tree. |
| `eva usage` | View local provider RPM and RPD usage counters. |
| `eva cache clear` | Clear cached LLM response objects. |

---

## Configuration Commands

```bash
eva config set-key <provider>               # Store key in OS keyring
eva config remove-key <provider>            # Remove key from OS keyring
eva config set-model <provider> <model>     # Configure default model for provider
eva config doctor                           # Run diagnostic health check on environment
eva config allow-command <prefix>           # Add command prefix to execution allowlist
eva config disallow-command <prefix>        # Remove command prefix from execution allowlist
eva config import-allowlist <path>          # Import allowlist from a file
```

---

## Shell & Global Options

```bash
eva --version                               # Print Eva version
eva --verbose ask "Why did this fail?"      # Enable verbose diagnostics logging
eva --install-completion                    # Install shell completion (bash/zsh/fish)
eva --show-completion                       # Print shell completion script
```

Verbose mode writes diagnostics to stderr and to Eva's log file.
