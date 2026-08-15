# Configuration & Environment

Eva provides flexible configuration options via command-line utilities, local configuration files, environment variables, and native OS keyring backends.

---

## Setting Active Provider & Keys

### Active Provider Selection

Select the primary LLM provider for queries:

```bash
eva use groq
```

### Storing Credentials via OS Keyring

Eva uses the OS keyring (Keychain on macOS, Secret Service/KWallet on Linux, Credential Manager on Windows) to securely store API keys without storing plain text on disk:

```bash
eva config set-key groq
eva config set-key openrouter
eva config set-key gemini
eva config set-key opencode_zen
```

To remove a stored key from the keyring:

```bash
eva config remove-key groq
```

---

## Headless & CI Environments

In headless environments (Docker containers, SSH servers, GitHub Actions CI runners) where an OS keyring is unavailable, configure keys using environment variables:

```bash
export EVA_GROQ_API_KEY="gsk_..."
export EVA_OPENROUTER_API_KEY="sk-or-v1-..."
export EVA_GEMINI_API_KEY="AIzaSy..."
export EVA_OPENCODE_ZEN_API_KEY="zen_..."
```

---

## Configuration File (`config.toml`)

Global user configurations are stored in `~/.config/eva/config.toml`:

```toml
default_provider = "groq"
fallback_order = ["groq", "openrouter", "gemini", "opencode_zen"]
telemetry_enabled = false
sandbox_risky_commands = true
allowed_command_prefixes = ["git", "npm", "cargo", "pytest", "ls"]

# v4.3.1 Configurability Options:
redaction_entropy_threshold = 3.5          # Default: 3.5 bits/char (0.0 to 8.0)
redaction_ignore_patterns = ["^SAFE_.*"]  # Regex patterns exempt from secret redaction
extra_ignored_dirs = ["build_scratch"]    # Additional directories to exclude from indexing
unignore_dirs = []                        # Directories to unignore from default ignore list
sensitive_file_allowlist = ["*.staging.env"] # Glob patterns exempt from sensitive file denylist
context_token_limit = 4000                # Optional context budget token limit override (null = provider default)

[providers.groq]
model = "llama-3.3-70b-versatile"
temperature = 0.2

[providers.openrouter]
model = "anthropic/claude-3.5-sonnet"
temperature = 0.2
```

---

## Secret Redaction & Shannon Entropy Tuning

Eva features a two-layer secret redaction engine: deterministic regex pattern matching and Shannon entropy analysis. You can tune the sensitivity or exempt specific token patterns without disabling safety defaults:

### Setting Entropy Threshold
```bash
# Set entropy threshold (default: 3.5 bits/char; 8.0 disables entropy-based redaction)
eva config set-redaction-threshold 4.0
```

### Redaction Ignore Patterns
Exempt specific safe tokens or environment variable prefixes from redaction:
```bash
eva config allow-redaction-pattern "^CUSTOM_SAFE_PREFIX_.*"
eva config disallow-redaction-pattern "^CUSTOM_SAFE_PREFIX_.*"
```

---

## Ignored Directories Overrides

By default, Eva automatically ignores standard heavy and cache directories (`.git`, `node_modules`, `__pycache__`, `.venv`, `.eva`, etc.) during file discovery and repo-wide packing:

```bash
# Add custom directory to process-wide ignored directories
eva config ignore-dir build_artifacts

# Unignore a previously ignored directory
eva config unignore-dir build_artifacts
```

---

## Sensitive File Allowlist & Overrides

Eva protects credentials by denylisting sensitive file types (`.env`, `*.pem`, `*.key`, `secrets.*`, `credentials.json`, `id_rsa*`). You can allowlist non-secret template files or override on a per-command basis:

### Persistent Allowlist
```bash
# Add glob pattern to sensitive file allowlist
eva config allow-sensitive-file "*.staging.env"

# Remove glob pattern from allowlist
eva config disallow-sensitive-file "*.staging.env"
```

### Per-Command `--force-include`
For one-off agentic investigations or repo packing involving specific files:
```bash
eva investigate "Analyze certificate configuration" . --force-include server.pem --yes
eva ask "Inspect staging environment" --repo . --force-include .env.staging --yes
```
> **Audit Note:** Every use of `--force-include` on a denylisted file is automatically recorded in the SHA-256 hash-chained audit log with action `sensitive_file_override`.

---

## Air-Gapped & Offline Tokenization

By default, Eva uses `tiktoken` for accurate BPE token counting. In restricted-network or air-gapped environments where the BPE vocabulary file cannot be downloaded:

- Eva automatically falls back to a `len(text) // 4` character-based approximation.
- A single `WARNING` log is emitted on first fallback; subsequent calls are silent.

For fully offline deployments, pre-download the vocabulary and set:

```bash
export EVA_TIKTOKEN_ENCODING_PATH="/path/to/cl100k_base.tiktoken"
```

Or in `config.toml`:

```toml
tiktoken_encoding_path = "/path/to/cl100k_base.tiktoken"
```

---

## Command Allowlist Configuration

The command allowlist restricts which commands `eva work` and `eva workflow` can execute. When empty (default), only the denylist is active.

```toml
allowed_command_prefixes = ["git", "npm", "cargo", "pytest", "ls", "cat"]
```

Manage via CLI:

```bash
eva config allow-command git
eva config allow-command npm
eva config disallow-command rm
eva config import-allowlist ./my-allowlist.txt
```

---

## Health Diagnostics (`eva config doctor`)

Run diagnostic verification on keyring integration, provider availability, environment variables, network connectivity, and cache state:

```bash
eva config doctor
```

Sample output:

```text
[✓] OS Keyring Backend: SecretService (Available)
[✓] Config File: ~/.config/eva/config.toml (Valid)
[✓] Provider Key 'groq': Configured via Keyring
[✓] Provider Key 'openrouter': Configured via Environment Variable
[!] Provider Key 'gemini': Missing key (Fallback active)
[✓] Audit Log: Hash Chain Intact (0 breaks detected)
[✓] Tiktoken: Encoding loaded (cl100k_base)
```

---

## Model Selection

Specify active models per provider:

```bash
eva config set-model groq llama-3.3-70b-versatile
eva config set-model openrouter anthropic/claude-3.5-sonnet
eva config set-model opencode_zen nemotron-3.5-lightning-free
```

