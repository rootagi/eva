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

[providers.groq]
model = "llama-3.3-70b-versatile"
temperature = 0.2

[providers.openrouter]
model = "anthropic/claude-3.5-sonnet"
temperature = 0.2
```

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
```
