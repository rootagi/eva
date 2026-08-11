# Security Model & Hardening Framework

Eva is designed with security and data privacy as core architectural invariants. The framework incorporates multi-layered defense-in-depth mechanisms for secret handling, command verification, log integrity, and environment isolation.

---

## 1. Secret & API-Key Redaction

Eva automatically redacts sensitive credentials **before** data is transmitted to remote AI providers or written to local disk (audit logs, replays, workspace session notes, and caches).

### Redaction Mechanisms

1. **Regex Pattern Matching**:
   - **OpenAI / Anthropic / OpenRouter Keys**: `sk-[A-Za-z0-9_-]{20,}`
   - **GitHub Access Tokens**: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
   - **GitLab Access Tokens**: `glpat-`
   - **AWS Access Key IDs**: `AKIA[0-9A-Z]{16}`
   - **Slack Tokens**: `xoxb-`, `xoxp-`, `xoxr-`, `xoxa-`, `xoxs-`
   - **Eva Provider Keys**: `EVA_<PROVIDER>_API_KEY=...`
   - **HTTP Auth Headers**: `Bearer ...`, `Basic ...`
   - **Generic Secret Assignments**: `api_key`, `secret`, `password`, `auth_token`, `access_token`
   - **PEM Private Key Blocks**: `-----BEGIN [RSA|EC|DSA|OPENSSH] PRIVATE KEY-----`

2. **Shannon Entropy Analysis**:
   For any string `S` with length >= 16 characters, Eva calculates its Shannon entropy:

   `H(S) = - ∑ p(x) * log2(p(x))`

   Tokens exceeding the threshold (entropy > 3.5 bits/character) are automatically redacted as `[REDACTED_HIGH_ENTROPY]`.

### Sensitive-File Denylist (Repo Context Packing)

Because `.gitignore` is not a security boundary, repository context packing (`eva ask --repo`) applies an explicit built-in denylist (`DENYLIST_PATTERNS`) **before** file contents are read, regardless of `.gitignore` state:

- **Environment Files**: `.env`, `.env.*`, `*.env`
- **Private Keys & Certificates**: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`
- **SSH Keys**: `id_rsa*`, `id_dsa*`, `id_ecdsa*`, `id_ed25519*`
- **Known Credentials & Tokens**: `credentials.json`, `credentials.*`, `secrets.*`, `.netrc`, `.npmrc`, `.pypirc`, `*.tfvars`

This denylist is applied as defense-in-depth alongside automatic text secret redaction (`redact_secrets`), which remains active on all packed text before provider transmission.

---

## 2. Hash-Chained Audit Log

All command generation events via `eva work` or `eva workflow` are recorded in an append-only, tamper-evident audit log located at `~/.config/eva/command_audit.jsonl`.

### Cryptographic Tamper Detection

Each record contains a sequence number `seq`, the previous record's hash `prev_hash`, and a SHA-256 signature `hash`:

`hash_i = SHA-256(prev_hash_(i-1) : canonical_json(record_i))`

- Genesis record starts with `prev_hash_0 = 0^64`.
- Any modification, deletion, or insertion of audit records breaks the SHA-256 hash chain and is detected by `eva config doctor`.

---

## 3. Command Execution Hardening & Defense in Depth

Eva implements a multi-layered defense-in-depth framework for commands validated and executed via `eva work` and `eva workflow`.

### Hardening Layers

1. **Argv-Based Execution (`shell=False`)**:
   Commands are parsed into argument arrays via `shlex.split` and executed directly without a shell interpreter, eliminating shell injection attacks (`|`, `;`, `&&`, `$()`).

2. **Regex Blast-Radius Denylist**:
   Blocks destructive commands (e.g., `rm -rf /`, `mkfs`, `dd`, `curl | bash`).

3. **Opt-In Command Allowlist**:
   When `allowed_command_prefixes` is set in `config.toml`, only explicit allowed binaries (e.g., `git`, `npm`, `pytest`) can run. Managed via `eva config allow-command` and `eva config disallow-command`.

4. **Safety Check Transparency (`--dry-run-explain`)**:
   Generates a detailed report of all safety check results before execution:

   ```bash
   eva work "find all TODO comments" --dry-run-explain
   ```

   Output includes: extraction result, blast-radius scan pass/fail, allowlist validation, and shlex syntax parsing status.

5. **Subprocess Sandboxing**:
   Optional sandboxing (`sandbox_risky_commands = true`) strips non-essential environment variables, sets `stdin=DEVNULL`, and enforces a 30-second timeout.

### What Is NOT Protected Against

- **Destructive Arguments to Allowed Commands**: If `git` is allowlisted, `git push --force` will be permitted.
- **Arbitrary Code Execution via Interpreters**: If `python` is allowlisted, `python -c "..."` can execute arbitrary logic.
- **TOCTOU Gaps**: Changes between command inspection and execution.
- **External Network Access**: Allowed network-capable binaries can make outbound connections.

---

## 4. Zero-Telemetry Policy

Eva operates under a strict opt-in telemetry policy (`telemetry_enabled = false` by default).

- **No Remote Telemetry by Default**: Zero analytics transmitted.
- **Strict Data Scope**: When enabled, only provider latency, success/failure status, and error class names are collected.
- **Strict Exclusion**: Prompt text, code snippets, file contents, terminal output, and shell commands are **never** collected under any circumstances.

---

## 5. Reporting Vulnerabilities

If you discover a security vulnerability in Eva, please do not open a public GitHub issue. Send a report to rootagi@duck.com or follow responsible disclosure practices.
