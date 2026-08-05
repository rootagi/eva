# Security Policy & Hardening Framework

Eva is designed as a safety-conscious command-line intelligence assistant. Security and data privacy are core architectural requirements, not optional add-ons.

---

## 1. Secret & API-Key Redaction

Eva automatically sanitizes text to redact sensitive credentials **before** data is sent over the network to AI providers or saved to local disk (audit logs, terminal replays, workspace session notes, and history).

### Redaction Mechanisms

1. **Regex Pattern Matching**:
   - **OpenAI / Anthropic / OpenRouter Keys**: `sk-[A-Za-z0-9_-]{20,}`
   - **GitHub Access Tokens**: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
   - **GitLab Personal Access Tokens**: `glpat-`
   - **AWS Access Key IDs**: `AKIA[0-9A-Z]{16}`
   - **Slack Tokens**: `xoxb-`, `xoxp-`, `xoxr-`, `xoxa-`, `xoxs-`
   - **Eva Provider Environment Variables**: `EVA_<PROVIDER>_API_KEY=...`
   - **HTTP Auth Headers**: `Bearer ...`, `Basic ...`
   - **Generic Secret Assignments**: `api_key`, `secret`, `password`, `auth_token`, `access_token`
   - **PEM Private Key Blocks**: `-----BEGIN [RSA|EC|DSA|OPENSSH] PRIVATE KEY-----`

2. **Shannon Entropy Analysis**:
   - Evaluates randomness for all strings $\ge 16$ characters using Shannon entropy:
     $$H(S) = -\sum_{i} p(x_i) \log_2 p(x_i)$$
   - Tokens exceeding the entropy threshold ($H(S) > 3.5$ bits/char) are automatically redacted as `[REDACTED_HIGH_ENTROPY]`.

---

## 2. Hash-Chained Audit Log

All executed, blocked, or declined commands generated via `eva work` or `eva workflow` are recorded in an append-only, tamper-evident audit log at `~/.config/eva/command_audit.jsonl`.

### Cryptographic Tamper Detection

Each log record includes a sequence number `seq`, the previous record's hash `prev_hash`, and a SHA-256 signature `hash`:
$$\text{hash}_i = \text{SHA-256}(\text{prev\_hash}_{i-1} \mathbin{:} \text{canonical\_json}(\text{record}_i))$$

- The first record in the chain uses $\text{prev\_hash}_0 = 0^{64}$.
- If an attacker modifies, deletes, or inserts an audit log record, `verify_audit_chain()` detects the cryptographic break and reports the exact sequence number where tampering occurred.

---

## 3. Sandboxed Execution (Opt-In)

Eva supports running potentially risky shell commands inside a restricted subprocess sandbox.

### Sandbox Controls

- **Environment Stripping**: Only explicit safe environment variables (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TMPDIR`, `PWD`) are passed into the process.
- **Input Isolation**: `stdin` is attached to `DEVNULL` to prevent unauthorized interactive sub-shells.
- **Timeout Enforcement**: Standard 30-second execution timeout; processes failing to complete are terminated with SIGKILL.
- **Opt-In Configuration**: Disabled by default to preserve normal user environment behavior. Enable in `~/.config/eva/config.toml`:
  ```toml
  [general]
  sandbox_risky_commands = true
  ```

---

## 4. Telemetry Privacy & Opt-In Policy

Eva includes zero default remote tracking or analytics.

- **Disabled by Default**: `telemetry_enabled = false`.
- **Strict Data Scope**: When explicitly enabled by the user, Eva collects **only**:
  - Provider response latency (seconds)
  - Provider success / failure status
  - Error class names (e.g. `RateLimitError`, `AuthError`)
- **Strict Exclusion**: Prompt text, code snippets, file paths, shell commands, and git diffs are **NEVER** collected or transmitted.

---

## 5. Reporting Vulnerabilities

If you discover a security vulnerability in Eva, please do not open a public GitHub issue. Send a report to rootagi@duck.com or follow responsible disclosure practices.
