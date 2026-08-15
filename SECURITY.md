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

2. **Shannon Entropy Analysis & Path-Aware Tokenization**:
   - Evaluates randomness for string tokens $\ge 16$ characters using Shannon entropy:
     $$H(S) = -\sum_{i} p(x_i) \log_2 p(x_i)$$
   - Paths are tokenized by path separators (`/`) and scored per segment to prevent false positive redactions of structured paths.
   - Tokens exceeding the configurable entropy threshold ($H(S) > 3.5$ bits/char by default) are automatically redacted as `[REDACTED_HIGH_ENTROPY]`.
   - Entropy threshold can be customized via `eva config set-redaction-threshold <val>`.
   - Specific regex patterns can be exempted from entropy redaction via `eva config allow-redaction-pattern <regex>` and `eva config disallow-redaction-pattern <regex>`.

3. **Sensitive File Protection & Overrides**:
   - High-risk credential and configuration files (`.env*`, `*.pem`, `*.key`, `credentials.*`, `secrets.*`, etc.) are blocked by default from indexing, repository packing, and agent file exploration.
   - Persistent allowlist patterns can be configured via `eva config allow-sensitive-file <pattern>` and `eva config disallow-sensitive-file <pattern>`.
   - Per-command overrides can be passed via `--force-include <pattern>` in `eva investigate` and `eva ask --repo`. Every force-included sensitive file access is recorded in the cryptographic audit log as a `sensitive_file_override` event.

---

## 2. Hash-Chained Audit Log

All executed, blocked, or declined commands generated via `eva work` or `eva workflow`, as well as sensitive file overrides (`--force-include`), are recorded in an append-only, tamper-evident audit log at `~/.config/eva/command_audit.jsonl`.


### Cryptographic Tamper Detection

Each log record includes a sequence number `seq`, the previous record's hash `prev_hash`, and a SHA-256 signature `hash`:
$$\text{hash}_i = \text{SHA-256}(\text{prev\_hash}_{i-1} \mathbin{:} \text{canonical\_json}(\text{record}_i))$$

- The first record in the chain uses $\text{prev\_hash}_0 = 0^{64}$.
- If an attacker modifies, deletes, or inserts an audit log record, `verify_audit_chain()` detects the cryptographic break and reports the exact sequence number where tampering occurred.

---

## 3. Command Execution Hardening & Defense in Depth

Eva implements a multi-layered defense-in-depth framework for commands validated and executed via `eva work` and `eva workflow`.

### Hardening Layers

1. **Regex Blast-Radius Denylist**:
   - Hard-blocks high-risk destructive command patterns (e.g. `rm -rf /`, `mkfs`, `dd` targeting block devices, fork bombs, and piping remote scripts into shells like `curl | bash`).
   - *Limitation*: Regex denylists are inherently bypassable (e.g., encoding tricks, unusual whitespace, aliasing, or indirect execution through wrapper scripts). They serve as a baseline safety floor, not a absolute security boundary.

2. **Opt-In Command Allowlist (`allowed_command_prefixes`)**:
   - Restricts command execution to an explicit set of allowed command prefixes (e.g., `git`, `npm`, `ls`, `cat`).
   - Disabled by default (`allowed_command_prefixes = []`). When enabled, any command whose prefix is not in the allowlist is rejected with `AllowlistViolationError`.
   - Managed via CLI (`eva config allow-command`, `eva config disallow-command`, `eva config import-allowlist <path>`) or edited directly in `config.toml`.

3. **Argv-Based Execution (No Shell Default)**:
   - Commands run via `shlex.split` and `shell=False` by default. This eliminates shell metacharacter injection risks (pipes `;`, `|`, `&&`, `$()`).
   - Shell feature evaluation (pipes and redirection) can be re-enabled per invocation using `--allow-shell-features`.

4. **Safety Check Transparency (`--dry-run-explain`)**:
   - Generates a full report of all safety checks (extraction, blast-radius scan, allowlist validation, shlex syntax parsing) before execution, allowing users to inspect exact pass/fail decisions.

5. **Subprocess Sandboxing (Opt-In)**:
   - **Environment Stripping**: Only safe environment variables (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TMPDIR`, `PWD`) are passed into the process.
   - **Input Isolation**: `stdin` attached to `DEVNULL` to prevent unauthorized interactive sub-shells.
   - **Timeout Enforcement**: 30-second execution timeout.
   - Enable via `sandbox_risky_commands = true` in `config.toml`.

### What Is NOT Protected Against

Eva is designed as a user-in-the-loop command generator and validator, not an unconstrained autonomous sandbox. The following security risks remain out of scope for automated validation:

- **Destructive Arguments to Allowed Commands**: If `git` is allowlisted, `git push --force` or `git reset --hard` will be permitted.
- **Arbitrary Code Execution via Allowed Interpreters**: If `python`, `node`, or `bash` are in the allowlist, inline scripts (e.g. `python -c "..."`) can execute arbitrary logic.
- **Time-of-Check to Time-of-Use (TOCTOU) Gaps**: Changes to filesystem state or targets between command inspection and execution.
- **External Network Access**: Allowed network-capable binaries (`curl`, `git fetch`, `npm install`) can make outbound network connections unless restricted at the OS/firewall level.

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

