# Eva Sec

`eva sec` is Eva's authorized security assessment and evidence-analysis module. It is designed for local repository checks, defensive media forensics, report normalization, and scoped web-app baseline testing.

Eva Sec does not install third-party tools automatically. Use `eva sec doctor` to see what is available and how to install missing tools.

## Commands

```bash
eva sec doctor
eva sec assess .
eva sec assess . --include-osv --include-syft --format terminal --format sarif
eva sec media analyze ./evidence/photo.jpg
eva sec ingest ./trivy-report.json
eva sec report
eva sec run ./examples/sec/local-repo-assessment.yaml --dry-run
eva sec zap https://staging.example.internal --scope ./examples/sec/scope.yaml --dry-run
```

## Normalized Finding Schema

All imported and generated findings are normalized to:

```text
id, tool, rule_id, title, severity, confidence, category,
file, line_start, line_end, target, evidence,
remediation, references, fingerprint, artifact_path
```

Console output, audit logs, and reports redact common secrets and high-entropy tokens before writing.

## Workflow Format

Security workflows are declarative YAML. They use a reviewed adapter registry rather than arbitrary commands.

```yaml
version: 1
name: secure-repo-assessment
scope: ./scope.yaml
artifacts_dir: .eva/artifacts
steps:
  - uses: trivy.filesystem
    with:
      path: .
      scanners: [vuln, secret, misconfig, license]

  - uses: semgrep.scan
    with:
      path: .
      config: auto

  - uses: gitleaks.scan
    with:
      path: .

  - uses: aegis.analyze
    when: input.evidence_image
    with:
      path: ${input.evidence_image}

  - uses: report.merge
    with:
      format: [terminal, json, markdown, sarif]
```

The workflow validator rejects `command`, `cmd`, `shell`, `bash`, `script`, and `run` keys, as well as pipes, redirects, command substitution, inline shell control syntax, and unknown adapters.

## Scope Files

Local repository scans do not need network authorization. ZAP operations always require a valid scope file.

```yaml
version: 1
engagement_id: local-dev-001
expires_at: 2026-12-31T23:59:59Z
paths:
  - .
web_targets:
  - https://staging.example.internal
allowed_ports: [80, 443]
max_requests_per_second: 2
max_concurrency: 2
max_duration_seconds: 600
allow_active_scanning: false
```

ZAP targets must match the approved scheme, host, port, and path scope. Expired scopes are rejected. Active scanning requires `allow_active_scanning: true`, `--active`, and confirmation unless `--yes` is supplied. `--yes` never bypasses an invalid, absent, or expired scope.

## Aegis Integration (`eva sec media`)

Eva directly vendors and integrates the full feature set from `rootagi/Aegis` directly within the CLI engine under `eva.security_tools.aegis_engine`, providing in-process forensic analysis, steganographic detection and simulation, cryptographic evidence signing, and safe evidence utilities:

### Forensic Analysis & Integrity
- `analyze`: Comprehensive image and media analysis (metadata, ELA, bitplanes, structural anomalies).
- `detect-stego`: Statistical and signature-based steganography detection.
- `scan-structure`: Structural validation and format conformance verification.
- `slice-bitplanes`: Extract and visualize individual RGB bitplanes.
- `extract-hidden`: Extract detected hidden streams or metadata payloads.
- `sanitize`: Strip metadata, GPS coords, ICC profiles, and hidden appended payloads from images.

### Cryptographic Signatures
- `sign` / `verify`: Symmetric HMAC-SHA256 evidence signature creation and verification.
- `keygen`: Generate Ed25519 asymmetric cryptographic keypairs for evidence authentication.
- `sign-asymmetric` / `verify-asymmetric`: Asymmetric Ed25519 evidence signing and verification.

### Steganographic Analysis & Carrier Testing
- `embed` / `extract`: Carrier steganography embedding and extraction.
- `palette-embed` / `palette-extract`: Color-palette steganographic carrier testing.
- `meta-embed` / `meta-extract`: Metadata channel (EXIF, XMP, ICC, GPS) carrier testing.
- `split` / `reconstruct`: Multi-carrier secret splitting across multiple media files.
- `fs-embed` / `fs-extract`: Extended filesystem attribute (xattr) carrier testing.

### Secure File Utilities
- `timestomp`: Clone timestamps between forensic artifacts or sanitize metadata time stamps.
- `shred`: Multi-pass DoD-compliant secure file shredding.

## Defensive YARA Scanning (`eva sec yara`)

Eva provides an integrated defensive YARA engine powered by `yara-python` with compiled rule caching and curated threat detection rules:

### Curated Rule Baseline (`src/eva/security_tools/rules/yara/`)
- `webshells.yar`: Detects PHP, JSP, ASPX webshell execution primitives, `eval(base64_decode(...))`, China Chopper, and command execution backdoors.
- `suspicious_packers.yar`: Signatures for UPX, ASPack, Themida, and PECompact.
- `embedded_pe.yar`: Detects embedded Windows PE executables inside non-executable media and documents (PDF, PNG, JPEG, GIF) with DOS stub validation.
- `obfuscation.yar`: Detects obfuscated PowerShell execution flags (`-w hidden -enc`, `DownloadString`, `IEX`) and base64 encoded binaries.
- `cve_exploits.yar`: Signatures for Log4j JNDI lookups and generic reverse shell commands.

### Commands
```bash
# Scan a directory recursively with default rules and export to SARIF
eva sec yara scan /var/www/html --recursive --format sarif

# Scan with custom rules file
eva sec yara scan /path/to/target --rules /path/to/custom.yar

# Precompile a directory of rules into a fast binary cache
eva sec yara compile src/eva/security_tools/rules/yara -o /tmp/rules.bin

# Scan using the precompiled rules binary
eva sec yara scan /path/to/target --rules /tmp/rules.bin
```

Rule matches are normalized into Eva's unified `Finding` model with severity mapped from YARA metadata tags and evidence detailing matched strings and byte offsets.

## Malware & Binary Static Analysis (`eva sec binary`)

Perform in-depth static analysis of executable binaries, byte distributions, and strings without executing untrusted code:

### ELF Binary Analysis (`eva sec binary elf`)
Extracts ELF headers, machine architecture, entry point, dynamically linked libraries, and dynamic symbols. Audits critical exploit mitigations:
- **Stack Canary**: Detects presence of stack protection guards (`__stack_chk_fail`).
- **RELRO**: Checks for Full RELRO (`BIND_NOW`), Partial RELRO, or None.
- **NX / DEP**: Validates non-executable stack (`GNU_STACK` permissions). Flags $W \oplus X$ violations (executable stacks).
- **PIE**: Validates Position Independent Executable status.

```bash
eva sec binary elf /usr/bin/ls
eva sec binary elf ./custom_daemon --format json
```

### Windows PE Analysis (`eva sec binary pe`)
Extracts DOS/NT headers, machine type, compilation timestamp, image base, entry point, imported DLLs/APIs, exported symbols, and section characteristics.
- Inspects `DllCharacteristics` for ASLR (`DYNAMIC_BASE`) and DEP (`NX_COMPAT`).
- Identifies $W \oplus X$ section violations: flags sections possessing both Read, Write, and Execute permissions (`IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE`).

```bash
eva sec binary pe /path/to/binary.exe
```

### Shannon Entropy Analysis (`eva sec binary entropy`)
Calculates Shannon entropy across uniform byte blocks and sliding windows (0.0 to 8.0 bits per byte).
- Flags high-entropy packed or encrypted regions ($\ge 7.2$ bits/byte) with `entropy.file.packed_encrypted` security findings.
- Handled safely on zero-filled and empty files without division-by-zero errors.

```bash
eva sec binary entropy /path/to/firmware.bin --block-size 1024
```

### Strings & IOC Extraction (`eva sec binary strings`)
Extracts ASCII and UTF-16 LE/BE strings and automatically classifies extracted tokens using defensive regex patterns:
- Public and private IPv4 addresses
- HTTP/HTTPS URLs
- Windows Registry persistence keys (`HKLM\...`, `HKCU\...`)
- PowerShell download cradles and invocation flags
- Unix reverse shell commands (`nc -e`, `sh -i`, `bash -i`)

```bash
eva sec binary strings /path/to/sample.bin --min-len 4
```

## Threat Intelligence & Enrichment (`eva sec intel`)

### Live CVE Enrichment (`eva sec intel cve`)
Queries the official NIST National Vulnerability Database (NVD) API v2 over HTTPS:
- Retrieves vulnerability descriptions, CVSS v3.1 base score, severity ratings, CWE weakness IDs, and affected CPE criteria.
- Validates CVE identifier syntax and normalizes vulnerabilities into unified `Finding` objects.

```bash
eva sec intel cve CVE-2021-44228
eva sec intel cve CVE-2024-3094 --format markdown
```

### Defensive Multi-Feed IOC Enrichment (`eva sec intel ioc`)
Automatically detects IOC type (IPv4, IPv6, Domain, URL, MD5, SHA-256) and queries free/open intelligence feeds (AlienVault OTX, URLhaus, AbuseIPDB, VirusTotal):
- **RFC 1918 Internal Network Protection**: Private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) are automatically protected; external queries to public threat feeds are immediately suppressed to prevent corporate infrastructure leakage.

```bash
eva sec intel ioc 8.8.8.8
eva sec intel ioc 192.168.1.1
eva sec intel ioc example.com
eva sec intel ioc e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Unstructured Log IOC Extraction (`eva sec intel extract`)
Parses raw text, terminal output, or log files, extracting and deduplicating public IPs, internal IPs, domains, URLs, hashes, and CVEs:
- Filters out domain false positives (`localhost`, `.internal`, `.local`) and redacts high-entropy secrets.

```bash
eva sec intel extract /var/log/auth.log
eva sec intel extract "C2 at 198.51.100.22 and http://evil.com/payload"
```

## Cross-Platform Endpoint Triage (`scripts/`)

Eva provides standalone, zero-dependency endpoint triage and hardening audit scripts for Windows and Linux endpoints.

### Windows PowerShell Suite (`scripts/windows/`)
- `Get-HostTriage.ps1`: Collects OS details, listening sockets, active processes, and startup run keys.
- `Audit-SystemHardening.ps1`: Audits UAC, SMBv1, Windows Firewall profiles, and PowerShell script logging.
- `Get-SecurityEvents.ps1`: Queries Event IDs 4624/4625, 4672, 4688, and 7045.
- `Find-SuspiciousPersistence.ps1`: Inspects Run/RunOnce keys, Startup folders, WMI event consumers, and BITS jobs.
- `Audit-UserAccounts.ps1`: Audits local administrators, guest account status, and password policies.
- `Get-NetworkTriage.ps1`: Collects active connections, DNS cache, and hosts file redirects.

### Linux POSIX Shell Suite (`scripts/linux/`)
- `host_triage.sh`: Zero-dependency POSIX script collecting kernel info, active listeners, cron jobs, and systemd timers.
- `audit_hardening.sh`: Inspects SSH daemon configuration, `/etc/login.defs`, sysctl parameters (ASLR, IP forward), and SUID binaries.
- `find_persistence.sh`: Inspects `/etc/ld.so.preload`, `/etc/rc.local`, cron directories, and systemd units for `/tmp` execution.
- `security_events.sh`: Analyzes failed SSH logons and non-root UID 0 accounts.
- `network_triage.sh`: Inspects default route, DNS resolvers, hosts file redirects, and firewall status.

### Unified Ingestion & Reporting
All triage scripts emit valid `eva.triage.v1` JSON. Ingest outputs directly into Eva:

```bash
# Run triage on endpoint
bash scripts/linux/audit_hardening.sh > /tmp/audit.json

# Ingest and normalize into Eva findings
eva sec ingest /tmp/audit.json --format terminal --format markdown --format sarif

# Render consolidated reports across all runs
eva sec report --format markdown --format sarif
```

## ZAP Rules

`eva sec zap` generates or imports an OWASP ZAP Automation Framework YAML plan. The default mode is passive/baseline scanning. Eva does not expose WAF bypass, stealth, brute force, evasion, exploit, or destructive modes.

Rate, concurrency, and duration limits live in the scope file and are included in the generated plan where supported by ZAP automation jobs. Keep ZAP policies conservative for shared staging environments.

## Artifacts and Audit

Each run writes artifacts under:

```text
.eva/artifacts/<run-id>/
```

Eva hashes inputs and generated artifacts with SHA-256 and adds run IDs, scope IDs, tool details, timestamps, artifact paths, and exit status to the existing hash-chained command audit log.

## Security Limitations

Scanner output, source code, media metadata, file content, and web responses are treated as untrusted. Eva Sec does not send evidence file content to remote LLM prompts. It normalizes summaries and redacted findings by default.

Third-party tools are optional. Missing binaries are skipped or reported with install guidance instead of being installed automatically.
