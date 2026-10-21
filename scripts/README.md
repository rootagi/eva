# Eva Endpoint Triage Scripts

Standalone, read-only collectors for Linux and Windows endpoints, plus small Python
utilities for orchestration, validation, and evidence handling. Every collector emits
`eva.triage.v1` JSON that `eva sec ingest` and `eva sec report` understand.

The scripts are intentionally dependency-light: the Linux suite uses POSIX shell and
common system utilities, the Windows suite uses built-in PowerShell/CIM cmdlets, and the
Python tooling uses only the standard library.

## Safety model

- **Read-only:** collectors inspect configuration, processes, logs, packages, and file
  metadata. They do not remove files, change policy, stop services, or execute inspected
  content.
- **Local by default:** nothing is uploaded. The cloud collectors query only link-local
  instance metadata services and emit identity/exposure facts, not secret values.
- **No installation:** missing tools are skipped or reported. Nothing is downloaded or
  installed.
- **Private temporary data:** Linux collectors use `umask 077` and private `mktemp`
  directories with cleanup traps where intermediate files are required.
- **Graceful degradation:** unprivileged runs still produce a report. Checks that need
  root/Administrator may be marked `unknown` or `skipped` instead of being reported as
  healthy.
- **Sensitive output:** reports can contain usernames, paths, command lines, addresses,
  and log excerpts. Treat them as evidence. Evidence bundles are **not encrypted**.
- **Antivirus interoperability:** Windows collectors contain defensive IOC patterns and
  may be flagged by aggressive endpoint security products. The current suite was validated
  with Microsoft Defender real-time protection enabled. If a script is quarantined, review
  it and use a targeted exclusion for the reviewed scripts directory only; do not disable
  real-time protection globally.

Run collectors as root (Linux) or an elevated Administrator (Windows) for full coverage,
but review scripts before use in restricted or regulated environments.

## Validation status

All 16 Windows collectors were executed on a Windows 10 22H2 endpoint (build 19045) with
Windows PowerShell 5.1 and Microsoft Defender enabled. Each collector produced valid
`eva.triage.v1` JSON, and all 16 reports ingested successfully with `eva sec ingest`.
The Windows-specific cmdlet, registry, event log, Defender, and WMI paths are therefore
exercised. Docker Desktop and WSL were not installed on that endpoint, so their
container-specific branches remain best-effort and should be validated on a host where
those features are present.

## JSON contract

Each report contains:

```json
{
  "schema": "eva.triage.v1",
  "tool": "triage-linux-...",
  "collected_at": "2026-10-20T12:00:00Z",
  "host": {"hostname": "endpoint-01"},
  "findings": [],
  "audits": [],
  "checks": []
}
```

`findings` drive severity reporting. `audits` and `checks` preserve pass/fail posture so
ingestion can retain clean-state evidence. See
[`docs/eva-sec.md`](../docs/eva-sec.md#cross-platform-endpoint-triage-scripts) for the
Eva Sec ingestion workflow.

## Linux collectors (`scripts/linux/`)

All scripts are POSIX `sh`-compatible and print JSON to stdout.

| Script | Coverage |
| --- | --- |
| `host_triage.sh` | Kernel, distribution, boot, virtualization, listeners, cron, systemd timers |
| `audit_hardening.sh` | SSH, `login.defs`, PAM, sysctl, SUID binaries, CIS-oriented checks |
| `find_persistence.sh` | Cron, systemd units/timers, init scripts, rc.local, shell profiles, loader preload, authorized keys |
| `security_events.sh` | Authentication failures, sudo activity, wtmp/loginctl sessions |
| `network_triage.sh` | Sockets, routes, DNS resolvers, hosts file, firewall state |
| `incident_response.sh` | Volatile snapshot: host identity, processes, deleted executables, listeners, mounts, kernel taint, recent files |
| `audit_accounts.sh` | Account database, UID 0 and duplicate IDs, password aging, sudoers, privileged groups, SSH keys |
| `analyze_logs.sh` | Auth/web log correlation: brute force, success-after-failure, web attack patterns |
| `detect_rootkits.sh` | Loader/DKMS/module checks, hidden processes, `/proc` anomalies, binary/package integrity, kernel taint |
| `hunt_suspicious_files.sh` | Read-only content and metadata hunting for webshells, download cradles, miners, reverse shells, hidden/temp executables |
| `network_forensics.sh` | Interfaces, promiscuous mode, routes, ARP/neighbors, listeners/connections, DNS, firewall, socket owners |
| `package_integrity.sh` | `dpkg --verify`/`rpm -Va`/`apk audit`, recent system-binary changes, high-risk permissions |
| `cloud_metadata.sh` | AWS/GCP/Azure link-local metadata identity, IMDSv2 posture, user-data presence/hash only |
| `container_triage.sh` | Docker/Podman/containerd exposure, privileged containers, host mounts, Kubernetes service-account clues |

`hunt_suspicious_files.sh` accepts additional web roots through `EVA_WEB_ROOTS`
(space-separated):

```bash
EVA_WEB_ROOTS="/var/www /srv/http" bash scripts/linux/hunt_suspicious_files.sh
```

`detect_rootkits.sh` and `package_integrity.sh` are the slow collectors because they run
full package verification. Skip them during quick sweeps with the orchestrator's
`--exclude-slow` flag.

## Windows collectors (`scripts/windows/`)

Run with Windows PowerShell 5.1 or PowerShell 7+. Scripts write JSON to stdout, or to the
path supplied with `-OutputFile`. File output is UTF-8 **without** a BOM so it can be
consumed by standard JSON parsers; Eva also accepts BOM-prefixed reports from older
collectors.

```powershell
pwsh -NoProfile -File .\Get-HostTriage.ps1 -OutputFile .\host.json
```

| Script | Coverage |
| --- | --- |
| `Get-HostTriage.ps1` | OS, processes, listeners, scheduled tasks, Run keys |
| `Audit-SystemHardening.ps1` | UAC, SMBv1, firewall profiles, PowerShell logging, Credential Guard |
| `Get-SecurityEvents.ps1` | 4624/4625/4672/4688/7045 event review |
| `Find-SuspiciousPersistence.ps1` | Run keys, Startup folders, WMI subscriptions, BITS, Winlogon/AppInit |
| `Audit-UserAccounts.ps1` | Local users, administrators, guest state, password policy, dormant accounts |
| `Get-NetworkTriage.ps1` | Connections, DNS cache, routes, hosts file |
| `Get-IncidentResponse.ps1` | Volatile host/process/network/service snapshot with hashes for suspicious binaries |
| `Get-ProcessTriage.ps1` | Parent/child anomalies, suspicious command lines, user-writable paths, signatures, LSASS/WDigest |
| `Get-Autoruns.ps1` | Extended autostarts: services, scheduled tasks, IFEO, WMI, BITS, logon scripts |
| `Audit-Credentials.ps1` | Account policy, autologon, cached logons, WDigest, LSA/Credential Guard, credential files, SSH key ACLs |
| `Get-LogForensics.ps1` | Security/System/PowerShell/Defender events, brute force, log clearing, 4104 script blocks |
| `Audit-DefenderConfig.ps1` | Defender service and feature state, signature age, ASR, exclusions, recent detections |
| `Get-NetworkForensics.ps1` | Interface/route/neighbor, connections with PID, high-risk ports, hosts hijacks, SMB/RDP/WinRM |
| `Find-Webshells.ps1` | IIS/Apache/PHP roots, execution primitives, encoded payloads, double extensions, file hashes |
| `Get-CloudMetadata.ps1` | AWS/GCP/Azure metadata identity, IMDSv2, user-data hash only, ambient credential variable names |
| `Get-ContainerTriage.ps1` | Docker Desktop/daemon exposure, privileged containers, sensitive mounts, WSL isolation |

Useful parameters:

```powershell
.\Audit-Credentials.ps1 -StaleDays 120 -OutputFile .\credentials.json
.\Get-LogForensics.ps1 -Hours 72 -MaxEvents 500 -OutputFile .\logs.json
.\Find-Webshells.ps1 -Path C:\inetpub\wwwroot,D:\apps -Days 14 -MaxFiles 5000
.\Get-IncidentResponse.ps1 -MaxProcesses 400 -OutputFile .\ir.json
```

On non-Windows hosts the scripts emit a valid fallback report describing unavailable
cmdlets rather than failing to parse. That fallback is useful for syntax checks only; it
does not validate real Windows telemetry.

## Orchestration (`scripts/triage_orchestrator.py`)

Requires Python 3.10+ and runs from the repository root.

```bash
# Discover collectors without running them
python3 scripts/triage_orchestrator.py --list

# Dry run (prints commands, executes nothing)
python3 scripts/triage_orchestrator.py --dry-run --exclude-slow

# Full Linux sweep with per-script timeout and machine-readable summary
python3 scripts/triage_orchestrator.py --output .eva/triage/run-01 --timeout 300 --json

# Selected collectors, fail CI at high severity
python3 scripts/triage_orchestrator.py \
  --script host_triage.sh --script audit_accounts.sh \
  --output .eva/triage/quick --fail-on high
```

Options:

| Option | Purpose |
| --- | --- |
| `--platform {auto,linux,windows}` | Select the collector suite |
| `--script GLOB` | Include matching scripts (repeatable) |
| `--exclude GLOB` | Exclude matching scripts (repeatable) |
| `--exclude-slow` | Skip rootkit and package integrity full scans |
| `--output DIR` | Output directory (a numeric suffix is added if a non-empty directory exists) |
| `--timeout SECONDS` | Per-script timeout, default 300 |
| `--fail-on LEVEL` | Exit non-zero when a finding meets/exceeds `info`…`critical` |
| `--list`, `--dry-run`, `--json`, `--quiet` | Discovery, preview, and output control |

Each run writes:

- `linux-<script>.json` / `windows-<script>.json` — individual ingestable reports
- `findings.jsonl` — flattened findings
- `summary.json` — counts, durations, failures, top findings
- `summary.md` — human-readable summary

Ingest the **individual reports**, not `summary.json`:

```bash
eva sec ingest .eva/triage/run-01/linux-*.json --format markdown --format sarif
eva sec report --format markdown
```

## Validation (`scripts/validate_triage.py`)

Validates schema, required finding fields, severities, timestamps, and optional metadata.

```bash
python3 scripts/validate_triage.py report1.json report2.json
python3 scripts/validate_triage.py .eva/triage/run-01 --strict --json
```

Exit codes: `0` valid, `1` invalid or warnings under `--strict`, `2` usage/IO error.

## Evidence bundles (`scripts/evidence_bundle.py`)

Creates a self-describing tar archive containing the evidence tree, an
`eva.evidence.v1` manifest with per-file SHA-256 hashes, and a detached
`<archive>.sha256` sidecar. The manifest records case ID, examiner, notes, host,
timestamps, and a chain-of-custody entry.

```bash
# Create (refuses to overwrite unless --force)
python3 scripts/evidence_bundle.py create .eva/triage/run-01 \
  --case-id CASE-2026-001 --examiner "A. Analyst" \
  --note "Initial triage" --output evidence/CASE-2026-001.tar.gz

# Verify archive hash, sidecar, manifest and every bundled file
python3 scripts/evidence_bundle.py verify evidence/CASE-2026-001.tar.gz --json

# Inspect metadata without rehashing the archive
python3 scripts/evidence_bundle.py list evidence/CASE-2026-001.tar.gz
```

`verify` detects modified archives, missing sidecars, malformed manifests, path
traversal entries, and per-file hash mismatches. Bundles are **unencrypted**; encrypt
them with your normal evidence-handling tooling before transport or long-term storage.
`create` emits a warning unless `--quiet` is supplied.

## Static checks

```bash
# Shell syntax
for f in scripts/linux/*.sh; do sh -n "$f"; done

# PowerShell parse check (PowerShell 7+)
pwsh -NoProfile -Command '$files = Get-ChildItem scripts/windows/*.ps1; $bad = 0; foreach ($f in $files) { $tokens = $null; $errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs); if ($errs.Count -gt 0) { $bad++; Write-Error "$($f.Name): $($errs[0])" } }; exit $bad'

# Python tooling
python3 -m py_compile scripts/*.py
uv run --extra dev ruff check scripts/
```

`scripts/test_vm_matrix.py` exercises all Linux collectors, the orchestrator, validator,
evidence bundle flow (including tamper detection), and Eva Sec ingestion/reporting on a
Linux host. Run it from the repository root:

```bash
python3 scripts/test_vm_matrix.py
```

The automated matrix does not run PowerShell. The Windows suite was separately validated
on a real Windows 10 22H2 endpoint with PowerShell 5.1 and Defender enabled; see
[Validation status](#validation-status). Re-run the suite on your own Windows build before
relying on it in production, especially when Docker Desktop or WSL is present.
