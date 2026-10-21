#!/usr/bin/env python3
"""Run Eva endpoint triage collectors and aggregate their findings.

The orchestrator discovers the standalone Linux/PowerShell collectors under
`scripts/`, executes the current platform's suite (or a selected subset), saves
each raw report, validates the `eva.triage.v1` contract, and writes a compact
run summary plus a findings JSONL file.

Standard library only. It does not modify endpoint state beyond writing its own
output directory under `.eva/triage/` (or the directory passed to --output).

Examples:
    python scripts/triage_orchestrator.py --list
    python scripts/triage_orchestrator.py --exclude-slow
    python scripts/triage_orchestrator.py --script incident_response.sh --script audit_accounts.sh
    python scripts/triage_orchestrator.py --fail-on high --json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
SCHEMA = "eva.triage.v1"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
SLOW_SCRIPTS = {"detect_rootkits.sh", "package_integrity.sh"}
PLATFORM_GLOBS = {"linux": "linux/*.sh", "windows": "windows/*.ps1"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def decode_output(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if not data:
        return ""
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def script_description(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if path.suffix.lower() == ".ps1":
        match = re.search(r"\.DESCRIPTION\s*(.*?)(?=\n\.PARAMETER|\n#>|$)", text, re.DOTALL)
        if match:
            lines = [line.strip() for line in match.group(1).splitlines() if line.strip()]
            return " ".join(lines[:4])[:300]
        return ""
    lines = []
    for line in text.splitlines()[:25]:
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        content = stripped[1:].strip()
        if not content or set(content) <= {"=", "-"}:
            continue
        if content.lower().startswith(("shellcheck", "copyright", "!")):
            continue
        lines.append(content)
        if len(lines) >= 3:
            break
    return " ".join(lines)[:300]


def discover_scripts(platform_name: str) -> list[dict[str, Any]]:
    pattern = PLATFORM_GLOBS[platform_name]
    scripts: list[dict[str, Any]] = []
    for path in sorted(SCRIPTS_DIR.glob(pattern)):
        if not path.is_file():
            continue
        scripts.append(
            {
                "name": path.name,
                "stem": path.stem,
                "platform": platform_name,
                "path": path,
                "relative_path": str(path.relative_to(REPO_ROOT)),
                "slow": path.name in SLOW_SCRIPTS,
                "description": script_description(path),
            }
        )
    return scripts


def pattern_matches(script: dict[str, Any], patterns: list[str]) -> bool:
    if not patterns:
        return False
    candidates = (
        script["name"],
        script["stem"],
        script["relative_path"],
        str(script["path"]),
    )
    for pattern in patterns:
        if any(fnmatch.fnmatch(candidate, pattern) or candidate == pattern for candidate in candidates):
            return True
    return False


def select_scripts(
    scripts: list[dict[str, Any]],
    include: list[str],
    exclude: list[str],
    exclude_slow: bool,
) -> list[dict[str, Any]]:
    selected = []
    for script in scripts:
        if include and not pattern_matches(script, include):
            continue
        if exclude and pattern_matches(script, exclude):
            continue
        if exclude_slow and script["slow"]:
            continue
        selected.append(script)
    return selected


def resolve_platform(value: str) -> str:
    if value != "auto":
        return value
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    raise SystemExit(f"Unsupported auto platform {platform.system()!r}; pass --platform linux or windows.")


def command_for(script: dict[str, Any]) -> list[str]:
    if script["platform"] == "linux":
        shell = shutil.which("bash") or shutil.which("sh")
        if not shell:
            raise SystemExit("No POSIX shell (bash or sh) was found in PATH.")
        return [shell, str(script["path"])]
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        raise SystemExit("PowerShell (pwsh or powershell) is required for Windows scripts but was not found.")
    return [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script["path"])]


def validate_report(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["report root is not a JSON object"]
    if data.get("schema") != SCHEMA:
        errors.append(f"schema is {data.get('schema')!r}, expected {SCHEMA!r}")
    if not isinstance(data.get("tool"), str) or not data.get("tool", "").strip():
        errors.append("top-level tool is missing")
    host = data.get("host")
    if not isinstance(host, dict) or not str(host.get("hostname") or "").strip():
        errors.append("host.hostname is missing")
    if not isinstance(data.get("collected_at"), str) or not data.get("collected_at"):
        errors.append("collected_at is missing")
    if not isinstance(data.get("findings"), list):
        errors.append("findings is not an array")
        return errors
    for index, item in enumerate(data["findings"]):
        if not isinstance(item, dict):
            errors.append(f"findings[{index}] is not an object")
            continue
        if not item.get("id") or not item.get("title"):
            errors.append(f"findings[{index}] is missing id or title")
        severity = str(item.get("severity") or "").lower()
        if severity not in SEVERITIES:
            errors.append(f"findings[{index}] has invalid severity {item.get('severity')!r}")
    return errors


def prepare_output_dir(requested: str | None) -> Path:
    if requested:
        base = Path(requested).expanduser().resolve()
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = REPO_ROOT / ".eva" / "triage" / timestamp
    candidate = base
    suffix = 1
    while candidate.exists() and any(candidate.iterdir()):
        candidate = base.with_name(f"{base.name}-{suffix}")
        suffix += 1
        if suffix > 1000:
            raise SystemExit(f"Could not find an unused output directory next to {base}")
    candidate.mkdir(parents=True, exist_ok=True)
    try:
        candidate.chmod(0o700)
    except OSError:
        pass
    return candidate


def write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("severity") or "unknown").lower() for item in findings)
    return {name: counts.get(name, 0) for name in SEVERITIES}


def run_script(script: dict[str, Any], output_dir: Path, timeout: int) -> dict[str, Any]:
    command = command_for(script)
    started = time.time()
    timed_out = False
    result: dict[str, Any] = {
        "name": script["name"],
        "relative_path": script["relative_path"],
        "command": command,
        "status": "failed",
        "exit_code": None,
        "duration_seconds": 0.0,
        "findings": 0,
        "severity_counts": {name: 0 for name in SEVERITIES},
        "output_file": "",
        "stderr": "",
        "errors": [],
    }
    try:
        proc = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "EVA_TRIAGE_ORCHESTRATED": "1"},
        )
        stdout = decode_output(proc.stdout)
        stderr = decode_output(proc.stderr)
        result["exit_code"] = proc.returncode
        result["stderr"] = stderr[-2000:]
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        result["status"] = "timeout"
        result["errors"].append(f"script exceeded {timeout}s timeout")
        stdout = decode_output(exc.stdout)
        stderr = decode_output(exc.stderr)
        result["stderr"] = stderr[-2000:]
    except OSError as exc:
        result["errors"].append(f"failed to start script: {exc}")
        result["duration_seconds"] = round(time.time() - started, 3)
        return result
    finally:
        result["duration_seconds"] = round(time.time() - started, 3)

    raw_path = output_dir / f"{script['platform']}-{script['stem']}.json"
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raw_path = output_dir / f"{script['platform']}-{script['stem']}.raw.txt"
        write_private(raw_path, stdout)
        result["output_file"] = str(raw_path)
        if not timed_out:
            result["status"] = "invalid-json"
            result["errors"].append(f"invalid JSON output: {exc.msg} at line {exc.lineno} column {exc.colno}")
        return result

    errors = validate_report(data)
    write_private(raw_path, stdout if stdout.endswith("\n") else stdout + "\n")
    result["output_file"] = str(raw_path)
    findings = data.get("findings", []) if isinstance(data, dict) else []
    if isinstance(findings, list):
        valid_findings = [item for item in findings if isinstance(item, dict)]
        result["findings"] = len(valid_findings)
        result["severity_counts"] = severity_counts(valid_findings)
    if errors:
        result["status"] = "invalid-report"
        result["errors"].extend(errors)
        return result
    if timed_out:
        result["status"] = "timeout"
        return result
    if result["exit_code"] not in (0, None):
        result["status"] = "script-error"
        result["errors"].append(f"script exited with status {result['exit_code']}")
        return result
    result["status"] = "ok"
    return result


def threshold_violation(findings: list[dict[str, Any]], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK.get(str(item.get("severity") or "").lower(), -1) >= threshold for item in findings)


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Eva Endpoint Triage Summary",
        "",
        f"- Collected: {summary['collected_at']}",
        f"- Platform: {summary['platform']}",
        f"- Output directory: `{summary['output_dir']}`",
        f"- Scripts: {summary['scripts_ok']}/{summary['scripts_total']} completed",
        f"- Findings: {summary['findings']}",
        "",
        "## Severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {summary['severity_counts'][severity]} |")
    lines.extend(["", "## Collectors", "", "| Script | Status | Findings | Duration |", "| --- | --- | ---: | ---: |"])
    for script in summary["scripts"]:
        lines.append(
            f"| `{script['name']}` | {script['status']} | {script['findings']} | {script['duration_seconds']:.1f}s |"
        )
    failed = [script for script in summary["scripts"] if script["status"] != "ok"]
    if failed:
        lines.extend(["", "## Collection Errors", ""])
        for script in failed:
            detail = "; ".join(script.get("errors") or []) or "unknown error"
            lines.append(f"- `{script['name']}` ({script['status']}): {detail}")
    top_findings = summary.get("top_findings", [])
    if top_findings:
        lines.extend(["", "## Highest-Severity Findings", "", "| Severity | Title | Source |", "| --- | --- | --- |"])
        for finding in top_findings:
            title = str(finding.get("title", "")).replace("|", "\\|").replace("\n", " ")
            source = str(finding.get("source_report", "")).replace("|", "\\|")
            lines.append(f"| {finding.get('severity', '')} | {title} | `{source}` |")
    lines.extend(
        [
            "",
            "Raw reports are in the output directory. Ingest the reviewed per-script reports with:",
            "",
            "```bash",
            f"eva sec ingest {summary['output_dir']}/{summary['platform']}-*.json",
            "```",
            "",
            "Do not ingest `summary.json`; it is orchestrator metadata, not a triage report.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Eva endpoint triage collectors and aggregate findings.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--platform", choices=("auto", "linux", "windows"), default="auto")
    parser.add_argument("--script", action="append", default=[], help="script name/glob to include (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], help="script name/glob to exclude (repeatable)")
    parser.add_argument("--exclude-slow", action="store_true", help="skip package and rootkit full scans")
    parser.add_argument("--output", help="output directory (default: .eva/triage/<timestamp>)")
    parser.add_argument("--timeout", type=int, default=300, help="per-script timeout in seconds")
    parser.add_argument(
        "--fail-on", choices=("none",) + SEVERITIES, default="none", help="exit non-zero at this severity"
    )
    parser.add_argument("--list", action="store_true", dest="list_scripts", help="list discovered scripts and exit")
    parser.add_argument("--dry-run", action="store_true", help="print commands without executing them")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit the run summary as JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress progress messages")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("--timeout must be positive")

    platform_name = resolve_platform(args.platform)
    scripts = discover_scripts(platform_name)
    selected = select_scripts(scripts, args.script, args.exclude, args.exclude_slow)

    if args.list_scripts:
        payload = [
            {
                "name": script["name"],
                "platform": script["platform"],
                "slow": script["slow"],
                "description": script["description"],
                "path": script["relative_path"],
            }
            for script in selected
        ]
        if args.json_output:
            print(json.dumps({"platform": platform_name, "scripts": payload}, indent=2))
        else:
            print(f"Platform: {platform_name}")
            for script in payload:
                marker = " [slow]" if script["slow"] else ""
                print(f"  {script['name']:<36}{marker} {script['description']}")
        return 0

    if not selected:
        print(f"No scripts matched for platform {platform_name}.", file=sys.stderr)
        return 2

    if args.dry_run:
        commands = []
        for script in selected:
            command = command_for(script)
            commands.append({"name": script["name"], "command": command})
            if not args.json_output:
                print(" ".join(command))
        if args.json_output:
            print(json.dumps({"platform": platform_name, "dry_run": True, "scripts": commands}, indent=2))
        return 0

    try:
        output_dir = prepare_output_dir(args.output)
    except OSError as exc:
        print(f"Cannot create output directory: {exc}", file=sys.stderr)
        return 2

    collected_at = utc_now()
    if not args.quiet:
        print(f"[+] Platform: {platform_name}", file=sys.stderr)
        print(f"[+] Output:   {output_dir}", file=sys.stderr)
        print(f"[+] Running {len(selected)} collector(s)...", file=sys.stderr)

    script_results: list[dict[str, Any]] = []
    aggregate: list[dict[str, Any]] = []
    for index, script in enumerate(selected, start=1):
        if not args.quiet:
            print(f"[{index}/{len(selected)}] {script['name']}", file=sys.stderr, flush=True)
        result = run_script(script, output_dir, args.timeout)
        script_results.append(result)
        if result["status"] == "ok" and result["output_file"]:
            report_path = Path(result["output_file"])
            try:
                report = json.loads(report_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                report = {}
            for finding in report.get("findings", []) if isinstance(report, dict) else []:
                if isinstance(finding, dict):
                    item = dict(finding)
                    item["source_report"] = report_path.name
                    aggregate.append(item)
        if not args.quiet:
            print(
                f"    {result['status']} ({result['findings']} findings, {result['duration_seconds']:.1f}s)",
                file=sys.stderr,
                flush=True,
            )

    aggregate.sort(
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity") or "").lower(), -1),
            str(item.get("rule_id") or ""),
            str(item.get("id") or ""),
        )
    )
    counts = severity_counts(aggregate)
    top_findings = aggregate[:100]
    scripts_ok = sum(1 for result in script_results if result["status"] == "ok")
    failed = [result for result in script_results if result["status"] != "ok"]
    threshold_failed = threshold_violation(aggregate, args.fail_on)
    summary = {
        "schema": "eva.triage.orchestrator.v1",
        "collected_at": collected_at,
        "platform": platform_name,
        "output_dir": str(output_dir),
        "scripts_total": len(script_results),
        "scripts_ok": scripts_ok,
        "scripts_failed": len(failed),
        "findings": len(aggregate),
        "severity_counts": counts,
        "fail_on": args.fail_on,
        "threshold_failed": threshold_failed,
        "scripts": script_results,
        "top_findings": top_findings,
    }

    findings_jsonl = "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=False) for item in aggregate)
    if findings_jsonl:
        findings_jsonl += "\n"
    write_private(output_dir / "findings.jsonl", findings_jsonl)
    write_private(output_dir / "summary.json", json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    write_private(output_dir / "summary.md", render_markdown(summary))

    if args.json_output:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print(file=sys.stderr)
        print(f"[+] Completed {scripts_ok}/{len(script_results)} collector(s)", file=sys.stderr)
        print(f"[+] Findings:   {len(aggregate)} {counts}", file=sys.stderr)
        print(f"[+] Summary:    {output_dir / 'summary.json'}", file=sys.stderr)
        if failed:
            print(f"[!] Collection errors: {len(failed)} (see summary.json)", file=sys.stderr)

    if failed or threshold_failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
