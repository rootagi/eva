"""Endpoint triage orchestrator and report validator for Eva."""

from __future__ import annotations

import argparse
import fnmatch
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA = "eva.triage.v1"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
CONFIDENCES = ("low", "medium", "high")
SLOW_SCRIPTS = {"detect_rootkits.sh", "package_integrity.sh"}
PLATFORM_GLOBS = {"linux": "linux/*.sh", "windows": "windows/*.ps1"}
FINGERPRINT_RE = re.compile(r"^[A-Fa-f0-9]{8,128}$")
REQUIRED_FINDING_STRINGS = ("id", "rule_id", "title", "category", "evidence", "remediation")
OPTIONAL_FINDING_STRINGS = ("file", "target", "tool")


@dataclass
class FileResult:
    path: str
    valid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    tool: str = ""
    hostname: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "valid": self.valid,
            "tool": self.tool,
            "hostname": self.hostname,
            "findings": self.findings,
            "severity_counts": self.severity_counts,
            "errors": self.errors,
            "warnings": self.warnings,
        }


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


def detect_platform() -> str:
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    return "linux"


def default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(".eva") / "triage" / stamp


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(f"{path.suffix}.tmp.{os.getpid()}")
    try:
        temp_path.write_text(content, encoding="utf-8")
        try:
            temp_path.chmod(0o600)
        except OSError:
            pass
        temp_path.replace(path)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def discover_collectors(platform_name: str, scripts_dir: Path | None = None) -> list[dict[str, Any]]:
    """Discover available collector scripts for the given platform."""
    pattern = PLATFORM_GLOBS.get(platform_name)
    if not pattern:
        return []

    candidate_dirs: list[Path] = []
    if scripts_dir:
        candidate_dirs.append(scripts_dir.resolve())
    candidate_dirs.append(Path(__file__).resolve().parent / "triage_scripts")
    candidate_dirs.append(Path.cwd() / "scripts")

    seen_names: set[str] = set()
    found: list[dict[str, Any]] = []

    for base_dir in candidate_dirs:
        if not base_dir.is_dir():
            continue
        for path in sorted(base_dir.glob(pattern)):
            if not path.is_file() or path.name in seen_names:
                continue
            seen_names.add(path.name)
            interpreter = "powershell" if path.suffix.lower() == ".ps1" else "bash"
            found.append(
                {
                    "name": path.name,
                    "relpath": str(path.relative_to(base_dir)),
                    "path": path,
                    "interpreter": interpreter,
                    "platform": platform_name,
                    "is_slow": path.name in SLOW_SCRIPTS,
                }
            )
    return found


discover_scripts = discover_collectors


def select_collectors(
    scripts: list[dict[str, Any]],
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    exclude_slow: bool = False,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    include_patterns = [pat.strip() for pat in (include or []) if pat.strip()]
    exclude_patterns = [pat.strip() for pat in (exclude or []) if pat.strip()]

    for script in scripts:
        name = script["name"]
        relpath = script["relpath"]
        if exclude_slow and script.get("is_slow"):
            continue
        if include_patterns and not any(
            fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(relpath, pat) or pat in (name, relpath)
            for pat in include_patterns
        ):
            continue
        if exclude_patterns and any(
            fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(relpath, pat) or pat in (name, relpath)
            for pat in exclude_patterns
        ):
            continue
        selected.append(script)
    return selected


select_scripts = select_collectors


def resolve_powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def build_command(script: dict[str, Any]) -> list[str]:
    path_str = str(script["path"])
    interpreter = script["interpreter"]
    if interpreter == "powershell":
        binary = resolve_powershell()
        if not binary:
            raise FileNotFoundError("PowerShell (pwsh or powershell) not found on PATH")
        return [binary, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path_str]
    bash_bin = shutil.which("bash") or "bash"
    return [bash_bin, path_str]


def validate_report_json(data: Any, path: Path | str) -> tuple[bool, list[str]]:
    result = validate_triage_document(data, path=str(path))
    return result.valid, result.errors


def run_collector(script: dict[str, Any], output_dir: Path, timeout: int = 180) -> dict[str, Any]:
    name = script["name"]
    stem = script["path"].stem
    started = time.time()
    result: dict[str, Any] = {
        "name": name,
        "path": str(script["path"]),
        "platform": script["platform"],
        "status": "error",
        "exit_code": None,
        "duration_seconds": 0.0,
        "findings": 0,
        "output_file": None,
        "raw_file": None,
        "errors": [],
    }

    try:
        cmd = build_command(script)
    except FileNotFoundError as exc:
        result["errors"].append(str(exc))
        result["duration_seconds"] = round(time.time() - started, 3)
        return result

    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["errors"].append(f"collector timed out after {timeout} seconds")
        result["duration_seconds"] = round(time.time() - started, 3)
        return result
    except OSError as exc:
        result["errors"].append(f"failed to spawn collector: {exc}")
        result["duration_seconds"] = round(time.time() - started, 3)
        return result

    result["duration_seconds"] = round(time.time() - started, 3)
    result["exit_code"] = proc.returncode
    stdout_text = decode_output(proc.stdout).strip()
    stderr_text = decode_output(proc.stderr).strip()

    if stderr_text:
        result["stderr_snippet"] = stderr_text[:500]

    raw_path = output_dir / f"{stem}.raw.txt"
    if stderr_text or proc.returncode != 0:
        raw_content = f"=== STDOUT ===\n{stdout_text}\n=== STDERR ===\n{stderr_text}\n"
        write_private(raw_path, raw_content)
        result["raw_file"] = str(raw_path)

    if not stdout_text:
        result["errors"].append("collector emitted empty stdout")
        return result

    try:
        parsed = json.loads(stdout_text)
    except json.JSONDecodeError as exc:
        result["errors"].append(f"stdout is not valid JSON: {exc}")
        if not result["raw_file"]:
            write_private(raw_path, stdout_text)
            result["raw_file"] = str(raw_path)
        return result

    valid, errors = validate_report_json(parsed, output_dir / f"{stem}.json")
    if not valid:
        result["errors"].extend(errors)
        if not result["raw_file"]:
            write_private(raw_path, stdout_text)
            result["raw_file"] = str(raw_path)
        return result

    out_json = output_dir / f"{stem}.json"
    write_private(out_json, json.dumps(parsed, indent=2, ensure_ascii=False) + "\n")
    result["output_file"] = str(out_json)
    result["findings"] = len(parsed.get("findings", []))
    result["status"] = "ok" if proc.returncode == 0 else "collector_nonzero_exit"
    return result


run_script = run_collector


def threshold_violation(findings: list[dict[str, Any]], fail_on: str) -> bool:
    if not fail_on or fail_on == "none":
        return False
    threshold_rank = SEVERITY_RANK.get(fail_on.lower())
    if threshold_rank is None:
        return False
    for finding in findings:
        sev = str(finding.get("severity") or "").lower()
        rank = SEVERITY_RANK.get(sev, -1)
        if rank >= threshold_rank:
            return True
    return False


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for finding in findings:
        sev = str(finding.get("severity") or "").lower()
        if sev in SEVERITY_RANK:
            counts[sev] += 1
        else:
            counts["unknown"] += 1
    return {name: counts.get(name, 0) for name in SEVERITIES}


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# Eva Triage Summary — {summary.get('collected_at', '')}",
        "",
        f"- **Platform:** {summary.get('platform')}",
        f"- **Output directory:** `{summary.get('output_dir')}`",
        f"- **Collectors run:** {summary.get('scripts_ok')}/{summary.get('scripts_total')} OK",
        f"- **Total findings:** {summary.get('findings')}",
        "",
        "## Severity Breakdown",
        "",
    ]
    counts = summary.get("severity_counts", {})
    for sev in SEVERITIES:
        lines.append(f"- **{sev.upper()}:** {counts.get(sev, 0)}")
    lines.append("")
    lines.append("## Collectors")
    lines.append("")
    for s in summary.get("scripts", []):
        lines.append(
            f"- `{s.get('name')}`: {s.get('status')} ({s.get('findings', 0)} findings, {s.get('duration_seconds', 0)}s)"
        )
    return "\n".join(lines) + "\n"


def run_triage(
    platform_name: str | None = None,
    scripts: list[str] | None = None,
    exclude: list[str] | None = None,
    exclude_slow: bool = False,
    output_dir: Path | None = None,
    timeout: int = 180,
    fail_on: str = "none",
    dry_run: bool = False,
    scripts_dir: Path | None = None,
) -> dict[str, Any]:
    """Execute triage suite and return summary dictionary with schema 'eva.triage.orchestrator.v1'."""
    platform_val = platform_name if platform_name and platform_name != "auto" else detect_platform()
    out_dir = (output_dir or default_output_dir()).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    available = discover_collectors(platform_val, scripts_dir=scripts_dir)
    selected = select_collectors(available, include=scripts, exclude=exclude, exclude_slow=exclude_slow)

    if dry_run:
        return {
            "schema": "eva.triage.orchestrator.v1",
            "collected_at": utc_now(),
            "platform": platform_val,
            "output_dir": str(out_dir),
            "scripts_total": len(selected),
            "scripts_ok": len(selected),
            "scripts_failed": 0,
            "findings": 0,
            "severity_counts": {s: 0 for s in SEVERITIES},
            "fail_on": fail_on,
            "threshold_failed": False,
            "scripts": [{"name": s["name"], "status": "dry_run", "path": str(s["path"])} for s in selected],
            "top_findings": [],
        }

    script_results: list[dict[str, Any]] = []
    aggregate: list[dict[str, Any]] = []

    for s in selected:
        res = run_collector(s, out_dir, timeout=timeout)
        script_results.append(res)
        if res["status"] == "ok" and res["output_file"]:
            try:
                report = json.loads(Path(res["output_file"]).read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                report = {}
            for finding in report.get("findings", []) if isinstance(report, dict) else []:
                if isinstance(finding, dict):
                    item = dict(finding)
                    item["source_report"] = Path(res["output_file"]).name
                    aggregate.append(item)

    aggregate.sort(
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity") or "").lower(), -1),
            str(item.get("rule_id") or ""),
            str(item.get("id") or ""),
        )
    )
    counts = severity_counts(aggregate)
    scripts_ok = sum(1 for r in script_results if r["status"] == "ok")
    failed = [r for r in script_results if r["status"] != "ok"]
    th_failed = threshold_violation(aggregate, fail_on)

    summary = {
        "schema": "eva.triage.orchestrator.v1",
        "collected_at": utc_now(),
        "platform": platform_val,
        "output_dir": str(out_dir),
        "scripts_total": len(script_results),
        "scripts_ok": scripts_ok,
        "scripts_failed": len(failed),
        "findings": len(aggregate),
        "severity_counts": counts,
        "fail_on": fail_on,
        "threshold_failed": th_failed,
        "scripts": script_results,
        "top_findings": aggregate[:100],
    }

    findings_jsonl = "\n".join(json.dumps(item, ensure_ascii=False) for item in aggregate)
    if findings_jsonl:
        findings_jsonl += "\n"
    write_private(out_dir / "findings.jsonl", findings_jsonl)
    write_private(out_dir / "summary.json", json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    write_private(out_dir / "summary.md", render_markdown(summary))

    return summary


# ===========================================================================
# Schema & Report Validation (eva.triage.v1)
# ===========================================================================


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _check_string(
    item: dict[str, Any],
    key: str,
    index: int,
    errors: list[str],
    warnings: list[str],
    required: bool,
) -> None:
    value = item.get(key)
    if value is None or value == "":
        message = f"findings[{index}] is missing {key!r}"
        if required:
            errors.append(message)
        else:
            warnings.append(message)
    elif not isinstance(value, str):
        errors.append(f"findings[{index}].{key} must be a string")


def _parse_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def validate_triage_document(data: Any, path: str = "", strict: bool = False) -> FileResult:
    """Validate a document against schema eva.triage.v1."""
    result = FileResult(path=path)
    if not isinstance(data, dict):
        result.errors.append("report root must be a JSON object")
        return result

    schema = data.get("schema")
    if schema != SCHEMA:
        if data.get("kind") == "eva-triage":
            result.warnings.append(f"schema is {schema!r}; kind='eva-triage' is accepted by Eva")
        else:
            result.errors.append(f"schema must be {SCHEMA!r}, got {schema!r}")

    tool = data.get("tool")
    if _is_text(tool):
        result.tool = str(tool).strip()
    else:
        result.errors.append("top-level 'tool' must be a non-empty string")

    host = data.get("host")
    if not isinstance(host, dict):
        result.errors.append("top-level 'host' must be an object")
    else:
        hostname = host.get("hostname")
        if _is_text(hostname):
            result.hostname = str(hostname).strip()
        else:
            result.errors.append("host.hostname must be a non-empty string")

    if not _parse_timestamp(data.get("collected_at")):
        result.errors.append("collected_at must be an ISO-8601 timestamp")

    metrics = data.get("metrics")
    if metrics is not None and not isinstance(metrics, dict):
        result.errors.append("metrics must be an object when present")

    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list):
        result.errors.append("top-level 'findings' must be an array")
        return result

    result.findings = len(raw_findings)
    severities: Counter[str] = Counter()
    ids: dict[str, int] = {}
    fingerprints: dict[str, int] = {}

    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            result.errors.append(f"findings[{index}] must be an object")
            continue

        for key in REQUIRED_FINDING_STRINGS:
            _check_string(item, key, index, result.errors, result.warnings, required=True)
        for key in OPTIONAL_FINDING_STRINGS:
            value = item.get(key)
            if value is None or value == "":
                if key in {"target", "tool"}:
                    result.warnings.append(f"findings[{index}] is missing optional {key!r}")
                continue
            if not isinstance(value, str):
                result.errors.append(f"findings[{index}].{key} must be a string")

        severity = item.get("severity")
        if not _is_text(severity):
            result.errors.append(f"findings[{index}].severity is required")
        else:
            normalized_severity = str(severity).strip().lower()
            if normalized_severity not in SEVERITIES:
                result.errors.append(f"findings[{index}].severity {severity!r} must be one of {', '.join(SEVERITIES)}")
            else:
                severities[normalized_severity] += 1

        confidence = item.get("confidence")
        if confidence is None:
            result.warnings.append(f"findings[{index}] is missing 'confidence' (Eva defaults to high)")
        elif not _is_text(confidence) or str(confidence).strip().lower() not in CONFIDENCES:
            result.errors.append(f"findings[{index}].confidence must be one of {', '.join(CONFIDENCES)}")

        finding_id = item.get("id")
        if _is_text(finding_id):
            previous = ids.get(str(finding_id))
            if previous is not None:
                result.errors.append(f"duplicate finding id {finding_id!r} at indexes {previous} and {index}")
            else:
                ids[str(finding_id)] = index

        fingerprint = item.get("fingerprint")
        if fingerprint is None or fingerprint == "":
            result.warnings.append(f"findings[{index}] is missing 'fingerprint'; deduplication may be weaker")
        elif not isinstance(fingerprint, str) or not FINGERPRINT_RE.fullmatch(fingerprint):
            result.errors.append(f"findings[{index}].fingerprint must be 8-128 hexadecimal characters")
        else:
            previous = fingerprints.get(fingerprint)
            if previous is not None:
                result.errors.append(f"duplicate fingerprint {fingerprint!r} at indexes {previous} and {index}")
            else:
                fingerprints[fingerprint] = index

        for key in ("line_start", "line_end"):
            value = item.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                result.errors.append(f"findings[{index}].{key} must be an integer when present")

        references = item.get("references")
        if references is not None and not isinstance(references, list):
            result.errors.append(f"findings[{index}].references must be an array when present")

    result.severity_counts = {name: severities.get(name, 0) for name in SEVERITIES}
    result.valid = not result.errors and (not strict or not result.warnings)
    return result


validate_document = validate_triage_document


def collect_json_files(targets: list[str]) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    missing: list[str] = []
    seen: set[Path] = set()
    for raw in targets:
        path = Path(raw).expanduser()
        if not path.exists():
            missing.append(raw)
            continue
        candidates = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                resolved = candidate.absolute()
            if resolved not in seen:
                seen.add(resolved)
                files.append(candidate)
    return files, missing


def validate_triage_files(targets: list[str | Path], strict: bool = False) -> dict[str, Any]:
    target_strings = [str(t) for t in targets]
    files, missing = collect_json_files(target_strings)

    results: list[dict[str, Any]] = []
    valid_count = 0

    for path in files:
        try:
            content = path.read_text(encoding="utf-8-sig")
            data = json.loads(content)
            res = validate_triage_document(data, path=str(path), strict=strict)
        except json.JSONDecodeError as exc:
            res = FileResult(path=str(path), valid=False, errors=[f"invalid JSON: {exc}"])
        except OSError as exc:
            res = FileResult(path=str(path), valid=False, errors=[f"cannot read file: {exc}"])

        if res.valid:
            valid_count += 1
        results.append(res.as_dict())

    return {
        "files_checked": len(files),
        "files_valid": valid_count,
        "files_failed": len(files) - valid_count,
        "missing_targets": missing,
        "all_valid": (len(files) > 0 and valid_count == len(files) and not missing),
        "results": results,
    }


# ===========================================================================
# Compatibility Entrypoints for scripts/
# ===========================================================================


def orchestrator_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Eva endpoint triage collectors")
    parser.add_argument("--platform", choices=("auto", "linux", "windows"), default="auto")
    parser.add_argument("--script", dest="scripts", action="append", default=[])
    parser.add_argument("--exclude", dest="exclude", action="append", default=[])
    parser.add_argument("--exclude-slow", action="store_true")
    parser.add_argument("-o", "--output", dest="output", type=Path)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--fail-on", choices=("none",) + SEVERITIES, default="none")
    parser.add_argument("--list", dest="list_only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", dest="json_output", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    platform_name = args.platform if args.platform != "auto" else detect_platform()
    available = discover_collectors(platform_name)

    if args.list_only:
        items = select_collectors(available, include=args.scripts, exclude=args.exclude, exclude_slow=args.exclude_slow)
        if args.json_output:
            print(json.dumps([{"name": s["name"], "path": str(s["path"])} for s in items], indent=2))
        else:
            for s in items:
                print(s["name"])
        return 0

    summary = run_triage(
        platform_name=platform_name,
        scripts=args.scripts,
        exclude=args.exclude,
        exclude_slow=args.exclude_slow,
        output_dir=args.output,
        timeout=args.timeout,
        fail_on=args.fail_on,
        dry_run=args.dry_run,
    )

    if args.json_output:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print(f"[+] Completed {summary['scripts_ok']}/{summary['scripts_total']} collector(s)", file=sys.stderr)
        print(f"[+] Findings: {summary['findings']}", file=sys.stderr)
        print(f"[+] Summary:  {summary['output_dir']}/summary.json", file=sys.stderr)

    if summary["scripts_failed"] > 0 or summary["threshold_failed"]:
        return 1
    return 0


def validator_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Eva endpoint triage reports")
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", dest="json_output", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    outcome = validate_triage_files(args.paths, strict=args.strict)
    if args.json_output:
        print(json.dumps(outcome, indent=2))
    elif not args.quiet:
        for r in outcome["results"]:
            status = "VALID" if r["valid"] else "FAILED"
            print(f"[{status}] {r['path']}")
            for err in r.get("errors", []):
                print(f"  Error: {err}", file=sys.stderr)

    if outcome["files_checked"] == 0 and outcome["missing_targets"]:
        return 2
    return 0 if outcome["all_valid"] else 1
