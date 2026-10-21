#!/usr/bin/env python3
"""Validate Eva endpoint triage reports (`eva.triage.v1`).

This is a standalone, standard-library-only validator. It checks the report
container, host metadata, timestamp, findings and fingerprint uniqueness so a
broken collector is caught before results are ingested into `eva sec`.

Example:
    python scripts/validate_triage.py /tmp/triage/*.json
    python scripts/validate_triage.py /tmp/triage --strict --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA = "eva.triage.v1"
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
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


def validate_document(data: Any, path: str, strict: bool = False) -> FileResult:
    result = FileResult(path=path)
    if not isinstance(data, dict):
        result.errors.append("report root must be a JSON object")
        return result

    schema = data.get("schema")
    if schema != SCHEMA:
        if data.get("kind") == "eva-triage":
            result.warnings.append(f"schema is {schema!r}; kind= 'eva-triage' is accepted by Eva")
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


def validate_file(path: Path, strict: bool = False) -> FileResult:
    result = FileResult(path=str(path))
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        result.errors.append(f"cannot read file: {exc}")
        return result
    except UnicodeDecodeError as exc:
        result.errors.append(f"file is not valid UTF-8: {exc}")
        return result

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.errors.append(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}")
        return result

    return validate_document(data, str(path), strict=strict)


def print_text(result: FileResult) -> None:
    state = "OK" if result.valid else "FAIL"
    summary = f"[{state}] {result.path}"
    if result.findings or result.severity_counts:
        counts = ", ".join(f"{name}={count}" for name, count in result.severity_counts.items() if count)
        summary += f" ({result.findings} findings"
        if counts:
            summary += f"; {counts}"
        summary += ")"
    print(summary)
    for error in result.errors:
        print(f"  error: {error}")
    for warning in result.warnings:
        print(f"  warning: {warning}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate Eva triage reports (eva.triage.v1).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("paths", nargs="+", help="report files or directories to validate")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings (missing optional metadata) as validation failures",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit a JSON validation summary")
    parser.add_argument("--quiet", action="store_true", help="suppress per-file text output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    files, missing = collect_json_files(args.paths)
    results: list[FileResult] = []
    for path in files:
        results.append(validate_file(path, strict=args.strict))

    for missing_path in missing:
        result = FileResult(path=missing_path)
        result.errors.append("path does not exist")
        results.append(result)

    invalid = [result for result in results if not result.valid]
    total_findings = sum(result.findings for result in results)
    total_errors = sum(len(result.errors) for result in results)
    total_warnings = sum(len(result.warnings) for result in results)
    summary = {
        "schema": "eva.validation.v1",
        "strict": args.strict,
        "files": len(results),
        "valid": len(results) - len(invalid),
        "invalid": len(invalid),
        "findings": total_findings,
        "errors": total_errors,
        "warnings": total_warnings,
        "results": [result.as_dict() for result in results],
    }

    if args.json_output:
        print(json.dumps(summary, indent=2, sort_keys=False))
    elif not args.quiet:
        for result in results:
            print_text(result)
        print(
            f"\nValidated {len(results)} file(s): "
            f"{summary['valid']} valid, {summary['invalid']} invalid, "
            f"{total_findings} finding(s), {total_errors} error(s), {total_warnings} warning(s)."
        )

    if not results:
        if not args.quiet and not args.json_output:
            print("No JSON reports found.", file=sys.stderr)
        return 2
    return 1 if invalid else 0


if __name__ == "__main__":
    raise SystemExit(main())
