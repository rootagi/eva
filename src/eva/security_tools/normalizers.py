from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from eva.security.redaction import redact_secrets
from eva.security_tools.models import Finding
from eva.security_tools.utils import read_json_file, sha256_text

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "note": "info",
    "info": "info",
    "informational": "info",
    "unknown": "unknown",
}


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"
    cleaned = str(value).strip().lower()
    if cleaned in SEVERITY_MAP:
        return SEVERITY_MAP[cleaned]
    first = cleaned.split()[0].rstrip("():;,")
    return SEVERITY_MAP.get(first, "unknown")


def fingerprint(tool: str, rule_id: str, title: str, location: str = "", evidence: str = "") -> str:
    return sha256_text(f"{tool}|{rule_id}|{title}|{location}|{evidence}")[:32]


def make_finding(
    *,
    tool: str,
    title: str,
    rule_id: str = "",
    severity: Any = "unknown",
    confidence: str = "unknown",
    category: str = "",
    file: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    target: str | None = None,
    evidence: str = "",
    remediation: str = "",
    references: list[str] | None = None,
    artifact_path: str | None = None,
) -> Finding:
    safe_evidence = redact_secrets(str(evidence or ""))[:4000]
    line_fragment = f"{file or target or ''}:{line_start or ''}:{line_end or ''}"
    rule = str(rule_id or "")
    fp = fingerprint(tool, rule, title, line_fragment, safe_evidence)
    return Finding(
        id=f"{tool}-{fp}",
        tool=tool,
        rule_id=rule,
        title=redact_secrets(str(title or rule or "Security finding")),
        severity=normalize_severity(severity),  # type: ignore[arg-type]
        confidence=confidence if confidence in {"high", "medium", "low", "unknown"} else "unknown",  # type: ignore[arg-type]
        category=str(category or ""),
        file=file,
        line_start=line_start,
        line_end=line_end,
        target=target,
        evidence=safe_evidence,
        remediation=redact_secrets(str(remediation or "")),
        references=[str(ref) for ref in (references or [])],
        fingerprint=fp,
        artifact_path=artifact_path,
    )


def normalize_trivy(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                make_finding(
                    tool="trivy",
                    rule_id=vuln.get("VulnerabilityID", ""),
                    title=vuln.get("Title") or vuln.get("PkgName") or "Vulnerability",
                    severity=vuln.get("Severity"),
                    category="vulnerability",
                    target=target,
                    evidence=f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')}",
                    remediation=vuln.get("FixedVersion", ""),
                    references=vuln.get("References", []),
                    artifact_path=artifact_path,
                )
            )
        for secret in result.get("Secrets", []) or []:
            findings.append(
                make_finding(
                    tool="trivy",
                    rule_id=secret.get("RuleID", ""),
                    title=secret.get("Title") or "Secret detected",
                    severity=secret.get("Severity", "high"),
                    confidence="high",
                    category="secret",
                    file=target,
                    line_start=secret.get("StartLine"),
                    line_end=secret.get("EndLine"),
                    evidence=secret.get("Match", ""),
                    artifact_path=artifact_path,
                )
            )
        for misconf in result.get("Misconfigurations", []) or []:
            findings.append(
                make_finding(
                    tool="trivy",
                    rule_id=misconf.get("ID", ""),
                    title=misconf.get("Title") or "Misconfiguration",
                    severity=misconf.get("Severity"),
                    category="misconfiguration",
                    file=target,
                    evidence=misconf.get("Message") or misconf.get("Description", ""),
                    remediation=misconf.get("Resolution", ""),
                    references=misconf.get("References", []),
                    artifact_path=artifact_path,
                )
            )
        for license_item in result.get("Licenses", []) or []:
            findings.append(
                make_finding(
                    tool="trivy",
                    rule_id=license_item.get("Name", ""),
                    title=f"License: {license_item.get('Name', 'unknown')}",
                    severity=license_item.get("Severity", "info"),
                    category="license",
                    target=target,
                    evidence=license_item.get("Category", ""),
                    artifact_path=artifact_path,
                )
            )
    return findings


def normalize_semgrep(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        extra = item.get("extra", {}) or {}
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        findings.append(
            make_finding(
                tool="semgrep",
                rule_id=item.get("check_id", ""),
                title=extra.get("message") or item.get("check_id") or "SAST finding",
                severity=metadata.get("severity") or extra.get("severity", "unknown"),
                confidence=str(metadata.get("confidence", "unknown")).lower(),
                category=metadata.get("category") or "sast",
                file=item.get("path"),
                line_start=start.get("line"),
                line_end=end.get("line"),
                evidence=extra.get("lines", ""),
                references=metadata.get("references", []) or metadata.get("source", []),
                artifact_path=artifact_path,
            )
        )
    return findings


def normalize_gitleaks(data: Any, artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for item in data if isinstance(data, list) else data.get("findings", []):
        findings.append(
            make_finding(
                tool="gitleaks",
                rule_id=item.get("RuleID") or item.get("rule_id", ""),
                title=item.get("Description") or item.get("description") or "Secret detected",
                severity="high",
                confidence="high",
                category="secret",
                file=item.get("File") or item.get("file"),
                line_start=item.get("StartLine") or item.get("line"),
                line_end=item.get("EndLine") or item.get("line"),
                evidence=item.get("Secret") or item.get("Match") or item.get("match", ""),
                artifact_path=artifact_path,
            )
        )
    return findings


def normalize_osv(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("results", []) or []:
        source = (result.get("source") or {}).get("path")
        for package in result.get("packages", []) or []:
            pkg = package.get("package", {}) or {}
            for vuln in package.get("vulnerabilities", []) or []:
                findings.append(
                    make_finding(
                        tool="osv-scanner",
                        rule_id=vuln.get("id", ""),
                        title=vuln.get("summary") or vuln.get("id") or "Dependency vulnerability",
                        severity=vuln.get("database_specific", {}).get("severity", "unknown"),
                        category="vulnerability",
                        file=source,
                        evidence=f"{pkg.get('name', '')} {pkg.get('version', '')}",
                        references=[ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")],
                        artifact_path=artifact_path,
                    )
                )
    return findings


def normalize_syft(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    components = data.get("components", []) or data.get("artifacts", [])
    if components:
        findings.append(
            make_finding(
                tool="syft",
                rule_id="sbom.inventory",
                title=f"SBOM inventory: {len(components)} components identified",
                severity="info",
                confidence="high",
                category="sbom",
                evidence=f"{len(components)} software packages cataloged in SBOM",
                artifact_path=artifact_path,
            )
        )
    return findings


def normalize_aegis(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    target = str(data.get("image") or data.get("image_path") or data.get("target") or "")
    if "sha256" in data or "hashes" in data:
        findings.append(
            make_finding(
                tool="aegis",
                rule_id="evidence.hash",
                title="Evidence hash recorded",
                severity="info",
                confidence="high",
                category="integrity",
                target=target,
                evidence=json.dumps(data.get("hashes") or {"sha256": data.get("sha256")}, sort_keys=True),
                artifact_path=artifact_path,
            )
        )
    for key in ("findings", "alerts", "anomalies", "issues"):
        raw_items = data.get(key)
        if isinstance(raw_items, list):
            for item in raw_items:
                if isinstance(item, dict):
                    findings.append(
                        make_finding(
                            tool="aegis",
                            rule_id=item.get("id") or item.get("rule_id") or key,
                            title=item.get("title") or item.get("message") or "Aegis forensic finding",
                            severity=item.get("severity", "info"),
                            confidence=item.get("confidence", "unknown"),
                            category=item.get("category", "forensics"),
                            file=item.get("file") or target or None,
                            line_start=item.get("line_start"),
                            line_end=item.get("line_end"),
                            target=item.get("target") or target or None,
                            evidence=item.get("evidence") or item.get("details") or "",
                            remediation=item.get("remediation", ""),
                            references=item.get("references", []),
                            artifact_path=artifact_path,
                        )
                    )
    binary_sec = data.get("binary") or data.get("structure")
    if isinstance(binary_sec, dict):
        anomalies = binary_sec.get("anomalies")
        if isinstance(anomalies, list):
            for anom in anomalies:
                findings.append(
                    make_finding(
                        tool="aegis",
                        rule_id="aegis.structure.anomaly",
                        title=f"Structural anomaly: {anom}",
                        severity="high" if "trailing" in str(anom).lower() else "medium",
                        confidence="high",
                        category="forensics",
                        target=target,
                        evidence=str(anom),
                        artifact_path=artifact_path,
                    )
                )
        if binary_sec.get("data_after_iend") or binary_sec.get("trailing_data"):
            findings.append(
                make_finding(
                    tool="aegis",
                    rule_id="aegis.structure.trailing_data",
                    title="Hidden trailing data appended to image",
                    severity="high",
                    confidence="high",
                    category="forensics",
                    target=target,
                    evidence=f"{binary_sec.get('data_after_iend_size', 'unknown')} bytes trailing data detected",
                    artifact_path=artifact_path,
                )
            )

    auth_sec = data.get("authenticity")
    if isinstance(auth_sec, dict) and (
        auth_sec.get("status") == "MANIPULATED" or auth_sec.get("manipulation_confidence", 0) > 0.7
    ):
        findings.append(
            make_finding(
                tool="aegis",
                rule_id="aegis.authenticity.manipulation",
                title="Image manipulation detected",
                severity="high",
                confidence="medium",
                category="forensics",
                target=target,
                evidence=f"ELA manipulation confidence: {auth_sec.get('manipulation_confidence')}",
                artifact_path=artifact_path,
            )
        )

    for name in ("steganography", "structure", "metadata", "integrity", "hidden_data", "binary"):
        section = data.get(name)
        if isinstance(section, dict) and (
            section.get("suspicious")
            or section.get("valid") is False
            or "SUSPICIOUS" in str(section.get("overall_status", ""))
        ):
            findings.append(
                make_finding(
                    tool="aegis",
                    rule_id=f"aegis.{name}",
                    title=f"Aegis {name.replace('_', ' ')} signal",
                    severity=section.get("severity", "medium"),
                    confidence=section.get("confidence", "unknown"),
                    category="forensics",
                    target=target,
                    evidence=json.dumps(section, sort_keys=True),
                    artifact_path=artifact_path,
                )
            )
    return findings


def normalize_zap(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    sites = data.get("site", []) or data.get("sites", [])
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        target = site.get("@name") or site.get("name")
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances", []) or [{}]
            for instance in instances:
                findings.append(
                    make_finding(
                        tool="zap",
                        rule_id=str(alert.get("pluginid") or alert.get("id") or ""),
                        title=alert.get("alert") or alert.get("name") or "ZAP finding",
                        severity=alert.get("riskdesc") or alert.get("risk") or "unknown",
                        confidence=str(alert.get("confidence", "unknown")).lower(),
                        category="web",
                        target=instance.get("uri") or target,
                        evidence=instance.get("evidence") or alert.get("desc", ""),
                        remediation=alert.get("solution", ""),
                        references=[alert.get("reference", "")] if alert.get("reference") else [],
                        artifact_path=artifact_path,
                    )
                )
    return findings


def normalize_sarif(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name", "sarif")
        for result in run.get("results", []) or []:
            location = (result.get("locations") or [{}])[0].get("physicalLocation") or {}
            region = location.get("region") or {}
            artifact = location.get("artifactLocation") or {}
            findings.append(
                make_finding(
                    tool=tool,
                    rule_id=result.get("ruleId", ""),
                    title=(result.get("message") or {}).get("text") or result.get("ruleId") or "SARIF finding",
                    severity=result.get("level", "unknown"),
                    category="sarif",
                    file=artifact.get("uri"),
                    line_start=region.get("startLine"),
                    line_end=region.get("endLine"),
                    evidence=(result.get("message") or {}).get("text", ""),
                    artifact_path=artifact_path,
                )
            )
    return findings


def normalize_triage(data: dict[str, Any], artifact_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    tool_name = str(data.get("tool") or "triage")
    host_info = data.get("host", {}) or {}
    hostname = host_info.get("hostname") or data.get("hostname") or ""

    for item in data.get("findings", []) or []:
        if isinstance(item, dict):
            findings.append(
                make_finding(
                    tool=item.get("tool") or tool_name,
                    rule_id=item.get("rule_id") or item.get("id") or "triage.finding",
                    title=item.get("title") or item.get("name") or "Triage finding",
                    severity=item.get("severity", "medium"),
                    confidence=item.get("confidence", "high"),
                    category=item.get("category", "triage"),
                    file=item.get("file"),
                    line_start=item.get("line_start"),
                    line_end=item.get("line_end"),
                    target=item.get("target") or hostname or None,
                    evidence=item.get("evidence") or item.get("description") or "",
                    remediation=item.get("remediation", ""),
                    references=item.get("references", []),
                    artifact_path=artifact_path,
                )
            )

    for check in data.get("audits", []) or data.get("checks", []) or []:
        if isinstance(check, dict) and check.get("status") in {"FAIL", "FAILED", "WARN", "WARNING"}:
            findings.append(
                make_finding(
                    tool=tool_name,
                    rule_id=check.get("id") or check.get("control_id") or "audit.failed",
                    title=check.get("title") or check.get("name") or "Audit control failure",
                    severity=check.get("severity", "medium"),
                    confidence="high",
                    category="hardening_audit",
                    target=hostname or None,
                    evidence=check.get("evidence") or check.get("current_value") or "",
                    remediation=check.get("remediation") or check.get("fix", ""),
                    references=check.get("references", []),
                    artifact_path=artifact_path,
                )
            )

    return findings


def _safe_int(val: Any) -> int | None:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _dict_to_finding(
    item: dict[str, Any],
    default_tool: str = "unknown",
    artifact_path: str | None = None,
) -> Finding:
    tool = str(item.get("tool") or default_tool or "unknown")
    rule = str(item.get("rule_id") or item.get("id") or "")
    title = str(item.get("title") or item.get("name") or rule or "Security finding")
    file_val = item.get("file") or item.get("path")
    line_start = _safe_int(item.get("line_start") or item.get("line"))
    line_end = _safe_int(item.get("line_end") or item.get("line"))
    target = item.get("target")
    evidence = item.get("evidence") or item.get("description") or ""
    remediation = item.get("remediation") or ""
    refs_raw = item.get("references") or []
    if isinstance(refs_raw, list):
        references = [str(r) for r in refs_raw if r]
    elif isinstance(refs_raw, str) and refs_raw:
        references = [refs_raw]
    else:
        references = []

    # Fingerprint resolution: preserve explicit fingerprint or compute canonical SHA-256
    fp = item.get("fingerprint")
    if not fp:
        loc = f"{file_val or target or ''}:{line_start or ''}:{line_end or ''}"
        fp = fingerprint(tool, rule, title, loc, redact_secrets(str(evidence or ""))[:4000])

    finding_id = str(item.get("id") or f"{tool}-{fp}")
    conf = str(item.get("confidence", "unknown")).lower()
    if conf not in {"high", "medium", "low", "unknown"}:
        conf = "unknown"

    return Finding(
        id=finding_id,
        tool=tool,
        rule_id=rule,
        title=redact_secrets(title),
        severity=normalize_severity(item.get("severity")),  # type: ignore[arg-type]
        confidence=conf,  # type: ignore[arg-type]
        category=str(item.get("category", "")),
        file=str(file_val) if file_val is not None else None,
        line_start=line_start,
        line_end=line_end,
        target=str(target) if target is not None else None,
        evidence=redact_secrets(str(evidence or ""))[:4000],
        remediation=redact_secrets(str(remediation or "")),
        references=references,
        fingerprint=str(fp),
        artifact_path=artifact_path,
    )


def _read_jsonl_file(path: Path | str) -> list[dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))
    return records


def normalize_report(path: Path | str) -> list[Finding]:
    p = Path(path)
    artifact_path = str(p)

    if p.suffix.lower() == ".jsonl":
        records = _read_jsonl_file(p)
        return [_dict_to_finding(r, artifact_path=artifact_path) for r in records if isinstance(r, dict)]

    try:
        data = read_json_file(p)
    except json.JSONDecodeError:
        try:
            records = _read_jsonl_file(p)
            if records:
                return [_dict_to_finding(r, artifact_path=artifact_path) for r in records if isinstance(r, dict)]
        except (json.JSONDecodeError, OSError, ValueError, TypeError) as exc:
            logger.debug("JSONL parse attempt failed for %s: %s", p, exc)
        raise

    if isinstance(data, dict) and "runs" in data:
        return normalize_sarif(data, artifact_path)
    if isinstance(data, dict) and ("bomFormat" in data or ("artifacts" in data and "schema" in data)):
        return normalize_syft(data, artifact_path)
    if isinstance(data, dict) and "Results" in data:
        return normalize_trivy(data, artifact_path)
    if isinstance(data, dict) and "results" in data and "errors" in data:
        return normalize_semgrep(data, artifact_path)
    if isinstance(data, dict) and ("site" in data or "sites" in data):
        return normalize_zap(data, artifact_path)
    if isinstance(data, dict) and (
        "schema" in data
        and "triage" in str(data.get("schema", "")).lower()
        or data.get("kind") == "eva-triage"
        or "triage" in str(data.get("tool", "")).lower()
    ):
        return normalize_triage(data, artifact_path)
    if isinstance(data, dict) and (
        "image" in data or "image_path" in data or "steganography" in data or data.get("tool") == "aegis"
    ):
        return normalize_aegis(data, artifact_path)
    if isinstance(data, dict) and "findings" in data:
        raw = data.get("findings")
        # Guard against integer/non-list "findings" (e.g. summary.json: "findings": 10)
        if isinstance(raw, list):
            default_tool = str(data.get("tool", "unknown"))
            return [
                _dict_to_finding(item, default_tool=default_tool, artifact_path=artifact_path)
                for item in raw
                if isinstance(item, dict)
            ]
        logger.debug(
            "Report %s contains non-list 'findings' field (%s); returning empty findings",
            artifact_path,
            type(raw).__name__,
        )
        return []
    if isinstance(data, list):
        if data and all(
            isinstance(item, dict)
            and ("fingerprint" in item or "tool" in item)
            and not ("RuleID" in item or "Secret" in item)
            for item in data
        ):
            return [_dict_to_finding(item, artifact_path=artifact_path) for item in data if isinstance(item, dict)]
        return normalize_gitleaks(data, artifact_path)
    return []


def findings_to_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules_by_tool: dict[str, dict[str, dict[str, Any]]] = {}
    results_by_tool: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        rule_id = finding.rule_id or finding.id
        rules_by_tool.setdefault(finding.tool, {})[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation or finding.title},
        }
        location: dict[str, Any] = {}
        if finding.file:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {
                        "startLine": finding.line_start or 1,
                        "endLine": finding.line_end or finding.line_start or 1,
                    },
                }
            }
        elif finding.target:
            location = {"logicalLocations": [{"fullyQualifiedName": finding.target}]}
        results_by_tool.setdefault(finding.tool, []).append(
            {
                "ruleId": rule_id,
                "level": "error"
                if finding.severity in {"critical", "high"}
                else "warning"
                if finding.severity in {"medium", "low"}
                else "note",
                "message": {"text": f"{finding.title}: {finding.evidence}".strip(": ")},
                "locations": [location] if location else [],
                "partialFingerprints": {"evaFingerprint": finding.fingerprint},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "rules": list(rules_by_tool[tool].values())}},
                "results": results_by_tool.get(tool, []),
            }
            for tool in sorted(results_by_tool)
        ],
    }
