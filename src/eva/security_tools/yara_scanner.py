from __future__ import annotations

import logging
from pathlib import Path

import yara

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding

logger = logging.getLogger(__name__)


def get_default_rules_path() -> Path:
    """Return the Path to the curated baseline defensive YARA rules directory."""
    return Path(__file__).resolve().parent / "rules" / "yara"


def compile_yara_rules(rules_source: Path | str, output_path: Path | str | None = None) -> yara.Rules:
    """Compile YARA rules from a single file or a directory of rule files.

    If output_path is provided, saves the compiled rules binary.
    """
    src = Path(rules_source).resolve()
    if not src.exists():
        raise FileNotFoundError(f"Rules source path not found: {src}")

    if src.is_file():
        # Check if it's already a compiled rules file
        try:
            compiled = yara.load(str(src))
            if output_path:
                compiled.save(str(output_path))
            return compiled
        except yara.Error:
            pass
        compiled = yara.compile(filepath=str(src))
    elif src.is_dir():
        rule_files = sorted([p for p in src.rglob("*") if p.is_file() and p.suffix.lower() in {".yar", ".yara"}])
        if not rule_files:
            raise ValueError(f"No .yar or .yara rule files found in {src}")
        filepaths = {f"rule_{i}_{p.stem}": str(p) for i, p in enumerate(rule_files)}
        compiled = yara.compile(filepaths=filepaths)
    else:
        raise ValueError(f"Invalid rules source: {src}")

    if output_path:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        compiled.save(str(out_p))

    return compiled


def _format_matched_strings(match: yara.Match) -> tuple[str, int | None]:
    """Extract human-readable evidence and lowest byte offset from a YARA Match."""
    evidence_parts: list[str] = []
    first_offset: int | None = None

    for string_match in getattr(match, "strings", []) or []:
        # Modern yara-python: string_match has identifier and instances
        identifier = getattr(string_match, "identifier", "")
        instances = getattr(string_match, "instances", None)

        if instances is not None:
            for inst in instances[:5]:
                offset = getattr(inst, "offset", None)
                matched_data = getattr(inst, "matched_data", b"")
                if first_offset is None and offset is not None:
                    first_offset = offset
                preview = repr(matched_data[:60])[1:]  # e.g. "b'foo'" -> "'foo'"
                evidence_parts.append(
                    f"{identifier} @ 0x{offset:x}: {preview}" if offset is not None else f"{identifier}: {preview}"
                )
        elif isinstance(string_match, tuple) and len(string_match) >= 3:
            # Older tuple format: (offset, identifier, data)
            offset, ident, data = string_match[0], string_match[1], string_match[2]
            if first_offset is None:
                first_offset = offset
            preview = repr(data[:60])[1:]
            evidence_parts.append(f"{ident} @ 0x{offset:x}: {preview}")

    evidence = "; ".join(evidence_parts[:10])
    if len(evidence_parts) > 10:
        evidence += f" (+{len(evidence_parts) - 10} more matches)"
    return evidence, first_offset


def normalize_yara_match(match: yara.Match, file_path: Path, artifact_path: str | None = None) -> Finding:
    """Normalize a yara.Match into EVA's unified Finding model."""
    meta = getattr(match, "meta", {}) or {}
    rule_name = str(getattr(match, "rule", "yara_match"))

    severity = meta.get("severity", "medium")
    confidence = meta.get("confidence", "high")
    category = meta.get("category", "signature")
    description = meta.get("description") or f"YARA rule match: {rule_name}"
    remediation = meta.get("remediation", "")
    references_meta = meta.get("references", [])
    if isinstance(references_meta, str):
        references = [references_meta]
    elif isinstance(references_meta, list):
        references = [str(r) for r in references_meta]
    else:
        references = []

    evidence, first_offset = _format_matched_strings(match)

    return make_finding(
        tool="yara",
        rule_id=rule_name,
        title=description,
        severity=severity,
        confidence=confidence,
        category=category,
        file=str(file_path),
        line_start=first_offset,
        evidence=evidence or f"Rule {rule_name} matched",
        remediation=remediation,
        references=references,
        artifact_path=artifact_path,
    )


def scan_with_yara(
    target_path: Path | str,
    rules: yara.Rules | Path | str | None = None,
    recursive: bool = True,
    artifact_path: str | None = None,
) -> list[Finding]:
    """Scan a target file or directory with YARA rules, returning normalized Findings."""
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path not found: {target}")

    # Resolve or compile rules
    if rules is None:
        compiled_rules = compile_yara_rules(get_default_rules_path())
    elif isinstance(rules, (str, Path)):
        compiled_rules = compile_yara_rules(Path(rules))
    elif isinstance(rules, yara.Rules):
        compiled_rules = rules
    else:
        raise TypeError(f"Expected yara.Rules or Path, got {type(rules)}")

    # Enumerate target files safely
    files_to_scan: list[Path] = []
    if target.is_file():
        files_to_scan.append(target)
    elif target.is_dir():
        pattern = "**/*" if recursive else "*"
        try:
            for item in target.glob(pattern):
                if item.is_file() and not item.is_symlink():
                    files_to_scan.append(item)
        except (PermissionError, OSError) as exc:
            logger.warning("Error enumerating files in %s: %s", target, exc)
    else:
        return []

    findings: list[Finding] = []
    for file_p in files_to_scan:
        try:
            matches = compiled_rules.match(str(file_p), timeout=60)
            for m in matches:
                finding = normalize_yara_match(m, file_p, artifact_path=artifact_path)
                findings.append(finding)
        except (yara.Error, PermissionError, OSError) as exc:
            logger.debug("YARA scan error on %s: %s", file_p, exc)
            continue

    return findings
