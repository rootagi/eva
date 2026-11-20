"""Defensive YARA rule compilation, bounded filesystem scanning, and match normalization."""

from __future__ import annotations

import logging
import os
import stat
import time
from pathlib import Path
from typing import Any

try:
    import yara
except ImportError:
    yara = None

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding

logger = logging.getLogger(__name__)

DEFAULT_MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MiB
DEFAULT_IGNORED_DIRS: set[str] = {
    ".git",
    ".eva",
    "node_modules",
    ".venv",
    "venv",
    "target",
    "dist",
    ".tox",
    "__pycache__",
}


class YaraScanResult(list):
    """List of Finding instances augmented with structured scan statistics."""

    def __init__(
        self,
        findings: list[Finding] | None = None,
        files_scanned: int = 0,
        files_skipped: int = 0,
        skipped_reasons: dict[str, int] | None = None,
        duration_seconds: float = 0.0,
        timed_out: bool = False,
    ):
        super().__init__(findings or [])
        self.files_scanned = files_scanned
        self.files_skipped = files_skipped
        self.skipped_reasons = skipped_reasons or {}
        self.duration_seconds = duration_seconds
        self.timed_out = timed_out

    @property
    def findings_count(self) -> int:
        return len(self)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "skipped_reasons": self.skipped_reasons,
            "findings_count": self.findings_count,
            "duration_s": round(self.duration_seconds, 3),
            "timed_out": self.timed_out,
        }


def get_default_rules_path() -> Path:
    """Return the Path to the curated baseline defensive YARA rules directory."""
    return Path(__file__).resolve().parent / "rules" / "yara"


def _require_yara():
    if yara is None:
        from eva.security_tools.deps import missing_extra_exit

        missing_extra_exit("sec", "YARA scanning")


def compile_yara_rules(rules_source: Path | str, output_path: Path | str | None = None) -> Any:
    """Compile YARA rules from a single file or a directory of rule files.

    If output_path is provided, saves the compiled rules binary.
    """
    _require_yara()
    src = Path(rules_source).resolve()
    if not src.exists():
        raise FileNotFoundError(f"Rules source path not found: {src}")

    if src.is_file():
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


def _format_matched_strings(match: Any) -> tuple[str, int | None]:
    """Extract human-readable evidence and lowest byte offset from a YARA Match."""
    evidence_parts: list[str] = []
    first_offset: int | None = None

    for string_match in getattr(match, "strings", []) or []:
        identifier = getattr(string_match, "identifier", "")
        instances = getattr(string_match, "instances", None)

        if instances is not None:
            for inst in instances[:5]:
                offset = getattr(inst, "offset", None)
                matched_data = getattr(inst, "matched_data", b"")
                if first_offset is None and offset is not None:
                    first_offset = offset
                preview = repr(matched_data[:60])[1:]
                evidence_parts.append(
                    f"{identifier} @ 0x{offset:x}: {preview}" if offset is not None else f"{identifier}: {preview}"
                )
        elif isinstance(string_match, tuple) and len(string_match) >= 3:
            offset, ident, data = string_match[0], string_match[1], string_match[2]
            if first_offset is None:
                first_offset = offset
            preview = repr(data[:60])[1:]
            evidence_parts.append(f"{ident} @ 0x{offset:x}: {preview}")

    evidence = "; ".join(evidence_parts[:10])
    if len(evidence_parts) > 10:
        evidence += f" (+{len(evidence_parts) - 10} more matches)"
    return evidence, first_offset


def normalize_yara_match(match: Any, file_path: Path, artifact_path: str | None = None) -> Finding:
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


def collect_scan_files(
    target: Path,
    recursive: bool = True,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    ignored_dirs: set[str] | None = None,
    include_ignored: bool = False,
) -> tuple[list[Path], dict[str, int]]:
    """Enumerate files to scan while respecting size bounds, symlink skipping, and directory pruning."""
    skip_counts: dict[str, int] = {"oversized": 0, "symlink": 0, "special": 0}
    files: list[Path] = []
    ignored = ignored_dirs or DEFAULT_IGNORED_DIRS

    if target.is_symlink():
        skip_counts["symlink"] += 1
        return files, skip_counts

    if target.is_file():
        try:
            st = target.stat()
            if not stat.S_ISREG(st.st_mode):
                skip_counts["special"] += 1
                return files, skip_counts
            if st.st_size > max_file_size_bytes:
                skip_counts["oversized"] += 1
                return files, skip_counts
            files.append(target)
        except OSError:
            pass
        return files, skip_counts

    if target.is_dir():
        for root, dirs, fnames in os.walk(target, followlinks=False):
            if not include_ignored:
                dirs[:] = [d for d in dirs if d not in ignored and not (Path(root) / d).is_symlink()]
            else:
                dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]

            for fname in sorted(fnames):
                fpath = Path(root) / fname
                if fpath.is_symlink():
                    skip_counts["symlink"] += 1
                    continue
                try:
                    st = fpath.stat()
                    if not stat.S_ISREG(st.st_mode):
                        skip_counts["special"] += 1
                        continue
                    if st.st_size > max_file_size_bytes:
                        skip_counts["oversized"] += 1
                        continue
                    files.append(fpath)
                except OSError:
                    continue

            if not recursive:
                dirs[:] = []

    return files, skip_counts


def scan_with_yara(
    target_path: Path | str,
    rules: Any = None,
    recursive: bool = True,
    artifact_path: str | None = None,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    ignored_dirs: set[str] | None = None,
    include_ignored: bool = False,
    scan_deadline_seconds: float | None = None,
) -> YaraScanResult:
    """Scan a target file or directory with YARA rules, returning a bounded YaraScanResult."""
    _require_yara()
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path not found: {target}")

    start_time = time.time()
    deadline = (start_time + scan_deadline_seconds) if scan_deadline_seconds is not None else None

    # Resolve or compile rules
    if rules is None:
        compiled_rules = compile_yara_rules(get_default_rules_path())
    elif isinstance(rules, (str, Path)):
        compiled_rules = compile_yara_rules(Path(rules))
    else:
        compiled_rules = rules

    files_to_scan, skipped_reasons = collect_scan_files(
        target,
        recursive=recursive,
        max_file_size_bytes=max_file_size_bytes,
        ignored_dirs=ignored_dirs,
        include_ignored=include_ignored,
    )

    findings: list[Finding] = []
    files_scanned = 0
    timed_out = False

    for file_p in files_to_scan:
        if deadline is not None and time.time() >= deadline:
            timed_out = True
            logger.warning("YARA scan deadline reached; halting early.")
            break

        try:
            matches = compiled_rules.match(str(file_p), timeout=60)
            files_scanned += 1
            for m in matches:
                finding = normalize_yara_match(m, file_p, artifact_path=artifact_path)
                findings.append(finding)
        except (yara.Error, PermissionError, OSError) as exc:
            logger.debug("YARA scan error on %s: %s", file_p, exc)
            continue

    duration = time.time() - start_time
    total_skipped = sum(skipped_reasons.values())

    return YaraScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_skipped=total_skipped,
        skipped_reasons=skipped_reasons,
        duration_seconds=duration,
        timed_out=timed_out,
    )


class YaraScanner:
    """Bounded, resilient YARA scanner respecting size caps, directory exclusions, and deadlines."""

    def __init__(
        self,
        rules: Any = None,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        ignored_dirs: set[str] | None = None,
        scan_deadline_seconds: float | None = None,
    ):
        self.rules = rules
        self.max_file_size_bytes = max_file_size_bytes
        self.ignored_dirs = ignored_dirs or DEFAULT_IGNORED_DIRS
        self.scan_deadline_seconds = scan_deadline_seconds
        self._compiled_rules = None

    def _get_compiled_rules(self):
        if self._compiled_rules is None:
            _require_yara()
            if self.rules is None:
                self._compiled_rules = compile_yara_rules(get_default_rules_path())
            elif isinstance(self.rules, (str, Path)):
                self._compiled_rules = compile_yara_rules(Path(self.rules))
            else:
                self._compiled_rules = self.rules
        return self._compiled_rules

    def scan_file(self, file_path: Path | str) -> dict[str, Any]:
        """Scan a single file with bounding checks. Returns dict with scan results or skipped status."""
        p = Path(file_path).resolve()
        if not p.exists():
            return {"skipped": True, "reason": "not_found", "matches": []}
        if p.is_symlink():
            return {"skipped": True, "reason": "symlink", "matches": []}
        try:
            st = p.stat()
            if not stat.S_ISREG(st.st_mode):
                return {"skipped": True, "reason": "not_regular_file", "matches": []}
            if st.st_size > self.max_file_size_bytes:
                return {"skipped": True, "reason": "oversized", "size": st.st_size, "matches": []}
        except OSError as exc:
            return {"skipped": True, "reason": str(exc), "matches": []}

        _require_yara()
        compiled = self._get_compiled_rules()
        try:
            matches = compiled.match(str(p), timeout=60)
            return {"skipped": False, "matches": [normalize_yara_match(m, p) for m in matches]}
        except (yara.Error, PermissionError, OSError) as exc:
            return {"skipped": True, "reason": str(exc), "matches": []}

    def scan(
        self,
        target_path: Path | str,
        recursive: bool = True,
        include_ignored: bool = False,
        artifact_path: str | None = None,
    ) -> YaraScanResult:
        return scan_with_yara(
            target_path=target_path,
            rules=self._get_compiled_rules(),
            recursive=recursive,
            max_file_size_bytes=self.max_file_size_bytes,
            ignored_dirs=self.ignored_dirs,
            include_ignored=include_ignored,
            scan_deadline_seconds=self.scan_deadline_seconds,
            artifact_path=artifact_path,
        )
