#!/usr/bin/env python3
"""Create and verify tamper-evident evidence bundles for Eva incident response.

A bundle is a tar archive containing the selected files under `bundle/evidence/`
plus `bundle/manifest.json`. The manifest records SHA-256, size, mode and mtime
for every file, case metadata, and an initial chain-of-custody entry. A
`.sha256` sidecar protects the archive itself.

Bundles are NOT encrypted. Treat them as sensitive evidence and store them on
encrypted media with access controls.

Examples:
    python scripts/evidence_bundle.py create /var/log/auth.log ./captures \
        --case-id IR-2026-042 --examiner "A. Analyst" -o /evidence/IR-2026-042.tar.gz
    python scripts/evidence_bundle.py verify /evidence/IR-2026-042.tar.gz
    python scripts/evidence_bundle.py list /evidence/IR-2026-042.tar.gz --json
"""

from __future__ import annotations

import argparse
import fnmatch
import getpass
import hashlib
import io
import json
import os
import re
import socket
import stat
import sys
import tarfile
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

BUNDLE_SCHEMA = "eva.evidence.v1"
ARCHIVE_ROOT = "bundle"
EVIDENCE_ROOT = "bundle/evidence"
MANIFEST_PATH = "bundle/manifest.json"
CHUNK_SIZE = 1024 * 1024


class BundleError(RuntimeError):
    """Raised when a bundle cannot be created or read."""


@dataclass
class EvidenceFile:
    source: Path
    archive_path: str
    size: int
    mode: int
    mtime: float
    sha256: str = ""

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "path": self.archive_path,
            "source": str(self.source),
            "size": self.size,
            "sha256": self.sha256,
            "mode": f"0o{self.mode:o}",
            "mtime": utc_iso(self.mtime),
        }


@dataclass
class Collection:
    files: list[EvidenceFile] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(handle: Any) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def safe_name(name: str, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip(" .")
    if cleaned in {"", ".", ".."}:
        return fallback
    return cleaned[:120]


def safe_archive_part(name: str) -> str:
    cleaned = name.replace("\\", "_").replace("/", "_").strip()
    if cleaned in {"", ".", ".."}:
        return "_"
    return cleaned


def sanitize_case_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return cleaned[:80] or f"case-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"


def is_excluded(path: Path, root: Path | None, patterns: Iterable[str]) -> bool:
    patterns = list(patterns)
    if not patterns:
        return False
    candidates = [path.name, str(path)]
    if root is not None:
        try:
            candidates.append(str(path.relative_to(root)))
        except ValueError:
            pass
    return any(fnmatch.fnmatch(candidate, pattern) for candidate in candidates for pattern in patterns)


def collect_source(
    source: Path,
    top_name: str,
    patterns: list[str],
    excluded_resolved: set[Path],
    collection: Collection,
    root: Path | None = None,
) -> None:
    try:
        resolved = source.resolve()
    except OSError:
        resolved = source.absolute()
    if resolved in excluded_resolved:
        return
    if source.is_symlink():
        collection.skipped.append({"source": str(source), "reason": "symbolic link"})
        return
    if source.is_dir():
        try:
            walker = os.walk(source, followlinks=False)
            for current, dirnames, filenames in walker:
                current_path = Path(current)
                dirnames[:] = sorted(
                    name
                    for name in dirnames
                    if not (current_path / name).is_symlink()
                    and not is_excluded(current_path / name, root or source, patterns)
                )
                for filename in sorted(filenames):
                    file_path = current_path / filename
                    if is_excluded(file_path, root or source, patterns):
                        continue
                    relative = file_path.relative_to(source)
                    archive_name = f"{EVIDENCE_ROOT}/{top_name}/" + "/".join(
                        safe_archive_part(part) for part in relative.parts
                    )
                    add_file(file_path, archive_name, excluded_resolved, collection)
        except OSError as exc:
            collection.skipped.append({"source": str(source), "reason": f"directory read error: {exc}"})
        return
    if source.is_file():
        add_file(source, f"{EVIDENCE_ROOT}/{top_name}/{safe_archive_part(source.name)}", excluded_resolved, collection)
        return
    collection.skipped.append({"source": str(source), "reason": "not a regular file or directory"})


def add_file(source: Path, archive_path: str, excluded_resolved: set[Path], collection: Collection) -> None:
    try:
        resolved = source.resolve()
    except OSError:
        resolved = source.absolute()
    if resolved in excluded_resolved:
        return
    if source.is_symlink():
        collection.skipped.append({"source": str(source), "reason": "symbolic link"})
        return
    try:
        info = source.stat()
    except OSError as exc:
        collection.skipped.append({"source": str(source), "reason": f"stat failed: {exc}"})
        return
    if not stat.S_ISREG(info.st_mode):
        collection.skipped.append({"source": str(source), "reason": "not a regular file"})
        return
    collection.files.append(
        EvidenceFile(
            source=source,
            archive_path=archive_path,
            size=info.st_size,
            mode=stat.S_IMODE(info.st_mode),
            mtime=info.st_mtime,
        )
    )


def collect_sources(
    sources: list[str],
    excludes: list[str],
    output: Path,
    sidecar: Path,
) -> Collection:
    collection = Collection()
    excluded_resolved = {output.resolve(), sidecar.resolve()}
    used_names: set[str] = set()
    seen_sources: set[Path] = set()
    for raw in sources:
        source = Path(raw).expanduser()
        if not source.exists():
            raise BundleError(f"source does not exist: {source}")
        try:
            resolved = source.resolve()
        except OSError:
            resolved = source.absolute()
        if resolved in seen_sources:
            collection.skipped.append({"source": str(source), "reason": "duplicate source"})
            continue
        seen_sources.add(resolved)

        base = safe_name(source.name or "root", "root")
        top_name = base
        suffix = 2
        while top_name in used_names:
            if source.is_dir():
                top_name = f"{base}-{suffix}"
            else:
                stem = safe_name(source.stem or "file", "file")
                extension = source.suffix if re.fullmatch(r"\.[A-Za-z0-9._-]+", source.suffix) else ""
                top_name = f"{stem}-{suffix}{extension}"
            suffix += 1
        used_names.add(top_name)
        collect_source(
            source, top_name, excludes, excluded_resolved, collection, root=source if source.is_dir() else None
        )
    collection.files.sort(key=lambda item: item.archive_path)
    return collection


def build_manifest(
    case_id: str,
    examiner: str,
    notes: list[str],
    source_arguments: list[str],
    collection: Collection,
    created_at: str,
) -> dict[str, Any]:
    return {
        "bundle_schema": BUNDLE_SCHEMA,
        "case_id": case_id,
        "created_at": created_at,
        "created_by": "eva/scripts/evidence_bundle.py",
        "hostname": socket.gethostname(),
        "examiner": examiner,
        "notes": notes,
        "source_arguments": source_arguments,
        "privacy": "not encrypted; may contain sensitive evidence",
        "file_count": len(collection.files),
        "total_bytes": sum(item.size for item in collection.files),
        "files": [item.manifest_entry() for item in collection.files],
        "skipped": collection.skipped,
        "chain_of_custody": [
            {
                "action": "created",
                "at": created_at,
                "actor": examiner,
                "detail": f"Created on {socket.gethostname()} with evidence_bundle.py",
            }
        ],
    }


def add_directory(tar: tarfile.TarFile, name: str, mtime: float) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o700
    info.mtime = int(mtime)
    tar.addfile(info)


def add_manifest(tar: tarfile.TarFile, manifest: dict[str, Any]) -> None:
    payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    info = tarfile.TarInfo(MANIFEST_PATH)
    info.size = len(payload)
    info.mode = 0o600
    info.mtime = int(datetime.now(timezone.utc).timestamp())
    tar.addfile(info, io.BytesIO(payload))


def add_evidence_file(tar: tarfile.TarFile, entry: EvidenceFile) -> None:
    try:
        before = entry.source.stat()
        with entry.source.open("rb") as handle:
            digest = hashlib.sha256()
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
            entry.sha256 = digest.hexdigest()
            after = entry.source.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise BundleError(f"file changed while hashing: {entry.source}")
            handle.seek(0)
            tar_info = tar.gettarinfo(str(entry.source), arcname=entry.archive_path)
            tar_info.mode = entry.mode
            tar_info.size = entry.size
            tar_info.mtime = int(entry.mtime)
            tar.addfile(tar_info, handle)
            after_add = entry.source.stat()
            if (before.st_size, before.st_mtime_ns) != (after_add.st_size, after_add.st_mtime_ns):
                raise BundleError(f"file changed while archiving: {entry.source}")
    except OSError as exc:
        raise BundleError(f"cannot add {entry.source}: {exc}") from exc


def write_sha256_sidecar(path: Path, archive_sha256: str) -> None:
    path.write_text(f"{archive_sha256}  {path.name.removesuffix('.sha256')}\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def create_bundle(args: argparse.Namespace) -> dict[str, Any]:
    created_at = utc_now()
    case_id = sanitize_case_id(args.case_id or f"case-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    examiner = args.examiner or getpass.getuser() or "unknown"
    compression = "gz" if args.compression == "gzip" else ""
    suffix = ".tar.gz" if compression else ".tar"
    if args.output:
        output = Path(args.output).expanduser()
    else:
        output = Path.cwd() / f"eva-evidence-{case_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}{suffix}"
    if compression:
        if output.suffix == ".tar":
            output = output.with_name(output.name + ".gz")
        elif output.suffix not in {".gz", ".tgz"}:
            output = output.with_name(output.name + ".tar.gz")
    else:
        if output.suffix in {".gz", ".tgz"}:
            output = output.with_suffix(".tar")
        elif output.suffix != ".tar":
            output = output.with_name(output.name + ".tar")
    output = output.absolute()
    sidecar = output.with_name(output.name + ".sha256")

    if (output.exists() or sidecar.exists()) and not args.force:
        raise BundleError(f"output already exists (use --force to replace): {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    collection = collect_sources(args.sources, args.exclude, output, sidecar)
    if not collection.files:
        raise BundleError("no regular files were selected for the bundle")

    for entry in collection.files:
        try:
            entry.sha256 = sha256_file(entry.source)
        except OSError as exc:
            raise BundleError(f"cannot hash {entry.source}: {exc}") from exc

    manifest = build_manifest(case_id, examiner, args.note, args.sources, collection, created_at)
    manifest["compression"] = args.compression
    file_descriptor, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    os.close(file_descriptor)
    temp_path = Path(temp_name)
    try:
        mode = "w:gz" if compression else "w"
        with tarfile.open(temp_path, mode=mode, format=tarfile.PAX_FORMAT) as tar:
            add_directory(tar, ARCHIVE_ROOT, time_now())
            add_directory(tar, EVIDENCE_ROOT, time_now())
            for entry in collection.files:
                add_evidence_file(tar, entry)
            manifest["files"] = [item.manifest_entry() for item in collection.files]
            add_manifest(tar, manifest)
        archive_sha256 = sha256_file(temp_path)
        if output.exists() and not args.force:
            raise BundleError(f"output appeared during collection: {output}")
        os.replace(temp_path, output)
        try:
            output.chmod(0o600)
        except OSError:
            pass
        write_sha256_sidecar(sidecar, archive_sha256)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    result = {
        "schema": "eva.evidence.create.v1",
        "valid": True,
        "archive": str(output),
        "archive_sha256": archive_sha256,
        "sidecar": str(sidecar),
        "case_id": case_id,
        "examiner": examiner,
        "file_count": len(collection.files),
        "total_bytes": sum(item.size for item in collection.files),
        "skipped": collection.skipped,
        "manifest": manifest,
    }
    return result


def time_now() -> float:
    return datetime.now(timezone.utc).timestamp()


def read_manifest(archive: Path) -> tuple[dict[str, Any], dict[str, tarfile.TarInfo], tarfile.TarFile]:
    try:
        tar = tarfile.open(archive, mode="r:*")  # noqa: SIM115 - ownership passes to the caller
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"cannot open archive: {exc}") from exc
    try:
        members: dict[str, tarfile.TarInfo] = {}
        for member in tar.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise BundleError(f"unsafe member path: {member.name}")
            if member.name in members:
                raise BundleError(f"duplicate archive member: {member.name}")
            if member.issym() or member.islnk():
                raise BundleError(f"links are not allowed in evidence bundles: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise BundleError(f"unsupported archive member type: {member.name}")
            members[member.name] = member
        manifest_member = members.get(MANIFEST_PATH)
        if manifest_member is None:
            raise BundleError(f"archive is missing {MANIFEST_PATH}")
        extracted = tar.extractfile(manifest_member)
        if extracted is None:
            raise BundleError("cannot read manifest")
        try:
            manifest = json.loads(extracted.read().decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError(f"invalid manifest JSON: {exc}") from exc
        if not isinstance(manifest, dict):
            raise BundleError("manifest root is not an object")
        if manifest.get("bundle_schema") != BUNDLE_SCHEMA:
            raise BundleError(f"unsupported bundle schema: {manifest.get('bundle_schema')!r}")
        return manifest, members, tar
    except Exception:
        tar.close()
        raise


def verify_bundle(args: argparse.Namespace) -> dict[str, Any]:
    archive = Path(args.archive).expanduser()
    if not archive.is_file():
        raise BundleError(f"archive does not exist: {archive}")
    archive_sha256 = sha256_file(archive)
    sidecar_path = Path(args.sidecar).expanduser() if args.sidecar else archive.with_name(archive.name + ".sha256")
    errors: list[str] = []
    warnings: list[str] = []
    sidecar_sha256 = ""
    if sidecar_path.is_file():
        try:
            first_line = sidecar_path.read_text(encoding="utf-8").splitlines()[0]
            sidecar_sha256 = first_line.split()[0].strip().lower()
            if sidecar_sha256 != archive_sha256:
                errors.append("archive SHA-256 does not match the .sha256 sidecar")
        except (OSError, IndexError) as exc:
            errors.append(f"cannot read sidecar: {exc}")
    else:
        warnings.append(f"sidecar not found: {sidecar_path}")

    manifest: dict[str, Any] = {}
    file_count = 0
    total_bytes = 0
    try:
        manifest, members, tar = read_manifest(archive)
        try:
            listed_files = manifest.get("files")
            if not isinstance(listed_files, list):
                errors.append("manifest.files is not an array")
                listed_files = []
            listed_paths: set[str] = set()
            for index, item in enumerate(listed_files):
                if not isinstance(item, dict):
                    errors.append(f"manifest.files[{index}] is not an object")
                    continue
                member_path = item.get("path")
                if not isinstance(member_path, str) or not member_path.startswith(f"{EVIDENCE_ROOT}/"):
                    errors.append(f"manifest.files[{index}] has an invalid path")
                    continue
                if member_path in listed_paths:
                    errors.append(f"duplicate manifest path: {member_path}")
                    continue
                listed_paths.add(member_path)
                member = members.get(member_path)
                if member is None:
                    errors.append(f"missing archive member: {member_path}")
                    continue
                expected_size = item.get("size")
                if not isinstance(expected_size, int) or member.size != expected_size:
                    errors.append(f"size mismatch for {member_path}")
                expected_hash = str(item.get("sha256") or "").lower()
                if not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
                    errors.append(f"invalid SHA-256 in manifest for {member_path}")
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    errors.append(f"cannot read archive member: {member_path}")
                    continue
                actual_hash = sha256_stream(extracted)
                if actual_hash != expected_hash:
                    errors.append(f"SHA-256 mismatch for {member_path}")
                file_count += 1
                total_bytes += member.size

            archive_files = {name for name, member in members.items() if member.isfile() and name != MANIFEST_PATH}
            extra = sorted(archive_files - listed_paths)
            if extra:
                errors.append(f"{len(extra)} archive file(s) are not listed in the manifest: {', '.join(extra[:5])}")
            if manifest.get("file_count") != len(listed_paths):
                errors.append("manifest.file_count does not match the number of listed files")
            expected_total = manifest.get("total_bytes")
            if expected_total is not None and expected_total != total_bytes:
                errors.append("manifest.total_bytes does not match the verified file sizes")
        finally:
            tar.close()
    except BundleError as exc:
        errors.append(str(exc))

    result = {
        "schema": "eva.evidence.verify.v1",
        "valid": not errors,
        "archive": str(archive),
        "archive_sha256": archive_sha256,
        "sidecar": str(sidecar_path),
        "sidecar_sha256": sidecar_sha256,
        "case_id": manifest.get("case_id", ""),
        "created_at": manifest.get("created_at", ""),
        "hostname": manifest.get("hostname", ""),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "errors": errors,
        "warnings": warnings,
        "manifest": manifest if args.include_manifest else None,
    }
    return result


def list_bundle(archive: Path) -> dict[str, Any]:
    manifest, members, tar = read_manifest(archive)
    try:
        files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
        return {
            "schema": "eva.evidence.list.v1",
            "archive": str(archive),
            "case_id": manifest.get("case_id", ""),
            "created_at": manifest.get("created_at", ""),
            "hostname": manifest.get("hostname", ""),
            "examiner": manifest.get("examiner", ""),
            "notes": manifest.get("notes", []),
            "privacy": manifest.get("privacy", ""),
            "file_count": len(files),
            "total_bytes": sum(item.get("size", 0) for item in files if isinstance(item, dict)),
            "members": len(members),
            "chain_of_custody": manifest.get("chain_of_custody", []),
            "manifest": manifest,
        }
    finally:
        tar.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create, verify, or inspect Eva evidence bundles.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a new evidence bundle")
    create.add_argument("sources", nargs="+", help="files or directories to include")
    create.add_argument("-o", "--output", help="output archive path")
    create.add_argument("--case-id", help="case or incident identifier")
    create.add_argument("--examiner", help="examiner name recorded in the manifest")
    create.add_argument("--note", action="append", default=[], help="case note (repeatable)")
    create.add_argument("--exclude", action="append", default=[], help="glob pattern to exclude (repeatable)")
    create.add_argument("--compression", choices=("gzip", "none"), default="gzip")
    create.add_argument("--force", action="store_true", help="replace an existing archive and sidecar")
    create.add_argument("--json", action="store_true", dest="json_output", help="emit JSON")
    create.add_argument("--quiet", action="store_true", help="suppress the encryption warning")

    verify = subparsers.add_parser("verify", help="verify archive hashes, manifest and sidecar")
    verify.add_argument("archive", help="evidence archive to verify")
    verify.add_argument("--sidecar", help="explicit sidecar path")
    verify.add_argument("--include-manifest", action="store_true", help="include the full manifest in JSON output")
    verify.add_argument("--json", action="store_true", dest="json_output", help="emit JSON")

    listing = subparsers.add_parser("list", help="show bundle metadata without hashing files")
    listing.add_argument("archive", help="evidence archive to inspect")
    listing.add_argument("--json", action="store_true", dest="json_output", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_bundle(args)
            if not args.quiet:
                print(
                    "WARNING: this bundle is not encrypted and may contain sensitive evidence.",
                    file=sys.stderr,
                )
            if args.json_output:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(f"Created evidence bundle: {result['archive']}")
                print(f"  case:       {result['case_id']}")
                print(f"  files:      {result['file_count']} ({result['total_bytes']} bytes)")
                print(f"  sha256:     {result['archive_sha256']}")
                print(f"  sidecar:    {result['sidecar']}")
                if result["skipped"]:
                    print(f"  skipped:    {len(result['skipped'])} item(s)")
            return 0
        if args.command == "verify":
            result = verify_bundle(args)
            if args.json_output:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                state = "OK" if result["valid"] else "FAILED"
                print(f"[{state}] {result['archive']}")
                print(f"  sha256: {result['archive_sha256']}")
                print(f"  files:  {result['file_count']} ({result['total_bytes']} bytes)")
                for error in result["errors"]:
                    print(f"  error: {error}")
                for warning in result["warnings"]:
                    print(f"  warning: {warning}")
            return 0 if result["valid"] else 1
        if args.command == "list":
            result = list_bundle(Path(args.archive).expanduser())
            if args.json_output:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(f"Case:      {result['case_id']}")
                print(f"Created:   {result['created_at']}")
                print(f"Host:      {result['hostname']}")
                print(f"Examiner:  {result['examiner']}")
                print(f"Files:     {result['file_count']} ({result['total_bytes']} bytes)")
                print(f"Privacy:   {result['privacy']}")
                if result["notes"]:
                    print("Notes:")
                    for note in result["notes"]:
                        print(f"  - {note}")
                if result["chain_of_custody"]:
                    print("Chain of custody:")
                    for event in result["chain_of_custody"]:
                        print(f"  - {event.get('at', '')} {event.get('action', '')} {event.get('actor', '')}")
            return 0
    except BundleError as exc:
        if getattr(args, "json_output", False):
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
