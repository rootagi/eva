"""Tamper-evident, authenticated evidence bundles with AES-256-GCM / PBKDF2 encryption."""

from __future__ import annotations

import argparse
import fnmatch
import getpass
import hashlib
import io
import json
import logging
import os
import re
import socket
import stat
import struct
import sys
import tarfile
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

BUNDLE_SCHEMA = "eva.evidence.v1"
ARCHIVE_ROOT = "bundle"
EVIDENCE_ROOT = "bundle/evidence"
MANIFEST_PATH = "bundle/manifest.json"
CHUNK_SIZE = 1024 * 1024
CONTAINER_MAGIC = b"EVABUND1"
DEFAULT_PBKDF2_ITERATIONS = 600_000


class BundleError(RuntimeError):
    """Raised when a bundle operation fails."""


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
            "mode": oct(self.mode),
            "mtime": datetime.fromtimestamp(self.mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sha256": self.sha256,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_container(plaintext: bytes, passphrase: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=CONTAINER_MAGIC)
    header = CONTAINER_MAGIC + salt + nonce + struct.pack(">I", iterations)
    return header + ciphertext


def decrypt_container(raw_bytes: bytes, passphrase: str) -> bytes:
    if len(raw_bytes) < 40:
        raise BundleError("Corrupt bundle: file size is smaller than header minimum")
    if not raw_bytes.startswith(CONTAINER_MAGIC):
        raise BundleError("Invalid container magic header")

    salt = raw_bytes[8:24]
    nonce = raw_bytes[24:36]
    (iterations,) = struct.unpack(">I", raw_bytes[36:40])
    ciphertext = raw_bytes[40:]

    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=CONTAINER_MAGIC)
    except InvalidTag as exc:
        raise BundleError("Decryption failed: incorrect passphrase or corrupted bundle") from exc
    return plaintext


def is_encrypted_bundle(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(len(CONTAINER_MAGIC))
            return magic == CONTAINER_MAGIC
    except OSError:
        return False


def resolve_passphrase(passphrase: str | None = None, prompt_text: str = "Enter bundle passphrase: ") -> str | None:
    if passphrase:
        return passphrase
    env_pass = os.getenv("EVA_BUNDLE_PASSPHRASE")
    if env_pass:
        return env_pass
    if sys.stdin.isatty():
        try:
            return getpass.getpass(prompt_text)
        except (EOFError, KeyboardInterrupt):
            return None
    return None


def sanitize_relative_path(path: str) -> str:
    norm = re.sub(r"^[a-zA-Z]:", "", path).replace("\\", "/")
    parts = [p for p in norm.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise BundleError(f"Directory traversal prohibited: {path!r}")
    return "/".join(parts)


def gather_evidence_files(
    targets: Iterable[str | Path],
    exclude_patterns: list[str] | None = None,
) -> list[EvidenceFile]:
    excludes = exclude_patterns or []
    files: list[EvidenceFile] = []
    seen_archive_paths: set[str] = set()

    for target_raw in targets:
        target = Path(target_raw).expanduser()
        if not target.exists():
            raise BundleError(f"Target does not exist: {target}")

        if target.is_symlink():
            logger.warning("Skipping symlink target: %s", target)
            continue

        if target.is_file():
            candidates = [(target, target.name)]
        elif target.is_dir():
            candidates = []
            for root, dirs, fnames in os.walk(target, followlinks=False):
                dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
                for fname in sorted(fnames):
                    fpath = Path(root) / fname
                    if fpath.is_symlink():
                        continue
                    rel = fpath.relative_to(target.parent)
                    candidates.append((fpath, str(rel)))
        else:
            continue

        for fpath, rel_str in candidates:
            sanitized = sanitize_relative_path(rel_str)
            if any(fnmatch.fnmatch(sanitized, pat) or fnmatch.fnmatch(fpath.name, pat) for pat in excludes):
                continue
            archive_path = f"{EVIDENCE_ROOT}/{sanitized}"
            if archive_path in seen_archive_paths:
                continue
            seen_archive_paths.add(archive_path)

            try:
                st = fpath.stat()
                if not stat.S_ISREG(st.st_mode):
                    continue
                files.append(
                    EvidenceFile(
                        source=fpath,
                        archive_path=archive_path,
                        size=st.st_size,
                        mode=st.st_mode,
                        mtime=st.st_mtime,
                        sha256="",
                    )
                )
            except OSError as exc:
                raise BundleError(f"Cannot stat evidence file {fpath}: {exc}") from exc

    return files


def create_bundle(
    targets: list[str | Path],
    output: Path,
    case_id: str | None = None,
    examiner: str | None = None,
    notes: list[str] | None = None,
    exclude: list[str] | None = None,
    compression: str = "gzip",
    force: bool = False,
    encrypt: bool = True,
    passphrase: str | None = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> dict[str, Any]:
    """Create an evidence bundle (encrypted by default with AES-256-GCM / PBKDF2)."""
    out_path = output.expanduser().resolve()
    if out_path.exists() and not force:
        raise BundleError(f"Output file already exists: {out_path} (use --force to overwrite)")

    if encrypt:
        resolved_pass = resolve_passphrase(passphrase, "Enter bundle encryption passphrase: ")
        if not resolved_pass:
            raise BundleError(
                "Passphrase required for encrypted bundle. Provide --passphrase, EVA_BUNDLE_PASSPHRASE, or --no-encrypt."
            )
        passphrase_val = resolved_pass
    else:
        passphrase_val = None

    evidence_items = gather_evidence_files(targets, exclude_patterns=exclude)
    if not evidence_items:
        raise BundleError("No eligible files found to package into evidence bundle")

    # Hash every evidence file
    for item in evidence_items:
        item.sha256 = sha256_file(item.source)

    manifest = {
        "schema": BUNDLE_SCHEMA,
        "created_at": utc_now(),
        "case_id": case_id or "UNASSIGNED",
        "examiner": examiner or getpass.getuser(),
        "hostname": socket.gethostname(),
        "encrypted": bool(encrypt),
        "notes": notes or [],
        "file_count": len(evidence_items),
        "total_size_bytes": sum(f.size for f in evidence_items),
        "chain_of_custody": [
            {
                "timestamp": utc_now(),
                "action": "bundle_created",
                "actor": examiner or getpass.getuser(),
                "details": f"Packaged {len(evidence_items)} evidence files",
            }
        ],
        "files": [item.manifest_entry() for item in evidence_items],
    }

    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    # Build tar in memory
    tar_buf = io.BytesIO()
    tar_mode = "w:gz" if compression == "gzip" else "w"
    with tarfile.open(fileobj=tar_buf, mode=tar_mode) as tar:
        # 1. Add manifest
        m_info = tarfile.TarInfo(name=MANIFEST_PATH)
        m_info.size = len(manifest_bytes)
        m_info.mtime = int(time.time())
        m_info.mode = 0o600
        tar.addfile(m_info, io.BytesIO(manifest_bytes))

        # 2. Add files
        for item in evidence_items:
            # Re-verify file has not changed during packaging
            current_hash = sha256_file(item.source)
            if current_hash != item.sha256:
                raise BundleError(f"File modified during packaging: {item.source}")

            with open(item.source, "rb") as f:
                f_info = tarfile.TarInfo(name=item.archive_path)
                f_info.size = item.size
                f_info.mtime = int(item.mtime)
                f_info.mode = item.mode
                tar.addfile(f_info, f)

    archive_bytes = tar_buf.getvalue()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if encrypt and passphrase_val:
        final_bytes = encrypt_container(archive_bytes, passphrase_val, iterations=iterations)
    else:
        final_bytes = archive_bytes

    out_path.write_bytes(final_bytes)
    try:
        out_path.chmod(0o600)
    except OSError:
        pass

    archive_sha256 = sha256_bytes(final_bytes)
    sidecar_path = out_path.with_name(f"{out_path.name}.sha256")
    sidecar_path.write_text(f"{archive_sha256}  {out_path.name}\n", encoding="utf-8")
    try:
        sidecar_path.chmod(0o600)
    except OSError:
        pass

    return {
        "status": "created",
        "archive": str(out_path),
        "sidecar": str(sidecar_path),
        "sha256": archive_sha256,
        "files_packaged": len(evidence_items),
        "total_bytes": len(final_bytes),
        "encrypted": encrypt,
        "case_id": manifest["case_id"],
    }


def open_bundle_tar(archive_path: Path, passphrase: str | None = None) -> tuple[tarfile.TarFile, bool]:
    """Open bundle tarfile, transparently decrypting if encrypted container."""
    if not archive_path.is_file():
        raise BundleError(f"Archive not found: {archive_path}")

    raw = archive_path.read_bytes()
    encrypted = raw.startswith(CONTAINER_MAGIC)

    if encrypted:
        resolved_pass = resolve_passphrase(passphrase, f"Enter passphrase for {archive_path.name}: ")
        if not resolved_pass:
            raise BundleError("Passphrase required to decrypt bundle")
        tar_bytes = decrypt_container(raw, resolved_pass)
        try:
            tar = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*")  # noqa: SIM115
        except (tarfile.TarError, OSError) as exc:
            raise BundleError(f"Corrupt or invalid archive: {exc}") from exc
    else:
        try:
            tar = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")  # noqa: SIM115
        except (tarfile.TarError, OSError) as exc:
            raise BundleError(f"Corrupt or invalid archive: {exc}") from exc

    return tar, encrypted


def verify_bundle(
    archive_path: Path,
    sidecar_path: Path | None = None,
    passphrase: str | None = None,
    include_manifest: bool = False,
) -> dict[str, Any]:
    """Verify sidecar integrity, container decryption, and inner file SHA-256 hashes."""
    arch = archive_path.expanduser().resolve()
    if not arch.is_file():
        return {"valid": False, "archive": str(arch), "errors": [f"Archive does not exist: {arch}"]}

    errors: list[str] = []
    sidecar = sidecar_path or arch.with_name(f"{arch.name}.sha256")
    sidecar_verified = False

    if sidecar.is_file():
        try:
            sidecar_text = sidecar.read_text(encoding="utf-8").strip()
            expected_hash = sidecar_text.split()[0]
            actual_hash = sha256_file(arch)
            if actual_hash.lower() != expected_hash.lower():
                errors.append(f"Sidecar SHA-256 mismatch: expected {expected_hash}, got {actual_hash}")
            else:
                sidecar_verified = True
        except (OSError, ValueError, IndexError) as exc:
            errors.append(f"Sidecar verification error: {exc}")

    try:
        tar, is_enc = open_bundle_tar(arch, passphrase=passphrase)
    except (BundleError, tarfile.TarError, OSError) as exc:
        errors.append(str(exc))
        return {
            "valid": False,
            "archive": str(arch),
            "errors": errors,
            "sidecar_verified": sidecar_verified,
        }

    manifest_data: dict[str, Any] = {}
    try:
        with tar:
            names = tar.getnames()
            if MANIFEST_PATH not in names:
                errors.append(f"Missing bundle manifest: {MANIFEST_PATH}")
                return {"valid": False, "archive": str(arch), "errors": errors}

            m_member = tar.getmember(MANIFEST_PATH)
            f_manifest = tar.extractfile(m_member)
            if not f_manifest:
                errors.append("Failed to extract manifest")
                return {"valid": False, "archive": str(arch), "errors": errors}

            try:
                manifest_data = json.loads(f_manifest.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
                errors.append(f"Corrupt manifest JSON: {exc}")
                return {"valid": False, "archive": str(arch), "errors": errors}

            # Verify files in manifest
            manifest_files = {f["path"]: f for f in manifest_data.get("files", []) if isinstance(f, dict)}

            archive_evidence_names = {m.name for m in tar.getmembers() if m.name != MANIFEST_PATH}
            manifest_file_names = set(manifest_files.keys())

            missing_files = manifest_file_names - archive_evidence_names
            for missing in sorted(missing_files):
                errors.append(f"File listed in manifest is missing from archive: {missing}")

            extra_files = archive_evidence_names - manifest_file_names
            for extra in sorted(extra_files):
                errors.append(f"Unmanifested file found in archive: {extra}")

            for member in tar.getmembers():
                name = member.name
                if name == MANIFEST_PATH:
                    continue
                if member.islnk() or member.issym():
                    errors.append(f"Symlinks forbidden in bundle: {name}")
                if name.startswith("/") or ".." in name:
                    errors.append(f"Illegal path in archive member: {name}")

                if name in manifest_files:
                    m_entry = manifest_files[name]
                    extracted_f = tar.extractfile(member)
                    if not extracted_f:
                        errors.append(f"Cannot read member {name}")
                        continue
                    data = extracted_f.read()
                    actual_m_hash = sha256_bytes(data)
                    if actual_m_hash != m_entry.get("sha256"):
                        errors.append(
                            f"Hash mismatch for {name}: expected {m_entry.get('sha256')}, got {actual_m_hash}"
                        )
                    if len(data) != m_entry.get("size"):
                        errors.append(f"Size mismatch for {name}: expected {m_entry.get('size')}, got {len(data)}")

    except (tarfile.TarError, OSError, ValueError, KeyError) as exc:
        errors.append(f"Archive extraction error: {exc}")

    is_valid = len(errors) == 0
    res = {
        "valid": is_valid,
        "archive": str(arch),
        "encrypted": is_enc,
        "sidecar_verified": sidecar_verified,
        "case_id": manifest_data.get("case_id"),
        "examiner": manifest_data.get("examiner"),
        "files_verified": len(manifest_data.get("files", [])),
        "errors": errors,
    }
    if include_manifest:
        res["manifest"] = manifest_data
    return res


def list_bundle(archive_path: Path, passphrase: str | None = None) -> dict[str, Any]:
    """Inspect and display bundle manifest metadata."""
    arch = archive_path.expanduser().resolve()
    tar, is_enc = open_bundle_tar(arch, passphrase=passphrase)

    with tar:
        if MANIFEST_PATH not in tar.getnames():
            raise BundleError(f"Missing {MANIFEST_PATH} in bundle")
        f_manifest = tar.extractfile(tar.getmember(MANIFEST_PATH))
        if not f_manifest:
            raise BundleError("Cannot extract manifest")
        manifest = json.loads(f_manifest.read().decode("utf-8"))

    manifest["encrypted"] = is_enc
    manifest["archive"] = str(arch)
    return manifest


# ===========================================================================
# Compatibility CLI Entrypoint for scripts/evidence_bundle.py
# ===========================================================================


def bundle_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Eva tamper-evident evidence bundle utility")
    sub = parser.add_subparsers(dest="command", required=True)

    # create
    create_p = sub.add_parser("create")
    create_p.add_argument("targets", nargs="+")
    create_p.add_argument("-o", "--output", required=True, type=Path)
    create_p.add_argument("--case-id")
    create_p.add_argument("--examiner")
    create_p.add_argument("--note", action="append", dest="notes", default=[])
    create_p.add_argument("--exclude", action="append", dest="exclude", default=[])
    create_p.add_argument("--compression", choices=("gzip", "none"), default="gzip")
    create_p.add_argument("--force", action="store_true")
    create_p.add_argument("--encrypt", action="store_true", default=False)
    create_p.add_argument("--no-encrypt", action="store_true")
    create_p.add_argument("--passphrase")
    create_p.add_argument("--json", dest="json_output", action="store_true")

    # verify
    verify_p = sub.add_parser("verify")
    verify_p.add_argument("archive", type=Path)
    verify_p.add_argument("--sidecar", type=Path)
    verify_p.add_argument("--passphrase")
    verify_p.add_argument("--include-manifest", action="store_true")
    verify_p.add_argument("--json", dest="json_output", action="store_true")

    # list
    list_p = sub.add_parser("list")
    list_p.add_argument("archive", type=Path)
    list_p.add_argument("--passphrase")
    list_p.add_argument("--json", dest="json_output", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "create":
        encrypt = args.encrypt and not args.no_encrypt
        if args.passphrase:
            encrypt = True
        try:
            res = create_bundle(
                targets=args.targets,
                output=args.output,
                case_id=args.case_id,
                examiner=args.examiner,
                notes=args.notes,
                exclude=args.exclude,
                compression=args.compression,
                force=args.force,
                encrypt=encrypt,
                passphrase=args.passphrase,
            )
            if args.json_output:
                print(json.dumps(res, indent=2))
            else:
                print(f"[+] Bundle created: {res['archive']}")
                print(f"[+] Sidecar: {res['sidecar']}")
            return 0
        except (BundleError, OSError, ValueError, KeyError) as exc:
            if args.json_output:
                print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
            else:
                print(f"Error: {exc}", file=sys.stderr)
            return 1

    if args.command == "verify":
        res = verify_bundle(
            archive_path=args.archive,
            sidecar_path=args.sidecar,
            passphrase=args.passphrase,
            include_manifest=args.include_manifest,
        )
        if args.json_output:
            print(json.dumps(res, indent=2))
        else:
            status = "VALID" if res["valid"] else "FAILED"
            print(f"[{status}] {res['archive']}")
            for err in res["errors"]:
                print(f"  Error: {err}", file=sys.stderr)
        return 0 if res["valid"] else 1

    if args.command == "list":
        try:
            res = list_bundle(args.archive, passphrase=args.passphrase)
            if args.json_output:
                print(json.dumps(res, indent=2))
            else:
                print(f"Case ID:   {res.get('case_id')}")
                print(f"Examiner:  {res.get('examiner')}")
                print(f"Encrypted: {res.get('encrypted')}")
                print(f"Files:     {res.get('file_count')}")
            return 0
        except (BundleError, OSError, ValueError, KeyError) as exc:
            if args.json_output:
                print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
            else:
                print(f"Error: {exc}", file=sys.stderr)
            return 1

    return 2
