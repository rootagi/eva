from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from eva.security.redaction import redact_secrets
from eva.security_tools.models import ArtifactRecord

SHELL_CONTROL_TOKENS = {"|", "||", "&&", ";", ">", ">>", "<", "<<", "&"}
COMMAND_SUBSTITUTION_PATTERNS = ("$(", "`")
UNSAFE_WORKFLOW_KEYS = {"command", "cmd", "shell", "bash", "script", "run"}
INPUT_REF_RE = re.compile(r"^\$\{input\.([A-Za-z_][A-Za-z0-9_]*)\}$")


class SecurityToolError(ValueError):
    pass


class UnsafeWorkflowValue(SecurityToolError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_run_id(prefix: str = "sec") -> str:
    return f"{prefix}-{utc_now().strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"


def ensure_run_dir(artifacts_dir: Path | str, run_id: str) -> Path:
    run_dir = Path(artifacts_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def artifact_record(path: Path | str, kind: str) -> ArtifactRecord:
    p = Path(path)
    return ArtifactRecord(path=str(p), sha256=sha256_file(p), kind=kind, size_bytes=p.stat().st_size)


def hash_input_path(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    if p.is_file():
        return {"path": str(p), "type": "file", "sha256": sha256_file(p), "size_bytes": p.stat().st_size}
    if p.is_dir():
        files = []
        for child in sorted(item for item in p.rglob("*") if item.is_file()):
            if ".git" in child.parts or ".eva" in child.parts:
                continue
            try:
                files.append(
                    {
                        "path": str(child.relative_to(p)),
                        "sha256": sha256_file(child),
                        "size_bytes": child.stat().st_size,
                    }
                )
            except OSError:
                continue
        return {"path": str(p), "type": "directory", "files": files, "file_count": len(files)}
    raise FileNotFoundError(f"input path does not exist: {p}")


def write_json_artifact(path: Path | str, data: Any, kind: str = "json") -> ArtifactRecord:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(redact_obj(data), f, indent=2, sort_keys=True)
        f.write("\n")
    return artifact_record(p, kind)


def write_text_artifact(path: Path | str, text: str, kind: str = "text") -> ArtifactRecord:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(redact_secrets(text), encoding="utf-8")
    return artifact_record(p, kind)


def read_json_file(path: Path | str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml_file(path: Path | str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(k): redact_obj(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    return value


def _has_shell_control(value: str) -> bool:
    if "\n" in value or "\r" in value:
        return True
    if any(pattern in value for pattern in COMMAND_SUBSTITUTION_PATTERNS):
        return not bool(INPUT_REF_RE.fullmatch(value))
    parts = value.split()
    return any(part in SHELL_CONTROL_TOKENS for part in parts)


def reject_unsafe_value(value: Any, path: str = "value") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_str = str(key)
            if key_str in UNSAFE_WORKFLOW_KEYS:
                raise UnsafeWorkflowValue(f"{path}.{key_str} is not allowed in eva sec workflows")
            reject_unsafe_value(item, f"{path}.{key_str}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_unsafe_value(item, f"{path}[{index}]")
    elif isinstance(value, str) and _has_shell_control(value):
        raise UnsafeWorkflowValue(f"{path} contains shell control syntax")


def resolve_input_refs(value: Any, inputs: dict[str, Any]) -> Any:
    if isinstance(value, str):
        match = INPUT_REF_RE.fullmatch(value)
        if match:
            return inputs.get(match.group(1))
        return value
    if isinstance(value, list):
        return [resolve_input_refs(item, inputs) for item in value]
    if isinstance(value, dict):
        return {str(k): resolve_input_refs(v, inputs) for k, v in value.items()}
    return value
