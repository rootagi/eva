import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eva.config import get_config_dir
from eva.security.redaction import redact_secrets

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def get_command_audit_log() -> Path:
    return get_config_dir() / "command_audit.jsonl"


def _sanitize_dict(data: Any) -> Any:
    """Recursively redact secrets in dict keys/values and list items."""
    if isinstance(data, str):
        return redact_secrets(data)
    if isinstance(data, dict):
        return {k: _sanitize_dict(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_dict(item) for item in data]
    return data


def compute_entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Compute sha256 hash over prev_hash and canonical JSON of entry payload."""
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    content = f"{prev_hash}:{canonical_json}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def append_command_audit(entry: dict[str, Any], log_file: Path | None = None):
    """Append a hash-chained audit entry to the audit log."""
    target_file = log_file or get_command_audit_log()
    target_file.parent.mkdir(parents=True, exist_ok=True)

    sanitized_entry = _sanitize_dict(entry)

    last_hash = GENESIS_HASH
    seq = 1

    if target_file.exists() and target_file.stat().st_size > 0:
        with open(target_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            if lines:
                try:
                    last_record = json.loads(lines[-1])
                    last_hash = last_record.get("hash", GENESIS_HASH)
                    seq = last_record.get("seq", len(lines)) + 1
                except (OSError, ValueError) as exc:
                    logger.debug("Failed to read last audit record: %s", exc)

    payload = {
        "seq": seq,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prev_hash": last_hash,
        **sanitized_entry,
    }

    entry_hash = compute_entry_hash(last_hash, payload)
    record = {"hash": entry_hash, **payload}

    with open(target_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def verify_audit_chain(log_file: Path | None = None) -> tuple[bool, int, str]:
    """Verify the integrity of the hash-chained audit log.

    Returns:
        (is_valid, last_valid_seq, message)
    """
    target_file = log_file or get_command_audit_log()

    if not target_file.exists() or target_file.stat().st_size == 0:
        return True, 0, "Audit log is empty or missing"

    expected_prev_hash = GENESIS_HASH
    count = 0

    with open(target_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                record = json.loads(line_str)
            except json.JSONDecodeError as exc:
                return False, count, f"Corrupted JSON on line {idx}: {exc}"

            stored_hash = record.get("hash")
            seq = record.get("seq")
            prev_hash = record.get("prev_hash")

            if not stored_hash or not prev_hash:
                return False, count, f"Missing hash fields on line {idx} (seq {seq})"

            if prev_hash != expected_prev_hash:
                return (
                    False,
                    count,
                    f"Previous hash mismatch at sequence {seq}: expected {expected_prev_hash}, got {prev_hash}",
                )

            # Reconstruct payload to compute hash
            payload = {k: v for k, v in record.items() if k != "hash"}
            computed = compute_entry_hash(prev_hash, payload)

            if computed != stored_hash:
                return (
                    False,
                    count,
                    f"Hash signature mismatch at sequence {seq}: computed {computed}, stored {stored_hash}",
                )

            expected_prev_hash = stored_hash
            count += 1

    return True, count, f"Audit log chain verified successfully ({count} entries)"


def append_investigation_audit(
    provider: str,
    query: str,
    files_read: list[str],
    turns_used: int,
    stopped_reason: str,
    log_file: Path | None = None,
):
    """Record an audit log entry for an agentic investigation session."""
    entry = {
        "command": "investigate",
        "provider": provider,
        "query": query,
        "files_read": files_read,
        "turns_used": turns_used,
        "stopped_reason": stopped_reason,
    }
    append_command_audit(entry, log_file=log_file)
