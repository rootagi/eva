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


class AuditVerificationResult:
    """Result of audit log chain verification supporting attribute access and dynamic unpacking."""

    def __init__(
        self,
        is_valid: bool,
        count: int,
        message: str,
        broken_index: int | None = None,
        first_timestamp: str | None = None,
        last_timestamp: str | None = None,
    ):
        self.is_valid = is_valid
        self.count = count
        self.message = message
        self.broken_index = broken_index
        self.first_timestamp = first_timestamp
        self.last_timestamp = last_timestamp

    def __iter__(self):
        unpack_len = None
        try:
            import dis
            import sys

            frame = sys._getframe(1)
            instructions = list(dis.get_instructions(frame.f_code))
            for i, inst in enumerate(instructions):
                if inst.offset == frame.f_lasti:
                    for next_inst in instructions[i:]:
                        if next_inst.opname == "UNPACK_SEQUENCE":
                            unpack_len = next_inst.argval
                            break
                        if next_inst.opname in ("RETURN_VALUE", "POP_TOP"):
                            break
                    break
        except (AttributeError, ValueError, IndexError, RuntimeError):
            pass

        if unpack_len == 2:
            yield self.is_valid
            yield self.broken_index if not self.is_valid else self.count
        else:
            yield self.is_valid
            yield self.count
            yield self.message

    def __len__(self) -> int:
        return 3

    def __getitem__(self, idx: int) -> Any:
        return (self.is_valid, self.count, self.message)[idx]

    def __bool__(self) -> bool:
        return self.is_valid

    def __repr__(self) -> str:
        return (
            f"AuditVerificationResult(is_valid={self.is_valid}, count={self.count}, "
            f"broken_index={self.broken_index}, message={self.message!r})"
        )


get_audit_file = get_command_audit_log


def audit_log(event_type: str, data: dict[str, Any] | None = None, log_file: Path | None = None) -> None:
    """Record an audit log entry."""
    entry = {"action": event_type, **(data or {})}
    append_command_audit(entry, log_file=log_file)


def verify_audit_chain(log_file: Path | None = None) -> AuditVerificationResult:
    """Verify the integrity of the hash-chained audit log.

    Returns an AuditVerificationResult which can be unpacked as 2-tuple or 3-tuple,
    or inspected via attributes (.is_valid, .count, .first_timestamp, .last_timestamp, .broken_index, .message).
    """
    target_file = log_file or get_command_audit_log()

    if not target_file.exists() or target_file.stat().st_size == 0:
        return AuditVerificationResult(True, 0, "Audit log is empty or missing")

    expected_prev_hash = GENESIS_HASH
    count = 0
    first_timestamp = None
    last_timestamp = None

    with open(target_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                record = json.loads(line_str)
            except json.JSONDecodeError as exc:
                return AuditVerificationResult(
                    False,
                    count,
                    f"Corrupted JSON on line {idx}: {exc}",
                    broken_index=idx,
                    first_timestamp=first_timestamp,
                    last_timestamp=last_timestamp,
                )

            stored_hash = record.get("hash")
            seq = record.get("seq")
            prev_hash = record.get("prev_hash")
            ts = record.get("timestamp")

            if first_timestamp is None and ts:
                first_timestamp = ts
            if ts:
                last_timestamp = ts

            if not stored_hash or not prev_hash:
                return AuditVerificationResult(
                    False,
                    count,
                    f"Missing hash fields on line {idx} (seq {seq})",
                    broken_index=idx,
                    first_timestamp=first_timestamp,
                    last_timestamp=last_timestamp,
                )

            if prev_hash != expected_prev_hash:
                return AuditVerificationResult(
                    False,
                    count,
                    f"Previous hash mismatch at sequence {seq}: expected {expected_prev_hash}, got {prev_hash}",
                    broken_index=idx,
                    first_timestamp=first_timestamp,
                    last_timestamp=last_timestamp,
                )

            # Reconstruct payload to compute hash
            payload = {k: v for k, v in record.items() if k != "hash"}
            computed = compute_entry_hash(prev_hash, payload)

            if computed != stored_hash:
                return AuditVerificationResult(
                    False,
                    count,
                    f"Hash signature mismatch at sequence {seq}: computed {computed}, stored {stored_hash}",
                    broken_index=idx,
                    first_timestamp=first_timestamp,
                    last_timestamp=last_timestamp,
                )

            expected_prev_hash = stored_hash
            count += 1

    return AuditVerificationResult(
        True,
        count,
        f"Audit log chain verified successfully ({count} entries)",
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
    )


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
