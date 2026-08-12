from datetime import datetime, timezone
from pathlib import Path

from eva.config import get_config_dir
from eva.replay.crypto import encrypt_json, restrict_permissions
from eva.security.redaction import redact_secrets


def get_replays_dir() -> Path:
    d = get_config_dir() / "replays"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_session_dir(session_id: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    d = get_replays_dir() / safe_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def record_replay_event(
    session_id: str,
    command: str,
    output: str,
    exit_code: int,
    duration_s: float,
    cwd: str | Path,
    replays_dir: Path | None = None,
):
    """Record a terminal execution event to session replay log.

    Secrets in command, output, and cwd are redacted at write time,
    and each record is encrypted at rest.
    """
    target_dir = (replays_dir / session_id) if replays_dir else get_session_dir(session_id)
    target_dir.mkdir(parents=True, exist_ok=True)

    meta_file = target_dir / "meta.json"
    if not meta_file.exists():
        meta_file.write_bytes(
            encrypt_json(
                {
                    "session_id": session_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        )
        restrict_permissions(meta_file)

    events_file = target_dir / "events.jsonl"

    clean_command = redact_secrets(command)
    clean_output = redact_secrets(output)
    clean_cwd = redact_secrets(str(cwd))

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": clean_command,
        "output": clean_output,
        "exit_code": exit_code,
        "duration_s": round(duration_s, 4),
        "cwd": clean_cwd,
    }

    with open(events_file, "ab") as f:
        f.write(encrypt_json(record) + b"\n")
    restrict_permissions(events_file)
