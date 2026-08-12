import json

import pytest

from eva.replay import list_replay_sessions, load_replay_session, record_replay_event
from eva.replay.crypto import decrypt_json_line


def test_replay_recording_and_loading(tmp_path):
    replays_dir = tmp_path / "replays"

    record_replay_event(
        session_id="test_session",
        command="echo hello",
        output="hello",
        exit_code=0,
        duration_s=0.12,
        cwd=tmp_path,
        replays_dir=replays_dir,
    )

    sessions = list_replay_sessions(replays_dir=replays_dir)
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "test_session"
    assert sessions[0]["event_count"] == 1

    events = load_replay_session("test_session", replays_dir=replays_dir)
    assert len(events) == 1
    assert events[0]["command"] == "echo hello"
    assert events[0]["output"] == "hello"
    assert events[0]["exit_code"] == 0


def test_replay_redacts_secrets_at_write_time(tmp_path):
    replays_dir = tmp_path / "replays"

    secret_key = "sk-1234567890123456789012345678901234567890"
    record_replay_event(
        session_id="secret_session",
        command=f"export API_KEY={secret_key}",
        output=f"Stored secret key {secret_key}",
        exit_code=0,
        duration_s=0.05,
        cwd=tmp_path,
        replays_dir=replays_dir,
    )

    events_file = replays_dir / "secret_session" / "events.jsonl"
    raw = events_file.read_bytes()

    # Ciphertext on disk must never contain the raw secret.
    assert secret_key.encode() not in raw

    # Decrypted content should show the redaction happened before encryption.
    decrypted = decrypt_json_line(raw.splitlines()[0])
    assert secret_key not in decrypted["command"]
    assert secret_key not in decrypted["output"]
    assert "REDACTED" in decrypted["command"]
    assert "REDACTED" in decrypted["output"]


def test_replay_events_file_is_encrypted_at_rest(tmp_path):
    """The whole point of the fix: plaintext JSON should never hit disk."""
    replays_dir = tmp_path / "replays"

    record_replay_event(
        session_id="enc_session",
        command="echo plaintext-marker",
        output="plaintext-marker output",
        exit_code=0,
        duration_s=0.01,
        cwd=tmp_path,
        replays_dir=replays_dir,
    )

    events_file = replays_dir / "enc_session" / "events.jsonl"
    meta_file = replays_dir / "enc_session" / "meta.json"

    for f in (events_file, meta_file):
        raw = f.read_bytes()
        # Encrypted bytes are not valid/parseable JSON.
        with pytest.raises((json.JSONDecodeError, UnicodeDecodeError, ValueError)):
            json.loads(raw)
        assert b"plaintext-marker" not in raw
        assert b"enc_session" not in raw or f == events_file  # session_id lives in meta, encrypted too


def test_load_replay_session_falls_back_to_legacy_plaintext(tmp_path):
    """Records written before encryption was introduced must still load."""
    replays_dir = tmp_path / "replays"
    session_dir = replays_dir / "legacy_session"
    session_dir.mkdir(parents=True)

    legacy_record = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "command": "echo legacy",
        "output": "legacy",
        "exit_code": 0,
        "duration_s": 0.01,
        "cwd": "/tmp",
    }
    (session_dir / "events.jsonl").write_text(json.dumps(legacy_record) + "\n", encoding="utf-8")

    events = load_replay_session("legacy_session", replays_dir=replays_dir)
    assert len(events) == 1
    assert events[0]["command"] == "echo legacy"


def test_replay_key_survives_process_restart(tmp_path, monkeypatch):
    """A fresh Fernet instance (simulating a new process) must still
    decrypt data written by a previous one, i.e. the key must persist."""
    from eva.replay import crypto

    replays_dir = tmp_path / "replays"
    record_replay_event(
        session_id="persist_session",
        command="echo persisted",
        output="persisted",
        exit_code=0,
        duration_s=0.01,
        cwd=tmp_path,
        replays_dir=replays_dir,
    )

    crypto.reset_cached_fernet()  # simulate a new process picking the key back up

    events = load_replay_session("persist_session", replays_dir=replays_dir)
    assert events[0]["command"] == "echo persisted"


def test_load_nonexistent_session(tmp_path):
    replays_dir = tmp_path / "replays"
    with pytest.raises(FileNotFoundError):
        load_replay_session("nonexistent_session", replays_dir=replays_dir)
