import pytest

from eva.replay import list_replay_sessions, load_replay_session, record_replay_event


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
    content = events_file.read_text(encoding="utf-8")

    assert secret_key not in content
    assert "REDACTED" in content


def test_load_nonexistent_session(tmp_path):
    replays_dir = tmp_path / "replays"
    with pytest.raises(FileNotFoundError):
        load_replay_session("nonexistent_session", replays_dir=replays_dir)
