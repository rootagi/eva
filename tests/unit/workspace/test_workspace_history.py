from pathlib import Path

from eva.workspace.session import (
    _deep_redact,
    add_history,
    create_workspace,
    get_history,
    has_active_workspace,
    record_command_history,
    set_active_workspace,
)


def test_deep_redact_nested_structures():
    secret = "sk-123456789012345678901234567890"
    data = {
        "api_key": secret,
        "nested": [
            f"Bearer {secret}",
            {"inner_key": secret},
        ],
        "safe_int": 42,
    }

    redacted = _deep_redact(data)
    assert secret not in str(redacted)
    assert "[REDACTED" in redacted["api_key"]
    assert "[REDACTED" in redacted["nested"][0]
    assert "[REDACTED" in redacted["nested"][1]["inner_key"]
    assert redacted["safe_int"] == 42


def test_add_and_get_history(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("eva.workspace.session.get_config_dir", lambda: tmp_path)

    # Directly add history to a named workspace
    add_history(
        name="test_ws",
        entry_type="ask",
        content={"query": "how to build", "status": "success"},
        metadata={"model": "gpt-4"},
    )

    history = get_history("test_ws")
    assert len(history) == 1
    assert history[0]["entry_type"] == "ask"
    assert history[0]["content"]["query"] == "how to build"
    assert history[0]["metadata"]["model"] == "gpt-4"


def test_record_command_history_lifecycle(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("eva.workspace.session.get_config_dir", lambda: tmp_path)

    # When no workspace is active, record_command_history is a no-op
    assert has_active_workspace() is False
    record_command_history("work", {"command": "git status"})

    # Verify no workspace history was created
    assert len(get_history()) == 0

    # Activate a workspace
    create_workspace("active_ws")
    set_active_workspace("active_ws")
    assert has_active_workspace() is True

    record_command_history("work", {"command": "git commit -m 'feat'"})
    active_history = get_history()
    assert len(active_history) == 1
    assert active_history[0]["entry_type"] == "work"
    assert active_history[0]["content"]["command"] == "git commit -m 'feat'"
