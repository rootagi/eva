import json

import pytest

from eva.security.work_safety import (
    CommandExtractionError,
    append_command_audit,
    get_command_audit_log,
    parse_safe_command,
)


def test_append_command_audit(monkeypatch, tmp_path):
    monkeypatch.setattr("eva.security.audit.get_config_dir", lambda: tmp_path)

    entry = {"query": "ls", "executed": True}
    append_command_audit(entry)

    log_path = get_command_audit_log()
    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    data = json.loads(lines[0])
    assert data["query"] == "ls"
    assert data["executed"] is True
    assert "timestamp" in data


def test_shlex_parse_error():
    with pytest.raises(CommandExtractionError, match="Failed to parse command arguments"):
        parse_safe_command("echo 'unclosed quote")
