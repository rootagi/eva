"""Unit tests for eva config audit verify and show commands."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from eva.cli.app import app
from eva.security.audit import audit_log, get_command_audit_log


@pytest.fixture
def runner():
    return CliRunner()


def test_audit_verify_empty(runner: CliRunner, tmp_path: Path, monkeypatch):
    monkeypatch.setattr("eva.config.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("eva.security.audit.get_config_dir", lambda: tmp_path)

    res = runner.invoke(app, ["config", "audit", "verify"])
    assert res.exit_code == 0
    assert "VALID" in res.output or "empty" in res.output.lower()


def test_audit_verify_valid_and_tampered(runner: CliRunner, tmp_path: Path, monkeypatch):
    monkeypatch.setattr("eva.config.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("eva.security.audit.get_config_dir", lambda: tmp_path)

    log_file = get_command_audit_log()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. Append valid entries
    audit_log("event_1", {"key": "value_1"}, log_file=log_file)
    audit_log("event_2", {"key": "value_2"}, log_file=log_file)

    res = runner.invoke(app, ["config", "audit", "verify"])
    assert res.exit_code == 0
    assert "VALID" in res.output

    # JSON verify output
    res_json = runner.invoke(app, ["config", "audit", "verify", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert data["valid"] is True
    assert data["entries"] == 2

    # 2. Tamper with entry
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[0])
    entry["action"] = "tampered"
    lines[0] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 3. Verification must fail with non-zero exit code
    res_fail = runner.invoke(app, ["config", "audit", "verify"])
    assert res_fail.exit_code == 1
    assert "COMPROMISED" in res_fail.output or "mismatch" in res_fail.output.lower()


def test_audit_show(runner: CliRunner, tmp_path: Path, monkeypatch):
    monkeypatch.setattr("eva.config.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("eva.security.audit.get_config_dir", lambda: tmp_path)

    log_file = get_command_audit_log()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    audit_log("run_cmd", {"command": "git status", "secret": "sk-1234567890abcdef1234567890abcdef"}, log_file=log_file)

    res = runner.invoke(app, ["config", "audit", "show"])
    assert res.exit_code == 0
    assert "run_cmd" in res.output
    # Secret should be redacted
    assert "sk-1234567890abcdef1234567890abcdef" not in res.output

    res_json = runner.invoke(app, ["config", "audit", "show", "--json"])
    assert res_json.exit_code == 0
    records = json.loads(res_json.output)
    assert len(records) == 1
    assert "run_cmd" in records[0].values()
