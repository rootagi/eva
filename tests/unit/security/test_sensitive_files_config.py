import json
from importlib import import_module
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from eva.agent.tools import list_directory, read_file, search_code
from eva.cli.app import app
from eva.indexing.packer import pack_repository
from eva.security.sensitive_files import (
    configure_sensitive_file_allowlist,
    is_sensitive_file,
)

app_module = import_module("eva.cli.app")
runner = CliRunner()


def test_sensitive_files_allowlist_config():
    try:
        assert is_sensitive_file("secrets.example.json") is True
        assert is_sensitive_file("secrets.json") is True

        configure_sensitive_file_allowlist(["secrets.example.json"])
        assert is_sensitive_file("secrets.example.json") is False
        assert is_sensitive_file("secrets.json") is True
    finally:
        configure_sensitive_file_allowlist([])


def test_tools_with_force_include(tmp_path: Path):
    pem_file = tmp_path / "server.pem"
    pem_file.write_text("CERT_CONTENT", encoding="utf-8")

    # Without force_include
    entries = list_directory(tmp_path)
    assert not any(e["name"] == "server.pem" for e in entries)

    res = read_file(tmp_path, "server.pem")
    assert res.success is False
    assert "File is excluded for security reasons" in (res.error or "")

    hits = search_code(tmp_path, "CERT_CONTENT")
    assert len(hits) == 0

    # With force_include
    entries_forced = list_directory(tmp_path, force_include={"server.pem"})
    assert any(e["name"] == "server.pem" for e in entries_forced)

    res_forced = read_file(tmp_path, "server.pem", force_include={"server.pem"})
    assert res_forced.success is True
    assert "CERT_CONTENT" in (res_forced.content or "")

    hits_forced = search_code(tmp_path, "CERT_CONTENT", force_include={"server.pem"})
    assert len(hits_forced) == 1
    assert hits_forced[0]["file"] == "server.pem"


def test_packer_with_force_include(tmp_path: Path):
    creds_file = tmp_path / "secrets.json"
    creds_file.write_text('{"user": "admin"}', encoding="utf-8")

    # Without force_include
    pack_res = pack_repository(tmp_path, max_tokens=1000)
    assert not any(f == "secrets.json" for f in pack_res.included_files)
    assert any(f == "secrets.json" and reason == "denylisted" for f, reason in pack_res.excluded_files)

    # With force_include
    pack_res_forced = pack_repository(tmp_path, max_tokens=1000, force_include={"secrets.json"})
    assert any(f == "secrets.json" for f in pack_res_forced.included_files)


def test_cli_investigate_force_include_audit(tmp_path: Path):
    pem_file = tmp_path / "server.pem"
    pem_file.write_text("CERT DATA", encoding="utf-8")
    audit_file = tmp_path / "audit.jsonl"

    with (
        patch.object(app_module, "is_tool_capable", return_value=True),
        patch.object(
            app_module,
            "run_investigation",
            return_value=MagicMock(
                final_answer="Found server.pem content",
                files_read=["server.pem"],
                turns_used=1,
                stopped_reason=MagicMock(value="completed"),
            ),
        ),
        patch("eva.security.audit.get_command_audit_log", return_value=audit_file),
    ):
        result = runner.invoke(
            app,
            ["investigate", "Check server.pem", str(tmp_path), "--yes", "--force-include", "server.pem"],
        )
        assert result.exit_code == 0
        assert "Found server.pem content" in result.stdout

        assert audit_file.exists()
        lines = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        override_entries = [e for e in lines if e.get("action") == "sensitive_file_override"]
        assert len(override_entries) == 1
        assert override_entries[0]["command"] == "investigate"
        assert override_entries[0]["path"] == "server.pem"


def test_cli_ask_repo_force_include_audit(tmp_path: Path):
    creds_file = tmp_path / "secrets.json"
    creds_file.write_text('{"token": "xyz"}', encoding="utf-8")
    audit_file = tmp_path / "audit.jsonl"

    with (
        patch.object(app_module, "dispatch", return_value=iter(["Repo answer"])),
        patch("eva.security.audit.get_command_audit_log", return_value=audit_file),
    ):
        result = runner.invoke(
            app,
            ["ask", "Check creds", "--repo", str(tmp_path), "--yes", "--force-include", "secrets.json"],
        )
        assert result.exit_code == 0
        assert "Repo answer" in result.stdout

        assert audit_file.exists()
        lines = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        override_entries = [e for e in lines if e.get("action") == "sensitive_file_override"]
        assert len(override_entries) == 1
        assert override_entries[0]["command"] == "ask"
        assert override_entries[0]["path"] == "secrets.json"
