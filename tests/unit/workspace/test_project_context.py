from importlib import import_module
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app
from eva.workspace.project_context import load_project_context

app_module = import_module("eva.cli.app")
runner = CliRunner()


def test_load_project_context_missing(tmp_path: Path):
    assert load_project_context(tmp_path) == ""


def test_load_project_context_empty(tmp_path: Path):
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("   \n\n", encoding="utf-8")
    assert load_project_context(tmp_path) == ""


def test_load_project_context_present(tmp_path: Path):
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("# Project rules\nUse pytest.", encoding="utf-8")
    content = load_project_context(tmp_path)
    assert "=== Project Memory (.eva/context.md) ===" in content
    assert "Use pytest." in content


def test_load_project_context_binary(tmp_path: Path):
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_bytes(b"\x00\x01\x02\xff\xfe")
    assert load_project_context(tmp_path) == ""


def test_cli_ask_with_project_context(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("Project Architecture: Clean Architecture", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Answer"])) as mock_dispatch:
        res = runner.invoke(app, ["ask", "How to design?"])
        assert res.exit_code == 0
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert "=== Project Memory (.eva/context.md) ===" in passed_context
        assert "Clean Architecture" in passed_context


def test_cli_ask_with_no_project_context_flag(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("Secret Context", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Answer"])) as mock_dispatch:
        res = runner.invoke(app, ["ask", "How to design?", "--no-project-context"])
        assert res.exit_code == 0
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert "Secret Context" not in passed_context


def test_cli_work_with_project_context(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("Tooling: cargo build", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["echo 1"])) as mock_dispatch:
        res = runner.invoke(app, ["work", "build project", "--dry-run"])
        assert res.exit_code == 0
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert "=== Project Memory (.eva/context.md) ===" in passed_context
        assert "cargo build" in passed_context


def test_cli_work_with_no_project_context_flag(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("Tooling: cargo build", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["echo 1"])) as mock_dispatch:
        res = runner.invoke(app, ["work", "build project", "--dry-run", "--no-project-context"])
        assert res.exit_code == 0
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert passed_context == ""


def test_cli_context_show(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res_empty = runner.invoke(app, ["context", "show"])
    assert res_empty.exit_code == 0
    assert "No project context found" in res_empty.output

    eva_dir = tmp_path / ".eva"
    eva_dir.mkdir()
    (eva_dir / "context.md").write_text("My Memory", encoding="utf-8")

    res_found = runner.invoke(app, ["context", "show"])
    assert res_found.exit_code == 0
    assert "=== Project Memory (.eva/context.md) ===" in res_found.stdout
    assert "My Memory" in res_found.stdout
