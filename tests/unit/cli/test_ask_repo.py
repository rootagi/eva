from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app

runner = CliRunner()


def test_ask_repo_dry_run(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")

    with patch("eva.cli.app.dispatch") as mock_dispatch:
        result = runner.invoke(app, ["ask", "Explain the repo", "--repo", str(tmp_path), "--dry-run"])
        assert result.exit_code == 0
        assert "Repository Context Packing Summary" in result.output
        assert "Dry run only" in result.output
        mock_dispatch.assert_not_called()


def test_ask_repo_requires_confirmation_when_yes_not_passed(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")

    with (
        patch("eva.cli.app.dispatch") as mock_dispatch,
        patch("typer.confirm", return_value=True) as mock_confirm,
    ):
        mock_dispatch.return_value = iter(["Model response"])
        result = runner.invoke(app, ["ask", "Explain the repo", "--repo", str(tmp_path)])
        assert result.exit_code == 0
        mock_confirm.assert_called_once()
        mock_dispatch.assert_called_once()


def test_ask_repo_with_yes_skips_confirmation(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")

    with (
        patch("eva.cli.app.dispatch") as mock_dispatch,
        patch("typer.confirm") as mock_confirm,
    ):
        mock_dispatch.return_value = iter(["Model response"])
        result = runner.invoke(app, ["ask", "Explain the repo", "--repo", str(tmp_path), "--yes"])
        assert result.exit_code == 0
        mock_confirm.assert_not_called()
        mock_dispatch.assert_called_once()


def test_ask_repo_declined_confirmation_does_not_dispatch(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")

    with (
        patch("eva.cli.app.dispatch") as mock_dispatch,
        patch("typer.confirm", return_value=False) as mock_confirm,
    ):
        result = runner.invoke(app, ["ask", "Explain the repo", "--repo", str(tmp_path)])
        assert result.exit_code == 0
        mock_confirm.assert_called_once()
        mock_dispatch.assert_not_called()


def test_ask_repo_audit_logging_on_send(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / ".env").write_text("SECRET=123\n")

    with (
        patch("eva.cli.app.dispatch") as mock_dispatch,
        patch("eva.cli.app.append_command_audit") as mock_audit,
    ):
        mock_dispatch.return_value = iter(["Model response"])
        result = runner.invoke(app, ["ask", "Explain", "--repo", str(tmp_path), "--yes"])
        assert result.exit_code == 0
        mock_audit.assert_called_once()
        call_kwargs = mock_audit.call_args[0][0]
        assert call_kwargs["action"] == "repo_pack"
        assert "app.py" in call_kwargs["included_files"]
        assert any(item["path"] == ".env" and item["reason"] == "denylisted" for item in call_kwargs["excluded_files"])


def test_ask_repo_no_audit_logging_on_dry_run_or_decline(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")

    with (
        patch("eva.cli.app.dispatch"),
        patch("eva.cli.app.append_command_audit") as mock_audit,
    ):
        runner.invoke(app, ["ask", "Explain", "--repo", str(tmp_path), "--dry-run"])
        mock_audit.assert_not_called()

    with (
        patch("eva.cli.app.dispatch"),
        patch("typer.confirm", return_value=False),
        patch("eva.cli.app.append_command_audit") as mock_audit,
    ):
        runner.invoke(app, ["ask", "Explain", "--repo", str(tmp_path)])
        mock_audit.assert_not_called()
