from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from eva.cli.app import app

runner = CliRunner()


def test_cli_work_auto_confirm_success():
    with (
        patch("eva.cli.app.dispatch", return_value=iter(["echo hello"])),
        patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run,
    ):
        res = runner.invoke(app, ["work", "echo hello", "-y"])
        assert res.exit_code == 0
        mock_run.assert_called_once()


def test_cli_work_user_declined():
    with patch("eva.cli.app.dispatch", return_value=iter(["echo hello"])), patch("typer.confirm", return_value=False):
        res = runner.invoke(app, ["work", "echo hello"])
        assert res.exit_code == 0
        assert "Generated command:" in res.output


def test_cli_explain_piped_stdin():
    with patch("eva.cli.app.dispatch", return_value=iter(["Piped stdin explanation"])):
        res = runner.invoke(app, ["explain"], input="def foo(): pass\n")
        assert res.exit_code == 0
        assert "Piped stdin explanation" in res.output


def test_cli_analyze_piped_stdin():
    with patch("eva.cli.app.dispatch", return_value=iter(["Piped analyze explanation"])):
        res = runner.invoke(app, ["analyze"], input="Traceback (most recent call last):\nError\n")
        assert res.exit_code == 0
        assert "Piped analyze explanation" in res.output


def test_cli_edit_patch_user_declined(tmp_path):
    target = tmp_path / "file.py"
    target.write_text("a = 1\n", encoding="utf-8")
    diff_text = f"--- a/{target}\n+++ b/{target}\n@@ -1,1 +1,1 @@\n-a = 1\n+a = 2\n"

    with patch("eva.cli.app.dispatch", return_value=iter([diff_text])), patch("typer.confirm", return_value=False):
        res = runner.invoke(app, ["edit", "change a", "-f", str(target)])
        assert res.exit_code == 0
        assert "Patch not applied." in res.output


def test_cli_edit_invalid_diff(tmp_path):
    target = tmp_path / "file.py"
    target.write_text("a = 1\n", encoding="utf-8")

    with patch("eva.cli.app.dispatch", return_value=iter(["Not a diff format"])):
        res = runner.invoke(app, ["edit", "change a", "-f", str(target)])
        assert res.exit_code == 1
        assert "Refusing to apply non-diff model output" in res.output
