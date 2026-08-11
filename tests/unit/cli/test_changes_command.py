from importlib import import_module
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from eva.cli.app import app

app_module = import_module("eva.cli.app")
runner = CliRunner()


def test_cli_changes_no_changes_exits_one():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = ""

    with patch.object(app_module, "run_git", return_value=mock_res):
        res = runner.invoke(app, ["changes"])
        assert res.exit_code == 1
        assert "No changes found." in res.output


def test_cli_changes_unstaged_and_staged():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "diff --git a/a.py b/a.py\n+new line"

    with (
        patch.object(app_module, "run_git", return_value=mock_res) as mock_run_git,
        patch.object(app_module, "dispatch", side_effect=lambda *a, **kw: iter(["Explanation of diff"])),
    ):
        res_unstaged = runner.invoke(app, ["changes"])
        assert res_unstaged.exit_code == 0
        assert "Explanation of diff" in res_unstaged.stdout
        mock_run_git.assert_called_with(["diff"])

        res_staged = runner.invoke(app, ["changes", "--staged"])
        assert res_staged.exit_code == 0
        assert "Explanation of diff" in res_staged.stdout
        mock_run_git.assert_called_with(["diff", "--staged"])


def test_cli_changes_git_failure():
    mock_res = MagicMock()
    mock_res.returncode = 128
    mock_res.stdout = ""

    with patch.object(app_module, "run_git", return_value=mock_res):
        res = runner.invoke(app, ["changes"])
        assert res.exit_code == 1
        assert "Failed to run git diff." in res.output
