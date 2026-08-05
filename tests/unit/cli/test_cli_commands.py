from importlib import import_module
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from eva.cli.app import app

app_module = import_module("eva.cli.app")
runner = CliRunner()


def test_cli_ask_command(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("sample content", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Answer to query"])):
        res = runner.invoke(app, ["ask", "what is in file?", "-f", str(f)])
        assert res.exit_code == 0
        assert "Answer to query" in res.stdout


def test_cli_explain_command(tmp_path):
    f = tmp_path / "script.py"
    f.write_text("print('hello')", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Explanation of script"])):
        res = runner.invoke(app, ["explain", str(f)])
        assert res.exit_code == 0
        assert "Explanation of script" in res.stdout


def test_cli_explain_directory_target(tmp_path):
    (tmp_path / "main.py").write_text("import os\n", encoding="utf-8")
    with patch.object(app_module, "dispatch", return_value=iter(["Directory structure explanation"])):
        res = runner.invoke(app, ["explain", str(tmp_path)])
        assert res.exit_code == 0
        assert "Directory structure explanation" in res.stdout


def test_cli_explain_concept_target():
    with patch.object(app_module, "dispatch", return_value=iter(["Concept explanation"])):
        res = runner.invoke(app, ["explain", "recursion"])
        assert res.exit_code == 0
        assert "Concept explanation" in res.stdout


def test_cli_analyze_command(tmp_path):
    f = tmp_path / "error.log"
    f.write_text("ERROR: Out of memory", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Analysis of error"])):
        res = runner.invoke(app, ["analyze", "-f", str(f)])
        assert res.exit_code == 0
        assert "Analysis of error" in res.stdout


def test_cli_work_dry_run():
    with patch.object(app_module, "dispatch", return_value=iter(["ls -la"])):
        res = runner.invoke(app, ["work", "list files", "--dry-run"])
        assert res.exit_code == 0
        assert "Dry run only" in res.output


def test_cli_work_unsafe_command_refusal():
    with patch.object(app_module, "dispatch", return_value=iter(["rm -rf /"])):
        res = runner.invoke(app, ["work", "delete everything"])
        assert res.exit_code == 1
        assert "Refusing to execute unsafe command" in res.output


def test_cli_edit_command_apply(tmp_path):
    target = tmp_path / "foo.py"
    target.write_text("val = 1\n", encoding="utf-8")
    diff_output = f"--- a/{target}\n+++ b/{target}\n@@ -1,1 +1,1 @@\n-val = 1\n+val = 2\n"

    with patch.object(app_module, "dispatch", return_value=iter([diff_output])):
        res = runner.invoke(app, ["edit", "change val to 2", "-f", str(target), "--apply"])
        assert res.exit_code == 0
        assert "Patch applied." in res.output
        assert target.read_text(encoding="utf-8") == "val = 2\n"


def test_cli_commit_command():
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "diff --git a/f.txt b/f.txt\n+change"

    with (
        patch.object(app_module, "run_git", return_value=mock_res),
        patch.object(app_module, "dispatch", return_value=iter(["feat: add change"])),
    ):
        res = runner.invoke(app, ["commit"])
        assert res.exit_code == 0
        assert "feat: add change" in res.stdout


def test_cli_use_command():
    res = runner.invoke(app, ["use", "groq"])
    assert res.exit_code == 0
    assert "Default provider set to groq" in res.output


def test_cli_set_key_command():
    with patch.object(app_module, "set_api_key"):
        res = runner.invoke(app, ["config", "set-key", "groq", "testkey123"])
        assert res.exit_code == 0
        assert "API key for 'groq' saved successfully." in res.output


def test_cli_remove_key_command():
    with patch.object(app_module, "clear_api_key"):
        res = runner.invoke(app, ["config", "remove-key", "groq"])
        assert res.exit_code == 0
        assert "API key for 'groq' removed successfully." in res.output


def test_cli_config_show_and_doctor():
    res_show = runner.invoke(app, ["config", "show"])
    assert res_show.exit_code == 0
    assert "Eva Configuration" in res_show.output

    res_doc = runner.invoke(app, ["config", "doctor"])
    assert res_doc.exit_code == 0
    assert "Environment Doctor" in res_doc.output


def test_cli_budget_show():
    res = runner.invoke(app, ["budget", "show"])
    assert res.exit_code == 0
    assert "Rate Limit Usage" in res.output


def test_cli_set_model_command():
    res = runner.invoke(app, ["config", "set-model", "groq", "llama-3.3-70b-versatile"])
    assert res.exit_code == 0
    assert "Model for provider 'groq' set to 'llama-3.3-70b-versatile'." in res.output


def test_cli_usage_alias():
    res_u = runner.invoke(app, ["usage"])
    assert res_u.exit_code == 0
    assert "Rate Limit Usage" in res_u.output
