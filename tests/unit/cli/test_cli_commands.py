from importlib import import_module
from pathlib import Path
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


def test_cli_ask_dir_command(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "main.py").write_text("print(1)\n", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Directory answer"])) as mock_dispatch:
        res = runner.invoke(app, ["ask", "explain directory structure", "--dir", str(d)])
        assert res.exit_code == 0
        assert "Directory answer" in res.stdout
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert f"=== Directory tree: {d} ===" in passed_context
        assert "main.py" in passed_context


def test_cli_ask_dir_invalid_path(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("not a dir", encoding="utf-8")

    res = runner.invoke(app, ["ask", "query", "--dir", str(f)])
    assert res.exit_code == 1
    assert "Not a directory" in res.output


def test_cli_ask_dir_and_file_combined(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("file content", encoding="utf-8")
    d = tmp_path / "src"
    d.mkdir()
    (d / "module.py").write_text("pass\n", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["Combined answer"])) as mock_dispatch:
        res = runner.invoke(app, ["ask", "compare file and dir", "-f", str(f), "-d", str(d)])
        assert res.exit_code == 0
        assert "Combined answer" in res.stdout
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert f"=== File: {f} ===" in passed_context
        assert f"=== Directory tree: {d} ===" in passed_context


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

    with patch.object(app_module, "dispatch", return_value=iter(["Analysis of error"])) as mock_dispatch:
        res = runner.invoke(app, ["analyze", "-f", str(f)])
        assert res.exit_code == 0
        assert "Analysis of error" in res.stdout
        mock_dispatch.assert_called_once()
        assert mock_dispatch.call_args[0][1] == "Analyze the provided content, identify issues, and suggest solutions."


def test_cli_analyze_custom_prompt():
    with patch.object(app_module, "dispatch", return_value=iter(["Custom analysis result"])) as mock_dispatch:
        res = runner.invoke(app, ["analyze", "Highlight high-severity secret exposures"], input="secret_key = 12345\n")
        assert res.exit_code == 0
        assert "Custom analysis result" in res.stdout
        mock_dispatch.assert_called_once()
        assert mock_dispatch.call_args[0][1] == "Highlight high-severity secret exposures"


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
        res = runner.invoke(app, ["commit-message"])
        assert res.exit_code == 0
        assert "feat: add change" in res.stdout


def test_cli_commit_old_name_removed():
    res = runner.invoke(app, ["commit"])
    assert res.exit_code != 0
    assert "No such command" in res.output or "Error:" in res.output


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


def test_cli_cache_clear_command():
    with patch.object(app_module, "clear_cache") as mock_clear:
        res = runner.invoke(app, ["cache", "clear"])
        assert res.exit_code == 0
        assert "Cache cleared." in res.output
        mock_clear.assert_called_once()


def test_cli_config_redaction_commands(tmp_path: Path):
    fake_config = app_module.load_config()
    with patch.object(app_module, "load_config", return_value=fake_config), patch.object(app_module, "save_config"):
        # set-redaction-threshold
        res_err = runner.invoke(app, ["config", "set-redaction-threshold", "9.5"])
        assert res_err.exit_code == 1

        res_ok = runner.invoke(app, ["config", "set-redaction-threshold", "4.2"])
        assert res_ok.exit_code == 0
        assert fake_config.general.redaction_entropy_threshold == 4.2

        # allow-redaction-pattern
        res_pat = runner.invoke(app, ["config", "allow-redaction-pattern", r"^test_.*"])
        assert res_pat.exit_code == 0
        assert r"^test_.*" in fake_config.general.redaction_ignore_patterns

        # disallow-redaction-pattern
        res_dis = runner.invoke(app, ["config", "disallow-redaction-pattern", r"^test_.*"])
        assert res_dis.exit_code == 0
        assert r"^test_.*" not in fake_config.general.redaction_ignore_patterns


def test_cli_config_ignored_dirs_commands():
    fake_config = app_module.load_config()
    with patch.object(app_module, "load_config", return_value=fake_config), patch.object(app_module, "save_config"):
        # ignore-dir
        res_ign = runner.invoke(app, ["config", "ignore-dir", "custom_build"])
        assert res_ign.exit_code == 0
        assert "custom_build" in fake_config.general.extra_ignored_dirs

        # unignore-dir
        res_unign = runner.invoke(app, ["config", "unignore-dir", "custom_build"])
        assert res_unign.exit_code == 0
        assert "custom_build" in fake_config.general.unignore_dirs
        assert "custom_build" not in fake_config.general.extra_ignored_dirs


def test_cli_config_sensitive_files_commands():
    fake_config = app_module.load_config()
    with patch.object(app_module, "load_config", return_value=fake_config), patch.object(app_module, "save_config"):
        # allow-sensitive-file
        res_allow = runner.invoke(app, ["config", "allow-sensitive-file", "*.example.env"])
        assert res_allow.exit_code == 0
        assert "*.example.env" in fake_config.general.sensitive_file_allowlist

        # disallow-sensitive-file
        res_disallow = runner.invoke(app, ["config", "disallow-sensitive-file", "*.example.env"])
        assert res_disallow.exit_code == 0
        assert "*.example.env" not in fake_config.general.sensitive_file_allowlist


def test_cli_context_token_limit_override(tmp_path: Path):
    f = tmp_path / "large.txt"
    f.write_text("token " * 2000, encoding="utf-8")

    fake_config = app_module.load_config()
    fake_config.general.context_token_limit = 50

    with (
        patch.object(app_module, "load_config", return_value=fake_config),
        patch.object(app_module, "dispatch", return_value=iter(["OK"])) as mock_dispatch,
    ):
        res = runner.invoke(app, ["ask", "Summarize", "-f", str(f)])
        assert res.exit_code == 0
        mock_dispatch.assert_called_once()
        passed_context = mock_dispatch.call_args[0][2]
        assert "[Context Trimmed]" in passed_context
