from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app

runner = CliRunner()


def test_cli_set_provider():
    res = runner.invoke(app, ["config", "set-provider", "groq"])
    assert res.exit_code == 0
    assert "Default provider set to groq" in res.output


def test_cli_set_key_getpass_prompt():
    with patch("getpass.getpass", return_value="secretkey"), patch("eva.cli.app.set_api_key"):
        res = runner.invoke(app, ["config", "set-key", "groq"])
        assert res.exit_code == 0
        assert "API key for 'groq' saved successfully." in res.output


def test_cli_set_key_empty_prompt():
    with patch("getpass.getpass", return_value="  "):
        res = runner.invoke(app, ["config", "set-key", "groq"])
        assert "API key cannot be empty." in res.output


def test_cli_explain_concept():
    with patch("eva.cli.app.dispatch", return_value=iter(["Concept explanation"])):
        res = runner.invoke(app, ["explain", "recursion"])
        assert res.exit_code == 0
        assert "Concept explanation" in res.output


def test_cli_explain_no_arg_no_stdin():
    with patch("eva.cli.app.dispatch", return_value=iter(["Repo explanation"])):
        res = runner.invoke(app, ["explain"])
        assert res.exit_code == 0
        assert "Repo explanation" in res.output


def test_cli_analyze_no_files_no_stdin():
    res = runner.invoke(app, ["analyze"])
    assert res.exit_code == 1
    assert "Provide files with -f or pipe stdout" in res.output


def test_cli_work_provider_error():
    with patch("eva.cli.app.dispatch", return_value=iter(["Error: provider offline"])):
        res = runner.invoke(app, ["work", "do something"])
        assert res.exit_code == 1
        assert "Error: provider offline" in res.output
