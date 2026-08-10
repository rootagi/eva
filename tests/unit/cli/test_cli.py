from typer.testing import CliRunner

from eva.cli.app import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Eva — Command Line Intelligence" in result.stdout


def test_cli_config_show():
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "Eva Configuration" in result.stdout


def test_cli_budget_show():
    result = runner.invoke(app, ["budget", "show"])
    assert result.exit_code == 0
    assert "Token Budget & Rate Limit Usage" in result.stdout


def test_cli_doctor():
    result = runner.invoke(app, ["config", "doctor"])
    assert result.exit_code == 0
    assert "Running Eva Environment Doctor" in result.output


def test_cli_show_completion(monkeypatch):
    monkeypatch.setattr("shellingham.detect_shell", lambda: ("bash", "/bin/bash"))
    result = runner.invoke(app, ["--show-completion"])
    assert result.exit_code == 0
    assert "_EVA_COMPLETE=complete_bash" in result.stdout or "_eva_completion" in result.stdout


def test_cli_completion_script_generation():
    from typer._completion_shared import get_completion_script

    for shell in ["bash", "zsh", "fish"]:
        script = get_completion_script(prog_name="eva", complete_var="_EVA_COMPLETE", shell=shell)
        assert len(script) > 0
