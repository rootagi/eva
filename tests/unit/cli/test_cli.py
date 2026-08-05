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
