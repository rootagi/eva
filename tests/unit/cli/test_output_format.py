import json
from importlib import import_module
from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app

app_module = import_module("eva.cli.app")
runner = CliRunner()


def test_ask_format_json_success():
    with patch.object(app_module, "dispatch", return_value=iter(["Here is the answer."])):
        result = runner.invoke(app, ["ask", "What is 2+2?", "--provider", "openrouter", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["content"] == "Here is the answer."
        assert data["is_error"] is False
        assert data["provider"] == "openrouter"


def test_ask_format_json_error():
    with patch.object(app_module, "dispatch", return_value=iter(["[Eva Error] Provider failed"])):
        result = runner.invoke(app, ["ask", "What is 2+2?", "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert "[Eva Error]" in data["content"]
        assert data["is_error"] is True


def test_explain_format_json_success(tmp_path):
    f = tmp_path / "hello.py"
    f.write_text("print('hello')", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["This script prints hello."])):
        result = runner.invoke(app, ["explain", str(f), "--provider", "openrouter", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["content"] == "This script prints hello."
        assert data["is_error"] is False
        assert data["provider"] == "openrouter"


def test_explain_format_json_error(tmp_path):
    f = tmp_path / "hello.py"
    f.write_text("print('hello')", encoding="utf-8")

    with patch.object(app_module, "dispatch", return_value=iter(["[Eva Error] Model error"])):
        result = runner.invoke(app, ["explain", str(f), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert data["is_error"] is True


def test_invalid_format_option():
    with patch.object(app_module, "dispatch") as mock_dispatch:
        result = runner.invoke(app, ["ask", "What is 2+2?", "--format", "xml"])
        assert result.exit_code == 1
        assert "Invalid --format 'xml'" in result.output
        mock_dispatch.assert_not_called()


def test_default_text_format():
    with patch.object(app_module, "dispatch", return_value=iter(["# Heading\nRegular output"])):
        result = runner.invoke(app, ["ask", "Tell me something"])
        assert result.exit_code == 0
        assert "Regular output" in result.stdout
