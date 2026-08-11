from importlib import import_module
from unittest.mock import patch

from typer.testing import CliRunner

from eva.agent.loop import InvestigationResult, StoppedReason

app_module = import_module("eva.cli.app")
app = app_module.app
runner = CliRunner()


def test_investigate_command_success_with_yes(tmp_path):
    mock_res = InvestigationResult(
        final_answer="The project entry point is app.py.",
        files_read=["app.py"],
        turns_used=2,
        stopped_reason=StoppedReason.COMPLETED,
    )

    with (
        patch.object(app_module, "is_tool_capable", return_value=True),
        patch.object(app_module, "run_investigation", return_value=mock_res) as mock_run,
        patch.object(app_module, "append_investigation_audit") as mock_audit,
    ):
        result = runner.invoke(
            app, ["investigate", "where is entry point?", str(tmp_path), "--yes", "--provider", "groq"]
        )

    assert result.exit_code == 0
    mock_run.assert_called_once()
    mock_audit.assert_called_once_with(
        provider="groq",
        query="where is entry point?",
        files_read=["app.py"],
        turns_used=2,
        stopped_reason="completed",
    )
    assert "The project entry point is app.py." in result.output


def test_investigate_command_declined_confirmation(tmp_path):
    with (
        patch.object(app_module, "is_tool_capable", return_value=True),
        patch.object(app_module, "run_investigation") as mock_run,
        patch.object(app_module, "append_investigation_audit") as mock_audit,
    ):
        # Simulate user answering "n" to confirmation prompt
        result = runner.invoke(app, ["investigate", "test query", str(tmp_path)], input="n\n")

    assert result.exit_code == 0
    mock_run.assert_not_called()
    mock_audit.assert_not_called()
    assert "Investigation cancelled" in result.output


def test_investigate_command_unsupported_provider_exits_early(tmp_path):
    with (
        patch.object(app_module, "is_tool_capable", return_value=False),
        patch.object(app_module, "run_investigation") as mock_run,
        patch.object(app_module, "append_investigation_audit") as mock_audit,
    ):
        result = runner.invoke(app, ["investigate", "test query", str(tmp_path), "--provider", "ollama"])

    assert result.exit_code == 1
    mock_run.assert_not_called()
    mock_audit.assert_not_called()
    assert "does not support agentic exploration" in result.output
