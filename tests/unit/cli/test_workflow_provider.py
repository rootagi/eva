from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from eva.cli.app import app
from eva.workflows.engine import Step, Workflow, run_workflow

runner = CliRunner()


def test_workflow_step_alias_and_id():
    """Verify Step is an alias for WorkflowStep and has id attribute."""
    step = Step(name="Test Step", command="echo 1", description="desc", id="step-1")
    assert step.id == "step-1"
    assert step.name == "Test Step"


def test_workflow_cli_rejects_unknown_provider(tmp_path: Path):
    """Verify workflow CLI errors out when an invalid provider is specified."""
    wf_file = tmp_path / "test.yaml"
    wf_file.write_text(
        """
name: invalid-provider-wf
description: Test invalid provider
steps:
  - name: step1
    command: echo hello
"""
    )
    result = runner.invoke(app, ["workflow", "run", str(wf_file), "--provider", "non_existent_provider_xyz"])
    assert result.exit_code != 0
    assert "Unknown or unsupported provider" in result.output


def test_workflow_pinned_provider_audit_logging(tmp_path: Path):
    """Verify run_workflow records pinned_provider in audit log and propagates to env."""
    wf = Workflow(
        name="test-pinned-wf",
        description="Testing pinned provider propagation",
        steps=[
            Step(name="echo-step", command="echo $EVA_PROVIDER", description="Verify env var"),
        ],
    )

    audit_records = []

    def mock_append_audit(record):
        audit_records.append(record)

    with patch("eva.workflows.engine.append_command_audit", side_effect=mock_append_audit):
        results = run_workflow(wf, interactive=False, pinned_provider="mock-provider")

    assert len(results) == 1
    assert results[0]["status"] == "success"

    # All audit records must include pinned_provider
    assert len(audit_records) >= 1
    for rec in audit_records:
        assert rec.get("pinned_provider") == "mock-provider"


def test_workflow_environment_provider_propagation(tmp_path: Path):
    """Verify EVA_PROVIDER and EVA_DEFAULT_PROVIDER are set in subprocess execution environment."""
    captured_envs = []

    def mock_run(argv, **kwargs):
        captured_envs.append(kwargs.get("env", {}))

        class MockRes:
            returncode = 0
            stdout = "done\n"
            stderr = ""

        return MockRes()

    wf = Workflow(
        name="test-env-wf",
        description="Test env wf description",
        steps=[
            Step(name="s1", command="echo test", description="desc"),
        ],
    )

    with patch("subprocess.run", side_effect=mock_run):
        run_workflow(wf, interactive=False, pinned_provider="custom-gemini")

    assert len(captured_envs) >= 1
    assert captured_envs[0].get("EVA_PROVIDER") == "custom-gemini"
    assert captured_envs[0].get("EVA_DEFAULT_PROVIDER") == "custom-gemini"
