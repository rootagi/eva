import pytest
from typer.testing import CliRunner

from eva.cli.app import app
from eva.workflows.engine import (
    Workflow,
    WorkflowStep,
    list_workflows,
    load_workflow,
    run_workflow,
)

runner = CliRunner()


def test_load_builtin_workflows():
    wf_health = load_workflow("repo_health")
    assert wf_health.name == "repo_health"
    assert len(wf_health.steps) >= 3

    wf_dep = load_workflow("dependency_audit")
    assert wf_dep.name == "dependency_audit"
    assert len(wf_dep.steps) >= 2

    wf_sec = load_workflow("security_scan")
    assert wf_sec.name == "security_scan"
    assert len(wf_sec.steps) >= 2


def test_list_workflows():
    wfs = list_workflows()
    names = [w["name"] for w in wfs]
    assert "repo_health" in names
    assert "dependency_audit" in names
    assert "security_scan" in names


def test_load_user_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr("eva.workflows.engine.get_user_workflows_dir", lambda: tmp_path)
    wf_file = tmp_path / "custom.yaml"
    wf_file.write_text(
        """
name: custom
description: Custom test workflow
version: "1.0"
steps:
  - name: Step One
    command: "echo step1"
    description: "First step"
""",
        encoding="utf-8",
    )

    wf = load_workflow("custom")
    assert wf.name == "custom"
    assert len(wf.steps) == 1
    assert wf.steps[0].command == "echo step1"


def test_load_workflow_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_workflow("non_existent_workflow_name")

    bad_root = tmp_path / "bad1.yaml"
    bad_root.write_text("just string", encoding="utf-8")
    with pytest.raises(ValueError, match="expected dictionary root"):
        load_workflow(str(bad_root))

    no_steps = tmp_path / "bad2.yaml"
    no_steps.write_text("name: test\nsteps: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="contains no steps"):
        load_workflow(str(no_steps))

    bad_step = tmp_path / "bad3.yaml"
    bad_step.write_text("name: test\nsteps:\n  - invalid_step_string\n", encoding="utf-8")
    with pytest.raises(ValueError, match="is not a dictionary"):
        load_workflow(str(bad_step))

    missing_cmd = tmp_path / "bad4.yaml"
    missing_cmd.write_text("name: test\nsteps:\n  - name: step1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing 'command'"):
        load_workflow(str(missing_cmd))


def test_run_workflow_end_to_end_repo_fixture(tmp_path):
    """Integration test: Built-in workflow runs end-to-end against a test fixture repo."""
    (tmp_path / "README.md").write_text("# Test Repo\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")

    import subprocess

    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=tmp_path, capture_output=True, check=True)

    wf = load_workflow("repo_health")

    monkeypatch_cwd = tmp_path
    import os

    old_cwd = os.getcwd()
    try:
        os.chdir(monkeypatch_cwd)
        results = run_workflow(wf, interactive=False)
        assert len(results) == len(wf.steps)
        assert all(r["status"] == "success" for r in results)
    finally:
        os.chdir(old_cwd)


def test_run_workflow_user_declined():
    wf = load_workflow("repo_health")
    results = run_workflow(wf, interactive=True, confirm_func=lambda msg: False)
    assert len(results) == 1
    assert results[0]["status"] == "declined"


def test_run_workflow_unsafe_command_blocked():
    wf = Workflow(name="unsafe_test", description="test unsafe", steps=[WorkflowStep(name="Blast", command="rm -rf /")])
    results = run_workflow(wf, interactive=False)
    assert len(results) == 1
    assert results[0]["status"] == "blocked_unsafe"


def test_run_workflow_step_failure():
    wf = Workflow(name="fail_test", description="test fail", steps=[WorkflowStep(name="Failing Step", command="false")])
    results = run_workflow(wf, interactive=False)
    assert len(results) == 1
    assert results[0]["status"] == "failed"


def test_workflow_cli_commands():
    res_list = runner.invoke(app, ["workflow", "list"])
    assert res_list.exit_code == 0
    assert "repo_health" in res_list.stdout

    res_show = runner.invoke(app, ["workflow", "show", "repo_health"])
    assert res_show.exit_code == 0
    assert "Working Tree Status" in res_show.stdout

    res_run_fail = runner.invoke(app, ["workflow", "run", "non_existent_wf"])
    assert res_run_fail.exit_code == 1

    res_show_fail = runner.invoke(app, ["workflow", "show", "non_existent_wf"])
    assert res_show_fail.exit_code == 1
