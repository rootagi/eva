import pytest
import yaml

from eva.security_tools.workflow import load_security_workflow


def test_workflow_rejects_unknown_adapter(tmp_path):
    plan = tmp_path / "plan.yaml"
    plan.write_text(
        yaml.safe_dump({"version": 1, "name": "bad", "steps": [{"uses": "shell.run", "with": {"path": "."}}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown eva sec adapter"):
        load_security_workflow(plan)


def test_workflow_rejects_shell_keys_and_tokens(tmp_path):
    plan = tmp_path / "plan.yaml"
    plan.write_text(
        """
version: 1
name: bad
steps:
  - uses: trivy.filesystem
    with:
      command: "touch owned"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not allowed"):
        load_security_workflow(plan)

    plan.write_text(
        """
version: 1
name: bad
steps:
  - uses: trivy.filesystem
    with:
      path: ". | sh"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="shell control"):
        load_security_workflow(plan)


def test_workflow_accepts_input_reference(tmp_path):
    plan = tmp_path / "plan.yaml"
    plan.write_text(
        """
version: 1
name: ok
steps:
  - uses: aegis.analyze
    when: input.evidence_image
    with:
      path: ${input.evidence_image}
""",
        encoding="utf-8",
    )
    wf = load_security_workflow(plan)
    assert wf.steps[0].uses == "aegis.analyze"


def test_run_security_workflow_execution(tmp_path):
    from eva.security_tools.workflow import run_security_workflow

    plan = tmp_path / "plan.yaml"
    art_dir = tmp_path / "artifacts"
    plan.write_text(
        f"""
version: 1
name: test-run
artifacts_dir: {art_dir}
inputs:
  evidence_image: ""
steps:
  - uses: trivy.filesystem
    with:
      path: .
  - uses: aegis.analyze
    when: input.evidence_image
    with:
      path: "${{input.evidence_image}}"
  - uses: report.merge
    with:
      format: [json, sarif]
""",
        encoding="utf-8",
    )
    _findings, context = run_security_workflow(plan, dry_run=True)
    assert context.dry_run is True
    assert context.run_dir.exists()
    assert (context.run_dir / "run-summary.json").exists()


def test_ingest_report(tmp_path):
    import json

    from eva.security_tools.workflow import ingest_report

    report_path = tmp_path / "input_report.json"
    report_path.write_text(
        json.dumps(
            [
                {
                    "RuleID": "test-key",
                    "Description": "Found key",
                    "File": "secret.py",
                    "StartLine": 1,
                    "EndLine": 1,
                    "Secret": "abc12345",
                }
            ]
        ),
        encoding="utf-8",
    )
    findings, context = ingest_report(report_path, artifacts_dir=tmp_path / "art")
    assert len(findings) == 1
    assert findings[0].rule_id == "test-key"
    assert (context.run_dir / "findings.json").exists()
    assert (context.run_dir / "report.sarif").exists()
