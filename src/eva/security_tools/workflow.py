from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from eva.security_tools.models import Finding, RunContext
from eva.security_tools.normalizers import normalize_report
from eva.security_tools.registry import get_adapter, list_adapters
from eva.security_tools.report import write_reports
from eva.security_tools.scope import ScopeFile, assert_zap_authorized, load_scope_file
from eva.security_tools.utils import (
    artifact_record,
    ensure_run_dir,
    load_yaml_file,
    new_run_id,
    reject_unsafe_value,
    resolve_input_refs,
    write_json_artifact,
)


class SecurityWorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    uses: str
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    when: str | None = None

    @field_validator("uses")
    @classmethod
    def uses_registered_adapter(cls, value: str) -> str:
        if value not in list_adapters() and value != "report.merge":
            raise ValueError(f"unknown eva sec adapter: {value}")
        return value

    @field_validator("with_")
    @classmethod
    def with_values_are_declarative(cls, value: dict[str, Any]) -> dict[str, Any]:
        reject_unsafe_value(value, "with")
        return value


class SecurityWorkflow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str
    scope: str | None = None
    artifacts_dir: str = ".eva/artifacts"
    inputs: dict[str, Any] = Field(default_factory=dict)
    steps: list[SecurityWorkflowStep]

    @field_validator("steps")
    @classmethod
    def has_steps(cls, value: list[SecurityWorkflowStep]) -> list[SecurityWorkflowStep]:
        if not value:
            raise ValueError("security workflow contains no steps")
        return value


def load_security_workflow(path: Path | str) -> SecurityWorkflow:
    data = load_yaml_file(path)
    if not isinstance(data, dict):
        raise TypeError("security workflow must be a YAML mapping")
    reject_unsafe_value(data, "workflow")
    return SecurityWorkflow.model_validate(data)


def _should_run(step: SecurityWorkflowStep, inputs: dict[str, Any]) -> bool:
    if not step.when:
        return True
    if step.when.startswith("input."):
        return bool(inputs.get(step.when.split(".", 1)[1]))
    raise ValueError(f"unsupported workflow condition: {step.when}")


def run_security_workflow(
    plan_path: Path | str,
    *,
    inputs: dict[str, Any] | None = None,
    dry_run: bool = False,
    yes: bool = False,
) -> tuple[list[Finding], RunContext]:
    plan = load_security_workflow(plan_path)
    merged_inputs = {**plan.inputs, **(inputs or {})}
    run_id = new_run_id("sec")
    run_dir = ensure_run_dir(Path(plan.artifacts_dir), run_id)
    scope: ScopeFile | None = load_scope_file(plan.scope) if plan.scope else None
    context = RunContext(
        run_id=run_id,
        root=Path.cwd(),
        artifacts_dir=Path(plan.artifacts_dir),
        run_dir=run_dir,
        dry_run=dry_run,
        scope_id=scope.engagement_id if scope else None,
    )
    findings: list[Finding] = []

    for step in plan.steps:
        if not _should_run(step, merged_inputs):
            continue
        params = resolve_input_refs(step.with_, merged_inputs)
        if step.uses == "report.merge":
            formats = params.get("format", ["terminal", "json", "markdown", "sarif"])
            write_reports(findings, run_dir, list(formats))
            continue
        adapter = get_adapter(step.uses)
        operation = step.uses.split(".", 1)[1]
        if step.uses.startswith("zap."):
            target = str(params.get("target", ""))
            active = step.uses == "zap.active" or bool(params.get("active"))
            assert_zap_authorized(target, scope, active=active)
            if active and not yes:
                raise PermissionError("active ZAP workflow steps require yes=True after scope review")
        result = adapter.execute(
            operation,
            params,
            cwd=Path.cwd(),
            run_dir=run_dir,
            run_id=run_id,
            dry_run=dry_run,
            scope_id=context.scope_id,
        )
        if result.output_path and Path(result.output_path).exists():
            context.artifacts.append(artifact_record(result.output_path, f"{step.uses}-output"))
            findings.extend(adapter.parse_output(Path(result.output_path), result.stdout))
        elif result.stdout:
            stdout_path = run_dir / f"{adapter.metadata.name}-{operation}-stdout.txt"
            context.artifacts.append(
                write_json_artifact(stdout_path.with_suffix(".json"), result.model_dump(mode="json"))
            )
            findings.extend(adapter.parse_output(stdout_path, result.stdout))

    write_json_artifact(
        run_dir / "run-summary.json",
        {
            "run_id": context.run_id,
            "workflow": plan.name,
            "scope_id": context.scope_id,
            "dry_run": dry_run,
            "artifacts": [a.model_dump() for a in context.artifacts],
            "findings_count": len(findings),
        },
        "run-summary",
    )
    write_reports(findings, run_dir, ["json", "markdown", "sarif"])
    return findings, context


def ingest_report(
    path: Path | str, *, artifacts_dir: Path | str = ".eva/artifacts"
) -> tuple[list[Finding], RunContext]:
    run_id = new_run_id("ingest")
    run_dir = ensure_run_dir(Path(artifacts_dir), run_id)
    findings = normalize_report(path)
    context = RunContext(run_id=run_id, root=Path.cwd(), artifacts_dir=Path(artifacts_dir), run_dir=run_dir)
    context.artifacts.append(artifact_record(path, "input-report"))
    write_reports(findings, run_dir, ["json", "markdown", "sarif"])
    return findings, context
