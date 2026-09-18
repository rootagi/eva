from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
Confidence = Literal["high", "medium", "low", "unknown"]
RiskLevel = Literal["local", "network-passive", "network-active"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tool: str
    rule_id: str = ""
    title: str
    severity: Severity = "unknown"
    confidence: Confidence = "unknown"
    category: str = ""
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    target: str | None = None
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    fingerprint: str
    artifact_path: str | None = None


class ArtifactRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    kind: str
    size_bytes: int


class AdapterMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    executable: str
    version_check: list[str]
    argv_schema: dict[str, Any]
    output_schema: str
    timeout: int
    required_capabilities: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = "local"
    supported_output_formats: list[str] = Field(default_factory=lambda: ["json"])


class ToolStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    executable: str
    installed: bool
    version: str | None = None
    supported_features: list[str] = Field(default_factory=list)
    install_hint: str
    error: str | None = None


class ToolExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter: str
    operation: str
    argv: list[str]
    dry_run: bool = False
    skipped: bool = False
    missing: bool = False
    timed_out: bool = False
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    output_path: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_s: float


class RunContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    run_id: str
    root: Path
    artifacts_dir: Path
    run_dir: Path
    dry_run: bool = False
    scope_id: str | None = None
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
