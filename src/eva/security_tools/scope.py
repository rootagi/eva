from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from eva.security_tools.utils import load_yaml_file


class ScopeError(ValueError):
    pass


class ScopeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    engagement_id: str
    expires_at: datetime
    paths: list[str] = Field(default_factory=list)
    web_targets: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    max_requests_per_second: float = Field(default=1.0, gt=0)
    max_concurrency: int = Field(default=1, ge=1)
    max_duration_seconds: int = Field(default=600, ge=1)
    allow_active_scanning: bool = False

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("allowed_ports cannot be empty")
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port: {port}")
        return value

    @field_validator("web_targets")
    @classmethod
    def validate_targets(cls, value: list[str]) -> list[str]:
        for target in value:
            parsed = urlparse(target)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"invalid web target: {target}")
        return value

    def assert_not_expired(self, now: datetime | None = None) -> None:
        current = now or datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= current:
            raise ScopeError(f"scope '{self.engagement_id}' expired at {expires.isoformat()}")

    def summary(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "expires_at": self.expires_at.isoformat(),
            "web_targets": self.web_targets,
            "allowed_ports": self.allowed_ports,
            "max_requests_per_second": self.max_requests_per_second,
            "max_concurrency": self.max_concurrency,
            "max_duration_seconds": self.max_duration_seconds,
            "allow_active_scanning": self.allow_active_scanning,
        }


def load_scope_file(path: Path | str) -> ScopeFile:
    data = load_yaml_file(path)
    if not isinstance(data, dict):
        raise ScopeError("scope file must be a YAML mapping")
    scope = ScopeFile.model_validate(data)
    scope.assert_not_expired()
    return scope


def _effective_port(parsed) -> int:
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _path_within_scope(target_path: str, allowed_path: str) -> bool:
    base = allowed_path or "/"
    path = target_path or "/"
    if base == "/":
        return True
    base = base.rstrip("/")
    return path == base or path.startswith(f"{base}/")


def assert_target_in_scope(target: str, scope: ScopeFile) -> None:
    scope.assert_not_expired()
    parsed_target = urlparse(target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
        raise ScopeError(f"invalid target URL: {target}")
    port = _effective_port(parsed_target)
    if port not in scope.allowed_ports:
        raise ScopeError(f"target port {port} is not in allowed_ports")
    for approved in scope.web_targets:
        parsed_approved = urlparse(approved)
        if parsed_target.scheme != parsed_approved.scheme:
            continue
        if (parsed_target.hostname or "").lower() != (parsed_approved.hostname or "").lower():
            continue
        approved_port = _effective_port(parsed_approved)
        if port != approved_port and parsed_approved.port is not None:
            continue
        if _path_within_scope(parsed_target.path, parsed_approved.path):
            return
    raise ScopeError(f"target is outside approved web_targets: {target}")


def assert_zap_authorized(target: str, scope: ScopeFile | None, *, active: bool) -> ScopeFile:
    if scope is None:
        raise ScopeError("ZAP operations require a valid scope file")
    assert_target_in_scope(target, scope)
    if active and not scope.allow_active_scanning:
        raise ScopeError("active scanning requires allow_active_scanning: true in the scope file")
    return scope
