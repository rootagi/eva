from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding
from eva.security_tools.normalizers import normalize_zap
from eva.security_tools.scope import ScopeFile
from eva.security_tools.utils import read_json_file, write_text_artifact


class ZapAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="zap",
        executable="zap.sh",
        version_check=["zap.sh", "-version"],
        argv_schema={"target": "url", "active": "bool", "scope": "ScopeFile"},
        output_schema="zap-json",
        timeout=900,
        required_capabilities=["passive-baseline", "zap-automation-framework", "sarif-import"],
        risk_level="network-passive",
        supported_output_formats=["json", "sarif", "yaml"],
    )
    install_hint = "Install OWASP ZAP from https://www.zaproxy.org/download/ and ensure zap.sh is on PATH."

    def output_suffix(self, operation: str) -> str:
        return "json"

    def build_plan(
        self,
        *,
        target: str,
        scope: ScopeFile,
        output_path: Path,
        active: bool = False,
    ) -> dict[str, Any]:
        jobs: list[dict[str, Any]] = [
            {
                "type": "passiveScan-config",
                "parameters": {
                    "maxAlertsPerRule": 100,
                    "scanOnlyInScope": True,
                    "maxBodySizeInBytesToScan": 262144,
                },
            },
            {
                "type": "spider",
                "parameters": {
                    "context": "eva-sec",
                    "url": target,
                    "maxDuration": max(1, scope.max_duration_seconds // 60),
                    "maxDepth": 5,
                },
            },
            {"type": "passiveScan-wait", "parameters": {"maxDuration": max(1, scope.max_duration_seconds // 60)}},
        ]
        if active:
            jobs.append(
                {
                    "type": "activeScan",
                    "parameters": {
                        "context": "eva-sec",
                        "policy": "Default Policy",
                        "maxScanDurationInMins": max(1, scope.max_duration_seconds // 60),
                        "maxRuleDurationInMins": 1,
                        "threadPerHost": scope.max_concurrency,
                    },
                }
            )
        jobs.append(
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": str(output_path.parent),
                    "reportFile": output_path.name,
                },
            }
        )
        return {
            "env": {
                "contexts": [
                    {
                        "name": "eva-sec",
                        "urls": scope.web_targets,
                        "includePaths": [f"{url}.*" for url in scope.web_targets],
                        "excludePaths": [],
                    }
                ],
                "parameters": {
                    "failOnError": False,
                    "failOnWarning": False,
                    "maxRequestsPerSecond": scope.max_requests_per_second,
                    "maxConcurrency": scope.max_concurrency,
                },
            },
            "jobs": jobs,
        }

    def write_plan(self, path: Path, plan: dict[str, Any]):
        text = yaml.safe_dump(plan, sort_keys=False)
        return write_text_artifact(path, text, "zap-plan")

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        plan_path = params.get("plan_path")
        if not plan_path:
            raise ValueError("zap adapter requires an Automation Framework plan path")
        return [self.metadata.executable, "-cmd", "-autorun", str(plan_path)]

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if output_path.exists():
            return normalize_zap(read_json_file(output_path), str(output_path))
        return []
