import json
from datetime import datetime, timedelta, timezone

import pytest

from eva.security_tools.scope import ScopeFile
from eva.security_tools.zap import ZapAdapter


def make_scope(**overrides):
    data = {
        "engagement_id": "eng-001",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        "paths": ["."],
        "web_targets": ["https://staging.example.internal/api"],
        "allowed_ports": [443],
        "max_requests_per_second": 3.5,
        "max_concurrency": 4,
        "max_duration_seconds": 900,
        "allow_active_scanning": False,
    }
    data.update(overrides)
    return ScopeFile.model_validate(data)


def test_zap_status():
    adapter = ZapAdapter()
    status = adapter.status()
    assert status.name == "zap"
    assert status.executable == "zap.sh"


def test_zap_build_plan_passive(tmp_path):
    adapter = ZapAdapter()
    scope = make_scope()
    output_path = tmp_path / "zap-report.json"

    plan = adapter.build_plan(
        target="https://staging.example.internal/api/users",
        scope=scope,
        output_path=output_path,
        active=False,
    )

    env_params = plan["env"]["parameters"]
    assert env_params["maxRequestsPerSecond"] == 3.5
    assert env_params["maxConcurrency"] == 4

    job_types = [j["type"] for j in plan["jobs"]]
    assert "passiveScan-config" in job_types
    assert "spider" in job_types
    assert "passiveScan-wait" in job_types
    assert "activeScan" not in job_types
    assert "report" in job_types


def test_zap_build_plan_active(tmp_path):
    adapter = ZapAdapter()
    scope = make_scope(allow_active_scanning=True)
    output_path = tmp_path / "zap-report.json"

    plan = adapter.build_plan(
        target="https://staging.example.internal/api/users",
        scope=scope,
        output_path=output_path,
        active=True,
    )

    job_types = [j["type"] for j in plan["jobs"]]
    assert "activeScan" in job_types
    active_job = next(j for j in plan["jobs"] if j["type"] == "activeScan")
    assert active_job["parameters"]["threadPerHost"] == 4


def test_zap_write_plan_and_build_argv(tmp_path):
    adapter = ZapAdapter()
    scope = make_scope()
    plan_path = tmp_path / "zap-plan.yaml"
    plan = adapter.build_plan(
        target="https://staging.example.internal/api",
        scope=scope,
        output_path=tmp_path / "out.json",
        active=False,
    )
    record = adapter.write_plan(plan_path, plan)
    assert record.path == str(plan_path)
    assert plan_path.exists()

    argv = adapter.build_argv("baseline", {"plan_path": str(plan_path)}, tmp_path / "out.json")
    assert argv == ["zap.sh", "-cmd", "-autorun", str(plan_path)]

    with pytest.raises(ValueError, match="requires an Automation Framework plan path"):
        adapter.build_argv("baseline", {}, tmp_path / "out.json")


def test_zap_parse_output(tmp_path):
    adapter = ZapAdapter()
    out_file = tmp_path / "zap-report.json"
    out_file.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "https://staging.example.internal",
                        "alerts": [
                            {
                                "pluginid": "10038",
                                "alert": "Content Security Policy (CSP) Header Not Set",
                                "riskdesc": "Medium (High)",
                                "confidence": "High",
                                "solution": "Ensure CSP is configured.",
                                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                                "instances": [
                                    {"uri": "https://staging.example.internal/api/login", "evidence": "X-Frame-Options"}
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    findings = adapter.parse_output(out_file)
    assert len(findings) == 1
    assert findings[0].tool == "zap"
    assert findings[0].rule_id == "10038"
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "high"
    assert findings[0].target == "https://staging.example.internal/api/login"
    assert "CSP" in findings[0].title
