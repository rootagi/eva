import json
import pytest
import respx
from httpx import Response

from eva.config import AppConfig
from eva.telemetry.metrics import record_provider_metric


def test_telemetry_off_by_default(tmp_path):
    config = AppConfig()
    # Ensure off by default
    assert config.general.telemetry_enabled is False

    telemetry_dir = tmp_path / "telemetry"

    # Attempt recording
    record_provider_metric("groq", 0.35, True, config=config, telemetry_dir=telemetry_dir)

    # Verify no directory or file created
    assert not (telemetry_dir / "metrics.jsonl").exists()


def test_telemetry_opt_in_recording(tmp_path):
    config = AppConfig()
    config.general.telemetry_enabled = True

    telemetry_dir = tmp_path / "telemetry"

    record_provider_metric("groq", 0.42, True, config=config, telemetry_dir=telemetry_dir)
    record_provider_metric(
        "openrouter", 1.15, False, error_type="RateLimitError", config=config, telemetry_dir=telemetry_dir
    )

    metrics_file = telemetry_dir / "metrics.jsonl"
    assert metrics_file.exists()

    lines = metrics_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    m1 = json.loads(lines[0])
    assert m1["provider"] == "groq"
    assert m1["latency_s"] == 0.42
    assert m1["success"] is True
    assert "prompt" not in m1
    assert "content" not in m1

    m2 = json.loads(lines[1])
    assert m2["provider"] == "openrouter"
    assert m2["success"] is False
    assert m2["error_type"] == "RateLimitError"


@respx.mock
def test_telemetry_export_endpoint(tmp_path):
    route = respx.post("https://telemetry.example.com/api/v1/metrics").mock(return_value=Response(200, json={"status": "ok"}))

    config = AppConfig()
    config.general.telemetry_enabled = True
    config.general.telemetry_export_endpoint = "https://telemetry.example.com/api/v1/metrics"

    telemetry_dir = tmp_path / "telemetry"

    record_provider_metric("gemini", 0.25, True, config=config, telemetry_dir=telemetry_dir)

    assert route.called
    req = route.calls.last.request
    body = json.loads(req.content)
    assert "metrics" in body
    assert body["metrics"][0]["provider"] == "gemini"
