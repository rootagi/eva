import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from eva.config import AppConfig, get_config_dir

logger = logging.getLogger(__name__)


def get_telemetry_dir() -> Path:
    d = get_config_dir() / "telemetry"
    d.mkdir(parents=True, exist_ok=True)
    return d


def record_provider_metric(
    provider_name: str,
    latency_s: float,
    success: bool,
    error_type: str | None = None,
    config: AppConfig | None = None,
    telemetry_dir: Path | None = None,
):
    """Record anonymized provider performance telemetry (latency, success rate, error type).

    Never records prompt text, file contents, or commands.
    Off by default — requires config.general.telemetry_enabled = True.
    """
    if not config or not config.general.telemetry_enabled:
        return  # Opt-in check: Off by default

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "provider_call",
        "provider": provider_name,
        "latency_s": round(latency_s, 4),
        "success": success,
        "error_type": error_type,
    }

    target_dir = telemetry_dir or get_telemetry_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    metrics_file = target_dir / "metrics.jsonl"

    with open(metrics_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    # Optional self-hosted export endpoint
    endpoint = config.general.telemetry_export_endpoint
    if endpoint and endpoint.strip():
        _export_metric(endpoint.strip(), record)


def _export_metric(endpoint: str, record: dict[str, Any]):
    """Export single metric record to self-hosted telemetry endpoint."""
    try:
        httpx.post(
            endpoint,
            json={"metrics": [record]},
            timeout=3.0,
            headers={"User-Agent": "Eva-Telemetry/1.0"},
        )
    except Exception as exc:
        logger.debug("Telemetry export POST to %s failed: %s", endpoint, exc)
