"""Telemetry metrics export helpers.

This module provides a simple helper to send metric records to an
HTTP endpoint. The previous commit accidentally left patch markers in
this file which caused a syntax error in CI; this change removes those
markers and narrows exception handling.
"""

from typing import Any, Dict
import logging

import httpx

logger = logging.getLogger(__name__)


def export_metrics(endpoint: str, record: Dict[str, Any]) -> None:
    """Send a single metric record to the given endpoint.

    Errors from the HTTP layer are caught and logged at debug level so
    telemetry failures do not interrupt normal application flow.
    """
    try:
        httpx.post(
            endpoint,
            json={"metrics": [record]},
            timeout=3.0,
            headers={"User-Agent": "Eva-Telemetry/1.0"},
        )
    except (OSError, httpx.HTTPError) as exc:
        # Narrow exception handling to expected HTTP/client errors and log for diagnostics
        logger.debug("Telemetry export POST to %s failed: %s", endpoint, exc)
