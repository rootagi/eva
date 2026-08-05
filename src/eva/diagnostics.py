"""Compatibility re-exports for diagnostics."""

from eva.telemetry.diagnostics import LOG_FORMAT, get_log_file, setup_logging

__all__ = [
    "LOG_FORMAT",
    "get_log_file",
    "setup_logging",
]
