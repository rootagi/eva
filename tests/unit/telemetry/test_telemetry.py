import logging

from eva.telemetry import setup_logging


def test_setup_logging(monkeypatch, tmp_path):
    import eva.telemetry.diagnostics as diag
    diag._logging_configured = False
    if hasattr(setup_logging, "_configured"):
        delattr(setup_logging, "_configured")
    monkeypatch.setattr("eva.telemetry.diagnostics.get_log_file", lambda: tmp_path / "eva.log")
    setup_logging(verbose=True)

    logger = logging.getLogger("eva.test")
    logger.debug("debug message test")

    log_content = (tmp_path / "eva.log").read_text(encoding="utf-8")
    assert "debug message test" in log_content
