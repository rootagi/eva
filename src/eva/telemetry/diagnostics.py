import logging
import os
from pathlib import Path

from eva.config import get_config_dir

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_logging_configured: bool = False


def get_log_file() -> Path:
    return get_config_dir() / "eva.log"


def setup_logging(verbose: bool = False):
    global _logging_configured
    if _logging_configured:
        root = logging.getLogger()
        root.setLevel(logging.DEBUG if verbose else logging.INFO)
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG if verbose else logging.CRITICAL + 1)
        return

    env_verbose = os.getenv("EVA_VERBOSE", "").lower() in {"1", "true", "yes", "debug"}
    verbose = verbose or env_verbose

    log_file = get_log_file()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG if verbose else logging.CRITICAL + 1)
    stream_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(stream_handler)

    _logging_configured = True
