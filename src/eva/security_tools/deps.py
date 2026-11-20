"""Dependency checking and actionable installation hints for optional extras."""

from __future__ import annotations

import importlib
from typing import NoReturn

import typer

from eva.ui.formatter import print_error

EXTRA_PACKAGES: dict[str, list[str]] = {
    "sec": ["yara", "pefile", "elftools"],
    "sec-media": ["PIL", "piexif", "numpy", "scipy", "Cryptodome", "argon2", "cv2"],
    "web-images": ["PIL"],
    "all": ["yara", "pefile", "elftools", "PIL", "numpy"],
}


def check_extra_available(extra_name: str) -> str | None:
    """Return None if all dependencies for extra are installed, or actionable install hint."""
    packages = EXTRA_PACKAGES.get(extra_name, [extra_name])
    for pkg in packages:
        if pkg in ("Cryptodome", "Crypto"):
            try:
                importlib.import_module("Crypto")
                continue
            except ImportError:
                try:
                    importlib.import_module("Cryptodome")
                    continue
                except ImportError:
                    return f'pip install "eva-cli[{extra_name}]"'
        try:
            importlib.import_module(pkg)
        except ImportError:
            return f'pip install "eva-cli[{extra_name}]"'
    return None


def missing_extra_exit(extra_name: str, feature_name: str) -> NoReturn:
    """Print an actionable installation hint and exit non-zero without traceback."""
    print_error(
        f"Feature '{feature_name}' requires the '{extra_name}' optional extra.\n"
        f"Install it with:\n"
        f'    pip install "eva-cli[{extra_name}]"\n'
        f"or with uv:\n"
        f'    uv add "eva-cli[{extra_name}]"'
    )
    raise typer.Exit(1)
