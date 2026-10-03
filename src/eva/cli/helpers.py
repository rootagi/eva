import importlib.metadata
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

console = Console()
err_console = Console(stderr=True)


def _get_version() -> str:
    try:
        from eva import __version__

        return __version__
    except (ImportError, AttributeError):
        try:
            return importlib.metadata.version("eva-cli")
        except importlib.metadata.PackageNotFoundError:
            return "unknown"


def _read_context_file(path: Path, header: str = "") -> str:
    from eva.indexing.io import ContextReadError, read_text_file_for_context
    from eva.ui.formatter import print_error

    try:
        text, warnings = read_text_file_for_context(path)
        for warning in warnings:
            err_console.print(f"[warning]Warning: {warning}[/warning]")
        prefix = f"\n=== {header} ===\n" if header else "\n"
        return f"{prefix}{text}\n"
    except ContextReadError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc


def _resolve_app_attr(name: str, default: Any) -> Any:
    """Return an attribute override from eva.cli.app if monkeypatched in tests, else default."""
    app_mod = sys.modules.get("eva.cli.app")
    if app_mod is not None and name in app_mod.__dict__:
        return app_mod.__dict__[name]
    return default
