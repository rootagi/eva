from pathlib import Path
from typing import Any

import typer

from eva.cli.commands.ask import analyze, ask, explain, investigate
from eva.cli.commands.budget import budget_app, usage
from eva.cli.commands.cache_cmd import cache_app
from eva.cli.commands.chat import chat
from eva.cli.commands.config_cmd import config_app, use
from eva.cli.commands.context import context_app
from eva.cli.commands.edit import changes, commit, edit
from eva.cli.commands.security import sec_app
from eva.cli.commands.work import replay, work
from eva.cli.commands.workflow import workflow_app
from eva.cli.commands.workspace import workspace_app
from eva.cli.helpers import _get_version, _resolve_app_attr, console

app = typer.Typer(
    name="eva",
    help="Eva — Command Line Intelligence",
    add_completion=True,
)

app.add_typer(config_app, name="config")
app.add_typer(budget_app, name="budget")
app.add_typer(workflow_app, name="workflow")
app.add_typer(workspace_app, name="workspace")
app.add_typer(cache_app, name="cache")
app.add_typer(context_app, name="context")
app.add_typer(sec_app, name="sec")

_loaded_plugins: list = []
_plugins_initialized: bool = False


def version_callback(value: bool):
    if value:
        print(f"Eva {_get_version()}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose debug logging.",
    ),
):
    global _loaded_plugins, _plugins_initialized
    if not _plugins_initialized:
        from eva.plugins import load_plugins

        _loaded_plugins = load_plugins(app)
        _plugins_initialized = True

    from eva.config import load_config as _load_config
    from eva.security.redaction import configure_redaction
    from eva.security.sensitive_files import configure_sensitive_file_allowlist
    from eva.telemetry.diagnostics import setup_logging
    from eva.workspace.gitignore import configure_ignored_dirs

    load_config = _resolve_app_attr("load_config", _load_config)

    setup_logging(verbose=verbose)
    config = load_config()
    configure_redaction(
        entropy_threshold=config.general.redaction_entropy_threshold,
        ignore_patterns=config.general.redaction_ignore_patterns,
    )
    configure_ignored_dirs(
        extra=config.general.extra_ignored_dirs,
        unignore=config.general.unignore_dirs,
    )
    configure_sensitive_file_allowlist(config.general.sensitive_file_allowlist)


@app.command()
def tree(
    path: Path = typer.Argument(Path("."), help="Directory path to visualize"),
):
    """Generate a directory tree respecting .gitignore."""
    from eva.indexing.tree import generate_tree

    result = generate_tree(path)
    console.print(result, end="")


@app.command()
def find(
    pattern: str = typer.Argument(..., help="File name or glob pattern (e.g. *.py)"),
    path: Path = typer.Argument(Path("."), help="Root directory to search"),
):
    """Find files locally respecting .gitignore."""
    from eva.indexing.finder import find_files

    found = False
    for p in find_files(path, pattern):
        try:
            rel = p.relative_to(Path.cwd())
            console.print(str(rel))
        except ValueError:
            console.print(str(p))
        found = True
    if not found:
        raise typer.Exit(1)


app.command()(ask)
app.command()(explain)
app.command()(investigate)
app.command()(analyze)
app.command()(chat)
app.command()(work)
app.command("commit-message")(commit)
app.command()(changes)
app.command()(edit)
app.command()(replay)
app.command()(use)
app.command()(usage)


_LAZY_ATTR_MAP: dict[str, tuple[str, str]] = {
    "dispatch": ("eva.providers", "dispatch"),
    "is_tool_capable": ("eva.providers", "is_tool_capable"),
    "get_provider": ("eva.providers", "get_provider"),
    "get_context_budget": ("eva.providers", "get_context_budget"),
    "_resolve_provider_name": ("eva.providers", "_resolve_provider_name"),
    "run_investigation": ("eva.agent", "run_investigation"),
    "StoppedReason": ("eva.agent", "StoppedReason"),
    "load_config": ("eva.config", "load_config"),
    "save_config": ("eva.config", "save_config"),
    "set_api_key": ("eva.config", "set_api_key"),
    "clear_api_key": ("eva.config", "clear_api_key"),
    "get_api_key": ("eva.config", "get_api_key"),
    "clear_cache": ("eva.cache", "clear_cache"),
    "run_git": ("eva.workspace.git_ops", "run_git"),
    "append_command_audit": ("eva.security.work_safety", "append_command_audit"),
    "append_investigation_audit": ("eva.security.audit", "append_investigation_audit"),
    "run_chat_session": ("eva.workflows.chat_session", "run_chat_session"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_ATTR_MAP:
        import importlib

        mod_name, attr_name = _LAZY_ATTR_MAP[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main_entry():
    app()


if __name__ == "__main__":
    main_entry()
