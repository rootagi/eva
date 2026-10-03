from pathlib import Path

import typer

from eva.cli.helpers import console

context_app = typer.Typer(help="Manage project memory and context.")


@context_app.command("show")
def show_context():
    """Display project context from .eva/context.md if present."""
    from eva.ui.formatter import print_info
    from eva.workspace.project_context import load_project_context

    ctx = load_project_context(Path.cwd())
    if ctx:
        console.print(ctx.strip())
    else:
        print_info("No project context found (.eva/context.md is missing or empty).")
