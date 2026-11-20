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


@context_app.command("init")
def init_context(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing .eva/context.md"),
):
    """Scaffold .eva/context.md project context file from detected project stack."""
    from eva.indexing.repo_index import init_context_md
    from eva.ui.formatter import print_success, print_warning

    target = Path.cwd() / ".eva" / "context.md"
    if target.exists() and not force:
        print_warning(f"Context file {target} already exists. Use --force to overwrite.")
        return

    path = init_context_md(Path.cwd(), force=force)
    print_success(f"Project context initialized at {path}")
