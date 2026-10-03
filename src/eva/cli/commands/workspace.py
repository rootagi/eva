import typer

from eva.cli.helpers import console

workspace_app = typer.Typer(help="Manage named session workspaces, notes, and bookmarks.")


def _display_workspace_summary(ws):
    console.print(f"[bold cyan]Workspace Session:[/bold cyan] {ws.name}")
    console.print(f"[dim]Created: {ws.created_at}[/dim]\n")

    if ws.notes:
        console.print("[bold yellow]Notes:[/bold yellow]")
        for note in ws.notes:
            console.print(f"  • {note}")
        console.print()

    if ws.bookmarks:
        console.print("[bold green]Bookmarks:[/bold green]")
        for bm in ws.bookmarks:
            console.print(f"  🔖 {bm}")
        console.print()

    if ws.history:
        console.print(f"[bold magenta]Recent Activity ({len(ws.history)} items):[/bold magenta]")
        for h in ws.history[-5:]:
            ts = h.get("timestamp", "")[:19].replace("T", " ")
            console.print(f"  [{ts}] ({h.get('type')}) {h.get('content')}")
        console.print()


@workspace_app.callback(invoke_without_command=True)
def workspace_callback(
    ctx: typer.Context,
):
    """Manage session workspaces, scoped history, notes, and bookmarks."""
    if ctx.invoked_subcommand is None:
        from eva.workspace.session import get_active_workspace, get_workspace

        active = get_active_workspace()
        ws = get_workspace(active)
        _display_workspace_summary(ws)


@workspace_app.command("switch")
def workspace_switch_cmd(name: str = typer.Argument(..., help="Workspace name to switch to")):
    """Switch active workspace."""
    from eva.ui.formatter import print_success
    from eva.workspace.session import set_active_workspace

    set_active_workspace(name)
    print_success(f"Switched active workspace to '{name}'.")


@workspace_app.command("create")
def workspace_create_cmd(name: str = typer.Argument(..., help="Workspace name to create")):
    """Create a new workspace."""
    from eva.ui.formatter import print_success
    from eva.workspace.session import create_workspace, set_active_workspace

    ws = create_workspace(name)
    set_active_workspace(name)
    print_success(f"Created and activated workspace '{ws.name}'.")


@workspace_app.command("list")
def workspace_list_cmd():
    """List all workspace sessions."""
    from rich.table import Table

    from eva.workspace.session import get_active_workspace, list_workspaces

    active = get_active_workspace()
    all_ws = list_workspaces()

    table = Table(title="Workspace Sessions")
    table.add_column("Workspace Name", style="cyan")
    table.add_column("Status", style="yellow")

    for w in all_ws:
        status = "[green]Active[/green]" if w == active else ""
        table.add_row(w, status)

    console.print(table)


@workspace_app.command("note")
def workspace_note_cmd(
    text: list[str] = typer.Argument(..., help="Note text to save in current workspace"),
):
    """Add a note to the active workspace."""
    from eva.ui.formatter import print_success
    from eva.workspace.session import add_note, get_active_workspace

    active = get_active_workspace()
    note_str = " ".join(text)
    add_note(active, note_str)
    print_success(f"Added note to workspace '{active}'.")


@workspace_app.command("bookmark")
def workspace_bookmark_cmd(
    path: str = typer.Argument(..., help="File path or URL to bookmark in current workspace"),
):
    """Bookmark a file path or URL in the active workspace."""
    from eva.ui.formatter import print_success
    from eva.workspace.session import add_bookmark, get_active_workspace

    active = get_active_workspace()
    add_bookmark(active, path)
    print_success(f"Bookmarked '{path}' in workspace '{active}'.")


@workspace_app.command("show")
def workspace_show_cmd(
    name: str | None = typer.Argument(None, help="Workspace name to show (defaults to active)"),
):
    """Show details for a workspace."""
    from eva.workspace.session import get_active_workspace, get_workspace

    target = name or get_active_workspace()
    ws = get_workspace(target)
    _display_workspace_summary(ws)
