import typer

from eva.cli.helpers import _resolve_app_attr, console

workflow_app = typer.Typer(help="Run and manage declarative multi-step workflows.")


@workflow_app.command("run")
def workflow_run_cmd(
    name: str = typer.Argument(..., help="Workflow name or YAML file path"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve all steps without interactive prompts"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Walk through workflow steps with an approval gate between each step."""
    from eva.config import load_config as _load_config
    from eva.ui.formatter import print_error
    from eva.workflows.engine import load_workflow, run_workflow

    load_config = _resolve_app_attr("load_config", _load_config)
    config = load_config()
    try:
        wf = load_workflow(name)
    except (FileNotFoundError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    results = run_workflow(wf, config=config, interactive=not yes)
    failed = [r for r in results if r.get("status") in {"failed", "blocked_unsafe", "blocked_ambiguous"}]
    if failed:
        raise typer.Exit(1)


@workflow_app.command("list")
def workflow_list_cmd():
    """List all available built-in and user-defined workflows."""
    from rich.table import Table

    from eva.ui.formatter import print_info
    from eva.workflows.engine import list_workflows

    wfs = list_workflows()
    if not wfs:
        print_info("No workflows found.")
        return

    table = Table(title="Available Workflows")
    table.add_column("Name", style="cyan")
    table.add_column("Source", style="yellow")
    table.add_column("Description", style="magenta")

    for w in wfs:
        table.add_row(w["name"], w["source"], w["description"])

    console.print(table)


@workflow_app.command("show")
def workflow_show_cmd(
    name: str = typer.Argument(..., help="Workflow name or YAML file path"),
):
    """Display workflow definition and steps without running it."""
    from rich.table import Table

    from eva.ui.formatter import print_error
    from eva.workflows.engine import load_workflow

    try:
        wf = load_workflow(name)
    except (FileNotFoundError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    console.print(f"[bold cyan]Workflow:[/bold cyan] {wf.name} (v{wf.version})")
    if wf.description:
        console.print(f"[italic]{wf.description}[/italic]\n")

    table = Table(title=f"Steps in {wf.name}")
    table.add_column("#", style="yellow")
    table.add_column("Step Name", style="cyan")
    table.add_column("Command", style="green")
    table.add_column("Description", style="magenta")

    for i, s in enumerate(wf.steps, start=1):
        table.add_row(str(i), s.name, s.command, s.description)

    console.print(table)
