import importlib.metadata
import os
import subprocess
import time
from pathlib import Path

import typer
from rich.console import Console

from eva.config import (
    KeyringUnavailableError,
    clear_api_key,
    get_api_key,
    get_api_key_env_var,
    get_config_file,
    keyring_backend_available,
    load_config,
    save_config,
    set_api_key,
)
from eva.indexing.finder import find_files
from eva.indexing.io import ContextReadError, read_text_file_for_context
from eva.indexing.repo_index import build_dep_graph, detect_stack
from eva.indexing.tokenizer import trim_context
from eva.indexing.tree import generate_tree
from eva.prompts import (
    ANALYZE_SYSTEM_PROMPT,
    ASK_SYSTEM_PROMPT,
    COMMIT_SYSTEM_PROMPT,
    EDIT_SYSTEM_PROMPT,
    EXPLAIN_SYSTEM_PROMPT,
    WORK_SYSTEM_PROMPT,
)
from eva.providers import dispatch, get_provider
from eva.replay import display_replay_session, list_replay_sessions, record_replay_event
from eva.security import run_sandboxed
from eva.security.work_safety import (
    CommandExtractionError,
    UnsafeCommandError,
    append_command_audit,
    get_command_audit_log,
    parse_safe_command,
)
from eva.telemetry.diagnostics import setup_logging
from eva.ui.formatter import is_ai_error, print_error, print_info, print_markdown, print_success
from eva.ui.streaming import stream_response
from eva.workflows.budget import load_budget, normalize_usage_stats, remaining_budget
from eva.workflows.chat_session import run_chat_session
from eva.workflows.engine import list_workflows, load_workflow, run_workflow
from eva.workspace.git_ops import apply_unified_diff, extract_unified_diff, run_git
from eva.workspace.session import (
    add_bookmark,
    add_note,
    create_workspace,
    get_active_workspace,
    get_workspace,
    list_workspaces,
    set_active_workspace,
)

app = typer.Typer(
    name="eva",
    help="Eva — Command Line Intelligence",
    add_completion=False,
)
config_app = typer.Typer(help="Manage Eva configuration and API keys.")
budget_app = typer.Typer(help="Inspect rate limits and token budget usage.")
workflow_app = typer.Typer(help="Run and manage declarative multi-step workflows.")
workspace_app = typer.Typer(help="Manage named session workspaces, notes, and bookmarks.")

app.add_typer(config_app, name="config")
app.add_typer(budget_app, name="budget")
app.add_typer(workflow_app, name="workflow")
app.add_typer(workspace_app, name="workspace")

console = Console()
err_console = Console(stderr=True)


def _get_version() -> str:
    try:
        return importlib.metadata.version("eva")
    except importlib.metadata.PackageNotFoundError:
        return "2.2.0"


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
    setup_logging(verbose=verbose)


def _read_context_file(path: Path, header: str = "") -> str:
    try:
        text, warnings = read_text_file_for_context(path)
        for warning in warnings:
            err_console.print(f"[warning]Warning: {warning}[/warning]")
        prefix = f"\n=== {header} ===\n" if header else "\n"
        return f"{prefix}{text}\n"
    except ContextReadError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc


@app.command()
def ask(
    query: list[str] = typer.Argument(..., help="The prompt or question to ask Eva"),
    files: list[Path] = typer.Option(None, "--file", "-f", help="Include file content as context"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Ask a question, optionally including local file context."""
    config = load_config()
    context = ""
    if files:
        for path in files:
            context += _read_context_file(path, header=f"File: {path}")

    query_str = " ".join(query)
    stream = dispatch(ASK_SYSTEM_PROMPT, query_str, context, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print_markdown(result)


@app.command()
def explain(
    target: str = typer.Argument(None, help="File path, concept, or pipe input to explain"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Explain a file, error log, or piped stdout."""
    config = load_config()
    context = ""
    query = "Explain this content."

    # Check for stdin (piped input)
    import sys

    if not sys.stdin.isatty():
        piped_input = sys.stdin.read()
        if piped_input.strip():
            context = f"\n=== Piped Input ===\n{piped_input}\n"
            if target:
                query = target

    if not context and target:
        path = Path(target)
        if path.exists() and path.is_file():
            context = _read_context_file(path, header=f"File: {path}")
            query = f"Explain the file {target}."
        elif path.exists() and path.is_dir():
            stack = detect_stack(path)
            dep_graph = build_dep_graph(path)
            context = f"\n=== Project Stack ===\n{stack.to_summary_string()}\n\n=== Dependency Graph ===\n{dep_graph.to_summary_string()}\n"
            query = f"Explain the repository structure and architecture at {target}."
        else:
            query = f"Explain: {target}"

    if not context and not target:
        path = Path(".")
        stack = detect_stack(path)
        dep_graph = build_dep_graph(path)
        context = f"\n=== Project Stack ===\n{stack.to_summary_string()}\n\n=== Dependency Graph ===\n{dep_graph.to_summary_string()}\n"
        query = "Explain the project structure, stack, and architecture of this repository."

    stream = dispatch(EXPLAIN_SYSTEM_PROMPT, query, context, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print_markdown(result)


@app.command()
def analyze(
    files: list[Path] = typer.Option(None, "--file", "-f", help="Files to analyze"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Analyze logs, errors, or file output."""
    config = load_config()
    context = ""
    import sys

    if not sys.stdin.isatty():
        piped_input = sys.stdin.read()
        if piped_input.strip():
            context += f"\n=== Piped Input ===\n{piped_input}\n"

    if files:
        for path in files:
            context += _read_context_file(path, header=f"File: {path}")

    if not context.strip():
        print_error("Provide files with -f or pipe stdout into 'eva analyze'.")
        raise typer.Exit(1)

    query = "Analyze the provided content, identify issues, and suggest solutions."
    stream = dispatch(ANALYZE_SYSTEM_PROMPT, query, context, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print_markdown(result)


@app.command()
def chat(
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    session: str | None = typer.Option(None, "--session", "-s", help="Save chat transcript under this session name"),
    resume: bool = typer.Option(False, "--resume", help="Resume the named session"),
):
    """Interactive REPL."""
    config = load_config()
    run_chat_session(config=config, provider=provider, session=session, resume=resume)


@app.command()
def work(
    query: list[str] = typer.Argument(..., help="The natural language command description"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    auto_confirm: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm execution"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate and audit the command without executing it"),
):
    """Execute a command generated from natural language."""
    config = load_config()
    query_str = " ".join(query)

    from rich.live import Live
    from rich.spinner import Spinner

    stream = dispatch(WORK_SYSTEM_PROMPT, query_str, "", config, pinned_provider=provider)

    model_output = ""
    spinner = Spinner("dots", text="Generating command...")
    with Live(spinner, console=err_console, refresh_per_second=15, transient=True):
        for chunk in stream:
            model_output += chunk

    if is_ai_error(model_output):
        append_command_audit(
            {"query": query_str, "model_output": model_output, "executed": False, "blocked_reason": "provider_error"}
        )
        print_error(model_output.strip())
        raise typer.Exit(1)

    try:
        parsed = parse_safe_command(model_output)
    except UnsafeCommandError as exc:
        append_command_audit(
            {
                "query": query_str,
                "model_output": model_output,
                "executed": False,
                "blocked_reason": f"unsafe_command: {exc}",
            }
        )
        print_error(f"Refusing to execute unsafe command: {exc}")
        raise typer.Exit(1) from exc
    except CommandExtractionError as exc:
        append_command_audit(
            {"query": query_str, "model_output": model_output, "executed": False, "blocked_reason": str(exc)}
        )
        print_error(f"Refusing to execute ambiguous model output: {exc}")
        raise typer.Exit(1) from exc

    err_console.print(f"[info]ℹ Generated command:\n> {parsed.command}\n[/info]")

    if dry_run:
        append_command_audit(
            {"query": query_str, "command": parsed.command, "argv": parsed.argv, "executed": False, "dry_run": True}
        )
        print_info(f"Dry run only. Audit log: {get_command_audit_log()}")
        return

    execute = auto_confirm
    if not execute:
        execute = typer.confirm("Do you want to execute this command?")

    if execute:
        start_t = time.time()
        active_session = get_active_workspace()

        if config.general.sandbox_risky_commands:
            print_info("[Eva Sandbox] Executing command in restricted sandbox environment...")
            res = run_sandboxed(parsed.command, cwd=Path.cwd())
            returncode = getattr(res, "returncode", 0)
            stdout_str = res.stdout if isinstance(getattr(res, "stdout", None), str) else ""
            stderr_str = res.stderr if isinstance(getattr(res, "stderr", None), str) else ""
            if stdout_str:
                console.print(stdout_str, end="")
            if stderr_str:
                err_console.print(stderr_str, end="")
            output_str = stdout_str + ("\n" + stderr_str if stderr_str else "")
        else:
            res = subprocess.run(parsed.command, shell=True, check=False, capture_output=True, text=True)
            returncode = getattr(res, "returncode", 0)
            stdout_str = res.stdout if isinstance(getattr(res, "stdout", None), str) else ""
            stderr_str = res.stderr if isinstance(getattr(res, "stderr", None), str) else ""
            if stdout_str:
                console.print(stdout_str, end="")
            if stderr_str:
                err_console.print(stderr_str, end="")
            output_str = stdout_str + ("\n" + stderr_str if stderr_str else "")

        duration = time.time() - start_t

        record_replay_event(
            session_id=active_session,
            command=parsed.command,
            output=output_str,
            exit_code=returncode,
            duration_s=duration,
            cwd=Path.cwd(),
        )

        append_command_audit(
            {
                "query": query_str,
                "command": parsed.command,
                "argv": parsed.argv,
                "executed": True,
                "return_code": returncode,
            }
        )
        if returncode != 0:
            # Check if execution failed due to missing root/sudo privileges
            if not parsed.command.strip().startswith("sudo ") and typer.confirm(
                "Command failed due to missing privileges. Retry with sudo?", default=True
            ):
                sudo_cmd = f"sudo {parsed.command}"
                s_res = subprocess.run(sudo_cmd, shell=True, check=False)
                if s_res.returncode != 0:
                    raise typer.Exit(s_res.returncode)
                return
            raise typer.Exit(returncode)
    else:
        append_command_audit(
            {
                "query": query_str,
                "command": parsed.command,
                "argv": parsed.argv,
                "executed": False,
                "blocked_reason": "user_declined",
            }
        )


@app.command()
def tree(
    path: Path = typer.Argument(Path("."), help="Directory path to visualize"),
):
    """Generate a directory tree respecting .gitignore."""
    result = generate_tree(path)
    console.print(result, end="")


@app.command()
def find(
    pattern: str = typer.Argument(..., help="File name or glob pattern (e.g. *.py)"),
    path: Path = typer.Argument(Path("."), help="Root directory to search"),
):
    """Find files locally respecting .gitignore."""
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


@app.command()
def commit(
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Generate a conventional commit message for staged changes."""
    diff_res = run_git(["diff", "--staged"])
    if diff_res.returncode != 0:
        print_error("Failed to run git diff.")
        raise typer.Exit(1)

    diff_text = diff_res.stdout.strip()
    if not diff_text:
        print_error("No staged changes found. Use 'git add' first.")
        raise typer.Exit(1)

    trimmed_diff = trim_context(diff_text, max_tokens=4000)
    config = load_config()
    stream = dispatch(COMMIT_SYSTEM_PROMPT, "Generate commit message", trimmed_diff, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print(result.strip())


@app.command()
def edit(
    query: list[str] = typer.Argument(..., help="Requested code change"),
    files: list[Path] = typer.Option(..., "--file", "-f", help="File to include and allow in the generated diff"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    apply_changes: bool = typer.Option(False, "--apply", help="Apply the generated patch after review confirmation"),
):
    """Generate a reviewable unified diff for file edits."""
    config = load_config()
    context = ""
    for path in files:
        context += _read_context_file(path, header=f"File: {path}")

    query_str = " ".join(query)
    stream = dispatch(EDIT_SYSTEM_PROMPT, query_str, context, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)

    try:
        diff_text = extract_unified_diff(result)
    except ValueError as exc:
        print_error(f"Refusing to apply non-diff model output: {exc}")
        console.print(result)
        raise typer.Exit(1) from exc

    console.print(diff_text)
    if not apply_changes and not typer.confirm("Apply this patch?"):
        print_info("Patch not applied.")
        return

    apply_unified_diff(diff_text)
    print_success("Patch applied.")


@app.command()
def replay(
    session: str = typer.Argument(None, help="Session name or ID to replay"),
    list_sessions: bool = typer.Option(False, "--list", "-l", help="List all available replay sessions"),
):
    """Replay recorded terminal execution sessions."""
    if list_sessions or not session:
        sessions = list_replay_sessions()
        if not sessions:
            print_info("No recorded replay sessions found.")
            return

        from rich.table import Table

        table = Table(title="Recorded Replay Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Created At", style="yellow")
        table.add_column("Recorded Events", style="magenta")

        for s in sessions:
            table.add_row(s["session_id"], s["created_at"], str(s["event_count"]))

        console.print(table)
        return

    try:
        display_replay_session(session, console=console)
    except FileNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc


@app.command()
def use(provider: str):
    """Set the default AI provider."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)
    config.general.default_provider = provider
    save_config(config)
    print_success(f"Default provider set to {provider}")


@app.command()
def usage():
    """Show normalized local provider usage counters."""
    show_budget()


@config_app.command("set-provider")
def set_provider(name: str):
    """Change the persistent default provider."""
    use(name)


@config_app.command("set-model")
def set_model_cmd(
    provider: str = typer.Argument(..., help="The provider name (e.g. openrouter, groq, gemini, ollama, llamacpp)"),
    model: str = typer.Argument(..., help="The model identifier to use for this provider"),
):
    """Set the active model for a specific provider."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    config.providers[provider].model = model
    save_config(config)
    print_success(f"Model for provider '{provider}' set to '{model}'.")


@config_app.command("set-key")
def set_key_cmd(
    provider: str = typer.Argument(..., help="The name of the provider (e.g. groq, openrouter)"),
    key: str | None = typer.Argument(None, help="The API key (if omitted, you will be prompted securely)"),
):
    """Store an API key via keyring."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    if not key:
        import getpass

        key = getpass.getpass(f"Enter API key for {provider}: ")
        if not key.strip():
            print_error("API key cannot be empty.")
            return

    try:
        set_api_key(provider, key.strip())
    except KeyringUnavailableError as exc:
        print_error(str(exc))
        env_var = get_api_key_env_var(provider)
        print_info(f"You can also export {env_var} in your shell environment.")
        raise typer.Exit(1) from exc

    print_success(f"API key for '{provider}' saved successfully.")


@config_app.command("remove-key")
def remove_key_cmd(
    provider: str = typer.Argument(..., help="The name of the provider (e.g. groq, openrouter, gemini)"),
):
    """Remove a stored API key from the OS keyring."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    try:
        clear_api_key(provider)
    except KeyringUnavailableError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    print_success(f"API key for '{provider}' removed successfully.")


@config_app.command("show")
def show_config():
    """Display current configuration, default provider, and key statuses."""
    config = load_config()

    from rich.table import Table

    table = Table(title="Eva Configuration")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Config Path", str(get_config_file()))
    table.add_row("Default Provider", config.general.default_provider)
    table.add_row("Fallback Enabled", str(config.general.fallback_enabled))
    table.add_row("Fallback Order", ", ".join(config.general.fallback_order))

    console.print(table)
    console.print()

    prov_table = Table(title="Configured Providers & Key Status")
    prov_table.add_column("Provider", style="cyan")
    prov_table.add_column("Model", style="yellow")
    prov_table.add_column("API Key Status", style="green")

    for name, p_cfg in config.providers.items():
        key = get_api_key(name)
        status = "[green]Configured[/green]" if key else "[red]Missing[/red]"
        is_default = " (default)" if name == config.general.default_provider else ""
        prov_table.add_row(f"{name}{is_default}", p_cfg.model, status)

    console.print(prov_table)


@config_app.command("doctor")
def doctor():
    """Diagnose environment, keyring backend, and provider connectivity."""
    print_info("Running Eva Environment Doctor...\n")

    ok, info = keyring_backend_available()
    if ok:
        print_success(f"Keyring Backend: Available ({info})")
    else:
        print_error(f"Keyring Backend: Unavailable ({info})")

    config = load_config()
    print_info(f"Default Provider: {config.general.default_provider}")

    for name in config.providers:
        key = get_api_key(name)
        env_var = get_api_key_env_var(name)
        if key:
            source = f"env var {env_var}" if os.getenv(env_var) else "keyring"
            print_success(f"Provider '{name}': API key found ({source})")
        else:
            print_error(f"Provider '{name}': No API key set (keyring or {env_var})")


@budget_app.command("show")
def show_budget():
    """Show current request usage counts and rate limit budgets."""
    config = load_config()
    budget = load_budget()

    from rich.table import Table

    table = Table(title="Token Budget & Rate Limit Usage")
    table.add_column("Provider", style="cyan")
    table.add_column("RPM Limit", style="yellow")
    table.add_column("Used (Min)", style="magenta")
    table.add_column("RPD Limit", style="yellow")
    table.add_column("Used (Day)", style="magenta")

    for name in config.providers:
        provider = get_provider(name)
        if not provider:
            continue

        rpd_rem, rpm_rem = remaining_budget(name, provider.max_rpm, provider.max_rpd)
        stats = budget.usage_by_provider.get(name)
        stats_norm = normalize_usage_stats(stats) if stats else None

        used_min = stats_norm.requests_this_minute if stats_norm else 0
        used_day = stats_norm.requests_today if stats_norm else 0

        table.add_row(
            name,
            str(provider.max_rpm),
            f"{used_min} ({rpm_rem} left)",
            str(provider.max_rpd),
            f"{used_day} ({rpd_rem} left)",
        )

    console.print(table)


# Workflow commands
@workflow_app.command("run")
def workflow_run_cmd(
    name: str = typer.Argument(..., help="Workflow name or YAML file path"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Walk through workflow steps with an approval gate between each step."""
    config = load_config()
    try:
        wf = load_workflow(name)
    except (FileNotFoundError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    results = run_workflow(wf, config=config, interactive=True)
    failed = [r for r in results if r.get("status") in {"failed", "blocked_unsafe", "blocked_ambiguous"}]
    if failed:
        raise typer.Exit(1)


@workflow_app.command("list")
def workflow_list_cmd():
    """List all available built-in and user-defined workflows."""
    from rich.table import Table

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


# Workspace commands
@workspace_app.callback(invoke_without_command=True)
def workspace_callback(
    ctx: typer.Context,
):
    """Manage session workspaces, scoped history, notes, and bookmarks."""
    if ctx.invoked_subcommand is None:
        active = get_active_workspace()
        ws = get_workspace(active)
        _display_workspace_summary(ws)


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


@workspace_app.command("switch")
def workspace_switch_cmd(name: str = typer.Argument(..., help="Workspace name to switch to")):
    """Switch active workspace."""
    set_active_workspace(name)
    print_success(f"Switched active workspace to '{name}'.")


@workspace_app.command("create")
def workspace_create_cmd(name: str = typer.Argument(..., help="Workspace name to create")):
    """Create a new workspace."""
    ws = create_workspace(name)
    set_active_workspace(name)
    print_success(f"Created and activated workspace '{ws.name}'.")


@workspace_app.command("list")
def workspace_list_cmd():
    """List all workspace sessions."""
    active = get_active_workspace()
    all_ws = list_workspaces()

    from rich.table import Table

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
    active = get_active_workspace()
    note_str = " ".join(text)
    add_note(active, note_str)
    print_success(f"Added note to workspace '{active}'.")


@workspace_app.command("bookmark")
def workspace_bookmark_cmd(
    path: str = typer.Argument(..., help="File path or URL to bookmark in current workspace"),
):
    """Bookmark a file path or URL in the active workspace."""
    active = get_active_workspace()
    add_bookmark(active, path)
    print_success(f"Bookmarked '{path}' in workspace '{active}'.")


@workspace_app.command("show")
def workspace_show_cmd(
    name: str | None = typer.Argument(None, help="Workspace name to show (defaults to active)"),
):
    """Show details for a workspace."""
    target = name or get_active_workspace()
    ws = get_workspace(target)
    _display_workspace_summary(ws)


def main_entry():
    app()


if __name__ == "__main__":
    main_entry()
