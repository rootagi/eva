from pathlib import Path

import typer

from eva.cli.helpers import _resolve_app_attr, console, err_console


def work(
    query: list[str] = typer.Argument(..., help="The natural language command description"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    auto_confirm: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm execution"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate and audit the command without executing it"),
    dry_run_explain: bool = typer.Option(
        False, "--dry-run-explain", help="Print safety checks passed/failed before executing"
    ),
    allow_shell_features: bool = typer.Option(
        False, "--allow-shell-features", help="Allow shell features (pipes, redirects) via shell execution"
    ),
    no_project_context: bool = typer.Option(
        False, "--no-project-context", help="Skip auto-loading .eva/context.md for this run"
    ),
):
    """Execute a command generated from natural language."""
    import shlex
    import subprocess
    import time

    from rich.live import Live
    from rich.spinner import Spinner

    from eva.config import load_config as _load_config
    from eva.prompts import WORK_SYSTEM_PROMPT
    from eva.providers import dispatch as _dispatch
    from eva.replay import record_replay_event
    from eva.security import run_sandboxed
    from eva.security.work_safety import (
        CommandExtractionError,
        UnsafeCommandError,
        explain_safety_checks,
        get_command_audit_log,
        parse_safe_command,
    )
    from eva.security.work_safety import (
        append_command_audit as _append_command_audit,
    )
    from eva.ui.formatter import is_ai_error, print_error, print_info
    from eva.workspace.project_context import load_project_context
    from eva.workspace.session import get_active_workspace

    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)
    append_command_audit = _resolve_app_attr("append_command_audit", _append_command_audit)

    config = load_config()
    query_str = " ".join(query)

    context = "" if no_project_context else load_project_context(Path.cwd())
    stream = dispatch(WORK_SYSTEM_PROMPT, query_str, context, config, pinned_provider=provider)

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

    if dry_run_explain:
        checks = explain_safety_checks(model_output, config.general.allowed_command_prefixes)
        from rich.table import Table

        table = Table(title="Command Safety Checks Summary")
        table.add_column("Safety Check", style="cyan")
        table.add_column("Status", style="yellow")
        table.add_column("Details", style="magenta")

        all_passed = True
        for chk in checks:
            status = "[green]PASSED[/green]" if chk["passed"] else "[red]FAILED[/red]"
            table.add_row(chk["check"], status, chk["detail"])
            if not chk["passed"]:
                all_passed = False

        console.print(table)
        append_command_audit(
            {
                "query": query_str,
                "model_output": model_output,
                "executed": False,
                "dry_run_explain": True,
                "passed_all_checks": all_passed,
            }
        )
        return

    try:
        parsed = parse_safe_command(model_output, allowed_prefixes=config.general.allowed_command_prefixes)
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
            res = run_sandboxed(parsed.command, cwd=Path.cwd(), allow_shell_features=allow_shell_features)
            returncode = getattr(res, "returncode", 0)
            stdout_str = res.stdout if isinstance(getattr(res, "stdout", None), str) else ""
            stderr_str = res.stderr if isinstance(getattr(res, "stderr", None), str) else ""
            if stdout_str:
                console.print(stdout_str, end="")
            if stderr_str:
                err_console.print(stderr_str, end="")
            output_str = stdout_str + ("\n" + stderr_str if stderr_str else "")
        else:
            if allow_shell_features:
                res = subprocess.run(parsed.command, shell=True, check=False, capture_output=True, text=True)
            else:
                try:
                    cmd_argv = shlex.split(parsed.command)
                    res = subprocess.run(cmd_argv, shell=False, check=False, capture_output=True, text=True)
                except ValueError:
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


def replay(
    session: str = typer.Argument(None, help="Session name or ID to replay"),
    list_sessions: bool = typer.Option(False, "--list", "-l", help="List all available replay sessions"),
):
    """Replay recorded terminal execution sessions."""
    from eva.replay import display_replay_session, list_replay_sessions
    from eva.ui.formatter import print_error, print_info

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
