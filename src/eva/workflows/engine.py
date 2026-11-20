import copy
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.prompt import Confirm

from eva.config import AppConfig, get_config_dir
from eva.security.redaction import redact_secrets
from eva.security.work_safety import (
    CommandExtractionError,
    UnsafeCommandError,
    append_command_audit,
    parse_safe_command,
)

logger = logging.getLogger(__name__)
err_console = Console(stderr=True)

SHELL_CONTROL_TOKENS = {"|", "||", "&&", ";", ">", ">>", "<", "<<", "$(", "`"}


@dataclass
class WorkflowStep:
    name: str = ""
    command: str = ""
    description: str = ""
    risk_level: str = "low"
    id: str = ""


Step = WorkflowStep


@dataclass
class Workflow:
    name: str
    description: str
    steps: list[WorkflowStep] = field(default_factory=list)
    version: str = "1.0"


__all__ = [
    "Step",
    "Workflow",
    "WorkflowStep",
    "get_builtins_dir",
    "get_user_workflows_dir",
    "list_workflows",
    "load_workflow",
    "run_workflow",
]


def _reject_shell_control_tokens(argv: list[str]) -> None:
    for token in argv:
        if token in SHELL_CONTROL_TOKENS or "$(" in token or "`" in token:
            raise UnsafeCommandError(f"Workflow commands cannot use shell control token: {token}")


def get_builtins_dir() -> Path:
    return Path(__file__).parent / "builtins"


def get_user_workflows_dir() -> Path:
    d = get_config_dir() / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_workflow(name_or_path: str) -> Workflow:
    """Load a workflow by name or file path."""
    path = Path(name_or_path)

    if not path.is_file():
        # Try user config dir
        user_path = get_user_workflows_dir() / f"{name_or_path}.yaml"
        if not user_path.is_file():
            user_path = get_user_workflows_dir() / f"{name_or_path}.yml"

        if user_path.is_file():
            path = user_path
        else:
            # Try builtin workflows
            builtin_path = get_builtins_dir() / f"{name_or_path}.yaml"
            if not builtin_path.is_file():
                builtin_path = get_builtins_dir() / f"{name_or_path}.yml"

            if builtin_path.is_file():
                path = builtin_path
            else:
                raise FileNotFoundError(f"Workflow '{name_or_path}' not found.")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid workflow format in {path}: expected dictionary root.")  # noqa: TRY004

    name = data.get("name", path.stem)
    description = data.get("description", "")
    version = str(data.get("version", "1.0"))
    steps_raw = data.get("steps", [])

    if not isinstance(steps_raw, list) or not steps_raw:
        raise ValueError(f"Workflow '{name}' contains no steps.")

    steps = []
    for i, s in enumerate(steps_raw):
        if not isinstance(s, dict):
            raise ValueError(f"Step {i + 1} in workflow '{name}' is not a dictionary.")  # noqa: TRY004
        step_name = s.get("name", f"Step {i + 1}")
        cmd = s.get("command", "")
        if not cmd:
            raise ValueError(f"Step '{step_name}' in workflow '{name}' missing 'command'.")
        desc = s.get("description", "")
        risk = s.get("risk_level", "low")
        step_id = s.get("id", f"step_{i + 1}")
        steps.append(WorkflowStep(name=step_name, command=cmd, description=desc, risk_level=risk, id=step_id))

    return Workflow(name=name, description=description, steps=steps, version=version)


def list_workflows() -> list[dict[str, Any]]:
    """List all available workflows (built-in and user-defined)."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Search user directory
    user_dir = get_user_workflows_dir()
    if user_dir.exists():
        for p in sorted(user_dir.glob("*.y*ml")):
            try:
                wf = load_workflow(str(p))
                results.append({"name": wf.name, "description": wf.description, "source": "user", "path": str(p)})
                seen.add(wf.name)
            except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
                logger.warning("Failed to load user workflow %s: %s", p, exc)

    # Search built-in directory
    builtin_dir = get_builtins_dir()
    if builtin_dir.exists():
        for p in sorted(builtin_dir.glob("*.y*ml")):
            try:
                wf = load_workflow(str(p))
                if wf.name not in seen:
                    results.append(
                        {"name": wf.name, "description": wf.description, "source": "builtin", "path": str(p)}
                    )
                    seen.add(wf.name)
            except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
                logger.warning("Failed to load builtin workflow %s: %s", p, exc)

    return results


def _dispatch_hook(hook_list: list[Any], method_name: str, *args: Any, **kwargs: Any) -> None:
    """Safely dispatch an observer hook across all registered instances.

    Guarantees:
    1. Isolated error handling: Exceptions raised by hooks are logged as warnings and suppressed.
    2. Read-only immutability: Arguments passed are deepcopied to prevent mutation by hooks.
    3. Flexible signatures: Supports single-arg (e.g. `on_workflow_start(workflow_name)`)
       and multi-arg (e.g. `on_workflow_start(workflow_id, context)`).
    """
    for h in hook_list:
        fn = getattr(h, method_name, None)
        if callable(fn):
            try:
                copied_args = copy.deepcopy(args)
                copied_kwargs = copy.deepcopy(kwargs)
                try:
                    fn(*copied_args, **copied_kwargs)
                except TypeError:
                    if copied_args:
                        fn(copied_args[0])
                    else:
                        raise
            except (Exception, SystemExit) as exc:
                logger.warning(
                    "Workflow hook '%s' on %r failed with exception: %s",
                    method_name,
                    h,
                    exc,
                    exc_info=True,
                )


def run_workflow(
    workflow: Workflow,
    config: AppConfig | None = None,
    interactive: bool = True,
    confirm_func: Any = None,
    pinned_provider: str | None = None,
    hooks: Any | None = None,
) -> list[dict[str, Any]]:
    """Walk through workflow steps with an approval gate between each step.

    Reuses the Phase 1 risk and approval safety policy.
    """
    results: list[dict[str, Any]] = []

    # Gather registered and passed hooks
    active_hooks: list[Any] = []
    if hooks is not None:
        if isinstance(hooks, (list, tuple)):
            active_hooks.extend(hooks)
        else:
            active_hooks.append(hooks)
    try:
        from eva.plugins.loader import get_workflow_hooks

        for h in get_workflow_hooks():
            if h not in active_hooks:
                active_hooks.append(h)
    except ImportError:
        pass

    wf_id = getattr(workflow, "name", "workflow")
    wf_context = {
        "workflow_name": workflow.name,
        "description": redact_secrets(workflow.description) if workflow.description else "",
        "version": getattr(workflow, "version", "1.0"),
        "steps_count": len(workflow.steps),
        "interactive": interactive,
        "pinned_provider": pinned_provider,
    }
    _dispatch_hook(active_hooks, "on_workflow_start", wf_id, wf_context)

    err_console.print(f"[bold cyan]Starting Workflow:[/bold cyan] {workflow.name}")
    if workflow.description:
        err_console.print(f"[dim]{workflow.description}[/dim]")
    err_console.print()

    for idx, step in enumerate(workflow.steps, start=1):
        step_id = getattr(step, "id", "") or f"step_{idx}"
        step_data = {
            "id": step_id,
            "name": step.name,
            "command": redact_secrets(step.command) if step.command else "",
            "description": redact_secrets(step.description) if step.description else "",
            "risk_level": step.risk_level,
            "index": idx,
            "pinned_provider": pinned_provider,
        }
        _dispatch_hook(active_hooks, "on_step_start", step_id, step_data)

        err_console.print(f"[bold yellow]Step {idx}/{len(workflow.steps)}:[/bold yellow] {step.name}")
        if step.description:
            err_console.print(f"  [italic]{step.description}[/italic]")
        err_console.print(f"  [cyan]> {step.command}[/cyan]")

        # 1. Safety Audit & Parsing using Phase 1 work_safety
        try:
            parsed = parse_safe_command(step.command)
        except UnsafeCommandError as exc:
            audit_entry = {
                "workflow": workflow.name,
                "step": step.name,
                "step_id": step_id,
                "command": step.command,
                "executed": False,
                "blocked_reason": f"unsafe_command: {exc}",
                "pinned_provider": pinned_provider,
            }
            if pinned_provider:
                audit_entry["provider"] = pinned_provider
            append_command_audit(audit_entry)
            err_console.print(f"  [bold red]Refusing to execute unsafe command in step '{step.name}': {exc}[/bold red]")
            results.append(
                {
                    "step": step.name,
                    "step_id": step_id,
                    "command": step.command,
                    "executed": False,
                    "status": "blocked_unsafe",
                    "error": str(exc),
                    "pinned_provider": pinned_provider,
                }
            )
            error_data = {
                "step": step.name,
                "step_id": step_id,
                "status": "blocked_unsafe",
                "error": redact_secrets(str(exc)),
                "pinned_provider": pinned_provider,
            }
            _dispatch_hook(active_hooks, "on_step_error", step_id, error_data)
            break
        except CommandExtractionError as exc:
            audit_entry = {
                "workflow": workflow.name,
                "step": step.name,
                "step_id": step_id,
                "command": step.command,
                "executed": False,
                "blocked_reason": f"ambiguous_command: {exc}",
                "pinned_provider": pinned_provider,
            }
            if pinned_provider:
                audit_entry["provider"] = pinned_provider
            append_command_audit(audit_entry)
            err_console.print(f"  [bold red]Ambiguous command output in step '{step.name}': {exc}[/bold red]")
            results.append(
                {
                    "step": step.name,
                    "step_id": step_id,
                    "command": step.command,
                    "executed": False,
                    "status": "blocked_ambiguous",
                    "error": str(exc),
                    "pinned_provider": pinned_provider,
                }
            )
            error_data = {
                "step": step.name,
                "step_id": step_id,
                "status": "blocked_ambiguous",
                "error": redact_secrets(str(exc)),
                "pinned_provider": pinned_provider,
            }
            _dispatch_hook(active_hooks, "on_step_error", step_id, error_data)
            break

        try:
            _reject_shell_control_tokens(parsed.argv)
        except UnsafeCommandError as exc:
            audit_entry = {
                "workflow": workflow.name,
                "step": step.name,
                "step_id": step_id,
                "command": parsed.command,
                "argv": parsed.argv,
                "executed": False,
                "blocked_reason": f"unsafe_shell_control: {exc}",
                "pinned_provider": pinned_provider,
            }
            if pinned_provider:
                audit_entry["provider"] = pinned_provider
            append_command_audit(audit_entry)
            err_console.print(f"  [bold red]Refusing workflow shell features in step '{step.name}': {exc}[/bold red]")
            results.append(
                {
                    "step": step.name,
                    "step_id": step_id,
                    "command": parsed.command,
                    "argv": parsed.argv,
                    "executed": False,
                    "status": "blocked_unsafe",
                    "error": str(exc),
                    "pinned_provider": pinned_provider,
                }
            )
            error_data = {
                "step": step.name,
                "step_id": step_id,
                "status": "blocked_unsafe",
                "error": redact_secrets(str(exc)),
                "pinned_provider": pinned_provider,
            }
            _dispatch_hook(active_hooks, "on_step_error", step_id, error_data)
            break

        # 2. Approval Gate (Human approval before execution)
        if interactive:
            if confirm_func:
                approved = confirm_func(f"Execute step '{step.name}' ({parsed.command})?")
            else:
                approved = Confirm.ask(f"Execute step '{step.name}'?", default=True)

            if not approved:
                audit_entry = {
                    "workflow": workflow.name,
                    "step": step.name,
                    "step_id": step_id,
                    "command": parsed.command,
                    "executed": False,
                    "blocked_reason": "user_declined",
                    "pinned_provider": pinned_provider,
                }
                if pinned_provider:
                    audit_entry["provider"] = pinned_provider
                append_command_audit(audit_entry)
                err_console.print(f"  [yellow]Step '{step.name}' declined by user. Stopping workflow.[/yellow]")
                results.append(
                    {
                        "step": step.name,
                        "step_id": step_id,
                        "command": parsed.command,
                        "executed": False,
                        "status": "declined",
                        "pinned_provider": pinned_provider,
                    }
                )
                error_data = {
                    "step": step.name,
                    "step_id": step_id,
                    "status": "declined",
                    "error": "user_declined",
                    "pinned_provider": pinned_provider,
                }
                _dispatch_hook(active_hooks, "on_step_error", step_id, error_data)
                break

        # 3. Execution
        started = time.time()
        env = os.environ.copy()
        if pinned_provider:
            env["EVA_PROVIDER"] = pinned_provider
            env["EVA_DEFAULT_PROVIDER"] = pinned_provider

        res = subprocess.run(parsed.argv, shell=False, capture_output=True, text=True, check=False, env=env)
        audit_entry = {
            "workflow": workflow.name,
            "step": step.name,
            "step_id": step_id,
            "command": parsed.command,
            "argv": parsed.argv,
            "executed": True,
            "return_code": res.returncode,
            "duration_s": round(time.time() - started, 3),
            "pinned_provider": pinned_provider,
        }
        if pinned_provider:
            audit_entry["provider"] = pinned_provider
        append_command_audit(audit_entry)

        step_result = {
            "step": step.name,
            "step_id": step_id,
            "command": parsed.command,
            "argv": parsed.argv,
            "executed": True,
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "status": "success" if res.returncode == 0 else "failed",
        }
        if pinned_provider:
            step_result["pinned_provider"] = pinned_provider
        results.append(step_result)

        hook_step_result = {
            "step": step.name,
            "step_id": step_id,
            "command": redact_secrets(parsed.command),
            "argv": [redact_secrets(arg) for arg in parsed.argv],
            "executed": True,
            "returncode": res.returncode,
            "stdout": redact_secrets(res.stdout),
            "stderr": redact_secrets(res.stderr),
            "status": "success" if res.returncode == 0 else "failed",
            "duration_s": round(time.time() - started, 3),
            "pinned_provider": pinned_provider,
        }
        _dispatch_hook(active_hooks, "on_step_complete", step_id, hook_step_result)
        if res.returncode != 0:
            _dispatch_hook(active_hooks, "on_step_error", step_id, hook_step_result)

        if res.stdout:
            print(res.stdout, end="" if res.stdout.endswith("\n") else "\n")
        if res.stderr and res.returncode != 0:
            err_console.print(f"[red]{res.stderr}[/red]")

        if res.returncode != 0:
            err_console.print(
                f"  [bold red]Step '{step.name}' failed with returncode {res.returncode}. Stopping workflow.[/bold red]"
            )
            break

        err_console.print(f"  [green]✔ Step '{step.name}' complete.[/green]\n")

    failed_steps = [
        r for r in results if r.get("status") in {"failed", "blocked_unsafe", "blocked_ambiguous", "declined"}
    ]
    wf_summary = {
        "workflow_name": workflow.name,
        "total_steps": len(workflow.steps),
        "executed_steps": len([r for r in results if r.get("executed")]),
        "successful_steps": len([r for r in results if r.get("status") == "success"]),
        "failed_steps": len(failed_steps),
        "status": "success" if (not failed_steps and len(results) == len(workflow.steps)) else "failed",
        "pinned_provider": pinned_provider,
        "results": [
            {
                **r,
                "command": redact_secrets(r["command"]) if "command" in r else "",
                "stdout": redact_secrets(r["stdout"]) if "stdout" in r else "",
                "stderr": redact_secrets(r["stderr"]) if "stderr" in r else "",
            }
            for r in results
        ],
    }
    _dispatch_hook(active_hooks, "on_workflow_complete", wf_id, wf_summary)

    return results
