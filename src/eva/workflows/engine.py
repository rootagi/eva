import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.prompt import Confirm

from eva.config import AppConfig, get_config_dir
from eva.security.work_safety import (
    CommandExtractionError,
    UnsafeCommandError,
    append_command_audit,
    parse_safe_command,
)

logger = logging.getLogger(__name__)
err_console = Console(stderr=True)


@dataclass
class WorkflowStep:
    name: str
    command: str
    description: str = ""
    risk_level: str = "low"


@dataclass
class Workflow:
    name: str
    description: str
    steps: list[WorkflowStep] = field(default_factory=list)
    version: str = "1.0"


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
        raise ValueError(f"Invalid workflow format in {path}: expected dictionary root.")

    name = data.get("name", path.stem)
    description = data.get("description", "")
    version = str(data.get("version", "1.0"))
    steps_raw = data.get("steps", [])

    if not isinstance(steps_raw, list) or not steps_raw:
        raise ValueError(f"Workflow '{name}' contains no steps.")

    steps = []
    for i, s in enumerate(steps_raw):
        if not isinstance(s, dict):
            raise ValueError(f"Step {i+1} in workflow '{name}' is not a dictionary.")
        step_name = s.get("name", f"Step {i+1}")
        cmd = s.get("command", "")
        if not cmd:
            raise ValueError(f"Step '{step_name}' in workflow '{name}' missing 'command'.")
        desc = s.get("description", "")
        risk = s.get("risk_level", "low")
        steps.append(WorkflowStep(name=step_name, command=cmd, description=desc, risk_level=risk))

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
            except Exception as exc:
                logger.warning("Failed to load user workflow %s: %s", p, exc)

    # Search built-in directory
    builtin_dir = get_builtins_dir()
    if builtin_dir.exists():
        for p in sorted(builtin_dir.glob("*.y*ml")):
            try:
                wf = load_workflow(str(p))
                if wf.name not in seen:
                    results.append({"name": wf.name, "description": wf.description, "source": "builtin", "path": str(p)})
                    seen.add(wf.name)
            except Exception as exc:
                logger.warning("Failed to load builtin workflow %s: %s", p, exc)

    return results


def run_workflow(
    workflow: Workflow,
    config: AppConfig | None = None,
    interactive: bool = True,
    confirm_func: Any = None,
) -> list[dict[str, Any]]:
    """Walk through workflow steps with an approval gate between each step.
    
    Reuses the Phase 1 risk and approval safety policy.
    """
    results = []

    err_console.print(f"[bold cyan]Starting Workflow:[/bold cyan] {workflow.name}")
    if workflow.description:
        err_console.print(f"[dim]{workflow.description}[/dim]")
    err_console.print()

    for idx, step in enumerate(workflow.steps, start=1):
        err_console.print(f"[bold yellow]Step {idx}/{len(workflow.steps)}:[/bold yellow] {step.name}")
        if step.description:
            err_console.print(f"  [italic]{step.description}[/italic]")
        err_console.print(f"  [cyan]> {step.command}[/cyan]")

        # 1. Safety Audit & Parsing using Phase 1 work_safety
        try:
            parsed = parse_safe_command(step.command)
        except UnsafeCommandError as exc:
            append_command_audit({
                "workflow": workflow.name,
                "step": step.name,
                "command": step.command,
                "executed": False,
                "blocked_reason": f"unsafe_command: {exc}",
            })
            err_console.print(f"  [bold red]Refusing to execute unsafe command in step '{step.name}': {exc}[/bold red]")
            results.append({
                "step": step.name,
                "command": step.command,
                "executed": False,
                "status": "blocked_unsafe",
                "error": str(exc),
            })
            break
        except CommandExtractionError as exc:
            append_command_audit({
                "workflow": workflow.name,
                "step": step.name,
                "command": step.command,
                "executed": False,
                "blocked_reason": f"ambiguous_command: {exc}",
            })
            err_console.print(f"  [bold red]Ambiguous command output in step '{step.name}': {exc}[/bold red]")
            results.append({
                "step": step.name,
                "command": step.command,
                "executed": False,
                "status": "blocked_ambiguous",
                "error": str(exc),
            })
            break

        # 2. Approval Gate (Human approval before execution)
        if interactive:
            if confirm_func:
                approved = confirm_func(f"Execute step '{step.name}' ({parsed.command})?")
            else:
                approved = Confirm.ask(f"Execute step '{step.name}'?", default=True)

            if not approved:
                append_command_audit({
                    "workflow": workflow.name,
                    "step": step.name,
                    "command": parsed.command,
                    "executed": False,
                    "blocked_reason": "user_declined",
                })
                err_console.print(f"  [yellow]Step '{step.name}' declined by user. Stopping workflow.[/yellow]")
                results.append({
                    "step": step.name,
                    "command": parsed.command,
                    "executed": False,
                    "status": "declined",
                })
                break

        # 3. Execution
        res = subprocess.run(parsed.command, shell=True, capture_output=True, text=True, check=False)
        append_command_audit({
            "workflow": workflow.name,
            "step": step.name,
            "command": parsed.command,
            "executed": True,
            "return_code": res.returncode,
        })

        step_result = {
            "step": step.name,
            "command": parsed.command,
            "executed": True,
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "status": "success" if res.returncode == 0 else "failed",
        }
        results.append(step_result)

        if res.stdout:
            print(res.stdout, end="" if res.stdout.endswith("\n") else "\n")
        if res.stderr and res.returncode != 0:
            err_console.print(f"[red]{res.stderr}[/red]")

        if res.returncode != 0:
            err_console.print(f"  [bold red]Step '{step.name}' failed with returncode {res.returncode}. Stopping workflow.[/bold red]")
            break

        err_console.print(f"  [green]✔ Step '{step.name}' complete.[/green]\n")

    return results
