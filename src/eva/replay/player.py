import json
import logging
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from eva.replay.recorder import get_replays_dir, get_session_dir

logger = logging.getLogger(__name__)


def list_replay_sessions(replays_dir: Path | None = None) -> list[dict[str, Any]]:
    """List all available recorded replay sessions."""
    root = replays_dir or get_replays_dir()
    if not root.exists():
        return []

    sessions = []
    for d in sorted(root.iterdir()):
        if d.is_dir():
            meta_file = d / "meta.json"
            events_file = d / "events.jsonl"
            created_at = "Unknown"
            count = 0
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    created_at = meta.get("created_at", created_at)
                except (OSError, ValueError) as exc:
                    logger.debug("Failed to read replay metadata %s: %s", meta_file, exc)
            if events_file.exists():
                try:
                    count = len([line for line in events_file.read_text(encoding="utf-8").splitlines() if line.strip()])
                except (OSError, ValueError) as exc:
                    logger.debug("Failed to read replay events %s: %s", events_file, exc)
            sessions.append(
                {
                    "session_id": d.name,
                    "created_at": created_at,
                    "event_count": count,
                }
            )
    return sessions


def load_replay_session(session_id: str, replays_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load all recorded events for a given session."""
    target_dir = (replays_dir / session_id) if replays_dir else get_session_dir(session_id)
    events_file = target_dir / "events.jsonl"

    if not events_file.exists():
        raise FileNotFoundError(f"Replay session '{session_id}' not found.")

    events = []
    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    return events


def display_replay_session(session_id: str, console: Console | None = None, replays_dir: Path | None = None):
    """Display recorded terminal replay session events."""
    c = console or Console()
    events = load_replay_session(session_id, replays_dir=replays_dir)

    if not events:
        c.print(f"[warning]No recorded events found in session '{session_id}'.[/warning]")
        return

    c.print(f"[bold cyan]▶ Terminal Replay: Session '{session_id}'[/bold cyan] ({len(events)} events)\n")

    for idx, ev in enumerate(events, start=1):
        ts = ev.get("timestamp", "")[:19].replace("T", " ")
        code = ev.get("exit_code", 0)
        dur = ev.get("duration_s", 0.0)
        status_str = "[green]✓ 0[/green]" if code == 0 else f"[red]✗ {code}[/red]"

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_row(f"[bold yellow]#{idx}[/bold yellow]", f"[dim]{ts}[/dim]", f"dir: {ev.get('cwd', '')}")
        table.add_row(
            "[bold cyan]Command:[/bold cyan]", f"[bold]{ev.get('command', '')}[/bold]", f"({dur}s, {status_str})"
        )

        c.print(table)
        output = ev.get("output", "")
        if output.strip():
            c.print(f"[dim]Output:[/dim]\n{output.strip()}\n")
        c.print("-" * 50)
