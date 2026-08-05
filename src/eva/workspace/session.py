import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eva.config import get_config_dir

logger = logging.getLogger(__name__)

from eva.security.redaction import redact_secrets

__all_redact__ = ["redact_secrets"]


@dataclass
class WorkspaceSession:
    name: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: list[str] = field(default_factory=list)
    bookmarks: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)


def get_workspaces_root() -> Path:
    d = get_config_dir() / "workspaces"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_active_workspace_file() -> Path:
    return get_config_dir() / "active_workspace"


def get_active_workspace() -> str:
    f = get_active_workspace_file()
    if f.exists():
        try:
            name = f.read_text(encoding="utf-8").strip()
            if name:
                return name
        except OSError as exc:
            logger.debug("Failed to read active workspace marker: %s", exc)
    return "default"


def set_active_workspace(name: str):
    safe_name = sanitize_workspace_name(name)
    # Ensure workspace exists
    get_workspace(safe_name)
    f = get_active_workspace_file()
    f.write_text(safe_name, encoding="utf-8")


def sanitize_workspace_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip()).strip("._")
    return cleaned or "default"


def get_workspace_dir(name: str) -> Path:
    safe_name = sanitize_workspace_name(name)
    d = get_workspaces_root() / safe_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_workspace(name: str) -> WorkspaceSession:
    safe_name = sanitize_workspace_name(name)
    wdir = get_workspace_dir(safe_name)

    meta_file = wdir / "meta.json"
    if not meta_file.exists():
        ws = WorkspaceSession(name=safe_name)
        meta_file.write_text(json.dumps({"name": ws.name, "created_at": ws.created_at}, indent=2), encoding="utf-8")
    else:
        ws = get_workspace(safe_name)

    return ws


def get_workspace(name: str) -> WorkspaceSession:
    safe_name = sanitize_workspace_name(name)
    wdir = get_workspace_dir(safe_name)

    meta_file = wdir / "meta.json"
    created_at = datetime.now(timezone.utc).isoformat()
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            created_at = meta.get("created_at", created_at)
        except (OSError, ValueError) as exc:
            logger.debug("Failed to read workspace metadata %s: %s", meta_file, exc)
    else:
        meta_file.write_text(json.dumps({"name": safe_name, "created_at": created_at}, indent=2), encoding="utf-8")

    # Load notes
    notes = []
    notes_file = wdir / "notes.md"
    if notes_file.exists():
        content = notes_file.read_text(encoding="utf-8", errors="replace")
        notes = [n.strip() for n in content.split("\n--- Note ---\n") if n.strip()]

    # Load bookmarks
    bookmarks = []
    bm_file = wdir / "bookmarks.json"
    if bm_file.exists():
        try:
            bookmarks = json.loads(bm_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.debug("Failed to read bookmarks %s: %s", bm_file, exc)

    # Load history
    history = []
    hist_file = wdir / "history.jsonl"
    if hist_file.exists():
        try:
            with open(hist_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        history.append(json.loads(line))
        except (OSError, ValueError) as exc:
            logger.debug("Failed to read workspace history %s: %s", hist_file, exc)

    return WorkspaceSession(
        name=safe_name,
        created_at=created_at,
        notes=notes,
        bookmarks=bookmarks,
        history=history,
    )


def list_workspaces() -> list[str]:
    root = get_workspaces_root()
    names = []
    for p in root.iterdir():
        if p.is_dir() and (p / "meta.json").exists():
            names.append(p.name)
    if not names:
        create_workspace("default")
        return ["default"]
    return sorted(names)


def add_note(name: str, note_text: str):
    wdir = get_workspace_dir(name)
    redacted_note = redact_secrets(note_text)
    notes_file = wdir / "notes.md"

    entry = f"\n--- Note ---\n{redacted_note.strip()}\n"
    with open(notes_file, "a", encoding="utf-8") as f:
        f.write(entry)


def add_bookmark(name: str, path_str: str):
    wdir = get_workspace_dir(name)
    bm_file = wdir / "bookmarks.json"
    bookmarks = []
    if bm_file.exists():
        try:
            bookmarks = json.loads(bm_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.debug("Failed to read bookmarks %s: %s", bm_file, exc)

    clean_path = redact_secrets(path_str.strip())
    if clean_path not in bookmarks:
        bookmarks.append(clean_path)
        bm_file.write_text(json.dumps(bookmarks, indent=2), encoding="utf-8")


def add_history(name: str, entry_type: str, content: str):
    wdir = get_workspace_dir(name)
    hist_file = wdir / "history.jsonl"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": entry_type,
        "content": redact_secrets(content),
    }

    with open(hist_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
