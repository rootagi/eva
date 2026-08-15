from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from eva.indexing.finder import find_files
from eva.indexing.io import ContextReadError, read_text_file_for_context
from eva.security.redaction import redact_secrets
from eva.security.sensitive_files import is_sensitive_file
from eva.workspace.gitignore import get_gitignore_spec, is_ignored


@dataclass
class ToolResult:
    success: bool
    content: str | None = None
    error: str | None = None


def _is_within_root(target: Path, root: Path) -> bool:
    try:
        resolved_target = target.resolve()
        resolved_root = root.resolve()
        return resolved_target == resolved_root or resolved_root in resolved_target.parents
    except (ValueError, OSError):
        return False


def list_directory(root: Path, path: str = ".", force_include: set[str] = frozenset()) -> list[dict]:
    """List directory entries relative to root, excluding gitignored and denylisted paths."""
    root_path = root.resolve()
    try:
        target_path = (root_path / path).resolve()
    except (ValueError, OSError):
        return []

    if not _is_within_root(target_path, root_path):
        return []

    if not target_path.is_dir():
        return []

    gitignore_spec = get_gitignore_spec(root_path)
    entries: list[dict] = []

    try:
        items = sorted(target_path.iterdir(), key=lambda p: (p.is_file(), p.name))
    except (PermissionError, OSError):
        return []

    for item in items:
        if is_ignored(item, root_path, gitignore_spec):
            continue
        try:
            rel_str = item.relative_to(root_path).as_posix()
        except ValueError:
            continue

        if is_sensitive_file(rel_str) and rel_str not in force_include and item.name not in force_include:
            continue

        if item.is_dir():
            entries.append({"name": item.name, "type": "dir", "path": rel_str})
        elif item.is_file():
            try:
                size = item.stat().st_size
            except OSError:
                size = 0
            entries.append({"name": item.name, "type": "file", "size": size, "path": rel_str})

    return entries


def read_file(root: Path, path: str, force_include: set[str] = frozenset()) -> ToolResult:
    """Read a text file from root, enforcing path containment, denylist, and secret redaction."""
    root_path = root.resolve()
    try:
        target_path = (root_path / path).resolve()
    except (ValueError, OSError) as exc:
        return ToolResult(success=False, error=f"Invalid path: {exc}")

    if not _is_within_root(target_path, root_path):
        return ToolResult(success=False, error="Path traversal outside repository root is forbidden")

    try:
        rel_path = target_path.relative_to(root_path).as_posix()
    except ValueError:
        return ToolResult(success=False, error="Path traversal outside repository root is forbidden")

    if is_sensitive_file(rel_path) and rel_path not in force_include and target_path.name not in force_include:
        return ToolResult(success=False, error="File is excluded for security reasons")

    gitignore_spec = get_gitignore_spec(root_path)
    if is_ignored(target_path, root_path, gitignore_spec):
        return ToolResult(success=False, error="File is excluded by .gitignore")

    if not target_path.is_file():
        return ToolResult(success=False, error=f"File not found or not a regular file: {path}")

    try:
        raw_text, _warnings = read_text_file_for_context(target_path)
    except ContextReadError as exc:
        return ToolResult(success=False, error=str(exc))
    except OSError as exc:
        return ToolResult(success=False, error=f"Failed to read file: {exc}")

    redacted_text = redact_secrets(raw_text)
    return ToolResult(success=True, content=redacted_text)


def search_code(
    root: Path, pattern: str, path: str = ".", max_results: int = 50, force_include: set[str] = frozenset()
) -> list[dict]:
    """Search for pattern across text files in root/path, capped at max_results."""
    root_path = root.resolve()
    try:
        search_root = (root_path / path).resolve()
    except (ValueError, OSError):
        return []

    if not _is_within_root(search_root, root_path):
        return []

    if not search_root.exists():
        return []

    try:
        regex = re.compile(pattern)
    except re.error:
        regex = re.compile(re.escape(pattern))

    gitignore_spec = get_gitignore_spec(root_path)
    results: list[dict] = []

    if search_root.is_file():
        candidate_files = [search_root]
    else:
        candidate_files = sorted(find_files(search_root, "*"), key=lambda p: p.as_posix())

    for file_path in candidate_files:
        if len(results) >= max_results:
            break

        if not file_path.is_file():
            continue

        if is_ignored(file_path, root_path, gitignore_spec):
            continue

        try:
            rel_str = file_path.relative_to(root_path).as_posix()
        except ValueError:
            continue

        if is_sensitive_file(rel_str) and rel_str not in force_include and file_path.name not in force_include:
            continue

        try:
            raw_text, _warnings = read_text_file_for_context(file_path)
        except (ContextReadError, OSError):
            continue

        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            if regex.search(line):
                results.append(
                    {
                        "file": rel_str,
                        "line": line_no,
                        "text": redact_secrets(line),
                    }
                )
                if len(results) >= max_results:
                    break

    return results
