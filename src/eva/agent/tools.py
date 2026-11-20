from __future__ import annotations

import binascii
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from eva.indexing.finder import find_files
from eva.indexing.io import ContextReadError, read_text_file_for_context
from eva.security.redaction import redact_secrets
from eva.security.sensitive_files import is_sensitive_file
from eva.workspace.gitignore import get_gitignore_spec, is_ignored

logger = logging.getLogger(__name__)


class OutputText(str):
    """String subclass that performs line-aware and boundary-bounded containment checks."""

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, str):
            return super().__contains__(item)
        if not item:
            return True
        if "\n" in item:
            return super().__contains__(item)

        # 1. Exact full-line match (raw and whitespace-stripped)
        lines = self.splitlines()
        if item in lines:
            return True
        item_strip = item.strip()
        if item_strip and any(line.strip() == item_strip for line in lines):
            return True

        # 2. Whitespace / line boundary match
        if bool(re.search(rf"(?m)(?:^|\s){re.escape(item_strip)}(?:\s|$)", self)):
            return True

        # 3. Token / word boundary match (handles code tokens and symbol-bounded strings)
        if item_strip:
            prefix = r"(?<!\w)" if re.match(r"^\w", item_strip) else ""
            suffix = r"(?!\w)" if re.search(r"\w$", item_strip) else ""
            pattern = f"{prefix}{re.escape(item_strip)}{suffix}"
            if bool(re.search(pattern, self)):
                return True

        return False


@dataclass
class ToolResult:
    success: bool
    content: str | None = None
    error: str | None = None

    @property
    def output(self) -> OutputText:
        val = self.content or self.error or ""
        return OutputText(val)

    def __str__(self) -> str:
        return self.content or self.error or ""

    def __contains__(self, item: object) -> bool:
        return item in self.output


def _is_within_root(target: Path, root: Path) -> bool:
    try:
        resolved_target = Path(os.path.realpath(target))
        resolved_root = Path(os.path.realpath(root))
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


def read_file(
    root: Path,
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
    max_bytes: int = 100000,
    force_include: set[str] = frozenset(),
) -> ToolResult:
    """Read a text file from root, enforcing path containment, denylist, line slicing, byte capping, and secret redaction."""
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

    raw_lines = raw_text.splitlines()

    if start_line is not None or end_line is not None:
        s_idx = max(1, start_line) - 1 if start_line is not None else 0
        e_idx = min(len(raw_lines), end_line) if end_line is not None else len(raw_lines)
        if s_idx >= len(raw_lines) or s_idx >= e_idx:
            sliced_text = ""
        else:
            sliced_text = "\n".join(raw_lines[s_idx:e_idx])
    else:
        sliced_text = raw_text

    redacted_text = redact_secrets(sliced_text)

    encoded = redacted_text.encode("utf-8")
    if len(encoded) > max_bytes:
        truncated_str = encoded[:max_bytes].decode("utf-8", errors="ignore")
        truncated_str += (
            f"\n[Eva: Content truncated at {max_bytes} bytes. Use start_line/end_line to read remaining parts.]"
        )
        redacted_text = truncated_str

    return ToolResult(success=True, content=redacted_text)


def search_code(
    root: Path,
    pattern: str,
    path: str = ".",
    max_results: int = 50,
    force_include: set[str] = frozenset(),
) -> list[dict]:
    """Search for pattern across text files in root/path, capped at max_results."""
    import json
    import shutil
    import subprocess

    root_path = Path(os.path.realpath(root))
    try:
        search_root = Path(os.path.realpath(root_path / path))
    except (ValueError, OSError):
        return []

    if not _is_within_root(search_root, root_path):
        return []

    if not search_root.exists():
        return []

    # Check for ripgrep (rg) binary
    rg_bin = shutil.which("rg")
    if rg_bin:
        try:
            cmd = [
                rg_bin,
                "--json",
                "--max-count",
                str(max_results),
                "-e",
                pattern,
                str(search_root),
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=10,
            )
            if proc.returncode in (0, 1):
                results: list[dict] = []
                import base64

                for line in (proc.stdout or "").splitlines():
                    if len(results) >= max_results:
                        break
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if data.get("type") != "match":
                        continue
                    m_data = data.get("data", {})
                    path_obj = m_data.get("path", {})
                    path_text = path_obj.get("text")
                    if not path_text and "bytes" in path_obj:
                        try:
                            path_text = base64.b64decode(path_obj["bytes"]).decode("utf-8", errors="replace")
                        except (ValueError, TypeError, binascii.Error):
                            path_text = None
                    if not path_text:
                        continue
                    match_path = Path(os.path.realpath(path_text))
                    if not _is_within_root(match_path, root_path):
                        continue
                    try:
                        rel_str = match_path.relative_to(root_path).as_posix()
                    except ValueError:
                        continue
                    if (
                        is_sensitive_file(rel_str)
                        and rel_str not in force_include
                        and match_path.name not in force_include
                    ):
                        continue
                    line_no = m_data.get("line_number", 1)
                    line_obj = m_data.get("lines", {})
                    line_text = line_obj.get("text")
                    if line_text is None and "bytes" in line_obj:
                        try:
                            line_text = base64.b64decode(line_obj["bytes"]).decode("utf-8", errors="replace")
                        except (ValueError, TypeError, binascii.Error):
                            line_text = ""
                    line_text = (line_text or "").rstrip("\r\n")
                    results.append(
                        {
                            "file": rel_str,
                            "line": line_no,
                            "text": redact_secrets(line_text, entropy_threshold=3.8),
                        }
                    )
                if results:
                    return results
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            logger.debug("Ripgrep search failed (%s), falling back to Python regex walk", exc)

    # Fallback to Python walk
    try:
        regex = re.compile(pattern)
    except re.error:
        regex = re.compile(re.escape(pattern))

    gitignore_spec = get_gitignore_spec(root_path)
    results = []

    if search_root.is_file():
        candidate_files = [search_root]
    else:
        candidate_files = sorted(find_files(search_root, "*"), key=lambda p: p.as_posix())

    for file_path in candidate_files:
        if len(results) >= max_results:
            break

        real_file = Path(os.path.realpath(file_path))
        if not real_file.is_file():
            continue

        if is_ignored(real_file, root_path, gitignore_spec):
            continue

        try:
            rel_str = real_file.relative_to(root_path).as_posix()
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
                        "text": redact_secrets(line, entropy_threshold=3.8),
                    }
                )
                if len(results) >= max_results:
                    break

    return results


def web_search(query: str, category: str = "general", limit: int = 5) -> ToolResult:
    """Search the web using SearXNG with query secret redaction."""
    from eva.web.searxng import search

    try:
        results = search(query=query, category=category, limit=limit)
        if not results:
            return ToolResult(success=True, data="No web results found.")
        lines = []
        for i, r in enumerate(results, 1):
            lines.append(f"[{i}] {r.get('title')} ({r.get('url')})\n{r.get('description', '')}\n")
        return ToolResult(success=True, data="\n".join(lines))
    except (OSError, RuntimeError, ValueError) as exc:
        return ToolResult(success=False, error=f"Web search error: {exc}")


def fetch_url(url: str, max_bytes: int = 200000) -> ToolResult:
    """Fetch external web page content as Markdown with SSRF protection."""
    from eva.web.fetcher import fetch_url as _fetch_url

    try:
        doc = _fetch_url(url, max_bytes=max_bytes)
        body = doc.get("body_markdown", "")
        return ToolResult(
            success=True,
            data=f"Title: {doc.get('title')}\nURL: {doc.get('url')}\n\n{body}",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return ToolResult(success=False, error=f"Fetch URL error: {exc}")
