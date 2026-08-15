from pathlib import Path

from eva.indexing.io import ContextReadError, read_text_file_for_context

PROJECT_CONTEXT_PATH = Path(".eva") / "context.md"


def load_project_context(root: Path = Path(".")) -> str:
    """Return formatted content of <root>/.eva/context.md, or '' if absent/unreadable.

    Never raises — a missing or unreadable memory file must not block ask/work.
    """
    path = root / PROJECT_CONTEXT_PATH
    if not path.exists() or not path.is_file():
        return ""
    try:
        text, _warnings = read_text_file_for_context(path)
    except ContextReadError:
        return ""
    if not text.strip():
        return ""
    return f"\n=== Project Memory ({PROJECT_CONTEXT_PATH.as_posix()}) ===\n{text}\n"
