import logging
from pathlib import Path

from eva.workspace.gitignore import get_gitignore_spec, is_ignored

logger = logging.getLogger(__name__)


def _build_tree(dir_path: Path, root_path: Path, spec, prefix: str = "") -> str:
    if is_ignored(dir_path, root_path, spec):
        return ""

    try:
        entries = sorted(dir_path.iterdir(), key=lambda x: (x.is_file(), x.name))
    except PermissionError:
        return ""

    # Filter ignored
    valid_entries = []
    for entry in entries:
        if not is_ignored(entry, root_path, spec):
            valid_entries.append(entry)

    tree_str = ""
    for i, entry in enumerate(valid_entries):
        is_last = i == len(valid_entries) - 1
        connector = "└── " if is_last else "├── "

        tree_str += f"{prefix}{connector}{entry.name}\n"

        if entry.is_dir():
            extension = "    " if is_last else "│   "
            tree_str += _build_tree(entry, root_path, spec, prefix + extension)

    return tree_str


try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


def generate_tree(path: str | Path) -> str:
    root_path = Path(path).resolve()

    if HAS_RUST:
        try:
            return eva_fastwalk.fast_generate_tree(str(root_path))
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Rust fast_generate_tree error, falling back to Python: %s", exc)

    spec = get_gitignore_spec(root_path)

    if not root_path.is_dir():
        return f"{root_path.name}\n"

    return f"{root_path.name}/\n" + _build_tree(root_path, root_path, spec)
