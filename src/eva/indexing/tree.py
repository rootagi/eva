import logging
from pathlib import Path

from eva.workspace.gitignore import (
    ALWAYS_IGNORED_DIRS,
    get_gitignore_spec,
    get_ignored_dirs_config,
    is_ignored,
)

logger = logging.getLogger(__name__)


def _build_tree(
    dir_path: Path,
    root_path: Path,
    spec,
    prefix: str = "",
    effective_ignored: set[str] | None = None,
) -> str:
    if is_ignored(dir_path, root_path, spec, effective_ignored=effective_ignored):
        return ""

    try:
        entries = sorted(dir_path.iterdir(), key=lambda x: (x.is_file(), x.name))
    except PermissionError:
        return ""

    valid_entries = []
    for entry in entries:
        if not is_ignored(entry, root_path, spec, effective_ignored=effective_ignored):
            valid_entries.append(entry)

    tree_str = ""
    for i, entry in enumerate(valid_entries):
        is_last = i == len(valid_entries) - 1
        connector = "└── " if is_last else "├── "

        tree_str += f"{prefix}{connector}{entry.name}\n"

        if entry.is_dir():
            extension = "    " if is_last else "│   "
            tree_str += _build_tree(
                entry,
                root_path,
                spec,
                prefix + extension,
                effective_ignored=effective_ignored,
            )

    return tree_str


try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


def generate_tree(
    path: str | Path,
    extra_ignored: list[str] | None = None,
    unignore: list[str] | None = None,
) -> str:
    root_path = Path(path).resolve()
    if not root_path.exists():
        return f"Path {root_path} does not exist\n"

    if extra_ignored is None and unignore is None:
        extra_cfg, unignore_cfg = get_ignored_dirs_config()
        if not extra_cfg and not unignore_cfg:
            try:
                from eva.config import load_config

                cfg = load_config()
                extra_cfg = cfg.general.extra_ignored_dirs
                unignore_cfg = cfg.general.unignore_dirs
            except (OSError, ValueError, TypeError) as exc:
                logger.debug("Failed to load config for ignored dirs: %s", exc)
        extra_ignored = extra_cfg
        unignore = unignore_cfg

    if HAS_RUST:
        try:
            try:
                return eva_fastwalk.fast_generate_tree(
                    str(root_path),
                    extra_ignored=extra_ignored,
                    unignore=unignore,
                )
            except TypeError:
                return eva_fastwalk.fast_generate_tree(str(root_path))
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Rust fast_generate_tree error, falling back to Python: %s", exc)

    spec = get_gitignore_spec(root_path)

    if not root_path.is_dir():
        return f"{root_path.name}\n"

    effective_ignored = set(ALWAYS_IGNORED_DIRS)
    if unignore:
        effective_ignored -= set(unignore)
    if extra_ignored:
        effective_ignored |= set(extra_ignored)

    return f"{root_path.name}/\n" + _build_tree(
        root_path,
        root_path,
        spec,
        effective_ignored=effective_ignored,
    )
