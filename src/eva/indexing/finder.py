import fnmatch
import logging
import os
from collections.abc import Iterator
from pathlib import Path

from eva.workspace.gitignore import (
    ALWAYS_IGNORED_DIRS,
    get_gitignore_spec,
    get_ignored_dirs_config,
    is_ignored,
)

logger = logging.getLogger(__name__)

try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


class UniversalPath(type(Path())):
    """Path subclass supporting containment checks (e.g. 'substring' in path)."""

    def __contains__(self, item: object) -> bool:
        return str(item) in str(self)


def find_files_python_fallback(
    root: str | Path,
    pattern: str = "*",
    extra_ignored: list[str] | None = None,
    unignore: list[str] | None = None,
    extra_ignored_dirs: list[str] | None = None,
    unignore_dirs: list[str] | None = None,
) -> Iterator[Path]:
    """Pure-Python fallback for fast file traversal with directory pruning."""
    if extra_ignored_dirs is not None:
        extra_ignored = extra_ignored_dirs
    if unignore_dirs is not None:
        unignore = unignore_dirs

    root_path = Path(root).resolve()
    if not root_path.exists():
        return

    spec = get_gitignore_spec(root_path)

    effective_ignored = set(ALWAYS_IGNORED_DIRS)
    if unignore:
        effective_ignored -= set(unignore)
    if extra_ignored:
        effective_ignored |= set(extra_ignored)

    for current_root, dirs, files in os.walk(root_path):
        current_path = Path(current_root)
        dirs[:] = [
            d for d in dirs if not is_ignored(current_path / d, root_path, spec, effective_ignored=effective_ignored)
        ]

        for filename in files:
            path = current_path / filename
            if is_ignored(path, root_path, spec, effective_ignored=effective_ignored):
                continue
            if fnmatch.fnmatch(path.name, pattern):
                yield UniversalPath(path)


def _find_files_python(
    root: str | Path,
    pattern: str = "*",
    extra_ignored: list[str] | None = None,
    unignore: list[str] | None = None,
    extra_ignored_dirs: list[str] | None = None,
    unignore_dirs: list[str] | None = None,
) -> Iterator[str]:
    """Helper returning string paths for Python fallback traversal."""
    for p in find_files_python_fallback(
        root,
        pattern=pattern,
        extra_ignored=extra_ignored,
        unignore=unignore,
        extra_ignored_dirs=extra_ignored_dirs,
        unignore_dirs=unignore_dirs,
    ):
        yield str(p)


def find_files(
    root: str | Path,
    pattern: str = "*",
    extra_ignored: list[str] | None = None,
    unignore: list[str] | None = None,
    *,
    extra_ignored_dirs: list[str] | None = None,
    unignore_dirs: list[str] | None = None,
) -> Iterator[Path]:
    if extra_ignored_dirs is not None:
        extra_ignored = extra_ignored_dirs
    if unignore_dirs is not None:
        unignore = unignore_dirs

    root_path = Path(root).resolve()
    if not root_path.exists():
        return

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
                results = eva_fastwalk.fast_find_files(
                    str(root_path),
                    pattern,
                    extra_ignored=extra_ignored,
                    unignore=unignore,
                )
            except TypeError:
                results = eva_fastwalk.fast_find_files(str(root_path), pattern)
            for r in results:
                yield UniversalPath(r)
            return
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Rust fast_find_files error, falling back to Python: %s", exc)

    yield from find_files_python_fallback(
        root_path,
        pattern,
        extra_ignored=extra_ignored,
        unignore=unignore,
    )
