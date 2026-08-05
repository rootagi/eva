import fnmatch
import logging
import os
from collections.abc import Iterator
from pathlib import Path

from eva.workspace.gitignore import get_gitignore_spec, is_ignored

logger = logging.getLogger(__name__)

try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


def find_files(root: str | Path, pattern: str) -> Iterator[Path]:
    root_path = Path(root).resolve()

    if HAS_RUST:
        try:
            results = eva_fastwalk.fast_find_files(str(root_path), pattern)
            for r in results:
                yield Path(r)
            return
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Rust fast_find_files error, falling back to Python: %s", exc)

    spec = get_gitignore_spec(root_path)

    for current_root, dirs, files in os.walk(root_path):
        current_path = Path(current_root)
        dirs[:] = [d for d in dirs if not is_ignored(current_path / d, root_path, spec)]

        for filename in files:
            path = current_path / filename
            if is_ignored(path, root_path, spec):
                continue
            if fnmatch.fnmatch(path.name, pattern):
                yield path
