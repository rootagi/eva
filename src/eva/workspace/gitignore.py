from pathlib import Path

import pathspec

ALWAYS_IGNORED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".next",
    "target",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def get_gitignore_spec(root_dir: Path) -> pathspec.PathSpec | None:
    gitignore_path = root_dir / ".gitignore"
    if not gitignore_path.exists():
        return None

    with open(gitignore_path, "r") as f:
        spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, f.readlines())
    return spec


def is_ignored(path: Path, root_dir: Path, spec: pathspec.PathSpec | None) -> bool:
    try:
        rel_path = path.relative_to(root_dir)
        if any(part in ALWAYS_IGNORED_DIRS for part in rel_path.parts):
            return True

        if spec is None:
            return False

        rel = rel_path.as_posix()
        if path.is_dir() and not rel.endswith("/"):
            rel += "/"
        return spec.match_file(rel)
    except ValueError:
        return False
