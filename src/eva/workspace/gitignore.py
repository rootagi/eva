from pathlib import Path

import pathspec

ALWAYS_IGNORED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".env",
    "dist",
    "build",
    ".next",
    "target",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".eva",
}


_effective_ignored_dirs: set[str] = set(ALWAYS_IGNORED_DIRS)
_configured_extra: list[str] = []
_configured_unignore: list[str] = []


def configure_ignored_dirs(extra: list[str], unignore: list[str]) -> None:
    """Set the process-wide always-ignored directory set. Call once at startup."""
    global _effective_ignored_dirs, _configured_extra, _configured_unignore
    _configured_extra = list(extra)
    _configured_unignore = list(unignore)
    base = set(ALWAYS_IGNORED_DIRS) - set(unignore)
    _effective_ignored_dirs = base | set(extra)


def get_ignored_dirs_config() -> tuple[list[str], list[str]]:
    """Return the currently configured (extra_ignored_dirs, unignore_dirs)."""
    return list(_configured_extra), list(_configured_unignore)


def get_gitignore_spec(root_dir: Path) -> pathspec.PathSpec | None:
    gitignore_path = root_dir / ".gitignore"
    if not gitignore_path.exists():
        return None

    with open(gitignore_path, "r") as f:
        spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, f.readlines())
    return spec


def is_ignored(
    path: Path,
    root_dir: Path,
    spec: pathspec.PathSpec | None,
    effective_ignored: set[str] | None = None,
) -> bool:
    try:
        rel_path = path.relative_to(root_dir)
        ignored_dirs = effective_ignored if effective_ignored is not None else _effective_ignored_dirs
        if any(part in ignored_dirs for part in rel_path.parts[:-1]):
            return True
        if path.is_dir() and rel_path.name in ignored_dirs:
            return True

        if spec is None:
            return False

        rel = rel_path.as_posix()
        if path.is_dir() and not rel.endswith("/"):
            rel += "/"
        return spec.match_file(rel)
    except ValueError:
        return False
