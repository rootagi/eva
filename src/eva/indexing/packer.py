"""Repository context packing for plain-text provider requests.

Files are ranked by local Python dependency-graph centrality when available.
Other repositories use a deterministic fallback: shallower paths, smaller files,
then lexicographic path order.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

import pathspec

from eva.indexing.finder import find_files
from eva.indexing.io import ContextReadError, read_text_file_for_context
from eva.indexing.repo_index import build_dep_graph, detect_stack
from eva.indexing.tokenizer import count_tokens, trim_context
from eva.indexing.tree import generate_tree
from eva.workspace.gitignore import get_gitignore_spec, is_ignored

SENSITIVE_FILE_PATTERNS = (
    ".env",
    ".env.*",
    "*.env",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.tfvars",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "credentials.*",
    "secrets.*",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
)


@dataclass
class PackResult:
    included_files: list[str]
    excluded_files: list[tuple[str, str]]
    total_tokens_included: int
    total_files_scanned: int
    packed_context: str


@dataclass
class _PackCandidate:
    relative_path: str
    text: str
    size_bytes: int
    dependency_score: int = 0

    @property
    def section(self) -> str:
        return f"\n\n--- {self.relative_path} ---\n{self.text}"


def _matches_sensitive_denylist(relative_path: str) -> bool:
    filename = Path(relative_path).name.lower()
    return any(fnmatch.fnmatchcase(filename, pattern) for pattern in SENSITIVE_FILE_PATTERNS)


def _module_name(relative_path: str) -> str | None:
    path = Path(relative_path)
    if path.suffix != ".py":
        return None

    parts = list(path.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or None


def _dependency_scores(root: Path) -> dict[str, int]:
    stack = detect_stack(root)
    if "Python" not in stack.languages:
        return {}

    graph = build_dep_graph(root)
    scores = {module_name: 0 for module_name in graph.nodes}
    for module_name, imports in graph.nodes.items():
        scores[module_name] += len(imports)
        for imported_module in imports:
            matching_modules = [
                candidate_module
                for candidate_module in graph.nodes
                if candidate_module == imported_module or candidate_module.startswith(f"{imported_module}.")
            ]
            for candidate_module in matching_modules:
                scores[candidate_module] += 1

    return scores


def _trim_to_budget(text: str, max_tokens: int) -> str:
    if max_tokens <= 0:
        return ""
    if count_tokens(text) <= max_tokens:
        return text

    trimmed = trim_context(text, max_tokens=max_tokens)
    if count_tokens(trimmed) <= max_tokens:
        return trimmed

    low = 0
    high = len(text)
    best = ""
    while low <= high:
        midpoint = (low + high) // 2
        candidate = text[:midpoint]
        if count_tokens(candidate) <= max_tokens:
            best = candidate
            low = midpoint + 1
        else:
            high = midpoint - 1
    return best


def _tree_context(root: Path) -> str:
    return f"# Repository tree\n\n```text\n{generate_tree(root).rstrip()}\n```\n"


def _omission_note(candidates: list[_PackCandidate]) -> str:
    omitted_tokens = sum(count_tokens(candidate.section) for candidate in candidates)
    return (
        "\n\n[Repository packing omitted "
        f"{len(candidates)} files ({omitted_tokens} estimated tokens) because the context budget was exceeded.]\n"
    )


def _candidate_sort_key(candidate: _PackCandidate) -> tuple[int, int, int, str]:
    return (
        -candidate.dependency_score,
        len(Path(candidate.relative_path).parts),
        candidate.size_bytes,
        candidate.relative_path,
    )


def pack_repository(
    root: Path, max_tokens: int, extra_ignore_patterns: list[str] | None = None
) -> PackResult:
    """Pack eligible repository files into a token-bounded plain-text context.

    The directory tree is always placed before file sections. File contents use
    dependency centrality for Python projects, with deterministic path-depth,
    size, and name ordering for all other cases.
    """
    if max_tokens <= 0:
        raise ValueError("max_tokens must be greater than zero")

    root_path = root.resolve()
    if not root_path.is_dir():
        raise ValueError(f"Repository root must be a directory: {root}")

    gitignore_spec = get_gitignore_spec(root_path)
    extra_ignore_spec = (
        pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, extra_ignore_patterns)
        if extra_ignore_patterns
        else None
    )
    excluded_files: list[tuple[str, str]] = []
    candidates: list[_PackCandidate] = []
    total_files_scanned = 0

    for path in sorted(find_files(root_path, "*"), key=lambda item: item.as_posix()):
        if not path.is_file() or is_ignored(path, root_path, gitignore_spec):
            continue

        total_files_scanned += 1
        relative_path = path.relative_to(root_path).as_posix()
        if extra_ignore_spec and extra_ignore_spec.match_file(relative_path):
            excluded_files.append((relative_path, "extra_ignored"))
            continue
        if _matches_sensitive_denylist(relative_path):
            excluded_files.append((relative_path, "denylisted"))
            continue

        try:
            text, _warnings = read_text_file_for_context(path)
        except (ContextReadError, OSError) as exc:
            reason = "binary" if "appears to be binary" in str(exc) else "unreadable"
            excluded_files.append((relative_path, reason))
            continue

        candidates.append(
            _PackCandidate(relative_path=relative_path, text=text, size_bytes=path.stat().st_size)
        )

    dependency_scores = _dependency_scores(root_path)
    for candidate in candidates:
        module_name = _module_name(candidate.relative_path)
        if module_name:
            candidate.dependency_score = dependency_scores.get(module_name, 0)
    candidates.sort(key=_candidate_sort_key)

    tree_context = _tree_context(root_path)
    complete_context = tree_context + "".join(candidate.section for candidate in candidates)
    if count_tokens(complete_context) <= max_tokens:
        return PackResult(
            included_files=[candidate.relative_path for candidate in candidates],
            excluded_files=excluded_files,
            total_tokens_included=count_tokens(complete_context),
            total_files_scanned=total_files_scanned,
            packed_context=complete_context,
        )

    if not candidates:
        packed_context = _trim_to_budget(tree_context, max_tokens)
        return PackResult(
            included_files=[],
            excluded_files=excluded_files,
            total_tokens_included=count_tokens(packed_context),
            total_files_scanned=total_files_scanned,
            packed_context=packed_context,
        )

    budget_excluded = list(candidates)
    included_candidates: list[_PackCandidate] = []
    packed_context = ""
    for _ in range(len(candidates) + 1):
        omission_note = _omission_note(budget_excluded)
        tree_budget = max_tokens - count_tokens(omission_note)
        packed_context = _trim_to_budget(tree_context, tree_budget)
        included_candidates = []
        new_budget_excluded: list[_PackCandidate] = []

        for candidate in candidates:
            candidate_context = packed_context + candidate.section + omission_note
            if count_tokens(candidate_context) <= max_tokens:
                packed_context += candidate.section
                included_candidates.append(candidate)
            else:
                new_budget_excluded.append(candidate)

        if [candidate.relative_path for candidate in new_budget_excluded] == [
            candidate.relative_path for candidate in budget_excluded
        ]:
            budget_excluded = new_budget_excluded
            break
        budget_excluded = new_budget_excluded

    omission_note = _omission_note(budget_excluded)
    packed_context = _trim_to_budget(packed_context + omission_note, max_tokens)
    excluded_files.extend((candidate.relative_path, "budget_exceeded") for candidate in budget_excluded)

    return PackResult(
        included_files=[candidate.relative_path for candidate in included_candidates],
        excluded_files=excluded_files,
        total_tokens_included=count_tokens(packed_context),
        total_files_scanned=total_files_scanned,
        packed_context=packed_context,
    )
