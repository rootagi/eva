import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from eva.workspace.gitignore import get_gitignore_spec, is_ignored

logger = logging.getLogger(__name__)


@dataclass
class ProjectStack:
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    ci_configs: list[str] = field(default_factory=list)
    test_frameworks: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    def to_summary_string(self) -> str:
        lines = []
        if self.languages:
            lines.append(f"Languages: {', '.join(self.languages)}")
        if self.frameworks:
            lines.append(f"Frameworks: {', '.join(self.frameworks)}")
        if self.package_managers:
            lines.append(f"Package Managers: {', '.join(self.package_managers)}")
        if self.test_frameworks:
            lines.append(f"Test Frameworks: {', '.join(self.test_frameworks)}")
        if self.ci_configs:
            lines.append(f"CI Configs: {', '.join(self.ci_configs)}")
        if self.dependencies:
            top_deps = self.dependencies[:15]
            lines.append(f"Key Dependencies ({len(self.dependencies)} total): {', '.join(top_deps)}")
        return "\n".join(lines) if lines else "No clear stack detected."


@dataclass
class DependencyGraph:
    nodes: dict[str, list[str]] = field(default_factory=dict)

    def add_node(self, node: str) -> None:
        if node not in self.nodes:
            self.nodes[node] = []

    def add_edge(self, source: str, target: str) -> None:
        self.add_node(source)
        self.add_node(target)
        if target not in self.nodes[source]:
            self.nodes[source].append(target)

    @property
    def edges(self) -> dict[str, list[str]]:
        return self.nodes

    def to_summary_string(self) -> str:
        if not self.nodes:
            return "Empty dependency graph."
        lines = ["Module Import Graph:"]
        for mod, imports in sorted(self.nodes.items()):
            if imports:
                lines.append(f"  {mod} -> {', '.join(sorted(set(imports)))}")
            else:
                lines.append(f"  {mod} (no local imports)")
        return "\n".join(lines)


# Backwards compatibility alias
DepGraph = DependencyGraph


def detect_stack(root_dir: str | Path) -> ProjectStack:
    root = Path(root_dir).resolve()
    stack = ProjectStack()

    if not root.is_dir():
        return stack

    # Detect CI configs
    github_workflows = root / ".github" / "workflows"
    if github_workflows.is_dir() and any(github_workflows.glob("*.y*ml")):
        stack.ci_configs.append("GitHub Actions")
    if (root / ".gitlab-ci.yml").exists():
        stack.ci_configs.append("GitLab CI")
    if (root / ".circleci").is_dir():
        stack.ci_configs.append("CircleCI")
    if (root / "Jenkinsfile").exists():
        stack.ci_configs.append("Jenkins")

    # Python stack detection
    pyproject = root / "pyproject.toml"
    reqs = root / "requirements.txt"
    setup_py = root / "setup.py"
    pipfile = root / "Pipfile"

    has_python = pyproject.exists() or reqs.exists() or setup_py.exists() or pipfile.exists()
    if not has_python and list(root.glob("*.py")):
        has_python = True

    if has_python:
        stack.languages.append("Python")
        if (root / "uv.lock").exists():
            stack.package_managers.append("uv")
        elif (root / "poetry.lock").exists():
            stack.package_managers.append("poetry")
        elif (root / "Pipfile.lock").exists():
            stack.package_managers.append("pipenv")
        else:
            stack.package_managers.append("pip")

        # Parse dependencies & frameworks
        deps: set[str] = set()
        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    clean = line.strip().strip('"').strip("'").lower()
                    for pkg in [
                        "django",
                        "flask",
                        "fastapi",
                        "pytest",
                        "torch",
                        "tensorflow",
                        "pydantic",
                        "typer",
                        "rich",
                        "ruff",
                    ]:
                        if pkg in clean:
                            deps.add(pkg)
            except OSError as exc:
                logger.debug("Failed to parse %s: %s", pyproject, exc)

        if reqs.exists():
            try:
                content = reqs.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip().lower()
                    if pkg and not pkg.startswith("#"):
                        deps.add(pkg)
            except OSError as exc:
                logger.debug("Failed to parse %s: %s", reqs, exc)

        for dep in deps:
            stack.dependencies.append(dep)
            if dep in {"django", "flask", "fastapi", "streamlit"} and dep.capitalize() not in stack.frameworks:
                stack.frameworks.append(dep.capitalize())
            if dep in {"pytest", "unittest"} and dep not in stack.test_frameworks:
                stack.test_frameworks.append(dep)

        if "pytest" not in stack.test_frameworks and ((root / "conftest.py").exists() or (root / "tests").is_dir()):
            stack.test_frameworks.append("pytest")

    # Node.js stack detection
    pkg_json = root / "package.json"
    if pkg_json.exists():
        stack.languages.append("JavaScript/TypeScript")
        if (root / "pnpm-lock.yaml").exists():
            stack.package_managers.append("pnpm")
        elif (root / "yarn.lock").exists():
            stack.package_managers.append("yarn")
        else:
            stack.package_managers.append("npm")

        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for dep in all_deps:
                stack.dependencies.append(dep)
                if dep in {"react", "next", "vue", "express", "angular"}:
                    stack.frameworks.append(dep)
                if dep in {"jest", "vitest", "mocha", "cypress"}:
                    stack.test_frameworks.append(dep)
        except (OSError, ValueError) as exc:
            logger.debug("Failed to parse %s: %s", pkg_json, exc)

    # Rust stack detection
    cargo_toml = root / "Cargo.toml"
    if cargo_toml.exists():
        stack.languages.append("Rust")
        stack.package_managers.append("cargo")
        stack.test_frameworks.append("cargo test")

    # Go stack detection
    go_mod = root / "go.mod"
    if go_mod.exists():
        stack.languages.append("Go")
        stack.package_managers.append("go modules")
        stack.test_frameworks.append("go test")

    return stack


def build_dep_graph(root_dir: str | Path) -> DepGraph:
    """Build a lightweight module-level import dependency graph for Python projects."""
    root = Path(root_dir).resolve()
    graph = DepGraph()

    if not root.is_dir():
        return graph

    spec = get_gitignore_spec(root)
    py_files = []

    for current_root, dirs, files in os.walk(root):
        cpath = Path(current_root)
        dirs[:] = [d for d in dirs if not is_ignored(cpath / d, root, spec)]
        for f in files:
            p = cpath / f
            if p.suffix == ".py" and not is_ignored(p, root, spec):
                py_files.append(p)

    # Collect module names
    module_names: set[str] = set()
    file_map: dict[Path, str] = {}

    for p in py_files:
        try:
            rel = p.relative_to(root)
            mod_parts = list(rel.parts)
            if mod_parts[-1] == "__init__.py":
                mod_parts.pop()
            else:
                mod_parts[-1] = p.stem
            mod_name = ".".join(mod_parts)
            if mod_name:
                module_names.add(mod_name)
                file_map[p] = mod_name
        except ValueError:
            continue

    # Parse imports
    for p, mod_name in file_map.items():
        imports = set()
        try:
            source = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(p))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        base = alias.name.split(".")[0]
                        if any(m.startswith(base) for m in module_names):
                            imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    base = node.module.split(".")[0]
                    if any(m.startswith(base) for m in module_names):
                        imports.add(node.module)
        except SyntaxError:
            pass
        except (OSError, ValueError) as exc:
            logger.debug("Failed parsing imports in %s: %s", p, exc)

        graph.nodes[mod_name] = sorted(imports)

    return graph


def extract_polyglot_imports(filename: str, content: str) -> list[str]:
    """Extract raw module/file import identifiers from polyglot source code (TS/JS, Go, Rust, Python)."""
    imports: list[str] = []
    p = Path(filename)
    ext = p.suffix.lower()

    if ext in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
        # ES imports and exports: import ... from '...' or export ... from '...'
        for match in re.finditer(r"""(?:import|export)\s+(?:[\w*\s{},$]+from\s+)?['"]([^'"]+)['"]""", content):
            imports.append(match.group(1))
        # CommonJS require: require('...')
        for match in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", content):
            imports.append(match.group(1))
        # Dynamic import: import('...')
        for match in re.finditer(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""", content):
            imports.append(match.group(1))

    elif ext == ".go":
        # Multi-line import block: import ( ... )
        for block in re.finditer(r"""import\s*\(\s*([^)]+)\)""", content, re.MULTILINE):
            block_content = block.group(1)
            for imp in re.finditer(r"""['"]([^'"]+)['"]""", block_content):
                imports.append(imp.group(1))
        # Single import: import "..."
        for match in re.finditer(r"""import\s+['"]([^'"]+)['"]""", content):
            imports.append(match.group(1))

    elif ext == ".rs":
        # Rust use: use ...;
        for match in re.finditer(r"""use\s+([^;]+);""", content):
            raw = match.group(1).strip()
            imports.append(raw)
        # Rust mod: mod ...;
        for match in re.finditer(r"""mod\s+([a-zA-Z0-9_]+)\s*;""", content):
            imports.append(match.group(1).strip())

    elif ext == ".py":
        try:
            tree = ast.parse(content, filename=filename)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
        except (SyntaxError, ValueError, OSError):
            for match in re.finditer(
                r"""^\s*(?:from\s+([a-zA-Z0-9_.]+)\s+import|import\s+([a-zA-Z0-9_.,\s]+))""", content, re.MULTILINE
            ):
                mod = match.group(1) or match.group(2)
                if mod:
                    imports.append(mod.strip())

    return sorted(dict.fromkeys(imports))


def normalize_repo_imports(root: str | Path, file_path: str, raw_imports: list[str]) -> list[str]:
    """Filter and normalize raw extracted imports to internal repository paths, excluding external packages."""
    root_path = Path(root).resolve()
    current_dir = (root_path / file_path).parent.resolve()
    internal_deps: list[str] = []

    for raw in raw_imports:
        if raw.startswith("."):
            # Relative import (e.g. ./util, ../service)
            candidate_base = (current_dir / raw).resolve()
            # Try extensions
            resolved_file = None
            if candidate_base.is_file():
                resolved_file = candidate_base
            else:
                for ext in [".ts", ".tsx", ".js", ".jsx", ".d.ts", ".json"]:
                    c = candidate_base.with_suffix(ext)
                    if c.is_file():
                        resolved_file = c
                        break
                if not resolved_file:
                    for idx in ["index.ts", "index.tsx", "index.js", "index.jsx"]:
                        c = candidate_base / idx
                        if c.is_file():
                            resolved_file = c
                            break

            if resolved_file is not None:
                try:
                    rel = resolved_file.relative_to(root_path).as_posix()
                    internal_deps.append(rel)
                    continue
                except ValueError:
                    pass
            elif str(candidate_base).startswith(str(root_path)):
                # Keep normalized relative path inside root
                try:
                    rel = candidate_base.relative_to(root_path).as_posix()
                    internal_deps.append(rel)
                    continue
                except ValueError:
                    pass
        else:
            # Non-relative import: check if it resolves to an internal repo path
            cand = (root_path / raw).resolve()
            if cand.exists() and str(cand).startswith(str(root_path)):
                try:
                    internal_deps.append(cand.relative_to(root_path).as_posix())
                except ValueError:
                    pass

    return sorted(dict.fromkeys(internal_deps))


def init_context_md(root_dir: str | Path, force: bool = False) -> Path:
    """Scaffold .eva/context.md project context file from detected project stack."""
    root = Path(root_dir).resolve()
    eva_dir = root / ".eva"
    eva_dir.mkdir(parents=True, exist_ok=True)
    target = eva_dir / "context.md"

    if target.exists() and not force:
        return target

    stack = detect_stack(root)
    content = f"""# Project Context

## Overview
{root.name}

## Stack
{stack.to_summary_string()}

## Architecture
- Root: {root}
- Languages: {", ".join(stack.languages) if stack.languages else "Unknown"}
- Frameworks: {", ".join(stack.frameworks) if stack.frameworks else "None detected"}
- Key Dependencies: {", ".join(stack.dependencies[:10]) if stack.dependencies else "None detected"}

## Development Notes
- Auto-generated by Eva CLI (`eva context init`).
"""
    target.write_text(content, encoding="utf-8")
    return target
