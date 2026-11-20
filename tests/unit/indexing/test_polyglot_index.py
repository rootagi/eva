from pathlib import Path

from eva.indexing.repo_index import (
    DependencyGraph,
    extract_polyglot_imports,
    init_context_md,
    normalize_repo_imports,
)


def test_extract_polyglot_imports_typescript():
    """Verify ES import and CommonJS require extraction from TypeScript / JavaScript."""
    content = """
    import React from 'react';
    import { helper } from './utils/helper';
    const config = require('./config.json');
    import type { MyType } from './types';
    """
    imports = extract_polyglot_imports("app.ts", content)
    assert "./utils/helper" in imports
    assert "./config.json" in imports
    assert "react" in imports


def test_extract_polyglot_imports_go():
    """Verify single and block import extraction from Go."""
    content = """
    package main

    import "fmt"
    import (
        "os"
        "github.com/gin-gonic/gin"
        "myrepo/internal/service"
    )
    """
    imports = extract_polyglot_imports("main.go", content)
    assert "fmt" in imports
    assert "os" in imports
    assert "myrepo/internal/service" in imports
    assert "github.com/gin-gonic/gin" in imports


def test_extract_polyglot_imports_rust():
    """Verify use and mod statement extraction from Rust."""
    content = """
    use std::io::Result;
    use crate::parser::parse_tokens;
    mod submod;
    """
    imports = extract_polyglot_imports("lib.rs", content)
    assert any("parser" in imp for imp in imports)
    assert "submod" in imports


def test_normalize_repo_imports(tmp_path: Path):
    """Verify normalize_repo_imports resolves internal dependencies and drops external ones."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "index.ts").write_text("// entry", encoding="utf-8")
    (root / "src" / "util.ts").write_text("// util", encoding="utf-8")

    raw = ["./util", "react", "lodash"]
    normalized = normalize_repo_imports(root, "src/index.ts", raw)
    assert "src/util.ts" in normalized
    assert "react" not in normalized


def test_dependency_graph():
    """Verify DependencyGraph nodes, edges, and summary generation."""
    graph = DependencyGraph()
    graph.add_node("a.py")
    graph.add_node("b.py")
    graph.add_edge("a.py", "b.py")

    assert "a.py" in graph.nodes
    assert "b.py" in graph.nodes
    assert "b.py" in graph.edges.get("a.py", set())

    summary = graph.to_summary_string()
    assert isinstance(summary, str)


def test_init_context_md(tmp_path: Path):
    """Verify init_context_md generates .eva/context.md and --force overwrites."""
    repo = tmp_path / "my_project"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")

    out_file = init_context_md(repo)
    assert out_file.exists()
    assert out_file.name == "context.md"

    original_text = out_file.read_text(encoding="utf-8")
    assert "Project Context" in original_text

    # Without force, does not overwrite modified
    out_file.write_text("custom user notes", encoding="utf-8")
    init_context_md(repo, force=False)
    assert out_file.read_text(encoding="utf-8") == "custom user notes"

    # With force=True, overwrites
    init_context_md(repo, force=True)
    assert "Project Context" in out_file.read_text(encoding="utf-8")
