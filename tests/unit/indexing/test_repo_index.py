from eva.indexing.repo_index import build_dep_graph, detect_stack


def test_detect_stack_python_repo(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
dependencies = [
    "fastapi>=0.100.0",
    "pytest>=8.0.0"
]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: CI\n", encoding="utf-8")

    stack = detect_stack(tmp_path)
    assert "Python" in stack.languages
    assert "uv" in stack.package_managers
    assert "Fastapi" in stack.frameworks
    assert "pytest" in stack.test_frameworks
    assert "GitHub Actions" in stack.ci_configs

    summary = stack.to_summary_string()
    assert "Languages: Python" in summary
    assert "Fastapi" in summary


def test_detect_stack_node_repo(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "^18.0.0"}, "devDependencies": {"jest": "^29.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("", encoding="utf-8")

    stack = detect_stack(tmp_path)
    assert "JavaScript/TypeScript" in stack.languages
    assert "pnpm" in stack.package_managers
    assert "react" in stack.frameworks
    assert "jest" in stack.test_frameworks


def test_detect_stack_rust_repo(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "foo"\n', encoding="utf-8")

    stack = detect_stack(tmp_path)
    assert "Rust" in stack.languages
    assert "cargo" in stack.package_managers
    assert "cargo test" in stack.test_frameworks


def test_build_dep_graph_python(tmp_path):
    (tmp_path / "a.py").write_text("import b\nfrom c import foo\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "c.py").write_text("def foo(): pass\n", encoding="utf-8")

    graph = build_dep_graph(tmp_path)
    assert "a" in graph.nodes
    assert "b" in graph.nodes["a"]
    assert "c" in graph.nodes["a"]
    assert graph.nodes["b"] == []

    summary = graph.to_summary_string()
    assert "a -> b, c" in summary
