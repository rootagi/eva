use glob::Pattern;
use ignore::WalkBuilder;
use pyo3::prelude::*;
use std::path::Path;

const ALWAYS_IGNORED_DIRS: &[&str] = &[
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
];

/// Fast gitignore-aware file walker in Rust using ripgrep's `ignore` crate.
#[pyfunction]
fn fast_find_files(root: &str, pattern: &str) -> PyResult<Vec<String>> {
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Ok(Vec::new());
    }

    let glob_pat = Pattern::new(pattern).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid glob pattern: {}", e))
    })?;

    let mut results = Vec::new();
    let walker = WalkBuilder::new(root_path)
        .standard_filters(true)
        .hidden(false)
        .build();

    for result in walker {
        match result {
            Ok(entry) => {
                if let Some(file_name) = entry.file_name().to_str() {
                    if ALWAYS_IGNORED_DIRS.contains(&file_name) {
                        continue;
                    }
                }
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let file_name = entry.file_name().to_string_lossy();
                    if glob_pat.matches(&file_name) {
                        results.push(entry.path().to_string_lossy().into_owned());
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Ok(results)
}

/// Fast gitignore-aware directory tree generator in Rust.
#[pyfunction]
fn fast_generate_tree(root: &str) -> PyResult<String> {
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Ok(format!("Path {} does not exist\n", root));
    }

    if root_path.is_file() {
        return Ok(format!(
            "{}\n",
            root_path.file_name().unwrap_or_default().to_string_lossy()
        ));
    }

    let mut tree_output = format!(
        "{}/\n",
        root_path.file_name().unwrap_or_default().to_string_lossy()
    );

    fn build_subtree(dir_path: &Path, root_path: &Path, prefix: &str, output: &mut String) {
        let mut entries = Vec::new();
        let walker = WalkBuilder::new(dir_path)
            .max_depth(Some(1))
            .standard_filters(true)
            .hidden(false)
            .build();

        for result in walker {
            if let Ok(entry) = result {
                if entry.path() != dir_path {
                    if let Some(file_name) = entry.file_name().to_str() {
                        if ALWAYS_IGNORED_DIRS.contains(&file_name) {
                            continue;
                        }
                    }
                    entries.push(entry);
                }
            }
        }

        entries.sort_by(|a, b| {
            let a_is_file = a.file_type().map_or(false, |ft| ft.is_file());
            let b_is_file = b.file_type().map_or(false, |ft| ft.is_file());
            (a_is_file, a.file_name()).cmp(&(b_is_file, b.file_name()))
        });

        let len = entries.len();
        for (i, entry) in entries.iter().enumerate() {
            let is_last = i == len - 1;
            let connector = if is_last { "└── " } else { "├── " };
            let name = entry.file_name().to_string_lossy();

            output.push_str(&format!("{}{}{}\n", prefix, connector, name));

            if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                let extension = if is_last { "    " } else { "│   " };
                build_subtree(
                    entry.path(),
                    root_path,
                    &format!("{}{}", prefix, extension),
                    output,
                );
            }
        }
    }

    build_subtree(root_path, root_path, "", &mut tree_output);
    Ok(tree_output)
}

#[pymodule]
fn eva_fastwalk(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(fast_find_files, m)?)?;
    m.add_function(wrap_pyfunction!(fast_generate_tree, m)?)?;
    Ok(())
}
