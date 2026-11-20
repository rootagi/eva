use glob::Pattern;
use ignore::WalkBuilder;
use pyo3::prelude::*;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

pub const ALWAYS_IGNORED_DIRS: &[&str] = &[
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
];

pub fn build_effective_ignored_dirs(
    extra_ignored: Option<Vec<String>>,
    unignore: Option<Vec<String>>,
) -> HashSet<String> {
    let mut set: HashSet<String> = ALWAYS_IGNORED_DIRS.iter().map(|&s| s.to_string()).collect();
    if let Some(unignore_list) = unignore {
        for u in unignore_list {
            set.remove(&u);
        }
    }
    if let Some(extra_list) = extra_ignored {
        for e in extra_list {
            set.insert(e);
        }
    }
    set
}

pub fn find_files_impl(
    root: &str,
    pattern: &str,
    extra_ignored: Option<Vec<String>>,
    unignore: Option<Vec<String>>,
) -> Result<Vec<String>, String> {
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Ok(Vec::new());
    }

    let glob_pat = Pattern::new(pattern).map_err(|e| format!("Invalid glob pattern: {}", e))?;

    let ignored_set = Arc::new(build_effective_ignored_dirs(extra_ignored, unignore));
    let filter_set = Arc::clone(&ignored_set);

    let walker = WalkBuilder::new(root_path)
        .standard_filters(true)
        .hidden(false)
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                if let Some(file_name) = entry.file_name().to_str() {
                    if filter_set.contains(file_name) {
                        return false;
                    }
                }
            }
            true
        })
        .build();

    let mut results = Vec::new();
    for result in walker {
        match result {
            Ok(entry) => {
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

pub fn generate_tree_impl(
    root: &str,
    extra_ignored: Option<Vec<String>>,
    unignore: Option<Vec<String>>,
) -> Result<String, String> {
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

    let ignored_set = Arc::new(build_effective_ignored_dirs(extra_ignored, unignore));

    fn build_subtree(
        dir_path: &Path,
        root_path: &Path,
        prefix: &str,
        ignored_set: &Arc<HashSet<String>>,
        output: &mut String,
    ) {
        let mut entries = Vec::new();
        let filter_set = Arc::clone(ignored_set);
        let walker = WalkBuilder::new(dir_path)
            .max_depth(Some(1))
            .standard_filters(true)
            .hidden(false)
            .filter_entry(move |entry| {
                if entry.depth() == 0 {
                    return true;
                }
                if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                    if let Some(file_name) = entry.file_name().to_str() {
                        if filter_set.contains(file_name) {
                            return false;
                        }
                    }
                }
                true
            })
            .build();

        for result in walker {
            if let Ok(entry) = result {
                if entry.path() != dir_path {
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
                    ignored_set,
                    output,
                );
            }
        }
    }

    build_subtree(root_path, root_path, "", &ignored_set, &mut tree_output);
    Ok(tree_output)
}

/// Fast gitignore-aware file walker in Rust using ripgrep's `ignore` crate.
#[pyfunction]
#[pyo3(signature = (root, pattern, extra_ignored=None, unignore=None))]
fn fast_find_files(
    root: &str,
    pattern: &str,
    extra_ignored: Option<Vec<String>>,
    unignore: Option<Vec<String>>,
) -> PyResult<Vec<String>> {
    find_files_impl(root, pattern, extra_ignored, unignore)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

/// Fast gitignore-aware directory tree generator in Rust.
#[pyfunction]
#[pyo3(signature = (root, extra_ignored=None, unignore=None))]
fn fast_generate_tree(
    root: &str,
    extra_ignored: Option<Vec<String>>,
    unignore: Option<Vec<String>>,
) -> PyResult<String> {
    generate_tree_impl(root, extra_ignored, unignore)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
}

#[pymodule]
fn eva_fastwalk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(fast_find_files, m)?)?;
    m.add_function(wrap_pyfunction!(fast_generate_tree, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    struct TempTestDir {
        path: PathBuf,
    }

    impl TempTestDir {
        fn new(prefix: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "eva_test_{}_{}_{}",
                prefix,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn create_file(&self, rel: &str, content: &[u8]) {
            let full_path = self.path.join(rel);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let mut f = File::create(&full_path).unwrap();
            f.write_all(content).unwrap();
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_effective_ignored_defaults() {
        let set = build_effective_ignored_dirs(None, None);
        assert!(set.contains(".git"));
        assert!(set.contains("node_modules"));
        assert!(set.contains("target"));
        assert!(set.contains(".venv"));
        assert!(set.contains(".eva"));
    }

    #[test]
    fn test_effective_ignored_unignore() {
        let set = build_effective_ignored_dirs(
            None,
            Some(vec!["target".to_string(), "node_modules".to_string()]),
        );
        assert!(!set.contains("target"));
        assert!(!set.contains("node_modules"));
        assert!(set.contains(".git"));
    }

    #[test]
    fn test_effective_ignored_extra() {
        let set = build_effective_ignored_dirs(Some(vec!["custom_dir".to_string()]), None);
        assert!(set.contains("custom_dir"));
        assert!(set.contains(".git"));
    }

    #[test]
    fn test_find_files_pruning() {
        let temp = TempTestDir::new("prune");
        temp.create_file("src/main.rs", b"fn main() {}");
        temp.create_file(".git/config", b"[core]");
        temp.create_file("node_modules/pkg/index.js", b"console.log()");
        temp.create_file("target/debug/app", b"binary");

        let files = find_files_impl(temp.path.to_str().unwrap(), "*", None, None).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("src/main.rs") || files[0].ends_with("src\\main.rs"));
    }

    #[test]
    fn test_find_files_unignore() {
        let temp = TempTestDir::new("unignore");
        temp.create_file("src/lib.rs", b"");
        temp.create_file("target/output.txt", b"output");
        temp.create_file("node_modules/foo.js", b"");

        let files = find_files_impl(
            temp.path.to_str().unwrap(),
            "*",
            None,
            Some(vec!["target".to_string()]),
        )
        .unwrap();

        assert_eq!(files.len(), 2);
        let found_names: Vec<String> = files
            .iter()
            .map(|f| Path::new(f).file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(found_names.contains(&"lib.rs".to_string()));
        assert!(found_names.contains(&"output.txt".to_string()));
    }

    #[test]
    fn test_find_files_extra_ignored() {
        let temp = TempTestDir::new("extra");
        temp.create_file("src/main.rs", b"");
        temp.create_file("docs/guide.md", b"");

        let files = find_files_impl(
            temp.path.to_str().unwrap(),
            "*",
            Some(vec!["docs".to_string()]),
            None,
        )
        .unwrap();

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("main.rs"));
    }

    #[test]
    fn test_find_files_pattern() {
        let temp = TempTestDir::new("pattern");
        temp.create_file("a.py", b"");
        temp.create_file("b.rs", b"");

        let files = find_files_impl(temp.path.to_str().unwrap(), "*.py", None, None).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("a.py"));
    }

    #[test]
    fn test_find_files_invalid_pattern() {
        let res = find_files_impl(".", "[invalid", None, None);
        assert!(res.is_err());
    }

    #[test]
    fn test_generate_tree_pruning_and_unignore() {
        let temp = TempTestDir::new("tree");
        temp.create_file("src/main.rs", b"");
        temp.create_file("target/build.log", b"");
        temp.create_file("node_modules/pkg/a.js", b"");

        let tree_default = generate_tree_impl(temp.path.to_str().unwrap(), None, None).unwrap();
        assert!(tree_default.contains("src"));
        assert!(tree_default.contains("main.rs"));
        assert!(!tree_default.contains("target"));
        assert!(!tree_default.contains("node_modules"));

        let tree_unignored = generate_tree_impl(
            temp.path.to_str().unwrap(),
            None,
            Some(vec!["target".to_string()]),
        )
        .unwrap();
        assert!(tree_unignored.contains("target"));
        assert!(tree_unignored.contains("build.log"));
        assert!(!tree_unignored.contains("node_modules"));
    }
}
