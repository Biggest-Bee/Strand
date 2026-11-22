//! Tests for the manifest dependency scanner (`manifests::scan_manifests`).

use std::fs;
use std::path::Path;

use strand_core::EdgeKind;
use strand_import::manifests::scan_manifests;

fn w(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

fn deps_of(out: &strand_import::scan::ScanOutput, manifest: &str) -> Vec<String> {
    let mut v: Vec<String> = out
        .edges
        .iter()
        .filter(|(s, _, _, _)| s == manifest)
        .map(|(_, d, _, _)| d.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn requirements_txt() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "requirements.txt",
        "# comment\nrequests==2.31.0\nFlask[async] >= 2.0 ; python_version >= '3.8'\n\
         -r extra.txt\n--index-url https://example.com\nurllib3 @ https://x/y.whl\n",
    );
    w(root, "extra.txt", "click>=8\n");
    let out = scan_manifests(root).unwrap();
    assert_eq!(
        deps_of(&out, "requirements.txt"),
        vec!["click", "flask", "requests", "urllib3"]
    );
    assert!(out.nodes.contains(&"requests".to_string()));
    assert!(out
        .edges
        .iter()
        .all(|(_, _, _, k)| *k == EdgeKind::Declared));
}

#[test]
fn requirements_subdir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "requirements/dev.txt", "pytest\nruff\n");
    let out = scan_manifests(root).unwrap();
    assert_eq!(deps_of(&out, "requirements/dev.txt"), vec!["pytest", "ruff"]);
}

#[test]
fn pyproject_pep621_and_poetry() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "pyproject.toml",
        r#"
[project]
name = "x"
dependencies = ["requests>=2", "django"]

[project.optional-dependencies]
dev = ["pytest", "ruff"]

[dependency-groups]
lint = ["mypy"]

[tool.poetry.dependencies]
python = "^3.11"
redis = "^5"
"#,
    );
    let out = scan_manifests(root).unwrap();
    assert_eq!(
        deps_of(&out, "pyproject.toml"),
        vec!["django", "mypy", "pytest", "redis", "requests", "ruff"]
    );
}

#[test]
fn pipfile_and_setup_cfg() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "Pipfile",
        "[packages]\nrequests = \"*\"\n[dev-packages]\npytest = \"*\"\n",
    );
    w(
        root,
        "setup.cfg",
        "[metadata]\nname = x\n\n[options]\ninstall_requires =\n    requests>=2,\n    click\n\n[options.extras_require]\ndev = pytest\n",
    );
    let out = scan_manifests(root).unwrap();
    assert_eq!(deps_of(&out, "Pipfile"), vec!["pytest", "requests"]);
    assert_eq!(deps_of(&out, "setup.cfg"), vec!["click", "requests"]);
}

#[test]
fn conda_environment_yml() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "environment.yml",
        r#"
name: env
dependencies:
  - python=3.11
  - numpy>=1.26
  - conda-forge::pandas=2.0
  - pip:
    - requests==2.31
    - git+https://github.com/x/y.git#egg=ygit
  - django>=4
"#,
    );
    let out = scan_manifests(root).unwrap();
    assert_eq!(
        deps_of(&out, "environment.yml"),
        vec!["django", "numpy", "pandas", "requests", "ygit"]
    );
}

#[test]
fn package_json() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "package.json",
        r#"{"name":"app","dependencies":{"react":"^18","lodash":"4"},
"devDependencies":{"vitest":"^1"},"peerDependencies":{"typescript":">=5"}}"#,
    );
    let out = scan_manifests(root).unwrap();
    assert_eq!(
        deps_of(&out, "package.json"),
        vec!["lodash", "react", "typescript", "vitest"]
    );
}

#[test]
fn cargo_toml_all_dep_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "Cargo.toml",
        r#"
[package]
name = "proj"

[dependencies]
serde = "1"
local = { path = "../local", package = "real-name" }

[dev-dependencies]
criterion = "0.5"

[target.'cfg(unix)'.dependencies]
nix = "0.27"
"#,
    );
    let out = scan_manifests(root).unwrap();
    assert_eq!(
        deps_of(&out, "Cargo.toml"),
        vec!["criterion", "nix", "real-name", "serde"]
    );
}

#[test]
fn scan_project_includes_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "a.py", "import os\n");
    w(root, "requirements.txt", "requests\n");
    let out =
        strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Python]).unwrap();
    assert!(out.edges.iter().any(|(s, d, _, _)| {
        s == "requirements.txt" && d == "requests"
    }));
}
