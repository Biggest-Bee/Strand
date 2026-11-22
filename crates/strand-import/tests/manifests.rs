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
        // `requests==2.31.0` pins to a versioned node id.
        vec!["click", "flask", "requests@2.31.0", "urllib3"]
    );
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

#[test]
fn composer_json_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("composer.json"),
        r#"{"require": {"php": ">=8.1", "laravel/framework": "^10.0"},
            "require-dev": {"phpunit/phpunit": "^10.0"}}"#,
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"laravel/framework"));
    assert!(deps.contains(&"phpunit/phpunit"));
    assert!(!deps.contains(&"php"));
}

#[test]
fn gemfile_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Gemfile"),
        "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem \"devise\"\n",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"rails"));
    assert!(deps.contains(&"devise"));
    assert_eq!(deps.len(), 2);
}

#[test]
fn pubspec_yaml_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("pubspec.yaml"),
        "name: my_app\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.2.0\ndev_dependencies:\n  test: ^1.24.0\n",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"http"));
    assert!(deps.contains(&"test"));
    assert!(deps.contains(&"flutter"));
}

#[test]
fn podfile_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Podfile"),
        "target 'App' do\n  pod 'Alamofire', '~> 5.9'\n  pod(\"DeviceKit\")\nend\n",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"Alamofire"));
    assert!(deps.contains(&"DeviceKit"));
}

#[test]
fn package_swift_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Package.swift"),
        "dependencies: [\n  .package(url: \"https://github.com/Alamofire/Alamofire.git\", from: \"5.9.0\"),\n  .package(path: \"../local\"),\n]\n",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert_eq!(deps, vec!["Alamofire"]);
}

#[test]
fn csproj_and_props_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("App.csproj"),
        "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" /></ItemGroup></Project>",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    assert!(out.edges.iter().any(|e| e.1 == "Newtonsoft.Json"));
}

#[test]
fn gradle_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("build.gradle.kts"),
        "dependencies {\n  implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")\n  testImplementation 'junit:junit:4.13.2'\n}\n",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"com.squareup.okhttp3:okhttp"));
    assert!(deps.contains(&"junit:junit"));
}

#[test]
fn workflow_and_dockerfile_deps() {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github").join("workflows");
    std::fs::create_dir_all(&wf).unwrap();
    std::fs::write(
        wf.join("ci.yml"),
        "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/local\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("Dockerfile"),
        "FROM python:3.12-slim AS base\nFROM scratch\n",
    )
    .unwrap();
    let out = strand_import::manifests::scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"actions/checkout@v4"));
    assert!(!deps.contains(&"./.github/actions/local"));
    assert!(deps.contains(&"python:3.12-slim"));
    assert!(!deps.contains(&"scratch"));
}

#[test]
fn deno_json_imports() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("deno.jsonc"),
        "{\n  // comment\n  \"imports\": {\n    \"lodash\": \"npm:lodash@4.17.21\",\n    \"fresh\": \"https://deno.land/x/fresh@1.6.8/mod.ts\",\n    \"local\": \"./src/local.ts\",\n  },\n}\n",
    )
    .unwrap();
    let out = scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"npm:lodash@4.17.21"));
    assert!(deps.contains(&"https://deno.land/x/fresh@1.6.8/mod.ts"));
    assert!(!deps.iter().any(|d| d.contains("local.ts")));
}

#[test]
fn cargo_workspace_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"a\"]\n[workspace.dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\nanyhow = \"1\"\n",
    )
    .unwrap();
    let out = scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"serde"));
    assert!(deps.contains(&"anyhow"));
}

#[test]
fn requirements_pins_emit_versioned_nodes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("requirements.txt"),
        "requests==2.31.0\nflask>=2.0\nurllib3===1.26.*\nclick\n",
    )
    .unwrap();
    let out = scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"requests@2.31.0"));
    assert!(deps.contains(&"urllib3@1.26"));
    assert!(deps.contains(&"flask")); // range spec stays bare
    assert!(deps.contains(&"click"));
}

#[test]
fn brewfile_and_compose_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Brewfile"),
        "brew 'postgresql@15'\ncask \"docker\"\n# brew 'commented'\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("compose.yaml"),
        "services:\n  db:\n    image: postgres:16\n  web:\n    build: .\n",
    )
    .unwrap();
    let out = scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"postgresql@15"));
    assert!(deps.contains(&"docker"));
    assert!(deps.contains(&"postgres:16"));
    assert!(!deps.iter().any(|d| d.contains("commented")));
}

#[test]
fn packages_config_and_paket() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("packages.config"),
        "<?xml version=\"1.0\"?><packages><package id=\"Newtonsoft.Json\" version=\"13.0.3\" /></packages>",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("paket.dependencies"),
        "nuget Newtonsoft.Json\ngithub \"akka/akka\"\n",
    )
    .unwrap();
    let out = scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"Newtonsoft.Json"));
    assert!(deps.contains(&"akka/akka"));
}

#[test]
fn version_catalog_and_setup_py() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("libs.versions.toml"),
        "[versions]\nokhttp = \"4.12.0\"\n[libraries]\nokhttp = { module = \"com.squareup.okhttp3:okhttp\", version.ref = \"okhttp\" }\njunit = \"junit:junit:4.13.2\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("setup.py"),
        "from setuptools import setup\nsetup(name='x', install_requires=['requests>=2', \"flask==3.0\"], python_requires='>=3.9')\n",
    )
    .unwrap();
    let out = scan_manifests(dir.path()).unwrap();
    let deps: Vec<&str> = out.edges.iter().map(|e| e.1.as_str()).collect();
    assert!(deps.contains(&"com.squareup.okhttp3:okhttp"));
    assert!(deps.contains(&"junit:junit"));
    assert!(deps.contains(&"requests"));
    assert!(deps.contains(&"flask@3.0")); // setup.py uses same pin path? no - check
    assert!(!deps.contains(&"python"));
}
