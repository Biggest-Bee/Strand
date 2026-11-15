//! Tests for the Rust source scanner (`scan::scan_rust`).

use std::fs;
use std::path::Path;

use strand_import::scan::{scan_lang, scan_rust, Lang};

fn w(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

/// Fixture project exercising mod decls, crate::/self::/super:: paths,
/// cross-file `use`, external-crate ignores, and dir skipping.
fn fixture(root: &Path) {
    w(root, "Cargo.toml", "[package]\nname = \"proj\"\nversion = \"0.1.0\"\n");
    w(
        root,
        "src/lib.rs",
        "mod foo;\nmod bar;\npub use foo::X;\n// use fake::Commented;\n",
    );
    w(
        root,
        "src/foo.rs",
        "use crate::bar::Thing;\nuse proj::bar::Thing as T2;\nuse std::io;\npub struct X;\n",
    );
    w(
        root,
        "src/bar/mod.rs",
        "use super::foo::X;\nuse self::inner::Y;\nmod inner;\npub struct Thing;\n",
    );
    w(root, "src/bar/inner.rs", "use crate::foo::X;\npub struct Y;\n");
    // Must be skipped entirely.
    w(root, "target/junk.rs", "use crate::foo::X;\n");
    w(root, "node_modules/dep.rs", "mod nothing;\n");
}

fn edges_of(out: &strand_import::scan::ScanOutput) -> Vec<(String, String)> {
    out.edges
        .iter()
        .map(|(s, d, _)| (s.clone(), d.clone()))
        .collect()
}

#[test]
fn scan_resolves_mod_and_use() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let out = scan_rust(dir.path()).unwrap();
    let edges = edges_of(&out);

    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    // mod declarations.
    assert!(has("src/lib.rs", "src/foo.rs"));
    assert!(has("src/lib.rs", "src/bar/mod.rs"));
    assert!(has("src/bar/mod.rs", "src/bar/inner.rs"));

    // use paths: crate::, self::, super::, workspace-crate name.
    assert!(has("src/foo.rs", "src/bar/mod.rs")); // crate::bar::Thing
    assert!(has("src/foo.rs", "src/bar/mod.rs")); // proj::bar::Thing (dedup below)
    assert!(has("src/bar/mod.rs", "src/foo.rs")); // super::foo::X
    assert!(has("src/bar/mod.rs", "src/bar/inner.rs")); // self::inner::Y
    assert!(has("src/bar/inner.rs", "src/foo.rs")); // crate::foo::X

    // External crates and comments produce no edges.
    assert!(!edges.iter().any(|(_, d)| d.contains("std")));
    assert!(!edges.iter().any(|(s, _)| s.contains("junk") || s.contains("dep")));

    // Every .rs file except skipped dirs is a node.
    assert!(out.nodes.contains(&"src/lib.rs".to_string()));
    assert!(out.nodes.contains(&"src/bar/inner.rs".to_string()));
    assert!(!out.nodes.iter().any(|n| n.contains("target") || n.contains("node_modules")));
}

#[test]
fn scan_dedups_edges() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let out = scan_rust(dir.path()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for (s, d, _) in &out.edges {
        assert!(seen.insert((s.clone(), d.clone())), "dup edge {s} -> {d}");
    }
}

#[test]
fn scan_rust_path_attr_and_include() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/lib.rs", "#[path = \"deep/hidden.rs\"]\nmod secret;\nmod real;\n");
    w(root, "src/deep/hidden.rs", "include!(\"gen/included.rs\");\n");
    w(root, "src/deep/gen/included.rs", "pub fn f() {}\n");
    w(root, "src/real.rs", "pub fn r() {}\n");
    let out = scan_rust(root).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));
    // #[path] resolves mod secret -> deep/hidden.rs (not secret.rs).
    assert!(has("src/lib.rs", "src/deep/hidden.rs"));
    // include! resolves relative to the including file's dir.
    assert!(has("src/deep/hidden.rs", "src/deep/gen/included.rs"));
    assert!(has("src/lib.rs", "src/real.rs"));
    // hidden.rs is a node even though nothing mod-declares it by name.
    assert!(out.nodes.contains(&"src/deep/hidden.rs".to_string()));
}

#[test]
fn scan_python_imports() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/mod.py", "import os\nimport pkg.util\nfrom . import helper\nfrom .util import thing\nfrom ..other import x\n");
    w(root, "pkg/util.py", "def thing(): pass\n");
    w(root, "pkg/helper.py", "");
    w(root, "other.py", "");
    w(root, "top.py", "from pkg import mod\nimport pkg.util as u\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("pkg/mod.py", "pkg/util.py")); // import pkg.util
    assert!(has("pkg/mod.py", "pkg/helper.py")); // from . import helper
    assert!(has("pkg/mod.py", "pkg/util.py")); // from .util import thing
    assert!(has("pkg/mod.py", "other.py")); // from ..other import x
    assert!(has("top.py", "pkg/mod.py")); // from pkg import mod (submodule)
    assert!(has("top.py", "pkg/util.py")); // import pkg.util
    // stdlib `os` produces no edge.
    assert!(!edges.iter().any(|(_, d)| d.contains("os")));
}

#[test]
fn scan_js_imports() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/index.ts", "import { a } from './a';\nimport './side';\nconst r = require('./b');\nexport * from './c';\nimport('react');\n");
    w(root, "src/a.ts", "export const a = 1;\n");
    w(root, "src/side.js", "");
    w(root, "src/b.tsx", "");
    w(root, "src/c/index.ts", "");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("src/index.ts", "src/a.ts"));
    assert!(has("src/index.ts", "src/side.js"));
    assert!(has("src/index.ts", "src/b.tsx"));
    assert!(has("src/index.ts", "src/c/index.ts")); // directory index resolution
    // 'react' is a bare specifier -> ignored.
    assert!(!edges.iter().any(|(_, d)| d.contains("react")));
}
