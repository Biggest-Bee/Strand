//! Tests for the Rust source scanner (`scan::scan_rust`).

use std::fs;
use std::path::Path;

use strand_import::scan::scan_rust;

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
