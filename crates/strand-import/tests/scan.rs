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
fn scan_python_nested_package_root() {
    // Layout like `repo/proj/proj/`: the top-level package lives one
    // directory down, so absolute imports only resolve when ancestor
    // dirs are tried as package roots (sys.path heuristic).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "proj/proj/__init__.py", "");
    w(root, "proj/proj/core.py", "from proj import util\nimport proj.helpers\n");
    w(root, "proj/proj/util.py", "");
    w(root, "proj/proj/helpers.py", "");
    w(root, "proj/run.py", "import proj.core\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("proj/proj/core.py", "proj/proj/util.py")); // from proj import util
    assert!(has("proj/proj/core.py", "proj/proj/helpers.py")); // import proj.helpers
    assert!(has("proj/run.py", "proj/proj/core.py")); // import proj.core
}

#[test]
fn scan_python_multiline_imports() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/util.py", "");
    w(root, "pkg/helper.py", "");
    w(root, "pkg/other.py", "");
    // Parenthesized import list spanning lines + backslash continuation.
    w(
        root,
        "pkg/mod.py",
        "from pkg import (\n    util,\n    helper\n)\nfrom pkg \\\n    import other\n",
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("pkg/mod.py".to_string(), d.to_string()));
    assert!(has("pkg/util.py"));
    assert!(has("pkg/helper.py"));
    assert!(has("pkg/other.py"));
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

#[test]
fn scan_js_tsconfig_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "tsconfig.json",
        r#"{
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@/*": ["src/*"],
                    "exact-dep": ["lib/exact.ts"],
                    "@/fallback/*": ["missing/*", "src/fb/*"]
                }
            }
        }"#,
    );
    w(root, "src/app/main.ts", "import { x } from '@/util/x';\nimport e from 'exact-dep';\nimport { f } from '@/fallback/thing';\nimport { b } from 'src/lib/base';\nimport 'react';\n");
    w(root, "src/util/x.ts", "export const x = 1;\n");
    w(root, "lib/exact.ts", "export default 0;\n");
    w(root, "src/fb/thing.ts", "export const f = 1;\n");
    w(root, "src/lib/base.ts", "export const b = 1;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("src/app/main.ts", "src/util/x.ts")); // @/* wildcard
    assert!(has("src/app/main.ts", "lib/exact.ts")); // exact key
    assert!(has("src/app/main.ts", "src/fb/thing.ts")); // second target tried
    assert!(has("src/app/main.ts", "src/lib/base.ts")); // baseUrl fallback
    assert!(!edges.iter().any(|(_, d)| d.contains("react")));
}

#[test]
fn scan_js_tsconfig_extends() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "tsconfig.base.json",
        r#"{ "compilerOptions": { "paths": { "@core/*": ["core/*"] } } }"#,
    );
    w(
        root,
        "tsconfig.json",
        r#"{ "extends": "./tsconfig.base.json",
             "compilerOptions": { "baseUrl": "src" } }"#,
    );
    w(root, "src/app.ts", "import { c } from '@core/thing';\n");
    w(root, "src/core/thing.ts", "export const c = 1;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    // Parent's `paths` inherited; targets resolve against child's
    // effective baseUrl (src) -> src/core/thing.ts.
    assert!(edges.contains(&(
        "src/app.ts".to_string(),
        "src/core/thing.ts".to_string()
    )));
}

#[test]
fn scan_js_tsconfig_jsonc_and_monorepo() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // JSONC: comments + trailing commas must be tolerated.
    w(
        root,
        "tsconfig.json",
        r#"{
            // root config
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@root/*": ["shared/*"], // trailing comment
                },
            }
        }"#,
    );
    // Two packages, each with its own tsconfig (monorepo): the
    // nearest ancestor config governs each file.
    w(
        root,
        "packages/app/tsconfig.json",
        r#"{ "compilerOptions": { "baseUrl": "src", "paths": { "@app/*": ["*"] } } }"#,
    );
    w(
        root,
        "packages/lib/tsconfig.json",
        r#"{ "compilerOptions": { "baseUrl": "src", "paths": { "@lib/*": ["*"] } } }"#,
    );
    w(root, "shared/util.ts", "export const u = 1;\n");
    w(root, "top.ts", "import { u } from '@root/util';\n");
    w(root, "packages/app/src/index.ts", "import { l } from '@app/lib/local';\n");
    w(root, "packages/app/src/lib/local.ts", "export const l = 1;\n");
    w(root, "packages/lib/src/index.ts", "import { l } from '@lib/thing';\n");
    w(root, "packages/lib/src/thing.ts", "export const l = 2;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("top.ts", "shared/util.ts")); // root tsconfig, JSONC parsed
    assert!(has("packages/app/src/index.ts", "packages/app/src/lib/local.ts"));
    assert!(has("packages/lib/src/index.ts", "packages/lib/src/thing.ts"));
    // packages/lib sees only its own config: exactly one edge, to thing.ts.
    let lib_edges: Vec<_> = edges
        .iter()
        .filter(|(s, _)| s == "packages/lib/src/index.ts")
        .collect();
    assert_eq!(lib_edges.len(), 1);
    assert_eq!(lib_edges[0].1, "packages/lib/src/thing.ts");
}

#[test]
fn scan_js_package_json_imports() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "package.json",
        r##"{
            "name": "pkg",
            "imports": {
                "#util": "./src/util.ts",
                "#feat/*": { "import": "./src/feat/*.ts", "default": "./src/fallback/*.ts" }
            }
        }"##,
    );
    w(root, "src/main.ts", "import { u } from '#util';\nimport { f } from '#feat/x';\n");
    w(root, "src/util.ts", "export const u = 1;\n");
    w(root, "src/feat/x.ts", "export const f = 1;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("src/main.ts", "src/util.ts"));
    assert!(has("src/main.ts", "src/feat/x.ts"));
}

#[test]
fn scan_ignores_use_inside_strings() {
    let dir = tempfile::tempdir().unwrap();
    w(dir.path(), "Cargo.toml", "[package]\nname = \"p\"\n");
    // `use`/`mod` tokens inside string literals must not create edges.
    w(
        dir.path(),
        "src/lib.rs",
        "mod real;\nconst S: &str = \"use fake::dep; mod ghost;\";\n",
    );
    w(dir.path(), "src/real.rs", "pub fn f() {}\n");
    let out = scan_rust(dir.path()).unwrap();
    let edges = edges_of(&out);
    assert!(edges.contains(&("src/lib.rs".into(), "src/real.rs".into())));
    assert_eq!(edges.len(), 1, "unexpected edges: {edges:?}");
}

#[test]
fn scan_handles_literals_and_lifetimes() {
    let dir = tempfile::tempdir().unwrap();
    w(dir.path(), "Cargo.toml", "[package]\nname = \"p\"\n");
    w(
        dir.path(),
        "src/lib.rs",
        concat!(
            "mod real;\n",
            "fn f<'a>(x: &'a str) -> char { '\"' }\n",
            "const RAW: &str = r#\"use fake::dep; mod ghost;\"#;\n",
            "const ESC: &str = \"use fake::dep; mod ghost;\";\n",
            "/* block\n use fake::dep; */\n",
            "/* outer /* inner use fake::dep; */ still comment */\n",
        ),
    );
    w(dir.path(), "src/real.rs", "pub fn f() {}\n");
    let out = scan_rust(dir.path()).unwrap();
    let edges = edges_of(&out);
    assert_eq!(edges.len(), 1, "unexpected edges: {edges:?}");
    assert_eq!(edges[0], ("src/lib.rs".into(), "src/real.rs".into()));
}

#[test]
fn scan_own_repo_is_sane() {
    // Dogfood: scan the Strand workspace itself. Must produce a non-trivial
    // file-level graph with no panics or garbage node names.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let out = scan_lang(&root, Lang::Rust).unwrap();
    assert!(out.edges.len() > 20, "only {} edges", out.edges.len());
    assert!(out.nodes.iter().all(|n| n.ends_with(".rs")));
    // strand-app's main.rs uses strand_core::algo/view paths, so it must
    // resolve into strand-core's module files.
    assert!(out.edges.iter().any(|(s, d, _)| {
        s == "crates/strand-app/src/main.rs" && d == "crates/strand-core/src/algo/mod.rs"
    }));
    assert!(out.edges.iter().any(|(s, d, _)| {
        s == "crates/strand-app/src/main.rs" && d == "crates/strand-store/src/lib.rs"
    }));
}
