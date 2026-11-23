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
    w(
        root,
        "Cargo.toml",
        "[package]\nname = \"proj\"\nversion = \"0.1.0\"\n",
    );
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
    w(
        root,
        "src/bar/inner.rs",
        "use crate::foo::X;\npub struct Y;\n",
    );
    // Must be skipped entirely.
    w(root, "target/junk.rs", "use crate::foo::X;\n");
    w(root, "node_modules/dep.rs", "mod nothing;\n");
}

fn edges_of(out: &strand_import::scan::ScanOutput) -> Vec<(String, String)> {
    out.edges
        .iter()
        .map(|(s, d, ..)| (s.clone(), d.clone()))
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
    assert!(!edges
        .iter()
        .any(|(s, _)| s.contains("junk") || s.contains("dep")));

    // Every .rs file except skipped dirs is a node.
    assert!(out.nodes.contains(&"src/lib.rs".to_string()));
    assert!(out.nodes.contains(&"src/bar/inner.rs".to_string()));
    assert!(!out
        .nodes
        .iter()
        .any(|n| n.contains("target") || n.contains("node_modules")));
}

#[test]
fn scan_dedups_edges() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let out = scan_rust(dir.path()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for (s, d, ..) in &out.edges {
        assert!(seen.insert((s.clone(), d.clone())), "dup edge {s} -> {d}");
    }
}

#[test]
fn scan_rust_path_attr_and_include() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "src/lib.rs",
        "#[path = \"deep/hidden.rs\"]\nmod secret;\nmod real;\n",
    );
    w(
        root,
        "src/deep/hidden.rs",
        "include!(\"gen/included.rs\");\n",
    );
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
    w(
        root,
        "top.py",
        "from pkg import mod\nimport pkg.util as u\n",
    );
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
    w(
        root,
        "proj/proj/core.py",
        "from proj import util\nimport proj.helpers\n",
    );
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
    assert!(edges.contains(&("src/app.ts".to_string(), "src/core/thing.ts".to_string())));
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
    w(
        root,
        "packages/app/src/index.ts",
        "import { l } from '@app/lib/local';\n",
    );
    w(
        root,
        "packages/app/src/lib/local.ts",
        "export const l = 1;\n",
    );
    w(
        root,
        "packages/lib/src/index.ts",
        "import { l } from '@lib/thing';\n",
    );
    w(root, "packages/lib/src/thing.ts", "export const l = 2;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("top.ts", "shared/util.ts")); // root tsconfig, JSONC parsed
    assert!(has(
        "packages/app/src/index.ts",
        "packages/app/src/lib/local.ts"
    ));
    assert!(has(
        "packages/lib/src/index.ts",
        "packages/lib/src/thing.ts"
    ));
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
    w(
        root,
        "src/main.ts",
        "import { u } from '#util';\nimport { f } from '#feat/x';\n",
    );
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
fn scan_rust_grouped_use_trees() {
    // `use a::{b, c::d}` must yield edges for every leaf - the old
    // text scanner stopped at `{` and saw only `a`.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "Cargo.toml", "[package]\nname = \"p\"\n");
    w(root, "src/lib.rs", "mod m;\nmod n;\n");
    w(root, "src/m.rs", "pub mod a;\npub mod b;\n");
    w(root, "src/m/a.rs", "pub struct A;\n");
    w(root, "src/m/b.rs", "pub struct B;\n");
    w(root, "src/n.rs", "pub struct N;\n");
    w(
        root,
        "src/user.rs",
        concat!(
            "use crate::m::{a::A, b::B as Bee};\n",
            "use crate::n;\n",
            "fn f() {\n    use crate::m::a::A as Local;\n    let _ = Local;\n}\n",
        ),
    );
    // Register user.rs as a module so it's part of the crate.
    let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    fs::write(root.join("src/lib.rs"), format!("{lib}mod user;\n")).unwrap();

    let out = scan_rust(root).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("src/user.rs", "src/m/a.rs")); // a::A leaf
    assert!(has("src/user.rs", "src/m/b.rs")); // b::B as Bee leaf
    assert!(has("src/user.rs", "src/n.rs")); // plain use crate::n
    assert!(has("src/user.rs", "src/m/a.rs")); // use inside fn body (dedup w/ above)
    assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
}

#[test]
fn scan_rust_parse_failure_warns_not_drops() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "Cargo.toml", "[package]\nname = \"p\"\n");
    w(root, "src/lib.rs", "mod good;\nmod bad;\n");
    w(root, "src/good.rs", "pub fn g() {}\n");
    // Syntactically invalid Rust: syn rejects it.
    w(root, "src/bad.rs", "pub fn broken( {\n");
    let out = scan_rust(root).unwrap();
    let edges = edges_of(&out);
    // The bad file is still a node; the good file still resolves.
    assert!(out.nodes.contains(&"src/bad.rs".to_string()));
    assert!(edges.contains(&("src/lib.rs".into(), "src/good.rs".into())));
    assert!(
        out.warnings.iter().any(|w| w.contains("src/bad.rs")),
        "expected a parse warning for src/bad.rs, got {:?}",
        out.warnings
    );
}

#[test]
fn scan_python_ignores_docstring_imports() {
    // `from x import y` inside a docstring/comment/string is not an
    // import - tree-sitter only emits real import statements.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/util.py", "");
    w(
        root,
        "pkg/mod.py",
        concat!(
            "def f():\n",
            "    \"\"\"Example:\n\n",
            "        from pkg import util\n",
            "        import os\n",
            "    \"\"\"\n",
            "    from pkg import util\n", // real import inside function
            "# from pkg import commented\n",
            "s = \"from pkg import stringy\"\n",
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    // `from pkg import util` depends on the package itself
    // (__init__.py) and on pkg/util.py - exactly two edges; nothing
    // from the docstring, comment, or string literal.
    assert_eq!(
        edges,
        vec![
            ("pkg/mod.py".to_string(), "pkg/__init__.py".to_string()),
            ("pkg/mod.py".to_string(), "pkg/util.py".to_string()),
        ],
        "unexpected edges: {edges:?}"
    );
    assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
}

#[test]
fn scan_python_dynamic_import_literals() {
    // import_module/__import__ with literal string args resolve like
    // normal imports; non-literal args stay invisible.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/plugins/__init__.py", "");
    w(root, "pkg/plugins/ldap.py", "");
    w(root, "pkg/plugins/oauth.py", "");
    w(root, "pkg/core.py", "");
    w(
        root,
        "pkg/loader.py",
        concat!(
            "import importlib\n",
            "importlib.import_module('pkg.plugins.ldap')\n",
            "from importlib import import_module\n",
            "import_module(\"pkg.plugins.oauth\")\n",
            "__import__('pkg.core')\n",
            "import_module('pkg.' + name)\n", // not literal: ignored
            "import_module(f'pkg.{name}')\n", // f-string: ignored
            "obj.import_module('pkg.core')\n", // attribute call: edge
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("pkg/loader.py".to_string(), d.to_string()));

    assert!(has("pkg/plugins/ldap.py"));
    assert!(has("pkg/plugins/oauth.py"));
    assert!(has("pkg/core.py")); // __import__ + attribute call (deduped)
                                 // Exactly three distinct deps - dynamic non-literals add nothing.
    assert_eq!(
        edges.iter().filter(|(s, _)| s == "pkg/loader.py").count(),
        3,
        "unexpected edges: {edges:?}"
    );
}

#[test]
fn scan_python_entry_points() {
    // [project.entry-points] in pyproject.toml registers plugins at
    // runtime; the config file becomes the edge source.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "myplugin/__init__.py", "");
    w(root, "myplugin/ldap.py", "class Plugin: pass\n");
    w(root, "myplugin/oauth.py", "class Plugin: pass\n");
    w(
        root,
        "pyproject.toml",
        concat!(
            "[project]\nname = \"myplugin\"\nversion = \"0.1.0\"\n\n",
            "[project.entry-points.\"myapp.plugins\"]\n",
            "ldap = \"myplugin.ldap:Plugin\"\n",
            "oauth = \"myplugin.oauth:Plugin [extra]\"\n",
            "broken = \"not a module!!\"\n",
        ),
    );
    // A pyproject with no entry points must not become a node.
    w(root, "other/pyproject.toml", "[project]\nname = \"x\"\n");
    w(root, "other/mod.py", "");
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("pyproject.toml", "myplugin/ldap.py"));
    assert!(has("pyproject.toml", "myplugin/oauth.py")); // "module:attr [extras]"
    assert!(out.nodes.contains(&"pyproject.toml".to_string()));
    assert!(!out.nodes.contains(&"other/pyproject.toml".to_string()));
}

#[test]
fn scan_python_setup_entry_points() {
    // setup.cfg [options.entry_points] and setup.py entry_points={}
    // dict literals get the same treatment as pyproject entry points.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/a.py", "");
    w(root, "pkg/b.py", "");
    w(
        root,
        "setup.cfg",
        concat!(
            "[metadata]\nname = pkg\n\n",
            "[options.entry_points]\n",
            "myapp.plugins =\n",
            "    ldap = pkg.a:Plugin\n",
            "    oauth = pkg.b:Plugin\n",
        ),
    );
    w(root, "pkg/c.py", "");
    w(root, "pkg/d.py", "");
    w(
        root,
        "setup.py",
        concat!(
            "from setuptools import setup\n",
            "EPS = {\n",
            "    \"myapp.plugins\": [\"ldap = pkg.a:Plugin\"],\n",
            "}\n",
            "MORE = dict(group=[\"oauth = pkg.b:Plugin\"])\n",
            "ALIAS = EPS\n",
            "setup(entry_points={\n",
            "    \"myapp.plugins\": [\"ldap = pkg.a:Plugin\"],\n",
            "    \"extra\": [\"c = pkg.c:Plugin\"],\n",
            "})\n",
            "setup(entry_points=EPS)\n",         // variable ref
            "setup(entry_points=ALIAS)\n",       // chained alias
            "setup(entry_points=MORE)\n",        // dict() call
            "setup(entry_points=build_eps())\n", // dynamic: invisible
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("setup.cfg", "pkg/a.py"));
    assert!(has("setup.cfg", "pkg/b.py"));
    assert!(has("setup.py", "pkg/a.py")); // literal dict
    assert!(has("setup.py", "pkg/c.py")); // second setup() call
    assert!(has("setup.py", "pkg/b.py")); // via dict() call alias
                                          // pkg/d.py is only reachable through build_eps() - stays invisible.
    assert!(!has("setup.py", "pkg/d.py"));
    assert!(out.nodes.contains(&"setup.cfg".to_string()));
    assert!(out.nodes.contains(&"setup.py".to_string()));
}

#[test]
fn scan_js_ignores_strings_and_comments() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/a.ts", "export const a = 1;\n");
    w(
        root,
        "src/index.ts",
        concat!(
            "import { a } from './a';\n",
            "const s = \"from './ghost' import x\";\n",
            "const t = `require('./tmpl')`;\n", // string content, not a call
            "// import y from './commented'\n",
            "/* export * from './blocked' */\n",
            "const r = require(`./real-tmpl`);\n", // template literal arg
            "import('./dyn-rel');\n",
        ),
    );
    w(root, "src/real-tmpl.ts", "export const t = 1;\n");
    w(root, "src/dyn-rel.ts", "export const d = 1;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    assert!(has("src/index.ts", "src/a.ts"));
    assert!(has("src/index.ts", "src/real-tmpl.ts")); // require(`...`)
    assert!(has("src/index.ts", "src/dyn-rel.ts")); // import('...')
    assert_eq!(edges.len(), 3, "unexpected edges: {edges:?}");
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
    // strand-gui's main.rs uses strand_core::algo/view paths, so it must
    // resolve into strand-core's module files.
    assert!(out.edges.iter().any(|(s, d, ..)| {
        s == "crates/strand-gui/src/main.rs" && d == "crates/strand-core/src/algo/mod.rs"
    }));
    assert!(out.edges.iter().any(|(s, d, ..)| {
        s == "crates/strand-gui/src/main.rs" && d == "crates/strand-store/src/lib.rs"
    }));
}

#[test]
fn scan_python_dynamic_site_warnings() {
    // Non-literal dynamic imports can't resolve - the scanner must warn
    // per file instead of silently dropping the edge. Literal calls
    // still resolve and produce no warning.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/a.py", "");
    w(root, "pkg/b.py", "");
    w(
        root,
        "pkg/loader.py",
        concat!(
            "from importlib import import_module\n",
            "import_module('pkg.a')\n",      // literal: edge, no warning
            "import_module(name)\n",         // variable: dynamic
            "import_module('pkg.' + mod)\n", // concat: dynamic
            "import_module(f'pkg.{mod}')\n", // f-string: dynamic
            "__import__(target)\n",          // dynamic
        ),
    );
    w(root, "pkg/quiet.py", "import pkg.a\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    assert!(edges.contains(&("pkg/loader.py".to_string(), "pkg/a.py".to_string())));
    assert_eq!(out.warnings.len(), 1, "warnings: {:?}", out.warnings);
    assert!(
        out.warnings[0].contains("pkg/loader.py")
            && out.warnings[0].contains("4 dynamic import site(s)"),
        "warning: {}",
        out.warnings[0]
    );
    assert!(
        !out.warnings.iter().any(|w| w.contains("quiet.py")),
        "clean file warned: {:?}",
        out.warnings
    );
}

#[test]
fn scan_python_manual_depends_on() {
    // `# strand: depends-on <target>` is the escape hatch for edges
    // static analysis can't see. Paths resolve relative to the file's
    // dir; dotted module paths also work. Missing targets are skipped.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/target.py", "");
    w(root, "pkg/sub/inner.py", "");
    w(root, "pkg/dynamic.py", "");
    w(
        root,
        "pkg/loader.py",
        concat!(
            "import importlib\n",
            "import_module(name)  # runtime picks the module\n",
            "# strand: depends-on pkg/target.py\n",
            "# strand: depends-on pkg.dotted_module\n", // unresolvable: skip
            "# strand: depends-on does/not/exist.py\n", // missing: skip
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    assert!(
        edges.contains(&("pkg/loader.py".to_string(), "pkg/target.py".to_string())),
        "manual edge missing: {edges:?}"
    );
    // Dynamic site still warns even though the manual edge covers it.
    assert!(out.warnings.iter().any(|w| w.contains("loader.py")));
}

#[test]
fn scan_python_manual_depends_on_relative() {
    // Relative path form resolves against the file's directory.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/util.py", "");
    w(root, "pkg/sub/mod.py", "# strand: depends-on ../util.py\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    assert!(
        edges.contains(&("pkg/sub/mod.py".to_string(), "pkg/util.py".to_string())),
        "relative manual edge missing: {edges:?}"
    );
}

#[test]
fn scan_js_dynamic_warnings_and_manual() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/a.ts", "export const a = 1;\n");
    w(root, "src/b.ts", "export const b = 1;\n");
    w(
        root,
        "src/index.ts",
        concat!(
            "import('./literal-rel');\n",     // literal dynamic: edge
            "import(name)\n",                 // variable: dynamic site
            "const r = require(someVar);\n",  // dynamic site
            "// strand: depends-on ./b.ts\n", // manual edge
        ),
    );
    w(root, "src/literal-rel.ts", "export const l = 1;\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("src/index.ts".to_string(), d.to_string()));
    assert!(has("src/literal-rel.ts"));
    assert!(has("src/b.ts"), "manual edge missing: {edges:?}");
    assert_eq!(out.warnings.len(), 1, "warnings: {:?}", out.warnings);
    assert!(
        out.warnings[0].contains("src/index.ts")
            && out.warnings[0].contains("2 dynamic import site(s)"),
        "warning: {}",
        out.warnings[0]
    );
}

#[test]
fn scan_rust_manual_depends_on() {
    // Same escape hatch for Rust files.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/lib.rs", "mod a;\n");
    w(root, "src/a.rs", "// strand: depends-on src/b.rs\n");
    w(root, "src/b.rs", "pub fn f() {}\n");
    let out = scan_rust(root).unwrap();
    let edges = edges_of(&out);
    assert!(
        edges.contains(&("src/a.rs".to_string(), "src/b.rs".to_string())),
        "rust manual edge missing: {edges:?}"
    );
}

#[test]
fn scan_rust_depinfo_cross_check() {
    // `.d` dep-info lists files rustc read. A .rs under the root that
    // isn't on disk (or wasn't walked) surfaces as a warning; paths
    // under target/ or outside the root are ignored.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/lib.rs", "pub fn f() {}\n");
    let canon = root.canonicalize().unwrap();
    let canon_str = canon
        .to_string_lossy()
        .trim_start_matches("\\\\?\\")
        .replace('\\', "/");
    let d = format!(
        "{canon_str}/target/debug/deps/proj-abc.d: {canon_str}/src/lib.rs {canon_str}/src/ghost.rs {canon_str}/target/debug/build/out/gen.rs C:/outside.rs\n"
    );
    w(root, "target/debug/deps/proj-abc.d", &d);
    let out = scan_rust(root).unwrap();
    assert_eq!(out.warnings.len(), 1, "warnings: {:?}", out.warnings);
    assert!(
        out.warnings[0].contains("src/ghost.rs"),
        "warning: {}",
        out.warnings[0]
    );
    assert!(!out.warnings[0].contains("gen.rs"));
    assert!(!out.warnings[0].contains("outside.rs"));
}

#[test]
fn scan_rust_depinfo_absent_is_quiet() {
    // No target/ dir -> no dep-info -> no warning.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/lib.rs", "pub fn f() {}\n");
    let out = scan_rust(root).unwrap();
    assert!(out.warnings.is_empty(), "warnings: {:?}", out.warnings);
}

#[test]
fn scan_python_reexport_chain() {
    // pkg/__init__.py re-exports a private module; callers import from
    // the package root. Impact on _impl.py must reach callers through
    // the __init__.py -> _impl.py edge.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(
        root,
        "pkg/__init__.py",
        "from ._impl import thing\nfrom . import helper\n",
    );
    w(root, "pkg/_impl.py", "thing = 1\n");
    w(root, "pkg/helper.py", "x = 2\n");
    w(root, "app.py", "from pkg import thing\nimport pkg.helper\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));

    // Caller sees the package root, not the private module directly.
    assert!(has("app.py", "pkg/__init__.py"), "edges: {edges:?}");
    // __init__'s relative imports reach the private modules.
    assert!(has("pkg/__init__.py", "pkg/_impl.py"), "edges: {edges:?}");
    assert!(has("pkg/__init__.py", "pkg/helper.py"), "edges: {edges:?}");
    // `import pkg.helper` also yields the submodule edge.
    assert!(has("app.py", "pkg/helper.py"), "edges: {edges:?}");
    // Transitive: _impl -> __init__ -> app is reachable via those edges.
}

#[test]
fn scan_python_getattr_dispatch_warning() {
    // getattr on an import-bound name is dynamic dispatch - module
    // __getattr__ can lazily import, hiding edges. Other getattr uses
    // (self, locals, non-imported names) don't count.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/mod.py", "");
    w(
        root,
        "app.py",
        concat!(
            "import pkg.mod\n",
            "from pkg import mod as pm\n",
            "getattr(pkg, name)\n",     // pkg bound by import: counts
            "getattr(pm, 'handler')\n", // pm bound by from-import: counts
            "getattr(self, name)\n",    // self: not import-bound
            "getattr(local_var, x)\n",  // not import-bound
            "getattr(pkg.mod, n)\n",    // attribute, not bare ident: skip
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    assert_eq!(out.warnings.len(), 1, "warnings: {:?}", out.warnings);
    assert!(
        out.warnings[0].contains("app.py") && out.warnings[0].contains('2'),
        "warning: {}",
        out.warnings[0]
    );
}

#[test]
fn scan_rust_depinfo_edgeless_module() {
    // A .rs file rustc compiled, the walk found, but no mod edge points
    // at - the macro-generated module signature. When the layout lets
    // us infer the parent (`src/x.rs` -> crate root, `a/b/c.rs` ->
    // `a/b.rs`/`a/b/mod.rs`), the edge is added; only files with no
    // inferable parent stay warnings. Crate roots (lib.rs, tests/)
    // are excluded.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/lib.rs", "pub fn f() {}\n");
    w(root, "src/macro_mod.rs", "pub fn g() {}\n"); // on disk, no mod decl
    w(root, "src/deep/x/y.rs", "pub fn h() {}\n"); // no parent candidate
    w(root, "tests/it.rs", "#[test] fn t() {}\n");
    let canon = root.canonicalize().unwrap();
    let canon_str = canon
        .to_string_lossy()
        .trim_start_matches("\\\\?\\")
        .replace('\\', "/");
    let d = format!(
        "{canon_str}/target/debug/deps/proj-abc.d: {canon_str}/src/lib.rs {canon_str}/src/macro_mod.rs {canon_str}/src/deep/x/y.rs {canon_str}/tests/it.rs\n"
    );
    w(root, "target/debug/deps/proj-abc.d", &d);
    let out = scan_rust(root).unwrap();
    let edges = edges_of(&out);
    // macro_mod.rs's deterministic parent is the crate root.
    assert!(
        edges.contains(&("src/lib.rs".to_string(), "src/macro_mod.rs".to_string())),
        "missing inferred parent edge: {edges:?}"
    );
    // y.rs has no `src/deep/x.rs`/`mod.rs` candidate - stays a warning.
    assert_eq!(out.warnings.len(), 1, "warnings: {:?}", out.warnings);
    assert!(
        out.warnings[0].contains("src/deep/x/y.rs")
            && out.warnings[0].contains("no incoming module edge"),
        "warning: {}",
        out.warnings[0]
    );
    assert!(!out.warnings[0].contains("macro_mod.rs"));
    assert!(!out.warnings[0].contains("lib.rs"));
    assert!(!out.warnings[0].contains("it.rs"));
}

#[test]
fn scan_python_const_prop_dynamic_imports() {
    // Computed import_module args resolve when every piece is a
    // literal-derived constant - set-of-strings domain, flow
    // insensitive, per file.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/plugins/__init__.py", "");
    w(root, "pkg/plugins/ldap.py", "");
    w(root, "pkg/a.py", "");
    w(root, "pkg/b.py", "");
    w(
        root,
        "pkg/loader.py",
        concat!(
            "from importlib import import_module\n",
            "NAME = 'ldap'\n",
            "import_module('pkg.plugins.' + NAME)\n", // const concat
            "import_module(f'pkg.plugins.{NAME}')\n", // f-string const
            "for n in ('a', 'b'):\n",
            "    import_module('pkg.' + n)\n", // for-loop expand
            "T = 'plugins.' + NAME\n",
            "import_module('pkg.' + T)\n", // chained const
            "J = '.'.join(['plugins', NAME])\n",
            "import_module('pkg.' + J)\n", // join
            "F = 'pkg.plugins.{}'.format(NAME)\n",
            "import_module(F)\n", // .format
            "P = 'pkg.plugins.%s' % NAME\n",
            "import_module(P)\n",                    // % formatting
            "import_module('pkg.' + unknown_var)\n", // still dynamic
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("pkg/loader.py".to_string(), d.to_string()));
    for d in ["pkg/plugins/ldap.py", "pkg/a.py", "pkg/b.py"] {
        assert!(has(d), "missing edge to {d}: {edges:?}");
    }
    // ldap reached via concat, f-string, chained, join, format, %.
    // pkg/plugins/__init__.py comes along as the package init of the
    // resolved submodule imports. unknown_var adds nothing and warns.
    assert_eq!(
        edges.iter().filter(|(s, _)| s == "pkg/loader.py").count(),
        4,
        "edges: {edges:?}"
    );
    assert!(out.warnings.iter().any(|w| w.contains("loader.py")));
}

#[test]
fn scan_python_const_prop_mutation_and_shadowing() {
    // Mutated containers and function params can't be trusted -
    // they stay dynamic rather than producing wrong edges.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/x.py", "");
    w(root, "pkg/y.py", "");
    w(
        root,
        "pkg/loader.py",
        concat!(
            "from importlib import import_module\n",
            "NAMES = ['x', 'y']\n",
            "NAMES.append('z')\n", // mutation -> unknown
            "for n in NAMES:\n",
            "    import_module('pkg.' + n)\n",
            "def f(NAME):\n",
            "    import_module('pkg.' + NAME)\n", // param shadows: unknown
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    assert!(
        !edges
            .iter()
            .any(|(s, d)| s == "pkg/loader.py" && d.starts_with("pkg/")),
        "unexpected resolved edges: {edges:?}"
    );
    // Both sites warn (loop + param use are 2 dynamic sites).
    assert!(out.warnings.iter().any(|w| w.contains("loader.py")));
}

#[test]
fn scan_python_glob_expansion() {
    // Literal glob patterns expand against the scanned file set -
    // plugin loaders get real edges, not warnings.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "app.py", "import glob\nimport os\n");
    w(root, "plugins/__init__.py", "");
    w(root, "plugins/a.py", "");
    w(root, "plugins/b.py", "");
    w(root, "plugins/sub/c.py", "");
    w(root, "other/d.py", "");
    w(
        root,
        "loader.py",
        concat!(
            "import glob\n",
            "for p in glob.glob('plugins/*.py'):\n",
            "    pass\n",
            "for p in glob.iglob('plugins/**/*.py'):\n",
            "    pass\n",
            "PAT = 'plugins/*.py'\n",
            "for p in glob.glob(PAT):\n",
            "    pass\n",
            "for p in glob.glob(some_var):\n", // dynamic -> warns, no edges
            "    pass\n",
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("loader.py".to_string(), d.to_string()));
    // `plugins/*.py` -> a.py, b.py, __init__.py (one segment only).
    // `plugins/**/*.py` -> all of plugins/ incl. sub/c.py.
    // PAT const -> same as first pattern. `other/d.py` never matched.
    for d in [
        "plugins/__init__.py",
        "plugins/a.py",
        "plugins/b.py",
        "plugins/sub/c.py",
    ] {
        assert!(has(d), "missing glob edge to {d}: {edges:?}");
    }
    assert!(!has("other/d.py"), "phantom glob edge: {edges:?}");
    assert!(!has("app.py"), "phantom glob edge: {edges:?}");
    assert!(out.warnings.iter().any(|w| w.contains("loader.py")));
}

#[test]
fn scan_python_framework_conventions() {
    // pytest_plugins, INSTALLED_APPS dotted strings, and conftest.py
    // ancestor edges are framework wiring the imports don't show.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "conftest.py", "");
    w(root, "tests/conftest.py", "");
    w(root, "tests/test_x.py", "def test_x(): pass\n");
    w(root, "tests/unit/test_y.py", "def test_y(): pass\n");
    w(root, "myapp/__init__.py", "");
    w(root, "myapp/apps.py", "");
    w(root, "myapp/plugins/ldap.py", "");
    w(root, "myapp/plugins/sql.py", "");
    w(root, "settings.py", "");
    w(
        root,
        "tests/conftest.py",
        "pytest_plugins = ['myapp.plugins.ldap', 'myapp.plugins.sql']\n",
    );
    w(
        root,
        "settings.py",
        concat!(
            "INSTALLED_APPS = [\n",
            "    'myapp',\n",
            "    'myapp.apps.MyConfig',\n", // class attr -> module prefix
            "]\n",
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |s: &str, d: &str| edges.contains(&(s.to_string(), d.to_string()));
    // pytest_plugins dotted strings -> module files.
    assert!(has("tests/conftest.py", "myapp/plugins/ldap.py"));
    assert!(has("tests/conftest.py", "myapp/plugins/sql.py"));
    // INSTALLED_APPS -> longest resolvable module prefix.
    assert!(has("settings.py", "myapp/__init__.py"));
    assert!(has("settings.py", "myapp/apps.py"));
    // conftest.py auto-loaded by every test module beneath it.
    assert!(has("tests/test_x.py", "tests/conftest.py"));
    assert!(has("tests/test_x.py", "conftest.py"));
    assert!(has("tests/unit/test_y.py", "tests/conftest.py"));
    assert!(has("tests/unit/test_y.py", "conftest.py"));
    // Non-test files get no conftest edges.
    assert!(!has("myapp/apps.py", "conftest.py"));
}

#[test]
fn scan_js_glob_expansion() {
    // require.context, import.meta.glob, and template/concat dynamic
    // imports expand against the scanned file set like webpack/vite
    // context modules do.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "plugins/a.ts", "export const a = 1;\n");
    w(root, "plugins/b.ts", "export const b = 1;\n");
    w(root, "plugins/sub/c.ts", "export const c = 1;\n");
    w(root, "plugins/deep/d.js", "module.exports = 1;\n");
    w(root, "other/e.ts", "export const e = 1;\n");
    w(
        root,
        "loader.ts",
        concat!(
            "const ctx = require.context('./plugins', true);\n",
            "const mods = import.meta.glob('./plugins/*.ts');\n",
            "const lazy = () => import(`./plugins/${name}.ts`);\n",
            "const lazy2 = () => import('./plugins/' + which);\n",
            "const dyn = () => import(someVar);\n", // still dynamic
        ),
    );
    let out = scan_lang(root, Lang::Js).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("loader.ts".to_string(), d.to_string()));
    // require.context recursive -> everything under plugins/.
    // import.meta.glob './plugins/*.ts' -> a.ts, b.ts only (one level).
    // template `./plugins/${name}.ts` -> a.ts, b.ts.
    // concat './plugins/' + which -> all under plugins/ (ext variants).
    for d in [
        "plugins/a.ts",
        "plugins/b.ts",
        "plugins/sub/c.ts",
        "plugins/deep/d.js",
    ] {
        assert!(has(d), "missing glob edge to {d}: {edges:?}");
    }
    assert!(!has("other/e.ts"), "phantom glob edge: {edges:?}");
    // `import(someVar)` has no anchor - warns, no edges.
    assert!(out.warnings.iter().any(|w| w.contains("loader.ts")));
}

#[test]
fn scan_python_entry_point_consumers() {
    // entry_points(group="x") callers link to every target declared
    // in that group across pyproject/setup.cfg/setup.py; no group
    // selects all.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "myapp/__init__.py", "");
    w(root, "myapp/cli.py", "def main(): pass\n");
    w(root, "myapp/hooks.py", "def hook(): pass\n");
    w(root, "myapp/extra.py", "def extra(): pass\n");
    w(root, "consumer.py", "");
    w(
        root,
        "pyproject.toml",
        concat!(
            "[project.entry-points.\"myapp.commands\"]\n",
            "run = \"myapp.cli:main\"\n",
            "[project.entry-points.\"myapp.hooks\"]\n",
            "pre = \"myapp.hooks:hook\"\n",
        ),
    );
    w(
        root,
        "setup.cfg",
        concat!(
            "[options.entry_points]\n",
            "myapp.extra =\n",
            "    go = myapp.extra:extra\n",
        ),
    );
    w(
        root,
        "consumer.py",
        concat!(
            "from importlib.metadata import entry_points\n",
            "def load():\n",
            "    eps = entry_points(group='myapp.commands')\n",
            "    all_eps = entry_points()\n",
            "    dyn = entry_points(group=compute())\n", // dynamic -> warns
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("consumer.py".to_string(), d.to_string()));
    // group='myapp.commands' -> cli.py target.
    assert!(has("myapp/cli.py"), "missing group edge: {edges:?}");
    // entry_points() with no group -> all declared targets.
    for d in ["myapp/cli.py", "myapp/hooks.py", "myapp/extra.py"] {
        assert!(has(d), "missing all-groups edge to {d}: {edges:?}");
    }
    // Config files still point at their declared targets.
    assert!(edges.contains(&("pyproject.toml".to_string(), "myapp/cli.py".to_string())));
    assert!(edges.contains(&("setup.cfg".to_string(), "myapp/extra.py".to_string())));
    // Computed group warns.
    assert!(out.warnings.iter().any(|w| w.contains("consumer.py")));
}

#[test]
fn scan_python_callsite_literal_propagation() {
    // `def load(name): import_module(name)` resolves through literal
    // call-site arguments in the same file.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "plugins/__init__.py", "");
    w(root, "plugins/ldap.py", "");
    w(root, "plugins/sql.py", "");
    w(
        root,
        "loader.py",
        concat!(
            "from importlib import import_module\n",
            "def load(name):\n",
            "    import_module('plugins.' + name)\n",
            "load('ldap')\n",
            "load(name='sql')\n",
            "def other(x):\n",
            "    import_module(x)\n", // param, no literal call sites
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let edges = edges_of(&out);
    let has = |d: &str| edges.contains(&("loader.py".to_string(), d.to_string()));
    assert!(has("plugins/ldap.py"), "edges: {edges:?}");
    assert!(has("plugins/sql.py"), "edges: {edges:?}");
    // `other`'s param never gets a literal call site -> still warns.
    assert!(out.warnings.iter().any(|w| w.contains("loader.py")));
}

#[test]
fn scan_python_env_config_warning_hint() {
    // Dynamic sites fed by env vars/config are still warned, now with
    // a hint naming the likely source.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "a.py", "");
    w(
        root,
        "loader.py",
        concat!(
            "import os\n",
            "from importlib import import_module\n",
            "import_module(os.environ['PLUGIN'])\n",
            "import_module(os.getenv('PLUGIN_NAME'))\n",
        ),
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    let w = out
        .warnings
        .iter()
        .find(|w| w.contains("loader.py"))
        .expect("expected dynamic warning");
    assert!(w.contains("env vars/config"), "{w}");
}

#[test]
fn scan_pub_cache_edges_end_to_end() {
    // pubspec.lock is flat, but the pub cache's hosted pubspec.yaml
    // files carry real deps - scan_project should BFS them.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        root.join("pubspec.lock"),
        "packages:\n  http:\n    dependency: \"direct main\"\n    description:\n      name: http\n      sha256: \"00\"\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.2.3\"\n  collection:\n    dependency: transitive\n    description:\n      name: collection\n      sha256: \"00\"\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.19.0\"\n",
    )
    .unwrap();
    let hp = cache.path().join("hosted/pub.dev/http-1.2.3/pubspec.yaml");
    std::fs::create_dir_all(hp.parent().unwrap()).unwrap();
    std::fs::write(
        &hp,
        "name: http\nversion: 1.2.3\ndependencies:\n  collection: ^1.0.0\n",
    )
    .unwrap();
    let cp = cache
        .path()
        .join("hosted/pub.dev/collection-1.19.0/pubspec.yaml");
    std::fs::create_dir_all(cp.parent().unwrap()).unwrap();
    std::fs::write(&cp, "name: collection\nversion: 1.19.0\n").unwrap();

    std::env::set_var("PUB_CACHE", cache.path());
    let out =
        strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Python]).unwrap();
    std::env::remove_var("PUB_CACHE");
    let has = |s: &str, d: &str| out.edges.iter().any(|(a, b, ..)| a == s && b == d);
    assert!(
        has("http@1.2.3", "collection@1.19.0"),
        "edges: {:?}",
        out.edges
    );
}

#[test]
fn scan_python_native_libs_and_data_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/app.py"),
        "import ctypes\n\
         lib = ctypes.CDLL(\"/usr/lib/libfoo.so.1\")\n\
         k32 = ctypes.windll.kernel32\n\
         msvcrt = ctypes.cdll.msvcrt\n\
         handle = ctypes.CDLL(None)\n\
         import os\n\
         f = open(\"config/app.yaml\")\n\
         p = __import__('pathlib').Path(\"data/input.csv\")\n\
         df = __import__('pandas').read_csv(\"missing.csv\")\n\
         dyn = ctypes.CDLL(get_lib_name())\n",
    )
    .unwrap();
    // Data files that exist on disk.
    std::fs::create_dir_all(root.join("config")).unwrap();
    std::fs::write(root.join("config/app.yaml"), "k: v\n").unwrap();
    std::fs::create_dir_all(root.join("data")).unwrap();
    std::fs::write(root.join("data/input.csv"), "a,b\n").unwrap();

    let out =
        strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Python]).unwrap();
    let has = |s: &str, d: &str| out.edges.iter().any(|(a, b, ..)| a == s && b == d);
    // Native lib edges: literal loads only; CDLL(None) skipped.
    assert!(
        has("src/app.py", "native:libfoo.so.1"),
        "edges: {:?}",
        out.edges
    );
    assert!(
        has("src/app.py", "native:kernel32"),
        "edges: {:?}",
        out.edges
    );
    assert!(has("src/app.py", "native:msvcrt"), "edges: {:?}", out.edges);
    assert!(
        !out.edges
            .iter()
            .any(|(_, d, ..)| d == "native:None" || d == "native:"),
        "edges: {:?}",
        out.edges
    );
    // Data file edges only for paths that exist.
    assert!(
        has("src/app.py", "config/app.yaml"),
        "edges: {:?}",
        out.edges
    );
    assert!(
        has("src/app.py", "data/input.csv"),
        "edges: {:?}",
        out.edges
    );
    assert!(!has("src/app.py", "missing.csv"), "edges: {:?}", out.edges);
    // Computed lib name -> dynamic warning.
    assert!(
        out.warnings.iter().any(|w| w.contains("native-library")),
        "warnings: {:?}",
        out.warnings
    );
}

#[test]
fn scan_js_native_and_data_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("index.js"),
        "const addon = require('./native/addon.node');\n\
         const bindings = require('bindings');\n\
         const foo = bindings('foo');\n\
         process.dlopen(module, '/opt/x/extra.node');\n\
         const fs = require('fs');\n\
         const cfg = fs.readFileSync('conf/settings.json', 'utf8');\n\
         fs.createReadStream('logs/out.txt');\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("conf")).unwrap();
    std::fs::write(root.join("conf/settings.json"), "{}").unwrap();
    std::fs::create_dir_all(root.join("logs")).unwrap();
    std::fs::write(root.join("logs/out.txt"), "").unwrap();

    let out = strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Js]).unwrap();
    let has = |d: &str| out.edges.iter().any(|(a, b, ..)| a == "index.js" && b == d);
    assert!(has("native:addon.node"), "edges: {:?}", out.edges);
    assert!(has("native:foo"), "edges: {:?}", out.edges);
    assert!(has("native:extra.node"), "edges: {:?}", out.edges);
    assert!(has("conf/settings.json"), "edges: {:?}", out.edges);
    assert!(has("logs/out.txt"), "edges: {:?}", out.edges);
}

#[test]
fn scan_rust_native_libs_and_data_includes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "#[link(name = \"sqlite3\", kind = \"dylib\")]\n\
         extern \"C\" { fn sqlite3_open(); }\n\
         pub static POLICY: &str = include_str!(\"policy.txt\");\n\
         pub static CERT: &[u8] = include_bytes!(\"certs/ca.pem\");\n",
    )
    .unwrap();
    std::fs::write(root.join("src/policy.txt"), "allow").unwrap();
    std::fs::create_dir_all(root.join("src/certs")).unwrap();
    std::fs::write(root.join("src/certs/ca.pem"), "pem").unwrap();
    std::fs::write(root.join("build.rs"),
        "fn main() { println!(\"cargo:rustc-link-lib=dylib=ssl\"); println!(\"cargo:rustc-link-search=native=/usr/lib\"); }\n")
    .unwrap();

    let out = strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Rust]).unwrap();
    let has = |s: &str, d: &str| out.edges.iter().any(|(a, b, ..)| a == s && b == d);
    assert!(
        has("src/lib.rs", "native:sqlite3"),
        "edges: {:?}",
        out.edges
    );
    assert!(
        has("src/lib.rs", "src/policy.txt"),
        "edges: {:?}",
        out.edges
    );
    assert!(
        has("src/lib.rs", "src/certs/ca.pem"),
        "edges: {:?}",
        out.edges
    );
    assert!(has("build.rs", "native:ssl"), "edges: {:?}", out.edges);
    // link-search is a dir, not a lib - no edge.
    assert!(
        !out.edges
            .iter()
            .any(|(_, d, ..)| d.contains("link-search") || d == "native:/usr/lib"),
        "edges: {:?}",
        out.edges
    );
}

#[test]
fn scan_python_entry_point_providers() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("plugin_host.py"),
        "from importlib.metadata import entry_points\n\
         eps = entry_points(group=\"myapp.filters\")\n",
    )
    .unwrap();
    // Installed provider dist with entry_points.txt.
    let di = root.join(".venv/lib/python3.11/site-packages/textpipe_future-1.2.0.dist-info");
    std::fs::create_dir_all(&di).unwrap();
    std::fs::write(
        di.join("METADATA"),
        "Name: textpipe-future\nVersion: 1.2.0\n",
    )
    .unwrap();
    std::fs::write(di.join("entry_points.txt"),
        "[myapp.filters]\nsummarize = textpipe_future:Summarize\n\n[console_scripts]\ncli = textpipe_future:main\n")
    .unwrap();

    let out =
        strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Python]).unwrap();
    // Consumer -> provider dist node (pep503-normalized name@version).
    assert!(
        out.edges
            .iter()
            .any(|(a, b, ..)| a == "plugin_host.py" && b == "textpipe-future@1.2.0"),
        "edges: {:?}",
        out.edges
    );
}

#[test]
fn scan_lockfile_drift_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // requirements pins urllib3==2.0.7 but uv.lock resolved 2.2.0.
    std::fs::write(root.join("requirements.txt"), "urllib3==2.0.7\n").unwrap();
    std::fs::write(root.join("uv.lock"),
        "version = 1\n[[package]]\nname = \"urllib3\"\nversion = \"2.2.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n")
    .unwrap();
    std::fs::write(root.join("app.py"), "import urllib3\n").unwrap();

    let out =
        strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Python]).unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("drift") || w.contains("no lockfile agrees")),
        "warnings: {:?}",
        out.warnings
    );
}

#[test]
fn scan_registry_configs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join(".npmrc"),
        "registry=https://npm.corp.example.com/\n@corp:registry=https://npm.corp.example.com/\n",
    )
    .unwrap();
    std::fs::write(
        root.join("pip.conf"),
        "[global]\nindex-url = https://pypi.corp.example.com/simple\n",
    )
    .unwrap();
    let cargo_dir = root.join(".cargo");
    std::fs::create_dir_all(&cargo_dir).unwrap();
    std::fs::write(cargo_dir.join("config.toml"),
        "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://cargo.corp.example.com/\"\n").unwrap();
    std::fs::write(
        root.join("package.json"),
        "{\"dependencies\":{\"left-pad\":\"1.3.0\"}}",
    )
    .unwrap();

    let out = strand_import::scan::scan_project(root, &[strand_import::scan::Lang::Js]).unwrap();
    let has = |d: &str| out.edges.iter().any(|(_, b, ..)| b == d);
    assert!(
        has("registry:https://npm.corp.example.com/"),
        "edges: {:?}",
        out.edges
    );
    assert!(
        has("registry:https://pypi.corp.example.com/simple"),
        "edges: {:?}",
        out.edges
    );
    assert!(
        has("registry:sparse+https://cargo.corp.example.com/"),
        "edges: {:?}",
        out.edges
    );
}
