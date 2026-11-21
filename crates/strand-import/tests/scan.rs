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
    for (s, d, _) in &out.edges {
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
    assert!(out.edges.iter().any(|(s, d, _)| {
        s == "crates/strand-gui/src/main.rs" && d == "crates/strand-core/src/algo/mod.rs"
    }));
    assert!(out.edges.iter().any(|(s, d, _)| {
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
