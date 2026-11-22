//! Regression tests for JS/TS and Python module resolution edge cases:
//! .mts/.cts/.d.ts, `.js`->`.ts` specifier remapping, JSON imports,
//! .pyi stubs, runpy.run_module/run_path.

use std::fs;
use std::path::Path;

use strand_import::scan::{scan_lang, Lang};

fn w(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

fn has_edge(out: &strand_import::scan::ScanOutput, src: &str, dst: &str) -> bool {
    out.edges.iter().any(|(s, d, _, _)| s == src && d == dst)
}

#[test]
fn js_mts_cts_dts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/mod.mts", "export const m = 1;\n");
    w(root, "src/legacy.cts", "export {};\n");
    w(root, "src/decl.d.ts", "export declare const d: number;\n");
    w(
        root,
        "src/use.ts",
        "import { m } from './mod.mjs';\nimport './legacy.cjs';\nimport { d } from './decl';\n",
    );
    let out = scan_lang(root, Lang::Js).unwrap();
    assert!(out.nodes.contains(&"src/mod.mts".to_string()));
    assert!(out.nodes.contains(&"src/legacy.cts".to_string()));
    assert!(has_edge(&out, "src/use.ts", "src/mod.mts"));
    assert!(has_edge(&out, "src/use.ts", "src/legacy.cts"));
    assert!(has_edge(&out, "src/use.ts", "src/decl.d.ts"));
}

#[test]
fn js_extension_remap() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/real.ts", "export const r = 1;\n");
    w(root, "src/use.ts", "import { r } from './real.js';\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    assert!(has_edge(&out, "src/use.ts", "src/real.ts"));
}

#[test]
fn js_json_import() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "src/data.json", "{\"a\": 1}\n");
    w(root, "src/use.ts", "import data from './data.json';\n");
    let out = scan_lang(root, Lang::Js).unwrap();
    assert!(has_edge(&out, "src/use.ts", "src/data.json"));
    // The json file itself contributes no import edges.
    assert!(!out.edges.iter().any(|(s, _, _, _)| s == "src/data.json"));
}

#[test]
fn py_pyi_stub_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/stub.pyi", "def f() -> int: ...\n");
    w(root, "pkg/impl.py", "def f() -> int: return 1\n");
    w(root, "user.py", "from pkg import stub\nfrom pkg import impl\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    assert!(has_edge(&out, "user.py", "pkg/stub.pyi"));
    assert!(has_edge(&out, "user.py", "pkg/impl.py"));
    // .py wins over .pyi for the same module name.
    w(root, "pkg/both.py", "x = 1\n");
    w(root, "pkg/both.pyi", "x: int\n");
    w(root, "user2.py", "import pkg.both\n");
    let out = scan_lang(root, Lang::Python).unwrap();
    assert!(has_edge(&out, "user2.py", "pkg/both.py"));
    assert!(!has_edge(&out, "user2.py", "pkg/both.pyi"));
}

#[test]
fn py_runpy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    w(root, "pkg/__init__.py", "");
    w(root, "pkg/mod.py", "");
    w(root, "scripts/tool.py", "print(1)\n");
    w(
        root,
        "runner.py",
        "import runpy\nrunpy.run_module(\"pkg.mod\")\nrunpy.run_path(\"scripts/tool.py\")\n",
    );
    let out = scan_lang(root, Lang::Python).unwrap();
    assert!(has_edge(&out, "runner.py", "pkg/mod.py"));
    assert!(has_edge(&out, "runner.py", "scripts/tool.py"));
}
