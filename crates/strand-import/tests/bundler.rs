//! "Ask the build tool" importer tests: webpack stats.json and
//! esbuild metafile JSON -> edge lists.

use strand_import::{detect_format, parse, EdgeList, Format};

fn pairs(edges: &EdgeList) -> Vec<(String, String)> {
    edges
        .iter()
        .map(|(s, d, _, _)| (s.clone(), d.clone()))
        .collect()
}

#[test]
fn webpack_stats_resolves_module_deps() {
    // Shape mirrors `webpack --json`: modules[].name is the
    // context-relative id, dependencies[] carry the resolved target
    // in `module`/`moduleId` (same namespace) plus absolute
    // `resolvedModule` and `external` flags.
    let json = r##"{
        "hash": "abc123",
        "outputPath": "/proj/dist",
        "modules": [
            {
                "name": "./src/app.ts",
                "identifier": "/proj/src/app.ts",
                "dependencies": [
                    {"module": "./src/lib/util.ts", "request": "./lib/util",
                     "resolvedModule": "/proj/src/lib/util.ts"},
                    {"module": "./src/dynamic.ts", "request": "./dynamic",
                     "resolvedModule": "/proj/src/dynamic.ts"},
                    {"module": "react", "external": true, "request": "react"},
                    {"module": "fs", "external": true, "request": "fs"}
                ]
            },
            {
                "name": "./src/lib/util.ts",
                "identifier": "/proj/src/lib/util.ts",
                "dependencies": [
                    {"module": "./src/types.ts", "request": "./types",
                     "resolvedModule": "/proj/src/types.ts"}
                ]
            },
            {
                "name": "./src/dynamic.ts",
                "identifier": "/proj/src/dynamic.ts",
                "dependencies": []
            },
            {
                "name": "./src/types.ts",
                "identifier": "/proj/src/types.ts"
            }
        ]
    }"##;
    let edges = parse(json, Format::WebpackStats).unwrap();
    let p = pairs(&edges);
    assert!(
        p.contains(&("src/app.ts".into(), "src/lib/util.ts".into())),
        "{p:?}"
    );
    assert!(
        p.contains(&("src/app.ts".into(), "src/dynamic.ts".into())),
        "{p:?}"
    );
    assert!(
        p.contains(&("src/lib/util.ts".into(), "src/types.ts".into())),
        "{p:?}"
    );
    // Externals and self-loops are excluded.
    assert_eq!(edges.len(), 3, "{p:?}");
    // Bundler-resolved edges are Resolved, not Static.
    assert!(edges
        .iter()
        .all(|(_, _, _, k)| { *k == strand_core::EdgeKind::Resolved }));
}

#[test]
fn webpack_stats_nested_modules() {
    // Concatenated modules nest under `modules`.
    let json = r##"{
        "hash": "x", "modules": [
            {"name": "./src/a.ts", "dependencies": [
                {"module": "./src/b.ts"}
            ], "modules": [
                {"name": "./src/inner.ts", "dependencies": [
                    {"module": "./src/b.ts"}
                ]}
            ]}
        ]
    }"##;
    let edges = parse(json, Format::WebpackStats).unwrap();
    let p = pairs(&edges);
    assert!(p.contains(&("src/a.ts".into(), "src/b.ts".into())), "{p:?}");
    assert!(
        p.contains(&("src/inner.ts".into(), "src/b.ts".into())),
        "{p:?}"
    );
}

#[test]
fn esbuild_meta_resolves_relative_imports() {
    let json = r##"{
        "inputs": {
            "src/app.ts": {
                "bytes": 100,
                "imports": [
                    {"path": "./lib/util", "kind": "import-statement"},
                    {"path": "./styles.css", "kind": "import-rule"},
                    {"path": "react", "kind": "import-statement", "external": true},
                    {"path": "./missing", "kind": "dynamic-import"}
                ]
            },
            "src/lib/util.ts": {"bytes": 50, "imports": []},
            "src/lib/helper.tsx": {"bytes": 30, "imports": []}
        },
        "outputs": {"dist/out.js": {"bytes": 999}}
    }"##;
    let edges = parse(json, Format::EsbuildMeta).unwrap();
    let p = pairs(&edges);
    // ./lib/util resolves via extension probing to util.ts.
    assert!(
        p.contains(&("src/app.ts".into(), "src/lib/util.ts".into())),
        "{p:?}"
    );
    // ./styles.css isn't a JS/TS input - skipped (not a scanned node).
    // ./missing has no matching input - skipped.
    // react is external - skipped.
    assert_eq!(edges.len(), 1, "{p:?}");
}

#[test]
fn esbuild_meta_index_and_parent_dir() {
    let json = r##"{
        "inputs": {
            "src/pages/home/index.tsx": {"bytes": 1, "imports": [
                {"path": "../shared", "kind": "import-statement"}
            ]},
            "src/pages/shared.ts": {"bytes": 1, "imports": []},
            "src/pages/shared/index.ts": {"bytes": 1, "imports": []}
        },
        "outputs": {}
    }"##;
    let edges = parse(json, Format::EsbuildMeta).unwrap();
    let p = pairs(&edges);
    // ../shared from src/pages/home -> src/pages/shared; direct file
    // hit wins over index probing? base "src/pages/shared" isn't an
    // input, so .ts probe hits src/pages/shared.ts first.
    assert!(
        p.contains(&(
            "src/pages/home/index.tsx".into(),
            "src/pages/shared.ts".into()
        )),
        "{p:?}"
    );
}

#[test]
fn detect_format_recognizes_bundler_json() {
    let wp = std::path::Path::new("stats.json");
    assert_eq!(
        detect_format(wp, r#"{"hash":"x","modules":[],"outputPath":"/d"}"#),
        Format::WebpackStats
    );
    let es = std::path::Path::new("meta.json");
    assert_eq!(
        detect_format(es, r#"{"inputs":{},"outputs":{}}"#),
        Format::EsbuildMeta
    );
    // cargo metadata still wins for its shape.
    let cargo = std::path::Path::new("meta.json");
    assert_eq!(
        detect_format(cargo, r#"{"packages":[],"workspace_members":[]}"#),
        Format::Cargo
    );
}
