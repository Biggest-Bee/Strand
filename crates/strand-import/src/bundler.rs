//! "Ask the build tool" importers: parse bundler metadata output
//! (`webpack --json` stats, `esbuild --metafile`) into edge lists.
//!
//! The bundler already resolved aliases, extension guessing, dynamic
//! `require.context`-style patterns, and loader chains - edges it
//! reports are deterministic, so they import as
//! [`strand_core::EdgeKind::Resolved`] (below `Static`, above
//! `Declared`). Paths are normalized to the module names webpack
//! reports (`./src/a.ts` -> `src/a.ts`); external/ node_modules
//! targets are skipped, matching the scan convention that
//! third-party packages are not nodes.

use std::collections::BTreeSet;

use serde_json::Value;
use strand_core::EdgeKind;

use crate::{err, EdgeList, Result};

/// `webpack --json` stats output.
pub fn webpack_stats(text: &str) -> Result<EdgeList> {
    let v: Value = serde_json::from_str(text).map_err(|e| err(format!("webpack stats: {e}")))?;
    let mut edges = EdgeList::new();
    let mut seen = BTreeSet::new();
    collect_modules(&v, &mut |module| {
        let Some(src) = module_path(module) else {
            return;
        };
        // `dependencies` may be absent; `modules` can nest (concatenated
        // modules) - handled by the outer recursion.
        if let Some(deps) = module.get("dependencies").and_then(Value::as_array) {
            for dep in deps {
                // Externals (node_modules, node: builtins) are not
                // project files - skip like the scanners do.
                if dep.get("external").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                let Some(dst) = dep_path(dep) else {
                    continue;
                };
                if src != dst && seen.insert((src.clone(), dst.clone())) {
                    edges.push((src.clone(), dst, None, EdgeKind::Resolved));
                }
            }
        }
    });
    Ok(edges)
}

/// Walk `modules` arrays recursively (webpack nests concatenated
/// modules) and call `f` on each module object.
fn collect_modules(v: &Value, f: &mut dyn FnMut(&Value)) {
    let Some(arr) = v.get("modules").and_then(Value::as_array) else {
        return;
    };
    for m in arr {
        f(m);
        collect_modules(m, f);
    }
}

/// A module's project-relative path: prefer `name` (context-relative,
/// e.g. `./src/a.ts`), fall back to `identifier` (absolute - kept
/// as-is since we can't know the context root).
fn module_path(m: &Value) -> Option<String> {
    for key in ["name", "identifier"] {
        if let Some(s) = m.get(key).and_then(Value::as_str) {
            let p = normalize_module_path(s);
            if !p.is_empty() && !p.starts_with("..") {
                return Some(p);
            }
        }
    }
    None
}

/// A dependency's resolved target path. `module`/`moduleId` share the
/// module `name` namespace (`./src/b.js`) so node names stay
/// consistent; `resolvedModule` is an absolute path - last resort.
fn dep_path(dep: &Value) -> Option<String> {
    for key in ["module", "moduleId", "resolvedModule"] {
        if let Some(s) = dep.get(key).and_then(Value::as_str) {
            let p = normalize_module_path(s);
            if !p.is_empty() && !p.starts_with("..") {
                return Some(p);
            }
        }
    }
    None
}

/// `./src/a.ts` -> `src/a.ts`; absolute paths keep their tail after
/// the last occurrence of a plausible project marker is impossible
/// without context, so absolute paths are kept verbatim (still
/// consistent node names within one stats file).
fn normalize_module_path(s: &str) -> String {
    let s = s.trim();
    let s = s.strip_prefix("./").unwrap_or(s);
    // Strip a leading slash only for obvious webpack "multi-module"
    // prefixes like "./node_modules/..." is NOT stripped - externals
    // are filtered earlier; keep the path as reported otherwise.
    s.replace('\\', "/")
}

/// `esbuild --metafile` JSON output.
///
/// `inputs` maps each source file to its byte size and `imports`
/// (the specifiers it imports, with `kind` and `external` flags).
/// Specifiers are resolved against the input set: relative paths get
/// extension/index probing (`./b` from `src/a.ts` tries
/// `src/b.ts`, `src/b.tsx`, ..., `src/b/index.ts`); bare specifiers
/// marked external are skipped, unmarked ones that match an input
/// path are linked (esbuild records the resolved path in `path` for
/// some kinds).
pub fn esbuild_meta(text: &str) -> Result<EdgeList> {
    let v: Value = serde_json::from_str(text).map_err(|e| err(format!("esbuild metafile: {e}")))?;
    let inputs = v
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| err("esbuild metafile: missing 'inputs'"))?;

    // Normalized input path set for resolution.
    let input_paths: BTreeSet<String> = inputs.keys().map(|k| normalize_module_path(k)).collect();

    let mut edges = EdgeList::new();
    let mut seen = BTreeSet::new();
    for (input, info) in inputs {
        let src = normalize_module_path(input);
        let Some(imps) = info.get("imports").and_then(Value::as_array) else {
            continue;
        };
        for imp in imps {
            if imp.get("external").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(spec) = imp.get("path").and_then(Value::as_str) else {
                continue;
            };
            let Some(dst) = resolve_esbuild_spec(&src, spec, &input_paths) else {
                continue;
            };
            if src != dst && seen.insert((src.clone(), dst.clone())) {
                edges.push((src.clone(), dst, None, EdgeKind::Resolved));
            }
        }
    }
    Ok(edges)
}

/// Resolve an esbuild import specifier against the known input set.
/// Relative specifiers resolve against the importer's directory with
/// JS/TS extension and `index.*` probing; bare specifiers only link
/// when they literally name an input path.
fn resolve_esbuild_spec(src: &str, spec: &str, inputs: &BTreeSet<String>) -> Option<String> {
    if spec.starts_with('.') {
        let dir = src.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let joined = if dir.is_empty() {
            spec.trim_start_matches("./").to_string()
        } else {
            format!("{dir}/{}", spec.trim_start_matches("./"))
        };
        // Normalize any "a/../b" segments naively.
        let mut parts: Vec<&str> = Vec::new();
        for seg in joined.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        let base = parts.join("/");
        // Direct hit, then extension probes, then index probes.
        if inputs.contains(&base) {
            return Some(base);
        }
        for ext in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
            let cand = format!("{base}.{ext}");
            if inputs.contains(&cand) {
                return Some(cand);
            }
        }
        for ext in ["ts", "tsx", "js", "jsx"] {
            let cand = format!("{base}/index.{ext}");
            if inputs.contains(&cand) {
                return Some(cand);
            }
        }
        return None;
    }
    // Bare specifier: only link if it literally matches an input
    // (path-mapped packages); otherwise it's a node_modules dep.
    let norm = normalize_module_path(spec);
    inputs.contains(&norm).then_some(norm)
}

/// Which bundler format a JSON text is, for [`crate::detect_format`].
pub fn sniff(text: &str) -> Option<crate::Format> {
    let t = text.trim_start();
    if !t.starts_with('{') {
        return None;
    }
    // esbuild metafile: top-level "inputs" + "outputs" objects.
    if t.contains("\"inputs\"") && t.contains("\"outputs\"") {
        return Some(crate::Format::EsbuildMeta);
    }
    // webpack stats: top-level "modules" array plus webpack markers.
    if t.contains("\"modules\"")
        && (t.contains("\"hash\"") || t.contains("\"outputPath\"") || t.contains("\"publicPath\""))
    {
        return Some(crate::Format::WebpackStats);
    }
    None
}
