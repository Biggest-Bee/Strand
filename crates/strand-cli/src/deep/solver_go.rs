//! Bottom-up SCC solver for Go - mirrors `solver_js.rs` over
//! `GoFile`s. NodeId = (package_dir, qualname) for functions and
//! (file_rel, "<module>") for top-level code. Same Tarjan/order/
//! fixpoint machinery; call edges resolve through
//! `facts_go::resolve_callee` (package scope + import paths +
//! type-env method resolution during analysis).
//!
//! Package-level variables are shared across a package's files:
//! `<module>` environments and type environments merge per dir
//! before function scopes are analyzed.

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::deep::facts::{Summary, VarState};
use crate::deep::facts_go::{self, analyze_function_go};
use crate::deep::go_deep::{self, GoFile, GoFuncInfo, GoModules};
use crate::deep::models::Model;
use crate::deep::solver::{order_sccs, tarjan_scc, NodeId, SolveOutput, SolveStats};

/// A function to analyze: where its body node lives.
struct FuncRef {
    file_idx: usize,
    /// Byte range of the function-ish node (None = module root).
    range: Option<(usize, usize)>,
    /// Function metadata (None for `<module>`).
    info: Option<GoFuncInfo>,
    qualname: String,

}

const FUNC_KINDS: &[&str] = &[
    "function_declaration",
    "method_declaration",
    "func_literal",
];

/// Collect all analyzable Go functions: every FuncInfo + each file's
/// top-level "<module>". Functions key by (package_dir, qualname) -
/// Go scopes them per package, so same-name funcs in different files
/// of one dir are the same entity (first definition wins; duplicate
/// definitions are a compile error anyway).
fn collect_funcs(parsed: &[GoFile]) -> HashMap<NodeId, FuncRef> {
    let mut out = HashMap::new();
    let mut seen: HashSet<NodeId> = HashSet::new();
    for (fi, f) in parsed.iter().enumerate() {
        let mkey = (f.rel.clone(), "<module>".to_string());
        seen.insert(mkey.clone());
        out.insert(
            mkey.clone(),
            FuncRef {
                file_idx: fi,
                range: None,
                info: None,
                qualname: "<module>".to_string(),
            },
        );
        for infos in f.funcs.values() {
            for info in infos {
                let key = (f.dir.clone(), info.qualname.clone());
                if !seen.insert(key.clone()) {
                    continue;
                }
                out.insert(
                    key.clone(),
                    FuncRef {
                        file_idx: fi,
                        range: Some((info.start, info.end)),
                        info: Some(info.clone()),
                        qualname: info.qualname.clone(),
                    },
                );
            }
        }
    }
    out
}

/// package dir -> indices into `parsed`.
fn pkg_dirs(parsed: &[GoFile]) -> HashMap<String, Vec<usize>> {
    let mut out: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in parsed.iter().enumerate() {
        out.entry(f.dir.clone()).or_default().push(i);
    }
    out
}

/// Recover the function-ish node for a FuncRef.
fn func_node<'t>(f: &'t GoFile, r: &FuncRef) -> Option<Node<'t>> {
    match r.range {
        None => Some(f.tree.root_node()),
        Some((s, e)) => {
            let n = f.tree.root_node().descendant_for_byte_range(s, e)?;
            if FUNC_KINDS.contains(&n.kind()) {
                return Some(n);
            }
            let mut cur = n;
            loop {
                if FUNC_KINDS.contains(&cur.kind()) {
                    return Some(cur);
                }
                cur = cur.parent()?;
            }
        }
    }
}

/// Build Go call edges (caller NodeId -> callee NodeId) restricted
/// to known functions. Resolution mirrors facts_go::resolve_callee
/// with a syntactic seed-type env (receiver methods resolve via
/// `s := &T{}` style declarations); the facts walk still applies
/// summaries with its own precise type env.
fn build_callgraph(
    parsed: &[GoFile],
    pkg_dirs: &HashMap<String, Vec<usize>>,
    mods: &GoModules,
    node_set: &HashSet<NodeId>,
    file_types: &[HashMap<String, String>],
) -> HashMap<NodeId, Vec<NodeId>> {
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    let mut seen: HashSet<(NodeId, NodeId)> = HashSet::new();
    for (fi, f) in parsed.iter().enumerate() {
        // Cheap gate: file must contain a call-ish token.
        if !f.text.contains('(') {
            continue;
        }
        let seed = &file_types[fi];
        for call in go_deep::call_nodes(f) {
            // Enclosing function -> caller NodeId.
            let caller = match go_deep::enclosing_func(call, f) {
                Some((_, info)) => (f.dir.clone(), info.qualname.clone()),
                None => (f.rel.clone(), "<module>".to_string()),
            };
            if !node_set.contains(&caller) {
                continue;
            }
            let Some(callee) =
                facts_go::resolve_callee(call, f, parsed, pkg_dirs, mods, Some(seed))
            else {
                continue;
            };
            if node_set.contains(&callee) && callee != caller {
                if seen.insert((caller.clone(), callee.clone())) {
                    adj.entry(caller).or_default().push(callee);
                }
            }
        }
    }
    adj
}

/// Run the full Go analysis.
pub fn solve_go(
    parsed: &[GoFile],
    mods: &GoModules,
    model: &Model,
) -> SolveOutput {
    let funcs = collect_funcs(parsed);
    let node_set: HashSet<NodeId> = funcs.keys().cloned().collect();
    let dirs = pkg_dirs(parsed);

    // Syntactic seed types: package-level `var` decls merge per
    // package dir; function-local decls stay per file (keyed by
    // file index) to avoid cross-file name pollution.
    let mut pkg_seed_types: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut file_seed_types: Vec<HashMap<String, String>> = vec![HashMap::new(); parsed.len()];
    for (i, f) in parsed.iter().enumerate() {
        let (local, pkg) = go_deep::seed_types(f);
        file_seed_types[i] = local;
        let t = pkg_seed_types.entry(f.dir.clone()).or_default();
        for (k, v) in pkg {
            t.entry(k).or_insert(v);
        }
    }
    // Per-file view: package seeds overlaid with that file's locals.
    let file_types: Vec<HashMap<String, String>> = parsed
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut m = pkg_seed_types.get(&f.dir).cloned().unwrap_or_default();
            for (k, v) in &file_seed_types[i] {
                m.insert(k.clone(), v.clone());
            }
            m
        })
        .collect();

    let adj = build_callgraph(parsed, &dirs, mods, &node_set, &file_types);

    let sccs = tarjan_scc(&node_set, &adj);
    let ordered = order_sccs(sccs, &adj);

    // Phase 0: per-file `<module>` analysis. Envs merge per package
    // dir (package-level vars are shared); types merge likewise.
    let empty_sums: HashMap<NodeId, Summary> = HashMap::new();
    let module_results: Vec<(usize, crate::deep::facts::FuncAnalysis, HashMap<String, String>)> =
        funcs
            .values()
            .filter(|r| r.qualname == "<module>")
            .collect::<Vec<_>>()
            .par_iter()
            .filter_map(|r| {
                let f = &parsed[r.file_idx];
                let (analysis, types) = analyze_function_go(
                    f,
                    f.tree.root_node(),
                    None,
                    "<module>",
                    model,
                    &empty_sums,
                    None,
                    None,
                    parsed,
                    &dirs,
                    mods,
                );
                Some((r.file_idx, analysis, types))
            })
            .collect();

    // Merge module envs + types per package dir.
    let mut pkg_globals: HashMap<String, HashMap<String, VarState>> = HashMap::new();
    let mut pkg_types: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (fi, analysis, types) in module_results {
        let dir = parsed[fi].dir.clone();
        let g = pkg_globals.entry(dir.clone()).or_default();
        for (k, v) in analysis.env {
            g.entry(k).or_default().join(&v);
        }
        let t = pkg_types.entry(dir).or_default();
        for (k, v) in types {
            t.entry(k).or_insert(v);
        }
    }
    // Package-level seed types fill gaps the module walk did not
    // reach (top-level `var s T` decls). Function-local seeds are
    // deliberately excluded - they are file-scoped.
    for (dir, seeds) in &pkg_seed_types {
        let t = pkg_types.entry(dir.clone()).or_default();
        for (k, v) in seeds {
            t.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    let mut summaries: HashMap<NodeId, Summary> = HashMap::new();
    let mut findings_dedup: HashMap<
        (SinkKindKey, String, u32, String, String),
        crate::deep::facts::Finding,
    > = HashMap::new();
    let mut stats = SolveStats {
        functions: funcs.len(),
        sccs: ordered.len(),
        cyclic_sccs: 0,
        fixpoint_iters: 0,
        findings: 0,
        budget_exceeded: 0,
    };

    for scc in &ordered {
        let cyclic = scc.len() > 1
            || scc
                .iter()
                .any(|n| adj.get(n).is_some_and(|v| v.contains(n)));
        if cyclic {
            stats.cyclic_sccs += 1;
        }
        let max_iters = if cyclic { 5 } else { 1 };
        for iter in 0..max_iters {
            let mut changed = false;
            for node in scc {
                let Some(fref) = funcs.get(node) else {
                    continue;
                };
                let f = &parsed[fref.file_idx];
                let Some(fnode) = func_node(f, fref) else {
                    continue;
                };
                let is_module = fref.qualname == "<module>";
                let globals = if is_module {
                    None
                } else {
                    pkg_globals.get(&f.dir)
                };
                let pt = if is_module {
                    None
                } else {
                    pkg_types.get(&f.dir)
                };
                let (analysis, _types) = analyze_function_go(
                    f,
                    fnode,
                    fref.info.as_ref(),
                    &fref.qualname,
                    model,
                    &summaries,
                    globals,
                    pt,
                    parsed,
                    &dirs,
                    mods,
                );
                if analysis.budget_hit {
                    stats.budget_exceeded += 1;
                }
                for finding in &analysis.summary.findings {
                    let key = (
                        SinkKindKey(finding.class.clone()),
                        finding.file.clone(),
                        finding.line,
                        finding.sink.clone(),
                        finding.source.clone(),
                    );
                    findings_dedup.entry(key).or_insert_with(|| finding.clone());
                }
                let sum = analysis.summary;
                let old = summaries.get(node);
                if old.is_none_or(|o| !o.flows_equal(&sum)) {
                    changed = true;
                }
                summaries.insert(node.clone(), sum);
            }
            stats.fixpoint_iters += 1;
            if !changed || iter + 1 == max_iters {
                break;
            }
        }
    }

    let mut findings: Vec<crate::deep::facts::Finding> = findings_dedup.into_values().collect();
    findings.sort_by(|a, b| {
        (&a.file, a.line, format!("{:?}", a.class), &a.sink).cmp(&(
            &b.file,
            b.line,
            format!("{:?}", b.class),
            &b.sink,
        ))
    });
    stats.findings = findings.len();

    SolveOutput {
        summaries,
        findings,
        stats,
    }
}

/// Wrapper for Ord on SinkKind in the dedup key (mirrors solver_js).
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct SinkKindKey(crate::deep::models::SinkKind);
