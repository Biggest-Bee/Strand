//! Bottom-up SCC solver for Rust - mirrors `solver_go.rs` over
//! `RsFile`s. NodeId = (file_rel, qualname): Rust items are
//! file-scoped modules, so functions key per file. `<module>` covers
//! top-level items (const/static initializers, macro calls).
//! Call edges resolve through `facts_rs::resolve_callee` (same-file
//! funcs, `::` paths via the module-suffix index, and type-env
//! method resolution during analysis).

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::deep::facts::{Summary, VarState};
use crate::deep::facts_rs::{self, analyze_function_rs};
use crate::deep::models::Model;
use crate::deep::rust_deep::{self, RsFile, RsFuncInfo};
use crate::deep::solver::{order_sccs, tarjan_scc, NodeId, SolveOutput, SolveStats};

/// A function to analyze: where its body node lives.
struct FuncRef {
    file_idx: usize,
    /// Byte range of the function-ish node (None = module root).
    range: Option<(usize, usize)>,
    /// Function metadata (None for `<module>`).
    info: Option<RsFuncInfo>,
    qualname: String,
}

/// Collect all analyzable Rust functions: every FuncInfo + each
/// file's top-level "<module>". Functions key by (file_rel,
/// qualname) - Rust scopes them per module (file), so same-name
/// funcs in different files are distinct entities.
fn collect_funcs(parsed: &[RsFile]) -> HashMap<NodeId, FuncRef> {
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
                let key = (f.rel.clone(), info.qualname.clone());
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

/// rel path -> file index.
fn file_index(parsed: &[RsFile]) -> HashMap<String, usize> {
    parsed
        .iter()
        .enumerate()
        .map(|(i, f)| (f.rel.clone(), i))
        .collect()
}

/// Recover the function-ish node for a FuncRef.
fn func_node<'t>(f: &'t RsFile, r: &FuncRef) -> Option<Node<'t>> {
    match r.range {
        None => Some(f.tree.root_node()),
        Some((s, e)) => {
            let n = f.tree.root_node().descendant_for_byte_range(s, e)?;
            if n.kind() == "function_item" {
                return Some(n);
            }
            let mut cur = n;
            loop {
                if cur.kind() == "function_item" {
                    return Some(cur);
                }
                cur = cur.parent()?;
            }
        }
    }
}

/// Build Rust call edges (caller NodeId -> callee NodeId)
/// restricted to known functions. Resolution mirrors
/// facts_rs::resolve_callee with no type env (typed-method calls
/// stay unresolved here - the facts walk resolves them with types
/// for summary application).
fn build_callgraph(
    parsed: &[RsFile],
    index: &HashMap<String, usize>,
    mod_index: &HashMap<String, usize>,
    node_set: &HashSet<NodeId>,
) -> HashMap<NodeId, Vec<NodeId>> {
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    let mut seen: HashSet<(NodeId, NodeId)> = HashSet::new();
    // Syntactic seed types (`let r = Runner::new()`, `let x: T`)
    // let method calls resolve for edge-building; the facts walk
    // rebuilds precise types during analysis.
    let seed: HashMap<String, HashMap<String, String>> = parsed
        .iter()
        .map(|f| (f.rel.clone(), rust_deep::seed_types(f)))
        .collect();
    for f in parsed.iter() {
        // Cheap gate: file must contain a call-ish token.
        if !f.text.contains('(') {
            continue;
        }
        for call in rust_deep::call_nodes(f) {
            // Enclosing function -> caller NodeId.
            let caller = match rust_deep::enclosing_func(call, f) {
                Some((qualname, _)) => (f.rel.clone(), qualname),
                None => (f.rel.clone(), "<module>".to_string()),
            };
            if !node_set.contains(&caller) {
                continue;
            }
            let Some(callee) = facts_rs::resolve_callee(
                call,
                f,
                parsed,
                index,
                mod_index,
                seed.get(&f.rel),
            ) else {
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

/// Run the full Rust analysis.
pub fn solve_rs(parsed: &[RsFile], model: &Model) -> SolveOutput {
    let funcs = collect_funcs(parsed);
    let node_set: HashSet<NodeId> = funcs.keys().cloned().collect();
    let index = file_index(parsed);
    let mod_index = rust_deep::module_index(parsed);

    let adj = build_callgraph(parsed, &index, &mod_index, &node_set);

    let sccs = tarjan_scc(&node_set, &adj);
    let ordered = order_sccs(sccs, &adj);

    // Phase 0: per-file `<module>` analysis. Envs merge per file
    // (Rust items are file-scoped); types merge likewise.
    let empty_sums: HashMap<NodeId, Summary> = HashMap::new();
    let module_results: Vec<(usize, crate::deep::facts::FuncAnalysis, HashMap<String, String>)> =
        funcs
            .values()
            .filter(|r| r.qualname == "<module>")
            .collect::<Vec<_>>()
            .par_iter()
            .filter_map(|r| {
                let f = &parsed[r.file_idx];
                let (analysis, types) = analyze_function_rs(
                    f,
                    f.tree.root_node(),
                    None,
                    "<module>",
                    model,
                    &empty_sums,
                    None,
                    None,
                    parsed,
                    &index,
                    &mod_index,
                );
                Some((r.file_idx, analysis, types))
            })
            .collect();

    // Merge module envs + types per file.
    let mut file_globals: HashMap<String, HashMap<String, VarState>> = HashMap::new();
    let mut file_types: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (fi, analysis, types) in module_results {
        let rel = parsed[fi].rel.clone();
        let g = file_globals.entry(rel.clone()).or_default();
        for (k, v) in analysis.env {
            g.entry(k).or_default().join(&v);
        }
        let t = file_types.entry(rel).or_default();
        for (k, v) in types {
            t.entry(k).or_insert(v);
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
                    file_globals.get(&f.rel)
                };
                let pt = if is_module {
                    None
                } else {
                    file_types.get(&f.rel)
                };
                let (analysis, _types) = analyze_function_rs(
                    f,
                    fnode,
                    fref.info.as_ref(),
                    &fref.qualname,
                    model,
                    &summaries,
                    globals,
                    pt,
                    parsed,
                    &index,
                    &mod_index,
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

/// Wrapper for Ord on SinkKind in the dedup key (mirrors solver_js/go).
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct SinkKindKey(crate::deep::models::SinkKind);
