//! Bottom-up SCC solver for JS/TS - mirrors `solver.rs` over
//! `JsFile`s. NodeId = (file_rel, qualname); "<module>" is top-level
//! code. Same Tarjan/order/fixpoint machinery, JS call edges built
//! from `call_expression`s resolved through `facts_js::resolve_callee`.

use rayon::prelude::*;
use std::collections::{BTreeSet, HashMap, HashSet};

use tree_sitter::Node;

use crate::facts::{Summary, VarState};
use crate::facts_js::{self, analyze_function_js};
use crate::js_ipa::{self, JsFile};
use crate::models::Model;
use crate::solver::{order_sccs, tarjan_scc, NodeId, SolveOutput, SolveStats};

/// A function to analyze: where its body node lives.
struct FuncRef {
    file_idx: usize,
    /// Byte range of the function-ish node (None = module root).
    range: Option<(usize, usize)>,
    params: Vec<String>,
    qualname: String,
}

/// Collect all analyzable JS functions: every FuncInfo + each file's
/// top-level "<module>". Group by qualname; last definition wins
/// (JS has no stub concept here; redeclarations shadow).
fn collect_funcs(parsed: &[JsFile]) -> HashMap<NodeId, FuncRef> {
    let mut out = HashMap::new();
    for (fi, f) in parsed.iter().enumerate() {
        out.insert(
            (f.rel.clone(), "<module>".to_string()),
            FuncRef {
                file_idx: fi,
                range: None,
                params: Vec::new(),
                qualname: "<module>".to_string(),
            },
        );
        let mut by_qual: HashMap<String, &crate::ipa::FuncInfo> = HashMap::new();
        for infos in f.funcs.values() {
            for info in infos {
                by_qual.insert(info.qualname.clone(), info);
            }
        }
        for (qual, info) in by_qual {
            out.insert(
                (f.rel.clone(), qual.clone()),
                FuncRef {
                    file_idx: fi,
                    range: Some((info.start, info.end)),
                    params: info.params.clone(),
                    qualname: qual,
                },
            );
        }
    }
    out
}

const FUNC_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
];

/// Recover the function-ish node for a FuncRef.
fn func_node<'t>(f: &'t JsFile, r: &FuncRef) -> Option<Node<'t>> {
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

/// Build JS call edges (caller NodeId -> callee NodeId) restricted
/// to known functions. Resolution mirrors facts_js::resolve_callee.
fn build_callgraph(
    parsed: &[JsFile],
    file_index: &HashMap<String, usize>,
    file_set: &BTreeSet<String>,
    node_set: &HashSet<NodeId>,
) -> HashMap<NodeId, Vec<NodeId>> {
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    let mut seen: HashSet<(NodeId, NodeId)> = HashSet::new();
    for (fi, f) in parsed.iter().enumerate() {
        let _ = fi;
        // Cheap gate: file must contain a call-ish token.
        if !f.text.contains('(') {
            continue;
        }
        for call in js_ipa::call_nodes(f) {
            // Enclosing function -> caller NodeId.
            let caller = match js_ipa::enclosing_func(call, f) {
                Some((_, info)) => (f.rel.clone(), info.qualname.clone()),
                None => (f.rel.clone(), "<module>".to_string()),
            };
            if !node_set.contains(&caller) {
                continue;
            }
            let Some(callee) = facts_js::resolve_callee(call, f, parsed, file_index, file_set)
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

/// Run the full JS/TS analysis.
pub fn solve_js(parsed: &[JsFile], file_set: &BTreeSet<String>, model: &Model) -> SolveOutput {
    let funcs = collect_funcs(parsed);
    let node_set: HashSet<NodeId> = funcs.keys().cloned().collect();
    let file_index: HashMap<String, usize> = parsed
        .iter()
        .enumerate()
        .map(|(i, f)| (f.rel.clone(), i))
        .collect();

    let adj = build_callgraph(parsed, &file_index, file_set, &node_set);

    let sccs = tarjan_scc(&node_set, &adj);
    let ordered = order_sccs(sccs, &adj);

    // Phase 0: module-level environments seed function scopes.
    let empty_sums: HashMap<NodeId, Summary> = HashMap::new();
    let module_envs: Vec<(usize, HashMap<String, VarState>)> = funcs
        .values()
        .filter(|r| r.qualname == "<module>")
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|r| {
            let f = &parsed[r.file_idx];
            let analysis = analyze_function_js(
                f,
                f.tree.root_node(),
                &[],
                "<module>",
                model,
                &empty_sums,
                None,
                file_set,
                parsed,
                &file_index,
                true,
            );
            Some((r.file_idx, analysis.env))
        })
        .collect();
    let file_globals: HashMap<usize, HashMap<String, VarState>> = module_envs.into_iter().collect();

    let mut summaries: HashMap<NodeId, Summary> = HashMap::new();
    let mut findings_dedup: HashMap<
        (SinkKindKey, String, u32, String, String),
        crate::facts::Finding,
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
                let globals = if fref.qualname == "<module>" {
                    None
                } else {
                    file_globals.get(&fref.file_idx)
                };
                let analysis = analyze_function_js(
                    f,
                    fnode,
                    &fref.params,
                    &fref.qualname,
                    model,
                    &summaries,
                    globals,
                    file_set,
                    parsed,
                    &file_index,
                    fref.qualname == "<module>",
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

    let mut findings: Vec<crate::facts::Finding> = findings_dedup.into_values().collect();
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

/// Wrapper for Ord on SinkKind in the dedup key (mirrors solver.rs).
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct SinkKindKey(crate::models::SinkKind);
