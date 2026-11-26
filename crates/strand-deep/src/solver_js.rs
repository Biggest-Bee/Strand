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
    params: Vec<Vec<String>>,
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

/// A resolved JS call site kept for type inference.
struct JsSite<'a> {
    caller: NodeId,
    callee: NodeId,
    call: Node<'a>,
}

/// Build JS call edges (caller NodeId -> callee NodeId) restricted
/// to known functions, plus the resolved sites for inference.
/// Resolution mirrors facts_js::resolve_callee.
fn build_callgraph<'a>(
    parsed: &'a [JsFile],
    file_index: &HashMap<String, usize>,
    file_set: &BTreeSet<String>,
    node_set: &HashSet<NodeId>,
    extra: &crate::ipa::AllSeeds,
) -> (HashMap<NodeId, Vec<NodeId>>, Vec<JsSite<'a>>) {
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    let mut sites = Vec::new();
    let mut seen: HashSet<(NodeId, NodeId)> = HashSet::new();
    for (fi, f) in parsed.iter().enumerate() {
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
            let Some(callee) = facts_js::resolve_callee(
                call,
                f,
                parsed,
                file_index,
                file_set,
                extra.get(&fi),
            ) else {
                continue;
            };
            if node_set.contains(&callee) && callee != caller {
                sites.push(JsSite {
                    caller: caller.clone(),
                    callee: callee.clone(),
                    call,
                });
                if seen.insert((caller.clone(), callee.clone())) {
                    adj.entry(caller).or_default().push(callee);
                }
            }
        }
    }
    (adj, sites)
}

/// Enclosing JS scope start_byte for `node`, or u32::MAX.
fn js_scope_key_at(node: Node) -> u32 {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if js_ipa::is_js_scope(n.kind()) {
            return n.start_byte() as u32;
        }
        anc = n.parent();
    }
    u32::MAX
}

/// Class a seed/ctor expression resolves to (spec, class), or None.
fn js_seed_class_of(
    node: Node,
    f: &JsFile,
    extra: Option<&crate::ipa::FileSeeds>,
) -> Option<(String, String)> {
    let text = f.text.as_str();
    match node.kind() {
        "new_expression" => {
            let ctor = node.child_by_field_name("constructor")?;
            js_ipa::js_ctor_target(ctor, text, &f.bindings)
        }
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            js_ipa::ctor_seed_at(node, f, name, extra)
        }
        "member_expression" | "subscript_expression" | "this"
        | "parenthesized_expression" => {
            let key = js_ipa::js_dotted(node, text)?;
            js_ipa::ctor_seed_at(node, f, &key, extra)
        }
        _ => None,
    }
}

/// `return` expressions owned by `fnode` (nested functions skipped);
/// arrow implicit returns count via the body expression.
fn js_return_exprs(fnode: Node) -> Vec<Node> {
    let mut out = Vec::new();
    if fnode.kind() == "arrow_function" {
        if let Some(body) = fnode.child_by_field_name("body") {
            if body.kind() != "statement_block" {
                out.push(body);
                return out;
            }
        }
    }
    let mut stack: Vec<Node> =
        fnode.children(&mut fnode.walk()).collect();
    while let Some(n) = stack.pop() {
        match n.kind() {
            k if js_ipa::is_js_scope(k) => {}
            "return_statement" => {
                if let Some(e) = n.named_child(0) {
                    out.push(e);
                }
            }
            _ => stack.extend(n.children(&mut n.walk())),
        }
    }
    out
}

/// LHS var key when `call` is the RHS of a declarator/assignment.
fn js_assignment_lhs(call: Node, f: &JsFile) -> Option<String> {
    let p = call.parent()?;
    let lhs = match p.kind() {
        "variable_declarator" => {
            if p.child_by_field_name("value")?.id() != call.id() {
                return None;
            }
            p.child_by_field_name("name")?
        }
        "assignment_expression" => {
            if p.child_by_field_name("right")?.id() != call.id() {
                return None;
            }
            p.child_by_field_name("left")?
        }
        _ => return None,
    };
    js_ipa::js_seed_lhs(lhs, f.text.as_str())
}

/// One round of JS param/return type inference; seeds only when all
/// observed sites agree on a single class.
fn infer_js_seeds<'a>(
    parsed: &'a [JsFile],
    funcs: &HashMap<NodeId, FuncRef>,
    sites: &[JsSite<'a>],
    prev: &crate::ipa::AllSeeds,
) -> crate::ipa::AllSeeds {
    use std::collections::HashSet;
    let mut out = prev.clone();

    // Return class per function.
    let mut ret_cls: HashMap<NodeId, (String, String)> = HashMap::new();
    for (nid, fr) in funcs {
        if fr.qualname == "<module>" {
            continue;
        }
        let f = &parsed[fr.file_idx];
        let Some(fnode) = func_node(f, fr) else { continue };
        let exprs = js_return_exprs(fnode);
        if exprs.is_empty() {
            continue;
        }
        let slice = prev.get(&fr.file_idx);
        let mut cls: Option<(String, String)> = None;
        let mut ok = true;
        for e in exprs {
            match js_seed_class_of(e, f, slice) {
                Some(c) => match &cls {
                    None => cls = Some(c),
                    Some(p) if *p == c => {}
                    _ => {
                        ok = false;
                        break;
                    }
                },
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            if let Some(c) = cls {
                ret_cls.insert(nid.clone(), c);
            }
        }
    }

    let mut votes: HashMap<(usize, u32, String), HashSet<(String, String)>> =
        HashMap::new();

    for site in sites {
        let Some(cfr) = funcs.get(&site.caller) else { continue };
        let Some(tfr) = funcs.get(&site.callee) else { continue };
        let cfi = cfr.file_idx;
        let cf = &parsed[cfi];
        let tf = &parsed[tfr.file_idx];
        let tscope = tfr.range.map(|r| r.0 as u32).unwrap_or(u32::MAX);
        let cscope = js_scope_key_at(site.call);
        let cslice = prev.get(&cfi);

        // Rest params (`...args`) make positional indices past the
        // rest unreliable; skip positional votes for such callees.
        let callee_has_rest = func_node(tf, tfr).is_some_and(|fn_| {
            let mut stack = vec![fn_];
            while let Some(n) = stack.pop() {
                if n.kind() == "formal_parameters" {
                    let mut cur = n.walk();
                    if n.children(&mut cur).any(|c| c.kind() == "rest_pattern") {
                        return true;
                    }
                }
                stack.extend(n.children(&mut n.walk()));
            }
            false
        });

        let Some(argn) = site.call.child_by_field_name("arguments") else {
            continue;
        };
        let kids: Vec<Node> =
            argn.named_children(&mut argn.walk()).collect();
        if kids.iter().any(|k| k.kind() == "spread_element") {
            continue;
        }
        let pos: Vec<Node> = kids.iter().copied().collect();

        for (i, group) in tfr.params.iter().enumerate() {
            if group.is_empty() || callee_has_rest {
                continue;
            }
            let Some(arg) = pos.get(i) else { continue };
            if let Some(c) = js_seed_class_of(*arg, cf, cslice) {
                for name in group {
                    votes
                        .entry((tfr.file_idx, tscope, name.clone()))
                        .or_default()
                        .insert(c.clone());
                }
            }
        }

        if let Some(rc) = ret_cls.get(&site.callee) {
            if let Some(lhs) = js_assignment_lhs(site.call, cf) {
                votes
                    .entry((cfi, cscope, lhs))
                    .or_default()
                    .insert(rc.clone());
            }
        }
    }

    for ((fi, scope, var), set) in votes {
        if set.len() == 1 {
            let (m, c) = set.into_iter().next().unwrap();
            out.entry(fi)
                .or_default()
                .entry(scope)
                .or_default()
                .insert(var, (m, c));
        }
    }
    out
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

    // Type inference fixpoint: inferred seeds widen the callgraph,
    // which can enable further inference. Bounded; seeds only grow.
    let mut extra = crate::ipa::AllSeeds::new();
    let (mut adj, mut sites) =
        build_callgraph(parsed, &file_index, file_set, &node_set, &extra);
    for _ in 0..6 {
        let next = infer_js_seeds(parsed, &funcs, &sites, &extra);
        if next == extra {
            break;
        }
        extra = next;
        let rebuilt =
            build_callgraph(parsed, &file_index, file_set, &node_set, &extra);
        adj = rebuilt.0;
        sites = rebuilt.1;
    }

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
                extra.get(&r.file_idx),
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
                    extra.get(&fref.file_idx),
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
