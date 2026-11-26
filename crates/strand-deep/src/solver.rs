//! Bottom-up SCC solver: computes function summaries callees-first,
//! iterates within cycles to a fixpoint, collects findings.
//!
//! Order: Tarjan SCC over the function call graph, components
//! processed in reverse topological order (callees before callers).
//! Single-node acyclic functions analyze once; cyclic SCCs iterate
//! until summaries stabilize (max 5 passes - then widen to current
//! state, findings stay conservative).

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::callgraph;
use crate::facts::{analyze_function, Finding, Summary, VarState};
use crate::ipa::PyFile;
use crate::models::{Model, SinkKind};

/// Node id: (module, qualname). "<module>" = top-level code.
pub type NodeId = (String, String);

pub struct SolveStats {
    pub functions: usize,
    pub sccs: usize,
    pub cyclic_sccs: usize,
    pub fixpoint_iters: usize,
    pub findings: usize,
    pub budget_exceeded: usize,
}

pub struct SolveOutput {
    pub summaries: HashMap<NodeId, Summary>,
    pub findings: Vec<Finding>,
    pub stats: SolveStats,
}

/// A function to analyze: where its body node lives.
struct FuncRef {
    file_idx: usize,
    /// Byte range of the function_definition (None = module root).
    range: Option<(usize, usize)>,
    params: Vec<Vec<String>>,
    qualname: String,
}

/// Collect all analyzable functions: every def + each file's
/// top-level "<module>".
fn collect_funcs(parsed: &[PyFile]) -> HashMap<NodeId, FuncRef> {
    let mut out = HashMap::new();
    for (fi, f) in parsed.iter().enumerate() {
        out.insert(
            (f.module.clone(), "<module>".to_string()),
            FuncRef {
                file_idx: fi,
                range: None,
                params: Vec::new(),
                qualname: "<module>".to_string(),
            },
        );
        // Group by qualname; prefer the last non-stub definition
        // (Python semantics: later def shadows earlier; overload
        // stubs are `...` bodies).
        let mut by_qual: HashMap<String, &crate::ipa::FuncInfo> = HashMap::new();
        for infos in f.funcs.values() {
            for info in infos {
                let e = by_qual.entry(info.qualname.clone()).or_insert(info);
                if info.is_stub {
                    // keep existing unless nothing yet
                    if e.is_stub {
                        *e = info;
                    }
                } else {
                    *e = info; // non-stub always wins; last wins
                }
            }
        }
        for (qual, info) in by_qual {
            out.insert(
                (f.module.clone(), qual.clone()),
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

/// Recover the function_definition node for a FuncRef.
fn func_node<'t>(f: &'t PyFile, r: &FuncRef) -> Option<Node<'t>> {
    match r.range {
        None => Some(f.tree.root_node()),
        Some((s, e)) => {
            let n = f.tree.root_node().descendant_for_byte_range(s, e)?;
            if n.kind() == "function_definition" {
                Some(n)
            } else {
                // Range may have landed on a child; walk up.
                let mut cur = n;
                loop {
                    if cur.kind() == "function_definition" {
                        return Some(cur);
                    }
                    cur = cur.parent()?;
                }
            }
        }
    }
}

/// Iterative Tarjan SCC. Returns components in reverse topological
/// order already? No - returns in Tarjan order; we sort by finish.
pub fn tarjan_scc(nodes: &HashSet<NodeId>, adj: &HashMap<NodeId, Vec<NodeId>>) -> Vec<Vec<NodeId>> {
    // Iterative Tarjan.
    struct Frame {
        node: NodeId,
        child_idx: usize,
    }
    let mut index_of: HashMap<NodeId, usize> = HashMap::new();
    let mut low: HashMap<NodeId, usize> = HashMap::new();
    let mut on_stack: HashSet<NodeId> = HashSet::new();
    let mut stack: Vec<NodeId> = Vec::new();
    let mut sccs: Vec<Vec<NodeId>> = Vec::new();
    let mut next_index = 0usize;

    for start in nodes {
        if index_of.contains_key(start) {
            continue;
        }
        let mut work: Vec<Frame> = vec![Frame {
            node: start.clone(),
            child_idx: 0,
        }];
        index_of.insert(start.clone(), next_index);
        low.insert(start.clone(), next_index);
        next_index += 1;
        stack.push(start.clone());
        on_stack.insert(start.clone());

        while let Some(frame) = work.last_mut() {
            let node = frame.node.clone();
            let children = adj.get(&node).cloned().unwrap_or_default();
            if frame.child_idx < children.len() {
                let child = children[frame.child_idx].clone();
                frame.child_idx += 1;
                if !nodes.contains(&child) {
                    continue;
                }
                if !index_of.contains_key(&child) {
                    index_of.insert(child.clone(), next_index);
                    low.insert(child.clone(), next_index);
                    next_index += 1;
                    stack.push(child.clone());
                    on_stack.insert(child.clone());
                    work.push(Frame {
                        node: child,
                        child_idx: 0,
                    });
                } else if on_stack.contains(&child) {
                    let li = low[&node].min(low[&child]);
                    low.insert(node.clone(), li);
                }
            } else {
                // Done with node: propagate lowlink to parent.
                work.pop();
                if let Some(parent) = work.last() {
                    let pl = low[&parent.node].min(low[&node]);
                    low.insert(parent.node.clone(), pl);
                }
                if low[&node] == index_of[&node] {
                    let mut scc = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack.remove(&w);
                        scc.push(w.clone());
                        if w == node {
                            break;
                        }
                    }
                    sccs.push(scc);
                }
            }
        }
    }
    sccs
}

/// Topological order of SCCs: Tarjan emits components in reverse
/// topo order already (sinks first) for this formulation - but we
/// verify by sorting on a computed finish order. Safer: build cond
/// graph and Kahn it.
pub fn order_sccs(
    sccs: Vec<Vec<NodeId>>,
    adj: &HashMap<NodeId, Vec<NodeId>>,
) -> Vec<Vec<NodeId>> {
    // Map node -> scc index.
    let mut comp_of: HashMap<NodeId, usize> = HashMap::new();
    for (i, scc) in sccs.iter().enumerate() {
        for n in scc {
            comp_of.insert(n.clone(), i);
        }
    }
    // Condensation edges: caller comp -> callee comp.
    let mut callees: Vec<HashSet<usize>> = vec![HashSet::new(); sccs.len()];
    let mut callers_count = vec![0usize; sccs.len()];
    for (n, targets) in adj {
        let Some(&a) = comp_of.get(n) else { continue };
        for t in targets {
            if let Some(&b) = comp_of.get(t) {
                if a != b && callees[a].insert(b) {
                    callers_count[b] += 1;
                }
            }
        }
    }
    // We want callees first: process comps with no unresolved
    // callees. callers_count[b] = number of comps b calls? We built
    // callees[a] = comps a calls. Process in order: a comp is ready
    // when all comps it calls are done -> track remaining callee deps.
    let mut remaining: Vec<usize> = callees.iter().map(|s| s.len()).collect();
    let mut done = vec![false; sccs.len()];
    let mut order = Vec::new();
    // Simple O(n^2) ready scan - comp counts are modest.
    loop {
        let mut progressed = false;
        for i in 0..sccs.len() {
            if !done[i] && remaining[i] == 0 {
                done[i] = true;
                order.push(i);
                progressed = true;
                // i is done; decrement remaining for comps that call i
                for (a, callee_set) in callees.iter().enumerate() {
                    if !done[a] && callee_set.contains(&i) {
                        remaining[a] -= 1;
                    }
                }
            }
        }
        if !progressed {
            // Cycle in condensation (shouldn't happen post-SCC) or
            // remaining>0 comps - append leftovers.
            for i in 0..sccs.len() {
                if !done[i] {
                    order.push(i);
                }
            }
            break;
        }
        if order.len() == sccs.len() {
            break;
        }
    }
    order.into_iter().map(|i| sccs[i].clone()).collect()
}

/// Enclosing function_definition start_byte for `node`, or
/// u32::MAX at module scope. Matches `py_ctor_seed_at` keys.
fn scope_key_at(node: Node) -> u32 {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if n.kind() == "function_definition" {
            return n.start_byte() as u32;
        }
        anc = n.parent();
    }
    u32::MAX
}

/// Class a seed/ctor expression resolves to, or None.
fn seed_class_of(
    node: Node,
    f: &PyFile,
    rb: &crate::ipa::RBindings,
    extra: Option<&crate::ipa::FileSeeds>,
) -> Option<(String, String)> {
    let text = f.text.as_str();
    match node.kind() {
        "call" => crate::ipa::py_ctor_target(node, f, rb, text),
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            crate::ipa::py_ctor_seed_at(node, f, name, extra)
        }
        "attribute" => {
            let key = crate::ipa::py_dotted(node, text)?;
            crate::ipa::py_ctor_seed_at(node, f, &key, extra)
        }
        _ => None,
    }
}

/// `return` expressions directly owned by `fnode` (nested defs,
/// lambdas and classes excluded).
fn return_exprs(fnode: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack: Vec<Node> =
        fnode.children(&mut fnode.walk()).collect();
    while let Some(n) = stack.pop() {
        match n.kind() {
            "function_definition" | "lambda" | "class_definition" => {}
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

/// LHS var key when `call` is the RHS of an assignment.
fn assignment_lhs(call: Node, f: &PyFile) -> Option<String> {
    let p = call.parent()?;
    if p.kind() != "assignment" {
        return None;
    }
    if p.child_by_field_name("right")?.id() != call.id() {
        return None;
    }
    let left = p.child_by_field_name("left")?;
    crate::ipa::py_seed_lhs(left, f.text.as_str())
}

/// One round of param/return type inference. A param (or
/// assignment target) gets a seed only when every observed
/// callsite/return agrees on a single class - disagreement stays
/// unresolved rather than guessing.
/// Return class per function: all return exprs agree on one class.
/// Used both for `x = f()` seeds and `f().m()` receiver resolution.
fn return_classes(
    parsed: &[PyFile],
    funcs: &HashMap<NodeId, FuncRef>,
    prev: &crate::ipa::AllSeeds,
) -> HashMap<NodeId, (String, String)> {
    let mut rb: HashMap<usize, crate::ipa::RBindings> = HashMap::new();
    let mut ret_cls: HashMap<NodeId, (String, String)> = HashMap::new();
    for (nid, fr) in funcs {
        if fr.qualname == "<module>" {
            continue;
        }
        let f = &parsed[fr.file_idx];
        let Some(fnode) = func_node(f, fr) else { continue };
        let exprs = return_exprs(fnode);
        if exprs.is_empty() {
            continue;
        }
        if !rb.contains_key(&fr.file_idx) {
            rb.insert(fr.file_idx, crate::ipa::resolve_bindings(f));
        }
        let r = &rb[&fr.file_idx];
        let slice = prev.get(&fr.file_idx);
        let mut cls: Option<(String, String)> = None;
        let mut ok = true;
        for e in exprs {
            match seed_class_of(e, f, r, slice) {
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
    ret_cls
}

fn infer_seeds(
    parsed: &[PyFile],
    funcs: &HashMap<NodeId, FuncRef>,
    cg: &callgraph::CallGraph,
    prev: &crate::ipa::AllSeeds,
) -> crate::ipa::AllSeeds {
    use std::collections::HashSet;
    let mut out = prev.clone();
    let mut rb: HashMap<usize, crate::ipa::RBindings> = HashMap::new();
    let ret_cls = return_classes(parsed, funcs, prev);

    // (file_idx, scope_key, var) -> candidate classes.
    let mut votes: HashMap<(usize, u32, String), HashSet<(String, String)>> =
        HashMap::new();

    for site in &cg.sites {
        let Some(cfr) = funcs.get(&site.caller) else { continue };
        let Some(tfr) = funcs.get(&site.callee) else { continue };
        let cfi = cfr.file_idx;
        let cf = &parsed[cfi];
        let Some(call) = cf
            .tree
            .root_node()
            .descendant_for_byte_range(site.start as usize, site.end as usize)
        else {
            continue;
        };
        if call.kind() != "call" {
            continue;
        }
        let tf = &parsed[tfr.file_idx];
        let tscope =
            tfr.range.map(|r| r.0 as u32).unwrap_or(u32::MAX);
        let cscope = scope_key_at(call);
        let cslice = prev.get(&cfi);

        // Callee has splat params -> positional mapping unreliable;
        // only keyword args are safe to bind.
        let callee_has_splat = func_node(tf, tfr).is_some_and(|fn_| {
            let mut stack = vec![fn_];
            while let Some(n) = stack.pop() {
                if n.kind() == "parameters" {
                    let mut cur = n.walk();
                    if n
                        .children(&mut cur)
                        .any(|c| {
                            c.kind().contains("splat")
                                || matches!(c.kind(), "/" | "*")
                        })
                    {
                        return true;
                    }
                }
                stack.extend(n.children(&mut n.walk()));
            }
            false
        });

        let Some(argn) = call.child_by_field_name("arguments") else {
            continue;
        };
        let kids: Vec<Node> =
            argn.named_children(&mut argn.walk()).collect();
        if kids.iter().any(|k| k.kind().contains("splat")) {
            continue;
        }
        let pos: Vec<Node> = kids
            .iter()
            .filter(|k| k.kind() != "keyword_argument")
            .copied()
            .collect();
        let kw: HashMap<String, Node> = kids
            .iter()
            .filter(|k| k.kind() == "keyword_argument")
            .filter_map(|k| {
                let name = k
                    .child_by_field_name("name")?
                    .utf8_text(cf.text.as_bytes())
                    .ok()?
                    .to_string();
                let val = k.child_by_field_name("value")?;
                Some((name, val))
            })
            .collect();

        if !rb.contains_key(&cfi) {
            rb.insert(cfi, crate::ipa::resolve_bindings(cf));
        }
        let cr = &rb[&cfi];

        for (i, group) in tfr.params.iter().enumerate() {
            if group.is_empty() {
                continue;
            }
            let arg = if callee_has_splat {
                // Positional indices past a splat are unreliable;
                // only keyword binding is sound.
                group.iter().find_map(|n| kw.get(n).copied())
            } else {
                pos.get(i)
                    .copied()
                    .or_else(|| group.iter().find_map(|n| kw.get(n).copied()))
            };
            let Some(arg) = arg else { continue };
            if let Some(c) = seed_class_of(arg, cf, cr, cslice) {
                for name in group {
                    votes
                        .entry((tfr.file_idx, tscope, name.clone()))
                        .or_default()
                        .insert(c.clone());
                }
            }
        }

        // `x = F()` where F provably returns class C -> seed x.
        if let Some(rc) = ret_cls.get(&site.callee) {
            if let Some(lhs) = assignment_lhs(call, cf) {
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

/// Run the full analysis.
pub fn solve(parsed: &[PyFile], model: &Model) -> SolveOutput {
    let funcs = collect_funcs(parsed);
    let node_set: HashSet<NodeId> = funcs.keys().cloned().collect();

    // Type inference fixpoint: inferred seeds widen the callgraph,
    // which can enable further inference. Bounded; seeds only grow.
    let mut extra = crate::ipa::AllSeeds::new();
    let mut ret = return_classes(parsed, &funcs, &extra);
    let mut cg = callgraph::build(parsed, &extra, &ret);
    for _ in 0..6 {
        let next = infer_seeds(parsed, &funcs, &cg, &extra);
        if next == extra {
            break;
        }
        extra = next;
        ret = return_classes(parsed, &funcs, &extra);
        cg = callgraph::build(parsed, &extra, &ret);
    }
    cg = callgraph::build(parsed, &extra, &ret);
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for ((cm, cf), (tm, tf)) in &cg.edges {
        let from = (cm.clone(), cf.clone());
        let to = (tm.clone(), tf.clone());
        if node_set.contains(&from) && node_set.contains(&to) {
            adj.entry(from).or_default().push(to);
        }
    }

    let sccs = tarjan_scc(&node_set, &adj);
    let ordered = order_sccs(sccs, &adj);

    // Phase 0: module-level environments. Python functions read their
    // module's globals, so each file's `<module>` body is analyzed once
    // up front (empty summaries - calls degrade to unknown_call_result)
    // and the resulting env seeds every function in that file.
    let empty_sums: HashMap<NodeId, Summary> = HashMap::new();
    let module_envs: Vec<(usize, HashMap<String, VarState>)> = funcs
        .values()
        .filter(|r| r.qualname == "<module>")
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|r| {
            let f = &parsed[r.file_idx];
            let analysis = analyze_function(
                f,
                f.tree.root_node(),
                &[],
                "<module>",
                model,
                &empty_sums,
                None,
                extra.get(&r.file_idx),
                Some(&ret),
            );
            Some((r.file_idx, analysis.env))
        })
        .collect();
    let file_globals: HashMap<usize, HashMap<String, VarState>> =
        module_envs.into_iter().collect();

    let mut summaries: HashMap<NodeId, Summary> = HashMap::new();
    let mut findings_dedup: HashMap<(SinkKindKey, String, u32, String, String), Finding> =
        HashMap::new();
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
            || scc.iter().any(|n| {
                adj.get(n).is_some_and(|v| v.contains(n))
            });
        if cyclic {
            stats.cyclic_sccs += 1;
        }
        let max_iters = if cyclic { 5 } else { 1 };
        let mut prev: HashMap<NodeId, Summary> = HashMap::new();
        for iter in 0..max_iters {
            let mut changed = false;
            for node in scc {
                let Some(fref) = funcs.get(node) else { continue };
                let f = &parsed[fref.file_idx];
                let Some(fnode) = func_node(f, fref) else { continue };
                let globals = if fref.qualname == "<module>" {
                    None
                } else {
                    file_globals.get(&fref.file_idx)
                };
                let analysis = analyze_function(
                    f,
                    fnode,
                    &fref.params,
                    &fref.qualname,
                    model,
                    &summaries,
                    globals,
                    extra.get(&fref.file_idx),
                    Some(&ret),
                );
                if analysis.budget_hit {
                    stats.budget_exceeded += 1;
                }
                // Collect findings every pass (dedup later).
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
                prev.insert(node.clone(), Summary::default());
            }
            stats.fixpoint_iters += 1;
            if !changed || iter + 1 == max_iters {
                break;
            }
        }
        let _ = prev;
    }

    let mut findings: Vec<Finding> = findings_dedup.into_values().collect();
    findings.sort_by(|a, b| {
        (&a.file, a.line, format!("{:?}", a.class), &a.sink)
            .cmp(&(&b.file, b.line, format!("{:?}", b.class), &b.sink))
    });
    stats.findings = findings.len();

    SolveOutput {
        summaries,
        findings,
        stats,
    }
}

/// Wrapper for Ord on SinkKind in the dedup key.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct SinkKindKey(SinkKind);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn run(files: &[(&str, &str)]) -> SolveOutput {
        let map: BTreeMap<String, String> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let parsed = crate::ipa::parse_all(&map);
        let model = crate::models::python_default().unwrap();
        solve(&parsed, &model)
    }

    #[test]
    fn taint_env_to_subprocess_cross_function() {
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

def run(name):
    subprocess.call(name)

def main():
    name = os.environ["X"]
    run(name)
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "expected interprocedural shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn splat_param_keeps_position() {
        // `*args` occupies position 1; `cmd` must still bind arg 2,
        // not shift to index 1.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

def run(*args, cmd):
    subprocess.call(cmd)

def main():
    run("a", cmd=os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")),
            "keyword-only cmd should resolve via keyword arg: {:?}",
            out.findings
        );
    }

    #[test]
    fn positional_after_default_keeps_index() {
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

def run(opts=None, cmd=None):
    subprocess.call(cmd)

def main():
    run(None, os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "cmd at position 1 must bind arg 1: {:?}",
            out.findings
        );
    }

    #[test]
    fn ctor_seed_resolves_instance_method() {
        // `r = Runner()` in main's scope lets `r.run(...)` resolve to
        // Runner.run; `self` must not shift cmd off arg position 0.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def run(self, cmd):
        subprocess.call(cmd)

def main():
    r = Runner()
    r.run(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "instance method call should propagate taint: {:?}",
            out.findings
        );
    }

    #[test]
    fn param_type_inference_resolves_method() {
        // `drive(r, cmd)` is only ever called with a Runner, so the
        // callsite-agreement pass seeds r -> Runner inside drive.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def run(self, cmd):
        subprocess.call(cmd)

def drive(r, cmd):
    r.run(cmd)

def main():
    drive(Runner(), os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "param type inference should resolve r.run: {:?}",
            out.findings
        );
    }

    #[test]
    fn return_type_seed_resolves_method() {
        // make() always returns Runner -> `r = make()` seeds r.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def run(self, cmd):
        subprocess.call(cmd)

def make():
    return Runner()

def main():
    r = make()
    r.run(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "return type seed should resolve r.run: {:?}",
            out.findings
        );
    }

    #[test]
    fn param_type_disagreement_stays_unresolved() {
        // Two callsites disagree on r's class -> no seed, no guess.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def run(self, cmd):
        subprocess.call(cmd)

class Other:
    def run(self, cmd):
        pass

def drive(r, cmd):
    r.run(cmd)

def main():
    drive(Runner(), os.environ["X"])
    drive(Other(), "safe")
"#,
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")),
            "disagreement must not guess a class: {:?}",
            out.findings
        );
    }

    #[test]
    fn call_result_receiver_resolves_method() {
        // getRunner().run(...) - the inner call's return class seeds
        // the receiver without any assignment.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def run(self, cmd):
        subprocess.call(cmd)

def get_runner():
    return Runner()

def main():
    get_runner().run(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "call-result receiver should resolve: {:?}",
            out.findings
        );
    }

    #[test]
    fn container_element_seed_resolves_method() {
        // rs = [Runner()] seeds the element type; rs[0].run resolves.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def run(self, cmd):
        subprocess.call(cmd)

def main():
    rs = [Runner()]
    rs[0].run(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "container element seed should resolve: {:?}",
            out.findings
        );
    }

    #[test]
    fn class_call_resolves_init() {
        // `Runner(x)` invokes Runner.__init__.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    def __init__(self, cmd):
        subprocess.call(cmd)

def main():
    Runner(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "class call should reach __init__ sink: {:?}",
            out.findings
        );
    }

    #[test]
    fn staticmethod_keeps_first_param() {
        // @staticmethod has no receiver - arg 0 binds param 0.
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

class Runner:
    @staticmethod
    def run(cmd):
        subprocess.call(cmd)

def main():
    r = Runner()
    r.run(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")),
            "staticmethod arg should bind param 0: {:?}",
            out.findings
        );
    }

    #[test]
    fn taint_argv_to_eval() {
        let out = run(&[(
            "app.py",
            "import sys\ndef main():\n    eval(sys.argv[1])\n",
        )]);
        assert!(out.findings.iter().any(|f| f.class == SinkKind::CodeExec));
    }

    #[test]
    fn null_guard_no_finding_unguarded_finding() {
        let guarded = run(&[(
            "t.py",
            "def maybe():\n    return None\n\ndef f():\n    x = maybe()\n    if x is None:\n        return\n    x.bit_length()\n",
        )]);
        assert!(
            !guarded.findings.iter().any(|f| f.class == SinkKind::NullDeref),
            "guarded deref should not flag: {:?}",
            guarded.findings
        );
        let unguarded = run(&[(
            "t.py",
            "def maybe():\n    return None\n\ndef f():\n    x = maybe()\n    x.bit_length()\n",
        )]);
        assert!(unguarded.findings.iter().any(|f| f.class == SinkKind::NullDeref));
    }

    #[test]
    fn null_isinstance_and_assert_narrowing() {
        let out = run(&[(
            "t.py",
            r#"
def get():
    return None

def f():
    x = get()
    assert x is not None
    x.bit_length()

def g():
    y = get()
    if isinstance(y, int):
        y.bit_length()
"#,
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::NullDeref),
            "assert/isinstance narrowing should suppress: {:?}",
            out.findings
        );
    }

    #[test]
    fn tuple_index_nullness() {
        let out = run(&[(
            "t.py",
            r#"
T = (None, {"a": 1})

def f():
    y = T[1]
    y.keys()
    z = T[0]
    z.bit_length()
"#,
        )]);
        let nd: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::NullDeref)
            .collect();
        assert_eq!(nd.len(), 1, "only T[0] should flag: {:?}", out.findings);
        assert_eq!(nd[0].line, 8);
    }

    #[test]
    fn leak_open_close_and_yield() {
        let out = run(&[(
            "t.py",
            r#"
def leaker():
    f = open("x")

def closer():
    f = open("x")
    f.close()

def gen():
    f = open("x")
    yield f
"#,
        )]);
        let leaks: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Leak)
            .collect();
        assert_eq!(leaks.len(), 1, "only leaker should flag: {:?}", out.findings);
        assert!(leaks[0].func.contains("leaker"));
    }

    #[test]
    fn recursive_scc_converges() {
        // Mutual recursion with taint flowing through params.
        let out = run(&[(
            "t.py",
            r#"
import os, subprocess

def a(x):
    if x:
        return b(x)
    subprocess.call(x)

def b(x):
    return a(x)

def main():
    a(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell),
            "taint should propagate through recursive cycle: {:?}",
            out.findings
        );
        assert!(out.stats.cyclic_sccs >= 1, "expected a cyclic SCC");
    }

    #[test]
    fn sanitizer_stops_taint() {
        let out = run(&[(
            "t.py",
            "import sys\ndef main():\n    x = int(sys.argv[1])\n    eval(x)\n",
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::CodeExec),
            "int() sanitizer should stop argv taint: {:?}",
            out.findings
        );
    }

    #[test]
    fn module_globals_visible_in_functions() {
        let out = run(&[(
            "t.py",
            "X = None\n\ndef f():\n    X.bit_length()\n",
        )]);
        assert!(out.findings.iter().any(|f| f.class == SinkKind::NullDeref));
    }
}
