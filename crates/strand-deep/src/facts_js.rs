//! Per-function dataflow facts for JS/TS: taint, null/undefined, and
//! resource tracking - the ECMAScript mirror of `facts.rs`.
//!
//! Same value domains and honesty contract: may-analyses with union
//! joins, single-pass (no intra-procedural fixpoint), env keys are
//! dotted member paths (`a.b.c`) with numeric subscripts kept as
//! `a[0]` and other subscripts collapsed to the base. `null`,
//! `undefined`, and `void x` all feed the `is_none` flag.
//!
//! Module identity is the project-relative file path; call
//! resolution reuses `js_ipa`'s binding/spec machinery so
//! `require`/`import` aliases behave identically to IPA.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use tree_sitter::Node;

use crate::facts::{Finding, FuncAnalysis, PendingSink, Summary, VarState};
use crate::js_ipa::{self, JsFile};
use crate::models::{Model, SinkKind};
use crate::solver::NodeId;

const NODE_BUDGET: usize = 100_000;

#[derive(Debug, Clone, Default)]
struct ExprVal {
    state: VarState,
    /// Set when the expr itself is a model source.
    source_label: Option<String>,
}

/// Shared context for one JS function's walk.
pub struct CtxJs<'a> {
    f: &'a JsFile,
    /// All parsed JS files + rel->index map, for cross-file callee
    /// qualname lookup.
    parsed: &'a [JsFile],
    file_index: &'a HashMap<String, usize>,
    file_set: &'a BTreeSet<String>,
    model: &'a Model,
    summaries: &'a HashMap<NodeId, Summary>,
    qualname: &'a str,
    acquired: Vec<(String, String, u32)>,
    released: HashSet<String>,
    escaped: HashSet<String>,
    ret: VarState,
    saw_return: bool,
    nodes_left: usize,
    pub budget_hit: bool,
    pub findings: Vec<Finding>,
    pub param_sinks: BTreeMap<usize, Vec<PendingSink>>,
    pub touches_unknown: bool,
    reported: HashSet<(SinkKind, u32, String, String)>,
    pending_result: Option<ExprVal>,
}

/// Analyze a JS function body. `func_node` = function-ish node or
/// the program root for `<module>`; `params` = ordered param names;
/// `qualname` = FuncInfo.qualname or "<module>".
pub fn analyze_function_js<'a>(
    f: &'a JsFile,
    func_node: Node,
    params: &[String],
    qualname: &str,
    model: &Model,
    summaries: &HashMap<NodeId, Summary>,
    globals: Option<&HashMap<String, VarState>>,
    file_set: &BTreeSet<String>,
    parsed: &'a [JsFile],
    file_index: &HashMap<String, usize>,
    module_level: bool,
) -> FuncAnalysis {
    let mut ctx = CtxJs {
        f,
        parsed,
        file_index,
        file_set,
        model,
        summaries,
        qualname,
        acquired: Vec::new(),
        released: HashSet::new(),
        escaped: HashSet::new(),
        ret: VarState::default(),
        saw_return: false,
        nodes_left: NODE_BUDGET,
        budget_hit: false,
        findings: Vec::new(),
        param_sinks: BTreeMap::new(),
        touches_unknown: false,
        reported: HashSet::new(),
        pending_result: None,
    };
    let mut env: HashMap<String, VarState> = globals.cloned().unwrap_or_default();
    for (i, p) in params.iter().enumerate() {
        env.insert(
            p.clone(),
            VarState {
                taint: Some(format!("param:{i}")),
                is_none: false,
                resource: None,
            },
        );
    }
    walk_body(func_node, &mut ctx, &mut env);

    for (var, kind, line) in &ctx.acquired {
        if ctx.released.contains(var) || ctx.escaped.contains(var) {
            continue;
        }
        let still_held = env.get(var).is_some_and(|st| st.resource.is_some());
        let was_returned = ctx.ret.resource.is_some();
        if still_held && !was_returned {
            ctx.findings.push(Finding {
                class: SinkKind::Leak,
                source: format!("resource:{kind}"),
                sink: format!("acquire {var}"),
                file: ctx.f.rel.clone(),
                line: *line,
                func: qualname.to_string(),
                via: vec![format!("{}.{}", ctx.f.rel, qualname)],
                confidence: 0.8,
            });
        }
    }

    // `<module>` fall-off yields module.exports (default {}), not
    // undefined - only an explicit `return null/undefined` makes the
    // module value none-ish. Functions falling off return undefined.
    let mut summary = Summary {
        may_return_none: ctx.ret.is_none || (!module_level && may_fall_off_js(func_node)),
        returns_tainted: ctx
            .ret
            .taint
            .as_ref()
            .is_some_and(|l| !l.starts_with("param:")),
        returns_unclosed: first_unclosed(&ctx),
        touches_unknown: ctx.touches_unknown,
        findings: std::mem::take(&mut ctx.findings),
        param_sinks: std::mem::take(&mut ctx.param_sinks),
        ..Default::default()
    };
    if let Some(label) = &ctx.ret.taint {
        if let Some(idx) = label.strip_prefix("param:").and_then(|r| r.parse().ok()) {
            summary.param_to_return.insert(idx);
        }
    }
    FuncAnalysis {
        summary,
        env,
        budget_hit: ctx.budget_hit,
    }
}

fn first_unclosed(ctx: &CtxJs) -> Option<String> {
    for (var, kind, _) in &ctx.acquired {
        if !ctx.released.contains(var) {
            return Some(kind.clone());
        }
    }
    ctx.ret.resource.clone()
}

/// Conservative fall-off check for JS statement kinds. JS functions
/// that reach the end return `undefined`, so a body that can
/// complete without `return` counts as may-return-none.
fn may_fall_off_js(node: Node) -> bool {
    match node.kind() {
        "return_statement" | "throw_statement" | "break_statement" | "continue_statement" => false,
        "statement_block" | "program" | "switch_body" => {
            let mut c = node.walk();
            match node.children(&mut c).last() {
                Some(last) => may_fall_off_js(last),
                None => true,
            }
        }
        "function_declaration"
        | "function_expression"
        | "method_definition"
        | "generator_function_declaration" => node
            .child_by_field_name("body")
            .map(may_fall_off_js)
            .unwrap_or(true),
        "arrow_function" => match node.child_by_field_name("body") {
            // Concise body `() => expr` always returns.
            Some(b) if b.kind() != "statement_block" => false,
            Some(b) => may_fall_off_js(b),
            None => true,
        },
        "if_statement" => {
            let cons = node.child_by_field_name("consequence");
            let alt = node.child_by_field_name("alternative");
            match (cons, alt) {
                (Some(_), None) => true, // no else: if can be skipped
                (Some(c), Some(a)) => may_fall_off_js(c) || may_fall_off_js(a),
                _ => true,
            }
        }
        "else_clause" => {
            let mut c = node.walk();
            node.children(&mut c)
                .last()
                .map(may_fall_off_js)
                .unwrap_or(true)
        }
        "try_statement" => {
            let body = node.child_by_field_name("body");
            let handler = node.child_by_field_name("handler");
            let fin = node.child_by_field_name("finalizer");
            let body_falls = body.map(may_fall_off_js).unwrap_or(true);
            let handler_falls = handler.map(may_fall_off_js).unwrap_or(false);
            let paths = body_falls || handler_falls;
            match fin {
                Some(f) => paths && may_fall_off_js(f),
                None => paths,
            }
        }
        "catch_clause" | "finally_clause" => node
            .child_by_field_name("body")
            .map(may_fall_off_js)
            .unwrap_or(true),
        "labeled_statement" => node
            .child_by_field_name("body")
            .map(may_fall_off_js)
            .unwrap_or(true),
        // Loops and switches may complete; conservative true.
        _ => true,
    }
}

fn line_of(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

fn budget(ctx: &mut CtxJs) -> bool {
    if ctx.nodes_left == 0 {
        ctx.budget_hit = true;
        return true;
    }
    ctx.nodes_left -= 1;
    false
}

/// Body node of a function-ish node: `body` field for declarations/
/// methods; arrow concise bodies are expressions.
fn fn_body(node: Node) -> Option<Node> {
    match node.kind() {
        "arrow_function" => node.child_by_field_name("body"),
        "function_declaration"
        | "function_expression"
        | "method_definition"
        | "generator_function_declaration" => node.child_by_field_name("body"),
        _ => None,
    }
}

/// Walk a function/program body: statement_block children as
/// statements; an arrow concise body is an implicit return expr.
fn walk_body(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) {
    if matches!(
        node.kind(),
        "function_declaration"
            | "function_expression"
            | "method_definition"
            | "generator_function_declaration"
            | "arrow_function"
    ) {
        match fn_body(node) {
            Some(b) if b.kind() == "statement_block" => walk_stmt(b, ctx, env),
            Some(b) => {
                // Arrow concise body: `() => expr` returns expr.
                ctx.saw_return = true;
                let v = eval_expr(b, ctx, env);
                ctx.ret.join(&v.state);
                if ctx.ret.taint.is_none() {
                    ctx.ret.taint = v.state.taint.clone();
                }
                if v.state.resource.is_some() && ctx.ret.resource.is_none() {
                    ctx.ret.resource = v.state.resource.clone();
                }
            }
            None => {}
        }
        return;
    }
    walk_stmt(node, ctx, env);
}

fn walk_stmt(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) {
    if budget(ctx) {
        return;
    }
    match node.kind() {
        "program" | "statement_block" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    walk_stmt(ch, ctx, env);
                }
            }
        }
        "expression_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.kind() == "variable_declarator" {
                    walk_declarator(ch, ctx, env);
                }
            }
        }
        "variable_declarator" => walk_declarator(node, ctx, env),
        "if_statement" => walk_if(node, ctx, env),
        "while_statement" | "do_statement" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                eval_expr(cond, ctx, env);
            }
            if let Some(body) = node.child_by_field_name("body") {
                walk_branch(body, ctx, env);
            }
        }
        "for_statement" => {
            if let Some(init) = node.child_by_field_name("initializer") {
                match init.kind() {
                    "lexical_declaration" | "variable_declaration" => walk_stmt(init, ctx, env),
                    "empty_statement" => {}
                    _ => {
                        eval_expr(init, ctx, env);
                    }
                }
            }
            if let Some(cond) = node.child_by_field_name("condition") {
                eval_expr(cond, ctx, env);
            }
            if let Some(body) = node.child_by_field_name("body") {
                walk_branch(body, ctx, env);
            }
            if let Some(inc) = node.child_by_field_name("increment") {
                eval_expr(inc, ctx, env);
            }
        }
        "for_in_statement" | "for_of_statement" => {
            if let Some(right) = node.child_by_field_name("right") {
                let rv = eval_expr(right, ctx, env);
                if let Some(left) = for_left_target(node) {
                    assign_for_target(left, &rv.state, ctx, env);
                }
            }
            if let Some(body) = node.child_by_field_name("body") {
                walk_branch(body, ctx, env);
            }
        }
        "try_statement" => {
            if let Some(body) = node.child_by_field_name("body") {
                walk_branch(body, ctx, env);
            }
            if let Some(handler) = node.child_by_field_name("handler") {
                walk_stmt(handler, ctx, env);
            }
            if let Some(fin) = node.child_by_field_name("finalizer") {
                walk_stmt(fin, ctx, env);
            }
        }
        "catch_clause" => {
            if let Some(param) = node.child_by_field_name("parameter") {
                if let Some(key) = pattern_keys(param, ctx) {
                    for k in key {
                        env.insert(k, VarState::default());
                    }
                }
            }
            if let Some(body) = node.child_by_field_name("body") {
                walk_branch(body, ctx, env);
            }
        }
        "finally_clause" => {
            if let Some(body) = node.child_by_field_name("body") {
                walk_stmt(body, ctx, env);
            }
        }
        "switch_statement" => {
            if let Some(v) = node.child_by_field_name("value") {
                eval_expr(v, ctx, env);
            }
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                match ch.kind() {
                    "switch_case" | "switch_default" => {
                        if ch.kind() == "switch_case" {
                            if let Some(v) = ch.child_by_field_name("value") {
                                eval_expr(v, ctx, env);
                            }
                        }
                        if let Some(body) = ch.child_by_field_name("body") {
                            walk_stmt(body, ctx, env);
                        } else {
                            let mut bc = ch.walk();
                            for b in ch.children(&mut bc) {
                                if b.is_named() && b.kind() != "expression" {
                                    walk_stmt(b, ctx, env);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "return_statement" => {
            ctx.saw_return = true;
            let mut has_expr = false;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    has_expr = true;
                    let v = eval_expr(ch, ctx, env);
                    ctx.ret.join(&v.state);
                    if ctx.ret.taint.is_none() {
                        ctx.ret.taint = v.state.taint.clone();
                    }
                    if v.state.resource.is_some() && ctx.ret.resource.is_none() {
                        ctx.ret.resource = v.state.resource.clone();
                    }
                }
            }
            // `return;` returns undefined.
            if !has_expr {
                ctx.ret.is_none = true;
            }
        }
        "throw_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "else_clause" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    walk_stmt(ch, ctx, env);
                }
            }
        }
        "labeled_statement" => {
            if let Some(body) = node.child_by_field_name("body") {
                walk_stmt(body, ctx, env);
            }
        }
        "export_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if !ch.is_named() {
                    continue;
                }
                match ch.kind() {
                    "lexical_declaration"
                    | "variable_declaration"
                    | "function_declaration"
                    | "class_declaration"
                    | "generator_function_declaration" => walk_stmt(ch, ctx, env),
                    _ => {
                        eval_expr(ch, ctx, env);
                    }
                }
            }
        }
        // Nested functions/classes are separate FuncRefs; imports are
        // pre-bound. Terminals and empties do nothing.
        "function_declaration"
        | "function_expression"
        | "arrow_function"
        | "method_definition"
        | "generator_function_declaration"
        | "class_declaration"
        | "class"
        | "import_statement"
        | "break_statement"
        | "continue_statement"
        | "debugger_statement"
        | "empty_statement" => {}
        _ => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if !ch.is_named() {
                    continue;
                }
                if is_stmt_kind(ch.kind()) {
                    walk_stmt(ch, ctx, env);
                } else {
                    eval_expr(ch, ctx, env);
                }
            }
        }
    }
}

/// Kinds that walk_stmt handles as statements (default-arm dispatch).
fn is_stmt_kind(kind: &str) -> bool {
    kind.ends_with("_statement")
        || kind.ends_with("_declaration")
        || matches!(
            kind,
            "statement_block"
                | "program"
                | "else_clause"
                | "switch_body"
                | "switch_case"
                | "switch_default"
                | "catch_clause"
                | "finally_clause"
                | "lexical_declaration"
                | "variable_declaration"
                | "expression_statement"
                | "export_statement"
                | "import_statement"
                | "labeled_statement"
                | "variable_declarator"
        )
}

/// `const x = expr` / `let {a, b} = expr` / `var [p, q] = expr`.
fn walk_declarator(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        // `let x;` declares undefined.
        for k in pattern_keys(name, ctx).unwrap_or_default() {
            env.insert(
                k,
                VarState {
                    is_none: true,
                    ..Default::default()
                },
            );
        }
        return;
    };
    let vv = eval_expr(value, ctx, env);
    // Function-valued declarators: state is a clean function object.
    assign_pattern(
        name,
        vv.state.clone(),
        vv.source_label.clone(),
        ctx,
        env,
        node,
    );
}

/// Left side of for-in/of: may be a bare pattern or a declaration.
fn for_left_target<'t>(node: Node<'t>) -> Option<Node<'t>> {
    let left = node.child_by_field_name("left")?;
    match left.kind() {
        "lexical_declaration" | "variable_declaration" => left
            .children(&mut left.walk())
            .find(|c| c.kind() == "variable_declarator")
            .and_then(|d| d.child_by_field_name("name")),
        _ => Some(left),
    }
}

/// Loop variable gets the iterable's taint but not its none-ness or
/// resource (elements aren't the collection itself).
fn assign_for_target(
    target: Node,
    state: &VarState,
    ctx: &mut CtxJs,
    env: &mut HashMap<String, VarState>,
) {
    let mut st = VarState::default();
    st.taint = state.taint.clone();
    assign_pattern(target, st, None, ctx, env, target);
}

/// All identifier keys bound by a pattern (object_pattern,
/// array_pattern, identifier, member/subscript for completeness).
fn pattern_keys(node: Node, ctx: &CtxJs) -> Option<Vec<String>> {
    let mut out = Vec::new();
    collect_pattern_keys(node, ctx, &mut out);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn collect_pattern_keys(node: Node, ctx: &CtxJs, out: &mut Vec<String>) {
    match node.kind() {
        "identifier" => {
            if let Ok(t) = node.utf8_text(ctx.f.text.as_bytes()) {
                out.push(t.to_string());
            }
        }
        "object_pattern"
        | "array_pattern"
        | "rest_pattern"
        | "assignment_pattern"
        | "parenthesized_expression" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    collect_pattern_keys(ch, ctx, out);
                }
            }
        }
        "pair_pattern" => {
            if let Some(v) = node.child_by_field_name("value") {
                collect_pattern_keys(v, ctx, out);
            }
        }
        "shorthand_property_identifier_pattern" => {
            if let Ok(t) = node.utf8_text(ctx.f.text.as_bytes()) {
                out.push(t.to_string());
            }
        }
        _ => {}
    }
}

/// Branch bodies run on a cloned env, then join back (may-analysis).
fn walk_branch(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) {
    walk_branch_narrow(node, ctx, env, &[]);
}

fn walk_branch_narrow(
    node: Node,
    ctx: &mut CtxJs,
    env: &mut HashMap<String, VarState>,
    narrow: &[(String, bool)],
) {
    let mut env2 = env.clone();
    for (key, is_none) in narrow {
        if let Some(st) = env2.get_mut(key.as_str()) {
            st.is_none = *is_none;
        }
    }
    walk_stmt(node, ctx, &mut env2);
    for (k, v) in env2 {
        env.entry(k).or_default().join(&v);
    }
}

type Narrows = (Vec<(String, bool)>, Vec<(String, bool)>);

/// Null-related condition analysis for JS: `x == null`,
/// `x === undefined`, `typeof x === "undefined"`, `!`/`&&`/`||`
/// recursion, `??` treated conservatively (no narrow).
fn null_checks(cond: Node, ctx: &CtxJs, env: &HashMap<String, VarState>) -> Narrows {
    match cond.kind() {
        "parenthesized_expression" => {
            let inner = cond.children(&mut cond.walk()).find(|k| k.is_named());
            match inner {
                Some(n) => null_checks(n, ctx, env),
                None => (vec![], vec![]),
            }
        }
        "unary_expression" => {
            let op = cond
                .child_by_field_name("operator")
                .and_then(|o| o.utf8_text(ctx.f.text.as_bytes()).ok())
                .unwrap_or("");
            if op == "!" {
                if let Some(arg) = cond.child_by_field_name("argument") {
                    let (a, b) = null_checks(arg, ctx, env);
                    return (b, a);
                }
            }
            (vec![], vec![])
        }
        "binary_expression" => {
            let op = cond
                .child_by_field_name("operator")
                .and_then(|o| o.utf8_text(ctx.f.text.as_bytes()).ok())
                .unwrap_or("");
            match op {
                "&&" | "||" => {
                    let l = cond.child_by_field_name("left");
                    let r = cond.child_by_field_name("right");
                    if let (Some(a), Some(b)) = (l, r) {
                        let (lt, lf) = null_checks(a, ctx, env);
                        let (rt, rf) = null_checks(b, ctx, env);
                        if op == "&&" {
                            let mut t = lt;
                            t.extend(rt);
                            (t, vec![])
                        } else {
                            let mut f = lf;
                            f.extend(rf);
                            (vec![], f)
                        }
                    } else {
                        (vec![], vec![])
                    }
                }
                "==" | "===" | "!=" | "!==" => leaf_null_check(cond, op, ctx, env),
                _ => (vec![], vec![]),
            }
        }
        _ => (vec![], vec![]),
    }
}

/// `x == null` / `x === undefined` / `typeof x === "undefined"`.
fn leaf_null_check(cond: Node, op: &str, ctx: &CtxJs, env: &HashMap<String, VarState>) -> Narrows {
    let l = cond.child_by_field_name("left");
    let r = cond.child_by_field_name("right");
    let (Some(left), Some(right)) = (l, r) else {
        return (vec![], vec![]);
    };
    // typeof x === "undefined" / typeof x !== "undefined"
    if left.kind() == "unary_expression" {
        let is_typeof = left
            .child_by_field_name("operator")
            .and_then(|o| o.utf8_text(ctx.f.text.as_bytes()).ok())
            .is_some_and(|o| o == "typeof");
        if is_typeof {
            if let Some(arg) = left.child_by_field_name("argument") {
                if right.kind() == "string" {
                    if let Ok(s) = right.utf8_text(ctx.f.text.as_bytes()) {
                        let inner = s
                            .trim_start_matches(['"', '\''])
                            .trim_end_matches(['"', '\'']);
                        if inner == "undefined" {
                            let is_none_true = matches!(op, "==" | "===");
                            if let Some(key) = expr_key(arg, ctx, env) {
                                return (
                                    vec![(key.clone(), is_none_true)],
                                    vec![(key, !is_none_true)],
                                );
                            }
                        }
                    }
                }
            }
        }
        return (vec![], vec![]);
    }
    // x == null / x === undefined (and inverses)
    let nullish = |n: Node| matches!(n.kind(), "null" | "undefined");
    let target = if nullish(right) {
        left
    } else if nullish(left) {
        right
    } else {
        return (vec![], vec![]);
    };
    // `== null` also catches undefined in JS semantics.
    let is_none_true = matches!(op, "==" | "===");
    match expr_key(target, ctx, env) {
        Some(key) => (
            vec![(key.clone(), is_none_true)],
            vec![(key, !is_none_true)],
        ),
        None => (vec![], vec![]),
    }
}

/// if/else with null-narrowing on branches and post-if guard
/// narrowing for terminal branches.
fn walk_if(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) {
    let cond = node.child_by_field_name("condition");
    let cons = node.child_by_field_name("consequence");
    let alt = node.child_by_field_name("alternative");
    let Some(cond) = cond else { return };
    eval_expr(cond, ctx, env);
    let check = null_checks(cond, ctx, env);

    let mut clauses: Vec<(Narrows, Node, bool)> = Vec::new();
    if let Some(c) = cons {
        clauses.push((check, c, false));
    }
    if let Some(a) = alt {
        // else_clause may wrap `else if` (nested if_statement) or a
        // plain statement/block.
        let inner = a.children(&mut a.walk()).find(|k| k.is_named());
        match inner {
            Some(n) if n.kind() == "if_statement" => {
                // else-if: recurse; its own walk_if handles narrows.
                clauses.push(((vec![], vec![]), n, true));
            }
            Some(n) => clauses.push(((vec![], vec![]), n, true)),
            None => {}
        }
    }

    let else_narrow: Vec<(String, bool)> = clauses
        .iter()
        .filter(|c| !c.2)
        .flat_map(|(narrows, _, _)| narrows.1.iter().cloned())
        .collect();
    for (narrows, suite, is_else) in &clauses {
        let narrow: &[(String, bool)] = if *is_else { &else_narrow } else { &narrows.0 };
        walk_branch_narrow(*suite, ctx, env, narrow);
    }

    // Post-if narrowing: single if/else in JS.
    let n = clauses.len();
    if n == 0 {
        return;
    }
    let terms: Vec<bool> = clauses
        .iter()
        .map(|(_, s, _)| !may_fall_off_js(*s))
        .collect();
    let has_else = clauses.iter().any(|c| c.2);
    if !has_else {
        // No else: terminal consequence -> condition false past if.
        if terms.get(0) == Some(&true) {
            for (key, v) in &clauses[0].0 .1 {
                if let Some(st) = env.get_mut(key.as_str()) {
                    st.is_none = *v;
                }
            }
        }
        return;
    }
    // With else: post-if reachable through whichever branch falls.
    let cons_falls = may_fall_off_js(clauses[0].1);
    let else_falls = may_fall_off_js(clauses[n - 1].1);
    if !cons_falls && else_falls {
        // Only else path reaches past -> condition was false.
        for (key, v) in &clauses[0].0 .1 {
            if let Some(st) = env.get_mut(key.as_str()) {
                st.is_none = *v;
            }
        }
    } else if cons_falls && !else_falls {
        // Only consequence path reaches past -> condition true.
        for (key, v) in &clauses[0].0 .0 {
            if let Some(st) = env.get_mut(key.as_str()) {
                st.is_none = *v;
            }
        }
    }
}

/// Assign evaluated state to a binding target (identifier, member,
/// subscript, or destructuring pattern).
fn assign_pattern(
    target: Node,
    state: VarState,
    source_label: Option<String>,
    ctx: &mut CtxJs,
    env: &mut HashMap<String, VarState>,
    assign_node: Node,
) {
    match target.kind() {
        "identifier" => {
            let Ok(name) = target.utf8_text(ctx.f.text.as_bytes()) else {
                return;
            };
            let mut st = state.clone();
            if st.taint.is_none() {
                st.taint = source_label;
            }
            if let Some(kind) = resource_kind_of(assign_node, ctx) {
                st.resource = Some(kind.clone());
                ctx.acquired
                    .push((name.to_string(), kind, line_of(assign_node)));
            }
            env.insert(name.to_string(), st);
            // Per-index/per-key element states for `x = [a, b]` and
            // `x = {k: v}` so `x[0]`/`x.k` resolve precisely (mirror
            // of Python's tuple/list per-index tracking). Stale
            // element entries are dropped when the container is
            // reassigned a non-literal.
            if let Some(rhs) = rhs_node(assign_node) {
                clear_element_states(env, name);
                record_element_states(name, rhs, ctx, env);
            } else {
                clear_element_states(env, name);
            }
        }
        "object_pattern" | "array_pattern" | "rest_pattern"
        | "assignment_pattern" | "parenthesized_expression" => {
            // Destructuring with a matching literal RHS distributes
            // per element: `const [a, b] = [tainted, clean]`.
            if target.kind() == "array_pattern" {
                if let Some(rhs) = rhs_node(assign_node) {
                    if rhs.kind() == "array"
                        && try_array_destructure(target, rhs, ctx, env)
                    {
                        return;
                    }
                }
            }
            if let Some(keys) = pattern_keys(target, ctx) {
                for k in keys {
                    let mut st = state.clone();
                    if st.taint.is_none() {
                        st.taint = source_label.clone();
                    }
                    env.insert(k, st);
                }
            }
        }
        "pair_pattern" => {
            if let Some(v) = target.child_by_field_name("value") {
                assign_pattern(v, state, source_label, ctx, env, assign_node);
            }
        }
        "member_expression" | "subscript_expression" => {
            if let Some(key) = expr_key(target, ctx, env) {
                let mut st = state.clone();
                if st.taint.is_none() {
                    st.taint = source_label;
                }
                if let Some(kind) = resource_kind_of(assign_node, ctx) {
                    st.resource = Some(kind.clone());
                    ctx.acquired.push((key.clone(), kind, line_of(assign_node)));
                }
                env.insert(key, st);
            }
        }
        _ => {}
    }
}

/// RHS expression node of an assignment-ish node (declarator value
/// or assignment right).
fn rhs_node(node: Node) -> Option<Node> {
    match node.kind() {
        "variable_declarator" => node.child_by_field_name("value"),
        "assignment_expression" | "augmented_assignment_expression" => {
            node.child_by_field_name("right")
        }
        _ => None,
    }
}

/// True if evaluating this expr cannot produce findings or mutate
/// analysis state (no calls, assignments, awaits, updates).
fn expr_is_side_effect_free(node: Node) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "call_expression" | "new_expression" | "assignment_expression"
                | "augmented_assignment_expression" | "await_expression"
                | "yield_expression" | "update_expression"
        ) {
            return false;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if ch.is_named() {
                stack.push(ch);
            }
        }
    }
    true
}

/// Drop tracked `name[i]` / `name.key` entries (container rebound).
fn clear_element_states(env: &mut HashMap<String, VarState>, name: &str) {
    let pi = format!("{name}[");
    let pk = format!("{name}.");
    env.retain(|k, _| !k.starts_with(&pi) && !k.starts_with(&pk));
}

/// Record `name[i]` / `name.key` env entries for array/object literal
/// RHS with side-effect-free elements (re-eval is finding-free).
fn record_element_states(
    name: &str,
    rhs: Node,
    ctx: &mut CtxJs,
    env: &mut HashMap<String, VarState>,
) {
    match rhs.kind() {
        "array" => {
            let elems: Vec<Node> = rhs
                .children(&mut rhs.walk())
                .filter(|k| k.is_named() && k.kind() != "spread_element")
                .collect();
            if elems.is_empty()
                || !elems.iter().all(|e| expr_is_side_effect_free(*e))
            {
                return;
            }
            for (i, e) in elems.iter().enumerate() {
                let v = eval_expr(*e, ctx, env);
                let mut est = v.state.clone();
                if est.taint.is_none() {
                    est.taint = v.source_label.clone();
                }
                env.insert(format!("{name}[{i}]"), est);
            }
        }
        "object" => {
            let mut c = rhs.walk();
            for ch in rhs.children(&mut c) {
                if ch.kind() != "pair" || !expr_is_side_effect_free(ch) {
                    continue;
                }
                let Some(key_node) = ch.child_by_field_name("key") else {
                    continue;
                };
                let key = match key_node.kind() {
                    "property_identifier" | "identifier" => key_node
                        .utf8_text(ctx.f.text.as_bytes())
                        .ok()
                        .map(str::to_string),
                    "string" | "number" => js_ipa::spec_string(
                        key_node,
                        ctx.f.text.as_str(),
                    )
                    .or_else(|| {
                        key_node
                            .utf8_text(ctx.f.text.as_bytes())
                            .ok()
                            .map(str::to_string)
                    }),
                    _ => None,
                };
                let (Some(key), Some(val)) =
                    (key, ch.child_by_field_name("value"))
                else {
                    continue;
                };
                if !expr_is_side_effect_free(val) {
                    continue;
                }
                let v = eval_expr(val, ctx, env);
                let mut est = v.state.clone();
                if est.taint.is_none() {
                    est.taint = v.source_label.clone();
                }
                env.insert(format!("{name}.{key}"), est);
            }
        }
        _ => {}
    }
}

/// `const [a, b] = [x, y]` with matching arity and side-effect-free
/// elements: distribute per-element states. Returns true when handled.
fn try_array_destructure(
    pat: Node,
    rhs: Node,
    ctx: &mut CtxJs,
    env: &mut HashMap<String, VarState>,
) -> bool {
    let elems: Vec<Node> = pat
        .children(&mut pat.walk())
        .filter(|k| k.is_named())
        .collect();
    let relems: Vec<Node> = rhs
        .children(&mut rhs.walk())
        .filter(|k| k.is_named() && k.kind() != "spread_element")
        .collect();
    if elems.len() != relems.len()
        || !relems.iter().all(|e| expr_is_side_effect_free(*e))
    {
        return false;
    }
    for (t, r) in elems.iter().zip(relems.iter()) {
        let v = eval_expr(*r, ctx, env);
        assign_pattern(*t, v.state.clone(), v.source_label.clone(), ctx, env, rhs);
    }
    true
}

/// If this assignment's RHS is a resource-acquiring call, return kind.
fn resource_kind_of(assign_node: Node, ctx: &CtxJs) -> Option<String> {
    let r = if assign_node.kind() == "variable_declarator" {
        assign_node.child_by_field_name("value")?
    } else {
        assign_node.child_by_field_name("right")?
    };
    if !matches!(r.kind(), "call_expression" | "new_expression") {
        return None;
    }
    let dotted = dotted_callee(r, ctx)?;
    let last = dotted.rsplit('.').next().unwrap_or(&dotted);
    Some(match last {
        "openSync" | "open" | "createReadStream" | "createWriteStream" | "createReadStreamSync" => {
            "file".into()
        }
        "connect" | "createConnection" => "conn".into(),
        "acquire" => "lock".into(),
        _ => return None,
    })
}

/// Dotted name of a call's callee expression.
fn dotted_callee(call: Node, ctx: &CtxJs) -> Option<String> {
    let func = if call.kind() == "new_expression" {
        call.child_by_field_name("constructor")?
    } else {
        call.child_by_field_name("function")?
    };
    dotted_expr(func, ctx)
}

/// Dotted name for identifier/member chains, resolving heads through
/// module bindings. `const {exec} = require('child_process')` makes
/// `exec` dotted "child_process.exec"; `import def from 'm'` treats
/// the default as the module itself (CJS interop).
fn dotted_expr(node: Node, ctx: &CtxJs) -> Option<String> {
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(text).ok()?;
            if name == "undefined" || name == "NaN" || name == "Infinity" {
                return Some(name.to_string());
            }
            match ctx.f.bindings.get(name) {
                Some((spec, member)) => {
                    let root = binding_root(spec, ctx);
                    match member.as_deref() {
                        None | Some("default") => Some(root),
                        Some(m) => Some(format!("{root}.{m}")),
                    }
                }
                None => Some(name.to_string()),
            }
        }
        "this" => Some("this".to_string()),
        "member_expression" => {
            let obj = node.child_by_field_name("object")?;
            let prop = node.child_by_field_name("property")?;
            let base = dotted_expr(obj, ctx)?;
            let p: String = match prop.kind() {
                "property_identifier" | "private_property_identifier" => {
                    prop.utf8_text(text).ok()?.to_string()
                }
                "string" | "number" => js_ipa::spec_string(prop, ctx.f.text.as_str())
                    .unwrap_or_else(|| prop.utf8_text(text).unwrap_or("").to_string()),
                _ => return None,
            };
            Some(format!("{base}.{p}"))
        }
        "subscript_expression" => {
            let obj = node.child_by_field_name("object")?;
            dotted_expr(obj, ctx)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            dotted_expr(inner, ctx)
        }
        _ => None,
    }
}

/// Root dotted name for a binding's module spec: bare specs stay
/// (`child_process`, `fs`); relative specs resolve to the project
/// file path (slashes kept - model names won't collide with paths).
fn binding_root(spec: &str, ctx: &CtxJs) -> String {
    if spec.starts_with('.') {
        js_ipa::resolve_spec(&ctx.f.rel, spec, ctx.file_set).unwrap_or_else(|| spec.to_string())
    } else {
        spec.to_string()
    }
}

/// Environment key for an lvalue-ish expression.
fn expr_key(node: Node, ctx: &CtxJs, env: &HashMap<String, VarState>) -> Option<String> {
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "identifier" => node.utf8_text(text).ok().map(|s| s.to_string()),
        "this" => Some("this".to_string()),
        "member_expression" => {
            let obj = node.child_by_field_name("object")?;
            let base = expr_key(obj, ctx, env)?;
            let prop = node.child_by_field_name("property")?;
            let p = prop.utf8_text(text).ok()?;
            Some(format!("{base}.{p}"))
        }
        "subscript_expression" => {
            let obj = node.child_by_field_name("object")?;
            let base = expr_key(obj, ctx, env)?;
            if let Some(idx) = node.child_by_field_name("index") {
                if idx.kind() == "number" {
                    if let Ok(i) = idx.utf8_text(text) {
                        if let Ok(n) = i.trim().parse::<i64>() {
                            return Some(format!("{base}[{n}]"));
                        }
                    }
                }
            }
            Some(base)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            expr_key(inner, ctx, env)
        }
        _ => None,
    }
}

/// Evaluate an expression to a VarState + optional source label.
fn eval_expr(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) -> ExprVal {
    if budget(ctx) {
        return ExprVal::default();
    }
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "string" | "number" | "true" | "false" | "regex" | "comment" => ExprVal::default(),
        "null" | "undefined" => ExprVal {
            state: VarState {
                is_none: true,
                ..Default::default()
            },
            source_label: None,
        },
        "identifier" => {
            let name = node.utf8_text(text).unwrap_or("");
            if name == "undefined" {
                return ExprVal {
                    state: VarState {
                        is_none: true,
                        ..Default::default()
                    },
                    source_label: None,
                };
            }
            ExprVal {
                state: env.get(name).cloned().unwrap_or_default(),
                source_label: None,
            }
        }
        "this" => ExprVal {
            state: env.get("this").cloned().unwrap_or_default(),
            source_label: None,
        },
        "member_expression" | "subscript_expression" => {
            if let Some(label) = source_label_of(node, ctx) {
                return ExprVal {
                    state: VarState {
                        taint: Some(label.clone()),
                        is_none: false,
                        resource: None,
                    },
                    source_label: Some(label),
                };
            }
            let base = if node.kind() == "member_expression" {
                node.child_by_field_name("object")
            } else {
                node.child_by_field_name("object")
            };
            let mut st = VarState::default();
            if let Some(b) = base {
                let bv = eval_expr(b, ctx, env);
                st = bv.state;
                // Optional chaining `?.` guards the null-deref.
                let optional = node.child_by_field_name("optional_chain").is_some();
                if st.is_none && !optional {
                    push_finding_at(ctx, SinkKind::NullDeref, "none", "member access", node, 0.8);
                    st.is_none = false;
                }
            }
            // env key lookup: an exact tracked entry (`x[0]`, `o.k`)
            // is authoritative for that element - sibling taint in
            // the container's joined state must not leak into it.
            // Dynamic subscripts with no exact entry fall back to
            // the container state.
            if let Some(key) = expr_key(node, ctx, env) {
                if env.contains_key(&key) {
                    // Exact tracked element/key state is authoritative.
                    st = env.get(&key).cloned().unwrap_or_default();
                } else {
                    let base = key
                        .split_once('[')
                        .map(|(b, _)| b)
                        .and_then(|b| env.get(b));
                    if let Some(prev) = base {
                        if prev.taint.is_some() || prev.is_none || prev.resource.is_some() {
                            let mut merged = st.clone();
                            if prev.taint.is_some() {
                                merged.taint = prev.taint.clone();
                            }
                            merged.is_none |= prev.is_none;
                            if prev.resource.is_some() {
                                merged.resource = prev.resource.clone();
                            }
                            st = merged;
                        }
                    }
                }
            }
            ExprVal {
                state: st,
                source_label: None,
            }
        }
        "call_expression" | "new_expression" => eval_call(node, ctx, env),
        "template_string" => eval_template(node, ctx, env),
        "binary_expression" => {
            let mut st = VarState::default();
            let mut label = None;
            for field in ["left", "right"] {
                if let Some(ch) = node.child_by_field_name(field) {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            ExprVal {
                state: st,
                source_label: label,
            }
        }
        "unary_expression" | "update_expression" => {
            let mut st = VarState::default();
            if let Some(arg) = node.child_by_field_name("argument") {
                let v = eval_expr(arg, ctx, env);
                // `void x` is undefined; other unary ops produce
                // clean scalars but still evaluate the operand.
                if node.kind() == "unary_expression" {
                    let op = node
                        .child_by_field_name("operator")
                        .and_then(|o| o.utf8_text(text).ok())
                        .unwrap_or("");
                    if op == "void" {
                        st.is_none = true;
                    }
                }
                let _ = v;
            }
            ExprVal {
                state: st,
                source_label: None,
            }
        }
        "ternary_expression" => {
            let mut st = VarState::default();
            let mut label = None;
            for field in ["condition", "consequence", "alternative"] {
                if let Some(ch) = node.child_by_field_name(field) {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            ExprVal {
                state: st,
                source_label: label,
            }
        }
        "array" | "object" | "sequence_expression" | "arguments" => {
            let mut st = VarState::default();
            let mut label = None;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            st.is_none = false;
            ExprVal {
                state: st,
                source_label: label,
            }
        }
        "pair" => {
            if let Some(v) = node.child_by_field_name("value") {
                eval_expr(v, ctx, env)
            } else {
                ExprVal::default()
            }
        }
        "parenthesized_expression" | "await_expression" | "yield_expression" | "spread_element" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named());
            match inner {
                Some(k) => eval_expr(k, ctx, env),
                None => ExprVal::default(),
            }
        }
        "assignment_expression" => {
            // JS assignments are expressions: `x = f()`, `a += b`.
            let right = node.child_by_field_name("right");
            let left = node.child_by_field_name("left");
            if let (Some(l), Some(r)) = (left, right) {
                let is_aug = node
                    .child_by_field_name("operator")
                    .and_then(|o| o.utf8_text(text).ok())
                    .is_some_and(|o| o != "=");
                let mut rv = eval_expr(r, ctx, env);
                if is_aug {
                    // `x += y`: result joins prior lhs state.
                    if let Some(key) = expr_key(l, ctx, env) {
                        if let Some(prev) = env.get(&key) {
                            let mut joined = prev.clone();
                            joined.join(&rv.state);
                            rv.state = joined;
                        }
                    }
                }
                assign_pattern(l, rv.state.clone(), rv.source_label.clone(), ctx, env, node);
                return rv;
            }
            ExprVal::default()
        }
        "augmented_assignment_expression" => {
            let right = node.child_by_field_name("right");
            let left = node.child_by_field_name("left");
            if let (Some(l), Some(r)) = (left, right) {
                let rv = eval_expr(r, ctx, env);
                assign_pattern(l, rv.state.clone(), rv.source_label.clone(), ctx, env, node);
                return rv;
            }
            ExprVal::default()
        }
        // Nested functions/classes evaluate to clean values; their
        // bodies are analyzed as separate FuncRefs.
        "function_declaration"
        | "function_expression"
        | "arrow_function"
        | "method_definition"
        | "generator_function_declaration"
        | "class_declaration"
        | "class"
        | "import_statement"
        | "lexical_declaration"
        | "variable_declaration" => ExprVal::default(),
        _ => {
            let mut st = VarState::default();
            let mut label = None;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            ExprVal {
                state: st,
                source_label: label,
            }
        }
    }
}

/// Template literal: fragments clean, substitutions propagate.
fn eval_template(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) -> ExprVal {
    let mut st = VarState::default();
    let mut label = None;
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        match ch.kind() {
            "template_substitution" => {
                let inner = ch.children(&mut ch.walk()).find(|x| x.is_named());
                if let Some(i) = inner {
                    let v = eval_expr(i, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            _ => {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                }
            }
        }
    }
    ExprVal {
        state: st,
        source_label: label,
    }
}

/// Is this expression a model source? Returns provenance label.
fn source_label_of(node: Node, ctx: &CtxJs) -> Option<String> {
    let dotted = dotted_expr(node, ctx)?;
    let kind = ctx.model.source_kind(&dotted)?;
    Some(format!("src:{kind:?}"))
}

/// Process a call/new: sinks, sources, sanitizers, resolved callees,
/// unknown-call taint propagation.
fn eval_call(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) -> ExprVal {
    if let Some(func) = node.child_by_field_name("function") {
        if matches!(func.kind(), "member_expression" | "subscript_expression") {
            eval_expr(func, ctx, env);
        }
    }
    if node.kind() == "new_expression" {
        if let Some(c) = node.child_by_field_name("constructor") {
            if matches!(c.kind(), "member_expression" | "subscript_expression") {
                eval_expr(c, ctx, env);
            }
        }
    }
    let Some(dotted) = dotted_callee(node, ctx) else {
        ctx.touches_unknown = true;
        return ExprVal::default();
    };

    let args = call_args(node, ctx, env);

    // Resource args may transfer ownership to the callee.
    if let Some(arglist) = node.child_by_field_name("arguments") {
        let mut ac = arglist.walk();
        let arg_nodes: Vec<Node> = arglist.children(&mut ac).filter(|k| k.is_named()).collect();
        for an in arg_nodes {
            let val = match an.kind() {
                "spread_element" => an.children(&mut an.walk()).find(|k| k.is_named()),
                _ => Some(an),
            };
            if let Some(v) = val {
                if let Some(key) = expr_key(v, ctx, env) {
                    if env.get(&key).is_some_and(|st| st.resource.is_some()) {
                        ctx.escaped.insert(key);
                    }
                }
            }
        }
    }

    // Explicit resource release: `x.close()`, `x.destroy()`,
    // `stream.end()`, `fs.closeSync(fd)`, `conn.disconnect()`.
    if let Some(func) = node.child_by_field_name("function") {
        if func.kind() == "member_expression" {
            if let Some(prop) = func.child_by_field_name("property") {
                if let Ok(attr_name) = prop.utf8_text(ctx.f.text.as_bytes()) {
                    if matches!(
                        attr_name,
                        "close"
                            | "end"
                            | "destroy"
                            | "disconnect"
                            | "release"
                            | "dispose"
                            | "unref"
                            | "pause"
                            | "resume"
                    ) {
                        // Only treat as release for known resource-ish
                        // receivers to avoid noise: env must hold it.
                        if let Some(obj) = func.child_by_field_name("object") {
                            if let Some(key) = expr_key(obj, ctx, env) {
                                if env.get(&key).is_some_and(|st| st.resource.is_some()) {
                                    ctx.released.insert(key.clone());
                                    if let Some(st) = env.get_mut(&key) {
                                        st.resource = None;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // `fs.closeSync(fd)` / `fs.close(fd, cb)` style releases.
    if matches!(
        dotted.rsplit('.').next().unwrap_or(""),
        "closeSync" | "close"
    ) {
        if let Some(arg0) = args_node_at(node, 0) {
            if let Some(key) = expr_key(arg0, ctx, env) {
                if env.get(&key).is_some_and(|st| st.resource.is_some()) {
                    ctx.released.insert(key.clone());
                    if let Some(st) = env.get_mut(&key) {
                        st.resource = None;
                    }
                }
            }
        }
    }

    // 1. Sink check by dotted name.
    let mut sink_hit: Vec<(SinkKind, usize)> = Vec::new();
    for rule in ctx.model.sinks_for(&dotted) {
        match rule.arg {
            Some(i) => {
                if i < args.len() {
                    sink_hit.push((rule.class.clone(), i));
                }
            }
            None => {
                for i in 0..args.len() {
                    sink_hit.push((rule.class.clone(), i));
                }
            }
        }
    }

    // 2. Source check.
    let mut result = ExprVal::default();
    if let Some(kind) = ctx.model.source_kind(&dotted) {
        result.source_label = Some(format!("src:{kind:?}"));
        result.state.taint = result.source_label.clone();
    }

    // 3. Sanitizer.
    let is_sanitizer = ctx
        .model
        .sanitizer_names()
        .contains(dotted.rsplit('.').next().unwrap_or(&dotted));

    // 4. Apply sink rules to arg states.
    if !is_sanitizer {
        for (class, idx) in &sink_hit {
            let Some(av) = args.get(*idx) else { continue };
            if let Some(label) = &av.state.taint {
                handle_sink_taint(ctx, class.clone(), label.clone(), &dotted, node);
            }
        }
    }

    // 5. Callee resolution + summary application.
    if let Some((cm, cf)) = resolve_callee(node, ctx.f, ctx.parsed, ctx.file_index, ctx.file_set) {
        let key = (cm.clone(), cf.clone());
        if let Some(sum) = ctx.summaries.get(&key) {
            apply_summary(node, ctx, env, &args, sum, &format!("{cm}.{cf}"));
        } else {
            unknown_call_result(&args, &mut result, ctx, &dotted);
        }
    } else {
        unknown_call_result(&args, &mut result, ctx, &dotted);
    }

    if let Some(pr) = ctx.pending_result.take() {
        if result.state.taint.is_none() {
            result.state.taint = pr.state.taint;
        }
        result.state.is_none |= pr.state.is_none;
        if result.state.resource.is_none() {
            result.state.resource = pr.state.resource;
        }
    }

    // Model propagators: declared arg->return flows for resolved
    // callees whose summary does not propagate taint.
    if result.state.taint.is_none()
        && ctx
            .model
            .propagators
            .iter()
            .any(|p| dotted == *p || dotted.ends_with(&format!(".{p}")))
    {
        if let Some(av) = args.iter().find(|a| a.state.taint.is_some()) {
            result.state.taint = av.state.taint.clone();
        }
    }

    if is_sanitizer {
        result.state.taint = None;
        result.source_label = None;
    }
    result
}

/// The nth named argument node of a call (no eval - for key lookup).
fn args_node_at<'t>(node: Node<'t>, idx: usize) -> Option<Node<'t>> {
    let args = node.child_by_field_name("arguments")?;
    args.children(&mut args.walk())
        .filter(|k| k.is_named())
        .nth(idx)
}

/// Tainted arg reached a sink: concrete finding or param flow.
fn handle_sink_taint(ctx: &mut CtxJs, class: SinkKind, label: String, sink_name: &str, node: Node) {
    if let Some(param_part) = label.strip_prefix("param:") {
        if let Ok(idx) = param_part.parse::<usize>() {
            let ps = PendingSink {
                class,
                file: ctx.f.rel.clone(),
                line: line_of(node),
                func: ctx.qualname.to_string(),
                sink: sink_name.to_string(),
                through: vec![format!("{}.{}", ctx.f.rel, ctx.qualname)],
            };
            ctx.param_sinks.entry(idx).or_default().push(ps);
            return;
        }
    }
    push_finding_at(ctx, class, &label, sink_name, node, 1.0);
}

fn push_finding_at(
    ctx: &mut CtxJs,
    class: SinkKind,
    source: &str,
    sink: &str,
    node: Node,
    conf: f32,
) {
    let key = (
        class.clone(),
        line_of(node),
        source.to_string(),
        sink.to_string(),
    );
    if !ctx.reported.insert(key) {
        return;
    }
    ctx.findings.push(Finding {
        class,
        source: source.to_string(),
        sink: sink.to_string(),
        file: ctx.f.rel.clone(),
        line: line_of(node),
        func: ctx.qualname.to_string(),
        via: vec![format!("{}.{}", ctx.f.rel, ctx.qualname)],
        confidence: conf,
    });
}

/// All argument value states of a call, in order.
fn call_args(node: Node, ctx: &mut CtxJs, env: &mut HashMap<String, VarState>) -> Vec<ExprVal> {
    let mut out = Vec::new();
    let Some(args) = node.child_by_field_name("arguments") else {
        return out;
    };
    let mut c = args.walk();
    for ch in args.children(&mut c) {
        if ch.is_named() {
            match ch.kind() {
                "spread_element" => {
                    if let Some(inner) = ch.children(&mut ch.walk()).find(|k| k.is_named()) {
                        out.push(eval_expr(inner, ctx, env));
                    }
                }
                _ => out.push(eval_expr(ch, ctx, env)),
            }
        }
    }
    out
}

/// Resolve this call's callee to (module_rel, qualname) using the
/// same rules as the JS call index: import/require bindings,
/// same-file functions, `this.` methods, namespace member calls.
pub fn resolve_callee(
    node: Node,
    f: &JsFile,
    parsed: &[JsFile],
    file_index: &HashMap<String, usize>,
    file_set: &BTreeSet<String>,
) -> Option<NodeId> {
    let func_node = if node.kind() == "new_expression" {
        node.child_by_field_name("constructor")?
    } else {
        node.child_by_field_name("function")?
    };
    match func_node.kind() {
        "identifier" => {
            let name = func_node.utf8_text(f.text.as_bytes()).ok()?;
            // Import/require-bound member: `const {f} = require('m')`.
            if let Some((spec, Some(member))) = f.bindings.get(name) {
                let m = js_ipa::resolve_spec(&f.rel, spec, file_set)?;
                return qualname_in(&m, member, parsed, file_index).map(|q| (m, q));
            }
            // Whole-module binding used as a function: `const f =
            // require('m')` then `f()` - f IS the module (usually
            // module.exports = function). Map to "<module>".
            if let Some((spec, None)) = f.bindings.get(name) {
                if let Some(m) = js_ipa::resolve_spec(&f.rel, spec, file_set) {
                    return Some((m, "<module>".to_string()));
                }
                return None;
            }
            // Same-file function.
            if let Some(q) = local_qualname(f, name) {
                return Some((f.rel.clone(), q));
            }
            None
        }
        "member_expression" => {
            let prop = func_node.child_by_field_name("property")?;
            let fname = prop.utf8_text(f.text.as_bytes()).ok()?;
            let obj = func_node.child_by_field_name("object")?;
            // `this.m()` inside a class -> Class.m
            if obj.kind() == "this" {
                if let Some(class) = enclosing_class(node, f) {
                    let qual = format!("{class}.{fname}");
                    if f.funcs.values().flatten().any(|i| i.qualname == qual) {
                        return Some((f.rel.clone(), qual));
                    }
                }
                return None;
            }
            // `ns.f()` / `m.f()` where m is a module binding.
            let module_file = object_module_js(obj, f, file_set)?;
            qualname_in(&module_file, fname, parsed, file_index).map(|q| (module_file, q))
        }
        "parenthesized_expression" => {
            let inner = func_node
                .children(&mut func_node.walk())
                .find(|k| k.is_named())?;
            // Recurse with a synthetic check: resolve inner directly.
            resolve_func_node(inner, f, parsed, file_index, file_set)
        }
        _ => None,
    }
}

fn resolve_func_node(
    func_node: Node,
    f: &JsFile,
    parsed: &[JsFile],
    file_index: &HashMap<String, usize>,
    file_set: &BTreeSet<String>,
) -> Option<NodeId> {
    // Same logic as resolve_callee's dispatch, minus the call wrapper.
    match func_node.kind() {
        "identifier" => {
            let name = func_node.utf8_text(f.text.as_bytes()).ok()?;
            if let Some((spec, Some(member))) = f.bindings.get(name) {
                let m = js_ipa::resolve_spec(&f.rel, spec, file_set)?;
                return qualname_in(&m, member, parsed, file_index).map(|q| (m, q));
            }
            if let Some((spec, None)) = f.bindings.get(name) {
                return js_ipa::resolve_spec(&f.rel, spec, file_set)
                    .map(|m| (m, "<module>".to_string()));
            }
            local_qualname(f, name).map(|q| (f.rel.clone(), q))
        }
        "member_expression" => {
            let prop = func_node.child_by_field_name("property")?;
            let fname = prop.utf8_text(f.text.as_bytes()).ok()?;
            let obj = func_node.child_by_field_name("object")?;
            if obj.kind() == "this" {
                if let Some(class) = enclosing_class_from(func_node, f) {
                    let qual = format!("{class}.{fname}");
                    if f.funcs.values().flatten().any(|i| i.qualname == qual) {
                        return Some((f.rel.clone(), qual));
                    }
                }
                return None;
            }
            let module_file = object_module_js(obj, f, file_set)?;
            qualname_in(&module_file, fname, parsed, file_index).map(|q| (module_file, q))
        }
        "parenthesized_expression" => {
            let inner = func_node
                .children(&mut func_node.walk())
                .find(|k| k.is_named())?;
            resolve_func_node(inner, f, parsed, file_index, file_set)
        }
        _ => None,
    }
}

/// Best qualname for a short function name in the CURRENT file:
/// prefer non-method, non-stub, last definition.
fn local_qualname(f: &JsFile, name: &str) -> Option<String> {
    f.funcs.get(name).and_then(|v| {
        v.iter()
            .rev()
            .find(|i| !i.is_method && !i.is_stub)
            .or_else(|| v.iter().rev().find(|i| !i.is_method))
            .or_else(|| v.last())
            .map(|i| i.qualname.clone())
    })
}

/// Qualname for an exported/member function name in a target file.
/// `member` is the import/export name; it matches the funcs short-name
/// key (function declarations, declarator-bound arrows, and methods
/// all key by short name). Prefer non-method, non-stub, last def.
fn qualname_in(
    module_file: &str,
    member: &str,
    parsed: &[JsFile],
    file_index: &HashMap<String, usize>,
) -> Option<String> {
    let idx = *file_index.get(module_file)?;
    let tf = parsed.get(idx)?;
    tf.funcs.get(member).and_then(|v| {
        v.iter()
            .rev()
            .find(|i| !i.is_method && !i.is_stub)
            .or_else(|| v.iter().rev().find(|i| !i.is_method))
            .or_else(|| v.last())
            .map(|i| i.qualname.clone())
    })
}

/// Object of a member call -> module file it refers to.
fn object_module_js(obj: Node, f: &JsFile, file_set: &BTreeSet<String>) -> Option<String> {
    match obj.kind() {
        "identifier" => {
            let name = obj.utf8_text(f.text.as_bytes()).ok()?;
            match f.bindings.get(name) {
                Some((spec, _)) => js_ipa::resolve_spec(&f.rel, spec, file_set),
                None => None,
            }
        }
        "member_expression" | "subscript_expression" => {
            // Dotted chain a.b.c - resolve the head object.
            let inner = if obj.kind() == "member_expression" {
                obj.child_by_field_name("object")?
            } else {
                obj.child_by_field_name("object")?
            };
            object_module_js(inner, f, file_set)
        }
        "this" => None,
        "parenthesized_expression" => {
            let inner = obj.children(&mut obj.walk()).find(|k| k.is_named())?;
            object_module_js(inner, f, file_set)
        }
        _ => None,
    }
}

/// Nearest enclosing class name of a node.
fn enclosing_class(node: Node, f: &JsFile) -> Option<String> {
    enclosing_class_from(node, f)
}

fn enclosing_class_from(node: Node, f: &JsFile) -> Option<String> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if n.kind() == "class_declaration" || n.kind() == "class" {
            return n
                .child_by_field_name("name")
                .and_then(|x| x.utf8_text(f.text.as_bytes()).ok())
                .map(|s| s.to_string());
        }
        anc = n.parent();
    }
    None
}

/// Apply a resolved callee's summary to this call.
fn apply_summary(
    _node: Node,
    ctx: &mut CtxJs,
    env: &mut HashMap<String, VarState>,
    args: &[ExprVal],
    sum: &Summary,
    callee_label: &str,
) {
    let _ = env;
    let caller_qual = format!("{}.{}", ctx.f.rel, ctx.qualname);
    let mut result_taint: Option<String> = None;
    let result_none = sum.may_return_none;
    let result_resource = sum.returns_unclosed.clone();

    for (i, av) in args.iter().enumerate() {
        if let Some(label) = &av.state.taint {
            if let Some(pending_list) = sum.param_sinks.get(&i) {
                for ps in pending_list {
                    if let Some(pi) = label
                        .strip_prefix("param:")
                        .and_then(|r| r.parse::<usize>().ok())
                    {
                        let mut through = vec![caller_qual.clone()];
                        through.extend(ps.through.iter().cloned());
                        ctx.param_sinks.entry(pi).or_default().push(PendingSink {
                            class: ps.class.clone(),
                            file: ps.file.clone(),
                            line: ps.line,
                            func: ps.func.clone(),
                            sink: ps.sink.clone(),
                            through,
                        });
                    } else {
                        let mut via = vec![caller_qual.clone()];
                        via.extend(ps.through.iter().cloned());
                        ctx.findings.push(Finding {
                            class: ps.class.clone(),
                            source: label.clone(),
                            sink: ps.sink.clone(),
                            file: ps.file.clone(),
                            line: ps.line,
                            func: ps.func.clone(),
                            via,
                            confidence: 0.9,
                        });
                    }
                }
            }
        }
        if sum.param_to_return.contains(&i) && result_taint.is_none() {
            result_taint = av.state.taint.clone();
        }
    }
    if sum.returns_tainted && result_taint.is_none() {
        result_taint = Some(format!("ret:{callee_label}"));
    }
    ctx.pending_result = Some(ExprVal {
        state: VarState {
            taint: result_taint,
            is_none: result_none,
            resource: result_resource,
        },
        source_label: None,
    });
}

/// Unresolvable/unknown callee: taint propagates arg->result
/// conservatively; flag touches_unknown.
fn unknown_call_result(args: &[ExprVal], result: &mut ExprVal, ctx: &mut CtxJs, dotted: &str) {
    ctx.touches_unknown = true;
    for av in args {
        if av.state.taint.is_some() {
            result.state.taint = Some(format!("call:{dotted}"));
            break;
        }
        if av.state.resource.is_some() && result.state.resource.is_none() {
            result.state.resource = av.state.resource.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::js_default;

    fn run(files: &[(&str, &str)]) -> crate::solver::SolveOutput {
        let file_set: BTreeSet<String> = files.iter().map(|(k, _)| k.to_string()).collect();
        let parsed: Vec<JsFile> = files
            .iter()
            .filter_map(|(rel, text)| js_ipa::analyze_source(rel, text))
            .collect();
        let model = js_default().unwrap();
        crate::solver_js::solve_js(&parsed, &file_set, &model)
    }

    #[test]
    fn taint_env_to_exec_cross_function() {
        let out = run(&[(
            "app.js",
            r#"
const cp = require('child_process');
function run(name) {
  cp.exec(name);
}
function main() {
  const name = process.env.X;
  run(name);
}
main();
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
    fn taint_argv_to_eval() {
        let out = run(&[(
            "app.js",
            "function main() {\n  eval(process.argv[2]);\n}\nmain();\n",
        )]);
        assert!(out.findings.iter().any(|f| f.class == SinkKind::CodeExec));
    }

    #[test]
    fn null_guard_no_finding_unguarded_finding() {
        let guarded = run(&[(
            "t.js",
            "function maybe() { return null; }\nfunction f() {\n  const x = maybe();\n  if (x == null) return;\n  x.bit_length();\n}\n",
        )]);
        assert!(
            !guarded
                .findings
                .iter()
                .any(|f| f.class == SinkKind::NullDeref),
            "guarded deref should not flag: {:?}",
            guarded.findings
        );
        let unguarded = run(&[(
            "t.js",
            "function maybe() { return null; }\nfunction f() {\n  const x = maybe();\n  x.bit_length();\n}\n",
        )]);
        assert!(unguarded
            .findings
            .iter()
            .any(|f| f.class == SinkKind::NullDeref));
    }

    #[test]
    fn sanitizer_stops_taint() {
        let out = run(&[(
            "t.js",
            "function main() {\n  const x = parseInt(process.argv[1], 10);\n  eval(x);\n}\n",
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::CodeExec),
            "parseInt sanitizer should stop argv taint: {:?}",
            out.findings
        );
    }

    #[test]
    fn per_index_array_tracking() {
        // x[0] tainted, x[1] clean - only index 0 should reach eval.
        let out = run(&[(
            "t.js",
            "function main() {\n  const pair = [process.env.X, 'ok'];\n  eval(pair[0]);\n  eval(pair[1]);\n}\n",
        )]);
        let hits: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::CodeExec)
            .collect();
        assert_eq!(hits.len(), 1, "only pair[0] should flag: {:?}", out.findings);
        assert_eq!(hits[0].line, 3);
    }

    #[test]
    fn array_destructuring_per_element() {
        let out = run(&[(
            "t.js",
            "function main() {\n  const [bad, good] = [process.env.X, 'ok'];\n  eval(bad);\n  eval(good);\n}\n",
        )]);
        let hits: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::CodeExec)
            .collect();
        assert_eq!(hits.len(), 1, "only bad should flag: {:?}", out.findings);
        assert_eq!(hits[0].line, 3);
    }

    #[test]
    fn object_literal_key_tracking() {
        let out = run(&[(
            "t.js",
            "const cp = require('child_process');\nfunction main() {\n  const o = { cmd: process.env.X, ok: 'ls' };\n  cp.exec(o.cmd);\n  cp.exec(o.ok);\n}\n",
        )]);
        let hits: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Shell)
            .collect();
        assert_eq!(hits.len(), 1, "only o.cmd should flag: {:?}", out.findings);
    }

    #[test]
    fn leak_open_close() {
        let out = run(&[(
            "t.js",
            "const fs = require('fs');\nfunction leaker() {\n  const fd = fs.openSync('x');\n}\nfunction closer() {\n  const fd = fs.openSync('x');\n  fs.closeSync(fd);\n}\n",
        )]);
        let leaks: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Leak)
            .collect();
        assert_eq!(
            leaks.len(),
            1,
            "only leaker should flag: {:?}",
            out.findings
        );
        assert!(leaks[0].func.contains("leaker"));
    }
}
