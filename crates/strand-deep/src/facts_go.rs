//! Per-function dataflow facts for Go: taint, nil, and resource
//! tracking - the Go mirror of `facts_js.rs`.
//!
//! Same value domains and honesty contract: may-analyses with union
//! joins, single-pass (no intra-procedural fixpoint), env keys are
//! dotted field paths (`a.b`) with numeric subscripts kept as
//! `a[0]` and other subscripts collapsed to the base. `nil` feeds
//! the `is_none` flag; Go has no undefined, and nilable zero values
//! (`var p *T`, bare `return` in a nilable-results func) count.
//!
//! Module identity is the package directory: calls resolve within
//! the caller's package (all files in the same dir) plus imported
//! project packages via go.mod module prefixes. Selector callees
//! resolve through a lightweight type environment (`x := T{}`,
//! `var db *sql.DB`, `x, _ := sql.Open(...)`) so `recv.Method()`
//! reaches same-package methods; external receivers stay unknown.
//!
//! Documented approximations: index expressions are not nil-deref
//! sinks (nil map reads are legal); comma-ok/type-assert second
//! values are not modeled; types set inside branches persist
//! (no per-branch type join); `defer`/`go` bodies evaluate at the
//! statement (release calls inside `defer f.Close()` still count).

use std::collections::{BTreeMap, HashMap, HashSet};

use tree_sitter::Node;

use crate::facts::{Finding, FuncAnalysis, PendingSink, Summary, VarState};
use crate::go_deep::{self, GoFile, GoFuncInfo, GoModules};
use crate::models::{Model, SinkKind};
use crate::solver::NodeId;

const NODE_BUDGET: usize = 100_000;

#[derive(Debug, Clone, Default)]
struct ExprVal {
    state: VarState,
    /// Set when the expr itself is a model source.
    source_label: Option<String>,
}

/// Shared context for one Go function's walk.
pub struct CtxGo<'a> {
    f: &'a GoFile,
    parsed: &'a [GoFile],
    /// package dir -> indices into `parsed`.
    pkg_dirs: &'a HashMap<String, Vec<usize>>,
    mods: &'a GoModules,
    model: &'a Model,
    summaries: &'a HashMap<NodeId, Summary>,
    qualname: &'a str,
    /// var/field key -> type name, for `recv.Method()` resolution.
    /// Mutated during the walk; branch bodies share it (documented).
    types: HashMap<String, String>,
    acquired: Vec<(String, String, u32)>,
    released: HashSet<String>,
    escaped: HashSet<String>,
    ret: VarState,
    saw_return: bool,
    /// Result types are nilable - bare `return` may yield nil.
    nilable_results: bool,
    nodes_left: usize,
    pub budget_hit: bool,
    pub findings: Vec<Finding>,
    pub param_sinks: BTreeMap<usize, Vec<PendingSink>>,
    pub touches_unknown: bool,
    reported: HashSet<(SinkKind, u32, String, String)>,
    pending_result: Option<ExprVal>,
}

/// Builtin names that are never project functions.
const GO_BUILTINS: &[&str] = &[
    "append", "cap", "clear", "close", "complex", "copy", "delete",
    "imag", "len", "make", "max", "min", "new", "panic", "print",
    "println", "real", "recover",
];

/// Call dotted names whose result is a known type (for `x.M()`
/// resolution). Keyed by canonical dotted callee.
const CALL_RET_TYPES: &[(&str, &str)] = &[
    ("sql.Open", "sql.DB"),
    ("sql.OpenDB", "sql.DB"),
    ("sql.Connect", "sql.DB"),
];

/// Analyze a Go function body. `func_node` = function_declaration /
/// method_declaration / func_literal or the source_file root for
/// `<module>`; `info` carries params/receiver/nilable-results for
/// real functions (None for module).
pub fn analyze_function_go<'a>(
    f: &'a GoFile,
    func_node: Node,
    info: Option<&GoFuncInfo>,
    qualname: &str,
    model: &Model,
    summaries: &HashMap<NodeId, Summary>,
    globals: Option<&HashMap<String, VarState>>,
    pkg_types: Option<&HashMap<String, String>>,
    parsed: &'a [GoFile],
    pkg_dirs: &'a HashMap<String, Vec<usize>>,
    mods: &'a GoModules,
) -> (FuncAnalysis, HashMap<String, String>) {
    let mut ctx = CtxGo {
        f,
        parsed,
        pkg_dirs,
        mods,
        model,
        summaries,
        qualname,
        types: pkg_types.cloned().unwrap_or_default(),
        acquired: Vec::new(),
        released: HashSet::new(),
        escaped: HashSet::new(),
        ret: VarState::default(),
        saw_return: false,
        nilable_results: info.map(|i| i.nilable_results).unwrap_or(false),
        nodes_left: NODE_BUDGET,
        budget_hit: false,
        findings: Vec::new(),
        param_sinks: BTreeMap::new(),
        touches_unknown: false,
        reported: HashSet::new(),
        pending_result: None,
    };
    // Method receiver seeds the type env: `func (s *Server) M()`
    // makes `s.Foo()` resolve to `Server.Foo`.
    if let Some(info) = info {
        if let Some((recv_name, recv_ty)) = &info.receiver {
            ctx.types.insert(recv_name.clone(), recv_ty.clone());
        }
    }
    let mut env: HashMap<String, VarState> = globals.cloned().unwrap_or_default();
    if let Some(info) = info {
        for (i, p) in info.params.iter().enumerate() {
            env.insert(
                p.clone(),
                VarState {
                    taint: Some(format!("param:{i}")),
                    is_none: false,
                    resource: None,
                },
            );
        }
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
                via: vec![qual_label(&ctx.f.dir, qualname)],
                confidence: 0.8,
            });
        }
    }

    // Go funcs with results must return on every path (compile
    // error otherwise); fall-off contributes nothing. Bare `return`
    // in a nilable-results func yields the zero value (nil).
    let mut summary = Summary {
        may_return_none: ctx.ret.is_none,
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
    let analysis = FuncAnalysis {
        summary,
        env,
        budget_hit: ctx.budget_hit,
    };
    (analysis, ctx.types)
}

fn first_unclosed(ctx: &CtxGo) -> Option<String> {
    for (var, kind, _) in &ctx.acquired {
        if !ctx.released.contains(var) {
            return Some(kind.clone());
        }
    }
    ctx.ret.resource.clone()
}

fn line_of(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

fn budget(ctx: &mut CtxGo) -> bool {
    if ctx.nodes_left == 0 {
        ctx.budget_hit = true;
        return true;
    }
    ctx.nodes_left -= 1;
    false
}

/// Body node of a function-ish node: `body` field is a block.
fn fn_body(node: Node) -> Option<Node> {
    node.child_by_field_name("body")
}

/// Walk a function/module body.
fn walk_body(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    match node.kind() {
        "function_declaration" | "method_declaration" | "func_literal" => {
            if let Some(b) = fn_body(node) {
                walk_stmt(b, ctx, env);
            }
        }
        _ => walk_stmt(node, ctx, env),
    }
}

fn walk_stmt(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    if budget(ctx) {
        return;
    }
    match node.kind() {
        "source_file" | "block" | "statement_list" => {
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
        "short_var_declaration" => walk_short_var(node, ctx, env),
        "var_declaration" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.kind() == "var_spec" {
                    walk_var_spec(ch, ctx, env);
                }
            }
        }
        "const_declaration" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.kind() == "const_spec" {
                    walk_var_spec(ch, ctx, env);
                }
            }
        }
        "var_spec" | "const_spec" => walk_var_spec(node, ctx, env),
        "assignment_statement" => walk_assignment(node, ctx, env),
        "if_statement" => walk_if(node, ctx, env),
        "for_statement" => walk_for(node, ctx, env),
        "expression_switch_statement" | "type_switch_statement" => {
            walk_switch(node, ctx, env)
        }
        "select_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    walk_stmt(ch, ctx, env);
                }
            }
        }
        "communication_case" | "expression_case" | "type_case"
        | "default_case" => {
            // Case bodies: children after the value/type list.
            let mut c = node.walk();
            let kids: Vec<Node> = node.children(&mut c).collect();
            for ch in kids {
                if !ch.is_named() {
                    continue;
                }
                match ch.kind() {
                    "expression_list" | "type_list" | "_type" | "expression" => {
                        eval_expr(ch, ctx, env);
                    }
                    "statement_list" | "block" => walk_branch(ch, ctx, env),
                    _ => walk_stmt(ch, ctx, env),
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
            // Bare `return` in a func with nilable results yields nil.
            if !has_expr && ctx.nilable_results {
                ctx.ret.is_none = true;
            }
        }
        "defer_statement" | "go_statement" => {
            // The call still executes (later for defer); evaluate it
            // now so sinks/releases inside count.
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "send_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "inc_statement" | "dec_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "labeled_statement" => {
            if let Some(body) = node.child_by_field_name("body") {
                walk_stmt(body, ctx, env);
            }
        }
        // Declarations/types/imports/funcs are handled elsewhere or
        // carry no runtime effect for the walker.
        "function_declaration"
        | "method_declaration"
        | "func_literal"
        | "type_declaration"
        | "type_spec"
        | "type_alias"
        | "import_declaration"
        | "package_clause"
        | "break_statement"
        | "continue_statement"
        | "fallthrough_statement"
        | "goto_statement"
        | "empty_statement"
        | "comment" => {}
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

/// Kinds walk_stmt handles as statements (default-arm dispatch).
fn is_stmt_kind(kind: &str) -> bool {
    kind.ends_with("_statement")
        || kind.ends_with("_declaration")
        || matches!(
            kind,
            "source_file"
                | "block"
                | "statement_list"
                | "expression_case"
                | "type_case"
                | "default_case"
                | "communication_case"
                | "var_spec"
                | "const_spec"
                | "labeled_statement"
                | "range_clause"
        )
}

/// `a, b := x, y` / `a, b := f()` - pairwise when arities match,
/// joined single-RHS multi-return otherwise (resource -> first).
fn walk_short_var(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let lefts = expr_list_nodes(left);
    let rights = expr_list_nodes(right);
    if lefts.is_empty() || rights.is_empty() {
        return;
    }
    if lefts.len() == rights.len() {
        for (l, r) in lefts.iter().zip(rights.iter()) {
            assign_target(*l, *r, node, ctx, env, true);
        }
    } else {
        // Multi-valued RHS (single call returning N values): join.
        let mut joined = VarState::default();
        let mut label = None;
        let mut rhs_ty: Option<String> = None;
        for r in &rights {
            let v = eval_expr(*r, ctx, env);
            joined.join(&v.state);
            if label.is_none() {
                label = v.source_label.clone();
            }
            if rhs_ty.is_none() {
                rhs_ty = call_ret_type(*r, ctx);
            }
        }
        for (i, l) in lefts.iter().enumerate() {
            assign_state(*l, joined.clone(), label.clone(), node, ctx, env, i == 0);
            if i == 0 {
                if let Some(t) = &rhs_ty {
                    if let Some(key) = expr_key(*l, ctx, env) {
                        ctx.types.insert(key, t.clone());
                    }
                }
            }
        }
    }
}

/// `var x T = v` / `var x T` / `var x = v` (+ const_spec same shape).
fn walk_var_spec(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    // Names: `name` field may repeat (var_spec has one name field
    // per spec; grouped `var a, b int` emits multiple specs or an
    // expression_list - handle both).
    let names: Vec<Node> = match node.child_by_field_name("name") {
        Some(n) => expr_list_nodes(n),
        None => Vec::new(),
    };
    let ty_node = node.child_by_field_name("type");
    let value = node.child_by_field_name("value");
    // Record declared types.
    if let Some(t) = ty_node.and_then(|t| go_deep::type_name_pub(t, ctx.f.text.as_str())) {
        for n in &names {
            if let Some(key) = expr_key(*n, ctx, env) {
                ctx.types.insert(key, t.clone());
            }
        }
    }
    match value {
        Some(v) => {
            let vals = expr_list_nodes(v);
            if names.len() == vals.len() {
                for (n, r) in names.iter().zip(vals.iter()) {
                    assign_target(*n, *r, node, ctx, env, true);
                }
            } else {
                let mut joined = VarState::default();
                let mut label = None;
                for r in &vals {
                    let vv = eval_expr(*r, ctx, env);
                    joined.join(&vv.state);
                    if label.is_none() {
                        label = vv.source_label.clone();
                    }
                }
                for (i, n) in names.iter().enumerate() {
                    assign_state(*n, joined.clone(), label.clone(), node, ctx, env, i == 0);
                }
            }
        }
        None => {
            // `var x T` zero value: nilable types start as nil.
            let nilable = ty_node.is_some_and(|t| go_deep::type_nilable_pub(t, ctx.f.text.as_str()));
            for n in &names {
                let key = expr_key(*n, ctx, env);
                if let Some(k) = key {
                    env.insert(
                        k,
                        VarState {
                            is_none: nilable,
                            ..Default::default()
                        },
                    );
                }
            }
        }
    }
}

/// `a = b` / `a += b` / `a[i] = v` - left/right are expression_lists.
fn walk_assignment(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    let op = node
        .child_by_field_name("operator")
        .and_then(|o| o.utf8_text(ctx.f.text.as_bytes()).ok())
        .unwrap_or("=");
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let lefts = expr_list_nodes(left);
    let rights = expr_list_nodes(right);
    if lefts.is_empty() || rights.is_empty() {
        return;
    }
    let is_plain = op == "=";
    if lefts.len() == rights.len() {
        for (l, r) in lefts.iter().zip(rights.iter()) {
            if is_plain {
                assign_target(*l, *r, node, ctx, env, true);
            } else {
                // `x += y`: eval rhs, join prior lhs state.
                let rv = eval_expr(*r, ctx, env);
                let mut st = rv.state.clone();
                if let Some(key) = expr_key(*l, ctx, env) {
                    if let Some(prev) = env.get(&key) {
                        let mut joined = prev.clone();
                        joined.join(&st);
                        st = joined;
                    }
                }
                assign_state(*l, st, rv.source_label.clone(), node, ctx, env, true);
            }
        }
    } else {
        let mut joined = VarState::default();
        let mut label = None;
        for r in &rights {
            let v = eval_expr(*r, ctx, env);
            joined.join(&v.state);
            if label.is_none() {
                label = v.source_label.clone();
            }
        }
        for (i, l) in lefts.iter().enumerate() {
            assign_state(*l, joined.clone(), label.clone(), node, ctx, env, i == 0);
        }
    }
}

/// Children of an expression_list (or the node itself if not a
/// list).
fn expr_list_nodes(node: Node) -> Vec<Node> {
    if node.kind() == "expression_list" {
        node.children(&mut node.walk())
            .filter(|k| k.is_named())
            .collect()
    } else {
        vec![node]
    }
}

/// Evaluate RHS expr, assign to LHS target (handles per-index
/// element recording and type inference for `:=`/`=`).
fn assign_target(
    lhs: Node,
    rhs: Node,
    assign_node: Node,
    ctx: &mut CtxGo,
    env: &mut HashMap<String, VarState>,
    record_resource: bool,
) {
    let v = eval_expr(rhs, ctx, env);
    assign_state(lhs, v.state.clone(), v.source_label.clone(), assign_node, ctx, env, record_resource);
    // Type inference: composite literal `x := T{}` / `&T{}`,
    // known call returns `x, _ := sql.Open(...)`.
    if let Some(key) = expr_key(lhs, ctx, env) {
        let ty = composite_type(rhs, ctx).or_else(|| call_ret_type(rhs, ctx));
        if let Some(t) = ty {
            ctx.types.insert(key, t);
        }
    }
}

/// Composite literal's type name: `T{...}` -> "T", `&T{...}` -> "T",
/// `pkg.T{...}` -> "pkg.T".
fn composite_type(node: Node, ctx: &CtxGo) -> Option<String> {
    composite_type_text(node, ctx.f.text.as_str())
}

/// Text-only variant for callee resolution (no Ctx available).
fn composite_type_text(node: Node, text: &str) -> Option<String> {
    let n = match node.kind() {
        "unary_expression" => {
            // `&T{}` - operand is the literal.
            node.children(&mut node.walk())
                .find(|k| k.is_named() && k.kind() == "composite_literal")?
        }
        "composite_literal" => node,
        "parenthesized_expression" => {
            node.children(&mut node.walk()).find(|k| k.is_named())?
        }
        _ => return None,
    };
    if n.kind() != "composite_literal" {
        return None;
    }
    let ty = n.child_by_field_name("type")?;
    go_deep::type_name_pub(ty, text)
}

/// Known call return types (`sql.Open` -> `sql.DB`).
fn call_ret_type(node: Node, ctx: &CtxGo) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let dotted = dotted_callee(node, ctx)?;
    CALL_RET_TYPES
        .iter()
        .find(|(n, _)| dotted == *n || dotted.ends_with(&format!(".{n}")))
        .map(|(_, t)| t.to_string())
}

/// Assign an already-evaluated state to an lvalue target.
#[allow(clippy::too_many_arguments)]
fn assign_state(
    target: Node,
    state: VarState,
    source_label: Option<String>,
    assign_node: Node,
    ctx: &mut CtxGo,
    env: &mut HashMap<String, VarState>,
    record_resource: bool,
) {
    match target.kind() {
        "identifier" | "blank_identifier" => {
            if target.kind() == "blank_identifier" {
                return;
            }
            let Ok(name) = target.utf8_text(ctx.f.text.as_bytes()) else {
                return;
            };
            let mut st = state.clone();
            if st.taint.is_none() {
                st.taint = source_label;
            }
            if record_resource {
                if let Some(kind) = resource_kind_of(assign_node, ctx) {
                    st.resource = Some(kind.clone());
                    ctx.acquired
                        .push((name.to_string(), kind, line_of(assign_node)));
                }
            }
            env.insert(name.to_string(), st);
            // Per-index/per-key element states for `x = []T{...}`
            // and keyed struct/map literals so `x[0]`/`x.Field`
            // resolve precisely; stale entries cleared on rebind.
            if let Some(rhs) = rhs_node(assign_node) {
                clear_element_states(env, name);
                record_element_states(name, rhs, ctx, env);
            } else {
                clear_element_states(env, name);
            }
        }
        "selector_expression" | "index_expression" => {
            if let Some(key) = expr_key(target, ctx, env) {
                let mut st = state.clone();
                if st.taint.is_none() {
                    st.taint = source_label;
                }
                if record_resource {
                    if let Some(kind) = resource_kind_of(assign_node, ctx) {
                        st.resource = Some(kind.clone());
                        ctx.acquired.push((key.clone(), kind, line_of(assign_node)));
                    }
                }
                env.insert(key, st);
            }
        }
        "parenthesized_expression" => {
            let inner = target
                .children(&mut target.walk())
                .find(|k| k.is_named());
            if let Some(i) = inner {
                assign_state(i, state, source_label, assign_node, ctx, env, record_resource);
            }
        }
        "expression_list" => {
            // Shouldn't reach (lists handled by callers); join to
            // each identifier child conservatively.
            let mut c = target.walk();
            for ch in target.children(&mut c) {
                if ch.is_named() && ch.kind() == "identifier" {
                    assign_state(ch, state.clone(), source_label.clone(), assign_node, ctx, env, false);
                }
            }
        }
        _ => {}
    }
}

/// RHS expression node of an assignment-ish node. Go wraps RHS in
/// `expression_list` even for single values - unwrap it so literal
/// tracking sees `[]T{...}` not the list.
fn rhs_node(node: Node) -> Option<Node> {
    let r = match node.kind() {
        "short_var_declaration" | "assignment_statement" => {
            node.child_by_field_name("right")
        }
        "var_spec" | "const_spec" => node.child_by_field_name("value"),
        _ => return None,
    }?;
    if r.kind() == "expression_list" {
        let kids: Vec<Node> = r
            .children(&mut r.walk())
            .filter(|k| k.is_named())
            .collect();
        return if kids.len() == 1 { Some(kids[0]) } else { None };
    }
    Some(r)
}

/// Drop tracked `name[i]` / `name.key` entries (container rebound).
fn clear_element_states(env: &mut HashMap<String, VarState>, name: &str) {
    let pi = format!("{name}[");
    let pk = format!("{name}.");
    env.retain(|k, _| !k.starts_with(&pi) && !k.starts_with(&pk));
}

/// Record `name[i]` / `name.key` env entries for composite literal
/// RHS with side-effect-free elements (re-eval is finding-free).
fn record_element_states(
    name: &str,
    rhs: Node,
    ctx: &mut CtxGo,
    env: &mut HashMap<String, VarState>,
) {
    // Unwrap `&T{...}`.
    let rhs = if rhs.kind() == "unary_expression" {
        match rhs
            .children(&mut rhs.walk())
            .find(|k| k.is_named() && k.kind() == "composite_literal")
        {
            Some(l) => l,
            None => return,
        }
    } else {
        rhs
    };
    if rhs.kind() != "composite_literal" {
        return;
    }
    let Some(body) = rhs.child_by_field_name("body") else {
        return;
    };
    if body.kind() != "literal_value" {
        return;
    }
    let mut c = body.walk();
    let elems: Vec<Node> = body
        .children(&mut c)
        .filter(|k| k.is_named())
        .collect();
    // Positional elements -> name[0], name[1], ...; keyed elements
    // (struct fields / map keys) -> name.Key.
    let mut idx = 0usize;
    for e in &elems {
        match e.kind() {
            "literal_element" => {
                if !expr_is_side_effect_free(*e) {
                    idx += 1;
                    continue;
                }
                let inner = e
                    .children(&mut e.walk())
                    .find(|k| k.is_named())
                    .unwrap_or(*e);
                let v = eval_expr(inner, ctx, env);
                let mut est = v.state.clone();
                if est.taint.is_none() {
                    est.taint = v.source_label.clone();
                }
                env.insert(format!("{name}[{idx}]"), est);
                idx += 1;
            }
            "keyed_element" => {
                let key_node = e.child_by_field_name("key");
                let val_node = e.child_by_field_name("value");
                let (Some(kn), Some(vn)) = (key_node, val_node) else {
                    continue;
                };
                if !expr_is_side_effect_free(vn) {
                    continue;
                }
                // key/value are literal_element wrappers; unwrap to
                // the inner expression for both text and eval.
                let key_inner = kn
                    .children(&mut kn.walk())
                    .find(|k| k.is_named())
                    .unwrap_or(kn);
                let val_inner = vn
                    .children(&mut vn.walk())
                    .find(|k| k.is_named())
                    .unwrap_or(vn);
                let key = match key_inner.kind() {
                    "field_identifier" | "identifier" => key_inner
                        .utf8_text(ctx.f.text.as_bytes())
                        .ok()
                        .map(str::to_string),
                    "interpreted_string_literal" | "raw_string_literal" => key_inner
                        .utf8_text(ctx.f.text.as_bytes())
                        .ok()
                        .map(|s| {
                            s.trim_matches('"')
                                .trim_matches('`')
                                .to_string()
                        }),
                    _ => None,
                };
                if let Some(key) = key {
                    let v = eval_expr(val_inner, ctx, env);
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
}

/// True if evaluating this expr cannot produce findings or mutate
/// analysis state (no calls, assignments, receives).
fn expr_is_side_effect_free(node: Node) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "call_expression" | "assignment_statement" | "send_statement"
                | "go_statement" | "defer_statement" | "inc_statement"
                | "dec_statement" | "receive_statement"
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

/// If this assignment's RHS is a resource-acquiring call, return kind.
fn resource_kind_of(assign_node: Node, ctx: &CtxGo) -> Option<String> {
    let r = match assign_node.kind() {
        "short_var_declaration" | "assignment_statement" => {
            assign_node.child_by_field_name("right")?
        }
        "var_spec" | "const_spec" => assign_node.child_by_field_name("value")?,
        _ => return None,
    };
    // For multi-RHS lists use the first (resource is conventionally
    // the first return value).
    let first = expr_list_nodes(r).into_iter().next()?;
    if first.kind() != "call_expression" {
        return None;
    }
    let dotted = dotted_callee(first, ctx)?;
    // Full-dotted matches for unambiguous acquisitions; bare last
    // segments for method-style returns (db.Query -> rows).
    let kind = match dotted.as_str() {
        "os.Open" | "os.Create" | "os.OpenFile" | "os.CreateTemp"
        | "os.NewFile" | "ioutil.TempFile" | "os.Pipe" => Some("file".to_string()),
        "net.Dial" | "net.DialTimeout" | "net.Listen" | "net.ListenTCP"
        | "net.ListenUDP" | "net.ListenUnix" | "sql.Open" | "sql.OpenDB"
        | "sql.Connect" => Some("conn".to_string()),
        _ => {
            let last = dotted.rsplit('.').next().unwrap_or(&dotted);
            match last {
                // sql.Rows / similar query results need Close.
                "Query" | "QueryContext" => Some("rows".to_string()),
                _ => None,
            }
        }
    };
    kind
}

/// Dotted name of a call's callee expression.
fn dotted_callee(call: Node, ctx: &CtxGo) -> Option<String> {
    let func = call.child_by_field_name("function")?;
    dotted_expr(func, ctx)
}

/// Canonical package name for an import path: if the path resolves
/// to a project package, use its real package clause name (import
/// aliases and unconventional dir names handled); else last element.
fn canonical_pkg_name(ctx: &CtxGo, path: &str) -> String {
    if let Some(dir) = go_deep::resolve_import(ctx.mods, path) {
        if let Some(idxs) = ctx.pkg_dirs.get(&dir) {
            for &i in idxs {
                if let Some(f) = ctx.parsed.get(i) {
                    if !f.package.is_empty() {
                        return f.package.clone();
                    }
                }
            }
        }
    }
    go_deep::canonical_external(path)
}

/// Dotted name for identifier/selector chains. Package qualifiers
/// resolve through import bindings to the canonical package name
/// (`e "os/exec"` -> `exec.Command`); var receivers stay literal
/// (`db.Query`), with bare-name model rules doing the matching.
fn dotted_expr(node: Node, ctx: &CtxGo) -> Option<String> {
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(text).ok()?;
            // Package qualifier -> canonical package name: project
            // imports resolve to the target's real package clause;
            // external imports use the last path element.
            if let Some((_canon, path)) = ctx.f.imports.get(name) {
                return Some(canonical_pkg_name(ctx, path));
            }
            Some(name.to_string())
        }
        "selector_expression" => {
            let obj = node.child_by_field_name("operand")?;
            let field = node.child_by_field_name("field")?;
            let base = dotted_expr(obj, ctx)?;
            let p = field.utf8_text(text).ok()?;
            Some(format!("{base}.{p}"))
        }
        "index_expression" | "slice_expression" => {
            let obj = node.child_by_field_name("operand")?;
            dotted_expr(obj, ctx)
        }
        "type_assertion_expression" | "type_conversion_expression" => {
            let obj = node.child_by_field_name("operand")?;
            dotted_expr(obj, ctx)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            dotted_expr(inner, ctx)
        }
        _ => None,
    }
}

/// Environment key for an lvalue-ish expression.
fn expr_key(node: Node, ctx: &CtxGo, env: &HashMap<String, VarState>) -> Option<String> {
    let _ = env;
    expr_key_text(node, ctx.f.text.as_str())
}

/// Text-only variant for callee resolution (no Ctx available).
fn expr_key_text(node: Node, text: &str) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(text.as_bytes()).ok().map(|s| s.to_string()),
        "selector_expression" => {
            let obj = node.child_by_field_name("operand")?;
            let base = expr_key_text(obj, text)?;
            let field = node.child_by_field_name("field")?;
            let p = field.utf8_text(text.as_bytes()).ok()?;
            Some(format!("{base}.{p}"))
        }
        "index_expression" => {
            let obj = node.child_by_field_name("operand")?;
            let base = expr_key_text(obj, text)?;
            if let Some(idx) = node.child_by_field_name("index") {
                if idx.kind() == "int_literal" {
                    if let Ok(i) = idx.utf8_text(text.as_bytes()) {
                        if let Ok(n) = i.trim().parse::<i64>() {
                            return Some(format!("{base}[{n}]"));
                        }
                    }
                }
            }
            Some(base)
        }
        "parenthesized_expression" | "type_assertion_expression" => {
            node.children(&mut node.walk())
                .find(|k| k.is_named())
                .and_then(|i| expr_key_text(i, text))
        }
        _ => None,
    }
}

/// Evaluate an expression to a VarState + optional source label.
fn eval_expr(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) -> ExprVal {
    if budget(ctx) {
        return ExprVal::default();
    }
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "interpreted_string_literal"
        | "raw_string_literal"
        | "rune_literal"
        | "int_literal"
        | "float_literal"
        | "imaginary_literal"
        | "true"
        | "false"
        | "comment"
        | "blank_identifier" => ExprVal::default(),
        "nil" => ExprVal {
            state: VarState {
                is_none: true,
                ..Default::default()
            },
            source_label: None,
        },
        "identifier" => {
            let name = node.utf8_text(text).unwrap_or("");
            ExprVal {
                state: env.get(name).cloned().unwrap_or_default(),
                source_label: None,
            }
        }
        "selector_expression" | "index_expression" | "slice_expression" => {
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
            // Evaluate operand for side effects + nil-deref (member
            // access on nil panics; index on nil map is legal so
            // index/slice operands are evaluated but not flagged).
            let mut st = VarState::default();
            if let Some(obj) = node.child_by_field_name("operand") {
                let bv = eval_expr(obj, ctx, env);
                st = bv.state;
                if node.kind() == "selector_expression" && st.is_none {
                    push_finding_at(ctx, SinkKind::NullDeref, "none", "member access", node, 0.8);
                    st.is_none = false;
                }
            }
            // Exact tracked key (`x[0]`, `x.Field`) is authoritative;
            // container joined state is fallback for dynamic keys.
            if let Some(key) = expr_key(node, ctx, env) {
                if env.contains_key(&key) {
                    st = env.get(&key).cloned().unwrap_or_default();
                } else {
                    let base = key
                        .split_once('[')
                        .map(|(b, _)| b)
                        .or_else(|| key.rsplit_once('.').map(|(b, _)| b))
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
        "call_expression" => eval_call(node, ctx, env),
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
        "unary_expression" => {
            // `*p` deref, `<-ch` receive, `&x`, `!x`, `-x`.
            let mut st = VarState::default();
            if let Some(arg) = node.child_by_field_name("operand") {
                let v = eval_expr(arg, ctx, env);
                st = v.state;
                let op = node
                    .children(&mut node.walk())
                    .find(|k| !k.is_named())
                    .and_then(|o| o.utf8_text(text).ok())
                    .unwrap_or("");
                if op == "&" {
                    // Address-of produces a pointer - the pointee's
                    // nil-ness doesn't transfer.
                    st.is_none = false;
                }
            }
            ExprVal {
                state: st,
                source_label: None,
            }
        }
        "type_assertion_expression" | "type_conversion_expression" => {
            // `x.(T)` / `T(x)`: value keeps operand state (comma-ok
            // second value handled by callers as bool - ignored).
            if let Some(arg) = node.child_by_field_name("operand") {
                eval_expr(arg, ctx, env)
            } else {
                ExprVal::default()
            }
        }
        "composite_literal" => {
            // `T{a: tainted}` - joined element state; per-key states
            // are recorded by assign_target for the bound variable.
            let mut st = VarState::default();
            let mut label = None;
            if let Some(body) = node.child_by_field_name("body") {
                let v = eval_expr(body, ctx, env);
                st = v.state;
                label = v.source_label;
            }
            st.is_none = false;
            ExprVal {
                state: st,
                source_label: label,
            }
        }
        "literal_value" | "element" | "keyed_element" => {
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
        "func_literal" | "function_declaration" | "method_declaration"
        | "type_declaration" | "import_declaration" => ExprVal::default(),
        "parenthesized_expression" | "receive_statement" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named());
            match inner {
                Some(k) => eval_expr(k, ctx, env),
                None => ExprVal::default(),
            }
        }
        "iota" => ExprVal::default(),
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

/// Is this expression a model source? Returns provenance label.
fn source_label_of(node: Node, ctx: &CtxGo) -> Option<String> {
    let dotted = dotted_expr(node, ctx)?;
    let kind = ctx.model.source_kind(&dotted)?;
    Some(format!("src:{kind:?}"))
}

/// Process a call: sinks, sources, sanitizers, resolved callees,
/// unknown-call taint propagation.
fn eval_call(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) -> ExprVal {
    // Evaluate the callee expression for side effects (selector
    // operand may itself contain calls).
    if let Some(func) = node.child_by_field_name("function") {
        if matches!(
            func.kind(),
            "selector_expression" | "index_expression" | "call_expression"
        ) {
            eval_expr(func, ctx, env);
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
        let arg_nodes: Vec<Node> = arglist
            .children(&mut ac)
            .filter(|k| k.is_named())
            .collect();
        for an in arg_nodes {
            if let Some(key) = expr_key(an, ctx, env) {
                if env.get(&key).is_some_and(|st| st.resource.is_some()) {
                    ctx.escaped.insert(key);
                }
            }
        }
    }

    // Explicit resource release: `f.Close()`, `tx.Rollback()`,
    // `ln.Close()`, `rows.Close()`.
    if let Some(func) = node.child_by_field_name("function") {
        if func.kind() == "selector_expression" {
            if let Some(field) = func.child_by_field_name("field") {
                if let Ok(attr_name) = field.utf8_text(ctx.f.text.as_bytes()) {
                    if matches!(
                        attr_name,
                        "Close" | "Rollback" | "Commit" | "Shutdown" | "Stop"
                    ) {
                        if let Some(obj) = func.child_by_field_name("operand") {
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

    // 3. Sanitizer (last-segment match, same convention as JS).
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
    if let Some((cm, cf)) = resolve_callee(
        node,
        ctx.f,
        ctx.parsed,
        ctx.pkg_dirs,
        ctx.mods,
        Some(&ctx.types),
    ) {
        let key = (cm.clone(), cf.clone());
        if let Some(sum) = ctx.summaries.get(&key) {
            apply_summary(node, ctx, &args, sum, &format!("{cm}.{cf}"));
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

/// Tainted arg reached a sink: concrete finding or param flow.
fn handle_sink_taint(ctx: &mut CtxGo, class: SinkKind, label: String, sink_name: &str, node: Node) {
    if let Some(param_part) = label.strip_prefix("param:") {
        if let Ok(idx) = param_part.parse::<usize>() {
            let ps = PendingSink {
                class,
                file: ctx.f.rel.clone(),
                line: line_of(node),
                func: ctx.qualname.to_string(),
                sink: sink_name.to_string(),
                through: vec![qual_label(&ctx.f.dir, ctx.qualname)],
            };
            ctx.param_sinks.entry(idx).or_default().push(ps);
            return;
        }
    }
    push_finding_at(ctx, class, &label, sink_name, node, 1.0);
}

fn push_finding_at(
    ctx: &mut CtxGo,
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
        via: vec![qual_label(&ctx.f.dir, ctx.qualname)],
        confidence: conf,
    });
}

/// All argument value states of a call, in order.
fn call_args(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) -> Vec<ExprVal> {
    let mut out = Vec::new();
    let Some(args) = node.child_by_field_name("arguments") else {
        return out;
    };
    let mut c = args.walk();
    for ch in args.children(&mut c) {
        if ch.is_named() {
            out.push(eval_expr(ch, ctx, env));
        }
    }
    out
}

/// Branch bodies run on a cloned env, then join back (may-analysis).
/// `ctx.types` is shared (documented approximation).
fn walk_branch(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    let mut env2 = env.clone();
    walk_stmt(node, ctx, &mut env2);
    for (k, v) in env2 {
        env.entry(k).or_default().join(&v);
    }
}

type Narrows = (Vec<(String, bool)>, Vec<(String, bool)>);

/// Nil-related condition analysis: `x == nil` / `x != nil`, `!`,
/// `&&` / `||` recursion. Go's only nil literal is `nil`.
fn null_checks(cond: Node, ctx: &CtxGo, env: &HashMap<String, VarState>) -> Narrows {
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
                .children(&mut cond.walk())
                .find(|k| !k.is_named())
                .and_then(|o| o.utf8_text(ctx.f.text.as_bytes()).ok())
                .unwrap_or("");
            if op == "!" {
                if let Some(arg) = cond.child_by_field_name("operand") {
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
                "==" | "!=" => leaf_null_check(cond, op, ctx, env),
                _ => (vec![], vec![]),
            }
        }
        _ => (vec![], vec![]),
    }
}

/// `x == nil` / `x != nil` (and swapped).
fn leaf_null_check(cond: Node, op: &str, ctx: &CtxGo, env: &HashMap<String, VarState>) -> Narrows {
    let l = cond.child_by_field_name("left");
    let r = cond.child_by_field_name("right");
    let (Some(left), Some(right)) = (l, r) else {
        return (vec![], vec![]);
    };
    let is_nil = |n: Node| n.kind() == "nil";
    let target = if is_nil(right) {
        left
    } else if is_nil(left) {
        right
    } else {
        return (vec![], vec![]);
    };
    // `== nil` -> true branch is none; `!= nil` -> false branch.
    let is_none_true = op == "==";
    match expr_key(target, ctx, env) {
        Some(key) => (
            vec![(key.clone(), is_none_true)],
            vec![(key, !is_none_true)],
        ),
        None => (vec![], vec![]),
    }
}

/// if/else-if/else with nil-narrowing, mirroring walk_if in JS.
fn walk_if(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    let cond = node.child_by_field_name("condition");
    let cons = node.child_by_field_name("consequence");
    let alt = node.child_by_field_name("alternative");
    // Optional initializer: `if x := f(); cond { }`.
    if let Some(init) = node.child_by_field_name("initializer") {
        walk_stmt(init, ctx, env);
    }
    let Some(cond) = cond else { return };
    eval_expr(cond, ctx, env);
    let check = null_checks(cond, ctx, env);

    // `if cond; init` form puts init first - handled above.
    let mut clauses: Vec<(Narrows, Node, bool)> = Vec::new();
    if let Some(c) = cons {
        clauses.push((check, c, false));
    }
    if let Some(a) = alt {
        // alternative is a block or an else-if if_statement.
        match a.kind() {
            "if_statement" => clauses.push(((vec![], vec![]), a, true)),
            _ => clauses.push(((vec![], vec![]), a, true)),
        }
    }

    let else_narrow: Vec<(String, bool)> = clauses
        .iter()
        .filter(|c| !c.2)
        .flat_map(|(narrows, _, _)| narrows.1.iter().cloned())
        .collect();
    for (narrows, suite, is_else) in &clauses {
        let narrow: &[(String, bool)] = if *is_else { &else_narrow } else { &narrows.0 };
        let mut env2 = env.clone();
        for (key, is_none) in narrow {
            if let Some(st) = env2.get_mut(key.as_str()) {
                st.is_none = *is_none;
            }
        }
        walk_stmt(*suite, ctx, &mut env2);
        for (k, v) in env2 {
            env.entry(k).or_default().join(&v);
        }
    }

    // Post-if narrowing: single if/else chain (Go allows else-if
    // nesting; approximate with first+last clauses like JS).
    let n = clauses.len();
    if n == 0 {
        return;
    }
    // terms[i] = consequence is terminal (cannot fall through) -
    // mirrors JS's `!may_fall_off`.
    let terms: Vec<bool> = clauses
        .iter()
        .map(|(_, s, _)| go_block_terminal(*s, ctx.f.text.as_str()))
        .collect();
    let has_else = clauses.iter().any(|c| c.2);
    if !has_else {
        if terms.get(0) == Some(&true) {
            for (key, v) in &clauses[0].0 .1 {
                if let Some(st) = env.get_mut(key.as_str()) {
                    st.is_none = *v;
                }
            }
        }
        return;
    }
    let cons_falls = !terms[0];
    let else_falls = !terms[n - 1];
    if !cons_falls && else_falls {
        for (key, v) in &clauses[0].0 .1 {
            if let Some(st) = env.get_mut(key.as_str()) {
                st.is_none = *v;
            }
        }
    } else if cons_falls && !else_falls {
        for (key, v) in &clauses[0].0 .0 {
            if let Some(st) = env.get_mut(key.as_str()) {
                st.is_none = *v;
            }
        }
    }
}

/// True if a Go statement/block cannot complete normally (ends in
/// return/panic or is itself terminal). Used for post-if narrowing.
fn go_block_terminal(node: Node, text: &str) -> bool {
    match node.kind() {
        "return_statement" | "goto_statement" => true,
        "block" | "statement_list" => {
            let mut c = node.walk();
            node.children(&mut c)
                .filter(|k| k.is_named())
                .last()
                .map(|l| go_block_terminal(l, text))
                .unwrap_or(false)
        }
        "if_statement" => {
            // Terminal only if both branches terminal.
            let cons = node.child_by_field_name("consequence");
            let alt = node.child_by_field_name("alternative");
            match (cons, alt) {
                (Some(c), Some(a)) => {
                    go_block_terminal(c, text) && go_block_terminal(a, text)
                }
                _ => false,
            }
        }
        "expression_statement" => {
            // `panic(...)` terminates.
            let mut stack = vec![node];
            while let Some(n) = stack.pop() {
                if n.kind() == "call_expression" {
                    if let Some(func) = n.child_by_field_name("function") {
                        if func.kind() == "identifier"
                            && func
                                .utf8_text(text.as_bytes())
                                .is_ok_and(|t| t == "panic")
                        {
                            return true;
                        }
                    }
                }
                let mut c = n.walk();
                for ch in n.children(&mut c) {
                    if ch.is_named() {
                        stack.push(ch);
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// for/range loops: evaluate init/cond/update, walk body as branch.
fn walk_for(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    // for_statement children: for_clause | range_clause | condition
    // expr + body block.
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if !ch.is_named() {
            continue;
        }
        match ch.kind() {
            "for_clause" => {
                for part in ["initializer", "condition", "update"] {
                    if let Some(p) = ch.child_by_field_name(part) {
                        match p.kind() {
                            "_simple_statement" | "short_var_declaration"
                            | "assignment_statement" | "inc_statement"
                            | "dec_statement" | "expression_statement" => {
                                walk_stmt(p, ctx, env);
                            }
                            _ => {
                                eval_expr(p, ctx, env);
                            }
                        }
                    }
                }
            }
            "range_clause" => {
                // `for k, v := range x` / `for x = range ch`.
                if let Some(right) = ch.child_by_field_name("right") {
                    let rv = eval_expr(right, ctx, env);
                    if let Some(left) = ch.child_by_field_name("left") {
                        // Element state: taint propagates, none-ness
                        // and resource don't (elements aren't the
                        // collection itself).
                        let mut st = VarState::default();
                        st.taint = rv.state.taint.clone();
                        let lefts = expr_list_nodes(left);
                        for l in lefts {
                            assign_state(l, st.clone(), None, ch, ctx, env, false);
                        }
                    }
                }
            }
            "block" => walk_branch(ch, ctx, env),
            _ => {
                // Condition expression or other clause: evaluate.
                eval_expr(ch, ctx, env);
            }
        }
    }
}

/// switch statements: evaluate tag, each case value, case bodies as
/// sequential branches (Go cases don't fall through by default -
/// approximate by walking each body on the joined env).
fn walk_switch(node: Node, ctx: &mut CtxGo, env: &mut HashMap<String, VarState>) {
    if let Some(v) = node.child_by_field_name("value") {
        eval_expr(v, ctx, env);
    }
    if let Some(init) = node.child_by_field_name("initializer") {
        walk_stmt(init, ctx, env);
    }
    if let Some(alias) = node.child_by_field_name("alias") {
        // type switch `switch v := x.(type)` - alias gets asserted
        // type per case; approximate: assign operand state.
        let _ = alias;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if ch.is_named() {
            match ch.kind() {
                "expression_case" | "type_case" | "default_case"
                | "communication_case" => walk_stmt(ch, ctx, env),
                "statement_list" | "block" => {
                    // Case list container: walk each case.
                    let mut cc = ch.walk();
                    for case in ch.children(&mut cc) {
                        if case.is_named() {
                            walk_stmt(case, ctx, env);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Resolve this call's callee to (pkg_dir, qualname).
///
/// `types` = optional var->type env for `recv.Method()` resolution
/// (present during facts walks; absent for callgraph building, which
/// then leaves typed-method calls unresolved - conservative).
pub fn resolve_callee(
    node: Node,
    f: &GoFile,
    parsed: &[GoFile],
    pkg_dirs: &HashMap<String, Vec<usize>>,
    mods: &GoModules,
    types: Option<&HashMap<String, String>>,
) -> Option<NodeId> {
    let func = node.child_by_field_name("function")?;
    resolve_func_node(func, f, parsed, pkg_dirs, mods, types)
}

fn resolve_func_node(
    func: Node,
    f: &GoFile,
    parsed: &[GoFile],
    pkg_dirs: &HashMap<String, Vec<usize>>,
    mods: &GoModules,
    types: Option<&HashMap<String, String>>,
) -> Option<NodeId> {
    let text = f.text.as_bytes();
    match func.kind() {
        "identifier" => {
            let name = func.utf8_text(text).ok()?;
            if GO_BUILTINS.contains(&name) {
                return None;
            }
            // Same-package function (any file in the dir).
            pkg_qualname(&f.dir, name, parsed, pkg_dirs)
                .map(|q| (f.dir.clone(), q))
        }
        "selector_expression" => {
            let field = func.child_by_field_name("field")?;
            let fname = field.utf8_text(text).ok()?;
            let obj = func.child_by_field_name("operand")?;
            selector_target(obj, fname, f, parsed, pkg_dirs, mods, types)
        }
        "parenthesized_expression" => {
            let inner = func
                .children(&mut func.walk())
                .find(|k| k.is_named())?;
            resolve_func_node(inner, f, parsed, pkg_dirs, mods, types)
        }
        _ => None,
    }
}

/// `operand.Name(...)` callee resolution.
fn selector_target(
    obj: Node,
    fname: &str,
    f: &GoFile,
    parsed: &[GoFile],
    pkg_dirs: &HashMap<String, Vec<usize>>,
    mods: &GoModules,
    types: Option<&HashMap<String, String>>,
) -> Option<NodeId> {
    let text = f.text.as_bytes();
    match obj.kind() {
        "identifier" => {
            let oname = obj.utf8_text(text).ok()?;
            // Package-qualified call: `pkg.Fn(...)`.
            if let Some((_canon, path)) = f.imports.get(oname) {
                let dir = go_deep::resolve_import(mods, path)?;
                return pkg_qualname(&dir, fname, parsed, pkg_dirs)
                    .map(|q| (dir, q));
            }
            // Receiver method: `recv.M(...)` via type env.
            if let Some(t) = types.and_then(|t| t.get(oname)) {
                let qual = format!("{t}.{fname}");
                if let Some(q) = pkg_qualname(&f.dir, &qual, parsed, pkg_dirs) {
                    return Some((f.dir.clone(), q));
                }
            }
            None
        }
        "composite_literal" => {
            // `T{}.M()` / `pkg.T{}.M()`.
            let ty = composite_type_text(obj, &f.text)?;
            method_via_type(&f.dir, &ty, fname, f, parsed, pkg_dirs, mods)
        }
        "selector_expression" | "index_expression" | "slice_expression"
        | "type_assertion_expression" => {
            // `x.Field.M()` / `m[k].M()` / `v.(T).M()`: the operand's
            // tracked type decides the method's package.
            let key = expr_key_text(obj, &f.text)?;
            let t = types?.get(&key)?;
            method_via_type(&f.dir, t, fname, f, parsed, pkg_dirs, mods)
        }
        "parenthesized_expression" => {
            let inner = obj
                .children(&mut obj.walk())
                .find(|k| k.is_named())?;
            selector_target(inner, fname, f, parsed, pkg_dirs, mods, types)
        }
        _ => None,
    }
}

/// Resolve `Type.Method` where `ty` may be local (`T`) or qualified
/// (`pkg.T`). Local types live in the caller's package dir; qualified
/// types resolve through the import path to the target package.
fn method_via_type(
    dir: &str,
    ty: &str,
    fname: &str,
    f: &GoFile,
    parsed: &[GoFile],
    pkg_dirs: &HashMap<String, Vec<usize>>,
    mods: &GoModules,
) -> Option<NodeId> {
    if let Some((pkg_alias, short)) = ty.split_once('.') {
        // `pkg.T` - the method's qualname in the target package is
        // `T.M` (receiver type name has no package prefix there).
        if let Some((_canon, path)) = f.imports.get(pkg_alias) {
            let tdir = go_deep::resolve_import(mods, path)?;
            let qual = format!("{short}.{fname}");
            return pkg_qualname(&tdir, &qual, parsed, pkg_dirs)
                .map(|q| (tdir, q));
        }
        return None;
    }
    let qual = format!("{ty}.{fname}");
    pkg_qualname(dir, &qual, parsed, pkg_dirs).map(|q| (dir.to_string(), q))
}

/// Find a function/method qualname in package `dir`: searches every
/// file of the package for a funcs entry whose qualname matches
/// `name` exactly (methods) or a non-method func for bare names.
fn pkg_qualname(
    dir: &str,
    name: &str,
    parsed: &[GoFile],
    pkg_dirs: &HashMap<String, Vec<usize>>,
) -> Option<String> {
    let short = name.rsplit('.').next().unwrap_or(name);
    let idxs = pkg_dirs.get(dir)?;
    let mut fallback: Option<String> = None;
    for &fi in idxs {
        let Some(f) = parsed.get(fi) else { continue };
        let Some(infos) = f.funcs.get(short) else {
            continue;
        };
        for info in infos.iter().rev() {
            if info.qualname == name {
                return Some(info.qualname.clone());
            }
            if fallback.is_none() && !name.contains('.') && !info.is_method {
                fallback = Some(info.qualname.clone());
            }
        }
    }
    fallback
}

/// Display label for a (dir, qualname) node: root dir "." has no
/// prefix, so `main` not `..main`.
fn qual_label(dir: &str, qual: &str) -> String {
    if dir == "." {
        qual.to_string()
    } else {
        format!("{dir}.{qual}")
    }
}

/// Apply a resolved callee's summary to this call.
fn apply_summary(
    _node: Node,
    ctx: &mut CtxGo,
    args: &[ExprVal],
    sum: &Summary,
    callee_label: &str,
) {
    let caller_qual = qual_label(&ctx.f.dir, ctx.qualname);
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
fn unknown_call_result(args: &[ExprVal], result: &mut ExprVal, ctx: &mut CtxGo, dotted: &str) {
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
    use crate::go_deep::{analyze_source, GoModules};
    use crate::models::go_default;
    use std::collections::BTreeSet;

    fn run(files: &[(&str, &str)]) -> crate::solver::SolveOutput {
        run_with_mods(files, GoModules { prefixes: vec![] })
    }

    fn run_with_mods(
        files: &[(&str, &str)],
        mods: GoModules,
    ) -> crate::solver::SolveOutput {
        let parsed: Vec<GoFile> = files
            .iter()
            .filter_map(|(rel, text)| analyze_source(rel, text))
            .collect();
        let file_set: BTreeSet<String> =
            files.iter().map(|(k, _)| k.to_string()).collect();
        let _ = file_set;
        let model = go_default().unwrap();
        crate::solver_go::solve_go(&parsed, &mods, &model)
    }

    #[test]
    fn taint_env_to_exec_cross_function() {
        let out = run(&[(
            "main.go",
            r#"package main

import (
	"os"
	"os/exec"
)

func run(name string) {
	exec.Command("sh", "-c", name)
}

func main() {
	name := os.Getenv("X")
	run(name)
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 1),
            "expected shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn taint_env_to_sql() {
        let out = run(&[(
            "main.go",
            r#"package main

import (
	"database/sql"
	"os"
)

var query = os.Getenv("Q")

func f(db *sql.DB) {
	rows, _ := db.Query(query)
	_ = rows
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Sql
                && f.source.contains("Env")),
            "expected sql finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn nil_guard_no_finding_unguarded_finding() {
        let guarded = run(&[(
            "t.go",
            r#"package main

type T struct{ A int }

func maybe() *T { return nil }

func f() {
	x := maybe()
	if x == nil {
		return
	}
	_ = x.A
}
"#,
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
            "t.go",
            r#"package main

type T struct{ A int }

func maybe() *T { return nil }

func f() {
	x := maybe()
	_ = x.A
}
"#,
        )]);
        assert!(unguarded
            .findings
            .iter()
            .any(|f| f.class == SinkKind::NullDeref));
    }

    #[test]
    fn sanitizer_stops_taint() {
        let out = run(&[(
            "t.go",
            r#"package main

import (
	"os"
	"os/exec"
	"strconv"
)

func main() {
	n, _ := strconv.Atoi(os.Getenv("X"))
	exec.Command("echo", strconv.Itoa(n))
}
"#,
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::Shell),
            "Atoi sanitizer should stop taint: {:?}",
            out.findings
        );
    }

    #[test]
    fn leak_open_without_close() {
        let out = run(&[(
            "t.go",
            r#"package main

import "os"

func f() {
	fh, _ := os.Open("/tmp/x")
	_ = fh
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Leak),
            "expected leak finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn leak_open_with_defer_close() {
        let out = run(&[(
            "t.go",
            r#"package main

import "os"

func f() {
	fh, _ := os.Open("/tmp/x")
	defer fh.Close()
	_ = fh
}
"#,
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::Leak),
            "defer Close should release: {:?}",
            out.findings
        );
    }

    #[test]
    fn per_index_composite_literal() {
        // pair[0] tainted, pair[1] clean - only index 0 should flag.
        let out = run(&[(
            "t.go",
            r#"package main

import (
	"os"
	"os/exec"
)

func main() {
	pair := []string{os.Getenv("X"), "ok"}
	exec.Command("sh", "-c", pair[0])
	exec.Command("sh", "-c", pair[1])
}
"#,
        )]);
        let hits: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Shell)
            .collect();
        assert_eq!(hits.len(), 1, "only pair[0] should flag: {:?}", out.findings);
        assert_eq!(hits[0].line, 10);
    }

    #[test]
    fn cross_package_call() {
        // util.Run flows param->exec.Command; main passes env taint
        // through an imported project package.
        let out = run_with_mods(
            &[
                (
                    "util/u.go",
                    r#"package util

import "os/exec"

func Run(name string) {
	exec.Command("sh", "-c", name)
}
"#,
                ),
                (
                    "main.go",
                    r#"package main

import (
	"os"
	"example.com/m/util"
)

func main() {
	util.Run(os.Getenv("X"))
}
"#,
                ),
            ],
            GoModules {
                prefixes: vec![("example.com/m".to_string(), ".".to_string())],
            },
        );
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")),
            "expected cross-package shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn method_call_resolution() {
        // s.Run(name) resolves through receiver type Server ->
        // Server.Run summary applies param->sink flow.
        let out = run(&[(
            "t.go",
            r#"package main

import (
	"os"
	"os/exec"
)

type Server struct{}

func (s *Server) Run(name string) {
	exec.Command("sh", "-c", name)
}

func main() {
	s := &Server{}
	s.Run(os.Getenv("X"))
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")),
            "expected method shell finding, got {:?}",
            out.findings
        );
    }
}
