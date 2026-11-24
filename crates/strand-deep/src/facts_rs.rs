//! Per-function dataflow facts for Rust: taint, Option-ness, and
//! resource tracking - the Rust mirror of `facts_go.rs`.
//!
//! Same value domains and honesty contract: may-analyses with union
//! joins, single-pass, env keys are `::`-joined paths (`x.f`) with
//! integer field access as `x.0` and numeric indices as `x[0]`.
//! `is_none` tracks Option-ness: `None`, Option-returning calls,
//! `?`-propagation, and `let`/match bindings of absent variants.
//!
//! Rust's null analog is `Option::unwrap()`/`expect()` panic on
//! `None` - flagged as NullDeref. Field access can't be none in
//! valid Rust (the type system prevents it), so member-access
//! derefs are not flagged; index OOB is untracked.
//!
//! Module identity is the file path. `use` imports resolve dotted
//! names to full `::` paths; project-internal paths resolve through
//! a module-suffix index (heuristic - see `rust_deep::module_index`).
//! Method calls resolve via a type env (`let s = T{..}`, `let s: T`,
//! `self` in impls) to same-file `Type::method` qualnames.
//!
//! Documented approximations: macro token trees are scanned for
//! identifier taint (no arg structure); `if let`/`match` payload
//! bindings get the scrutinee state with none-ness cleared;
//! `use x::*` glob imports are not modeled; resource tracking is
//! minimal because Rust RAII closes handles on drop (no explicit
//! Close to require - acquisitions still tracked for `returns_unclosed`).

use std::collections::{BTreeMap, HashMap, HashSet};

use tree_sitter::Node;

use crate::facts::{Finding, FuncAnalysis, PendingSink, Summary, VarState};
use crate::models::{Model, SinkKind};
use crate::rust_deep::{self, RsFile, RsFuncInfo};
use crate::solver::NodeId;

const NODE_BUDGET: usize = 100_000;

#[derive(Debug, Clone, Default)]
struct ExprVal {
    state: VarState,
    /// Set when the expr itself is a model source.
    source_label: Option<String>,
    /// Per-element states for array/tuple literals, in child order.
    /// Empty for other expressions. Captured during the single eval
    /// so `x[i]`/destructuring don't re-evaluate (and double-report)
    /// elements.
    elems: Vec<(VarState, Option<String>)>,
    /// Per-field states for struct literals: (field, state, label).
    fields: Vec<(String, VarState, Option<String>)>,
}

/// Shared context for one Rust function's walk.
pub struct CtxRs<'a> {
    f: &'a RsFile,
    /// All parsed Rust files + rel->index (for cross-file callee
    /// qualname lookup).
    parsed: &'a [RsFile],
    file_index: &'a HashMap<String, usize>,
    /// Module-path suffix -> file index (cross-file resolution).
    mod_index: &'a HashMap<String, usize>,
    model: &'a Model,
    summaries: &'a HashMap<NodeId, Summary>,
    qualname: &'a str,
    /// var/field key -> type name, for `recv.Method()` resolution.
    types: HashMap<String, String>,
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

/// Methods that panic on absent values (Option/Result unwrap family).
const PANIC_METHODS: &[&str] = &[
    "unwrap",
    "expect",
    "unwrap_err",
    "expect_err",
];

/// Enum variant constructors producing a definite Some/Ok value.
const OK_VARIANTS: &[&str] = &["Some", "Ok"];

/// Call dotted names whose result is a known type.
const CALL_RET_TYPES: &[(&str, &str)] = &[
    ("std::fs::File::open", "std::fs::File"),
    ("std::fs::File::create", "std::fs::File"),
    ("std::fs::File::open", "std::fs::File"),
];

/// Analyze a Rust function body. `func_node` = function_item or the
/// source_file root for `<module>`; `info` carries params/receiver
/// for real functions (None for module).
pub fn analyze_function_rs<'a>(
    f: &'a RsFile,
    func_node: Node,
    info: Option<&RsFuncInfo>,
    qualname: &str,
    model: &Model,
    summaries: &HashMap<NodeId, Summary>,
    globals: Option<&HashMap<String, VarState>>,
    pkg_types: Option<&HashMap<String, String>>,
    parsed: &'a [RsFile],
    file_index: &'a HashMap<String, usize>,
    mod_index: &'a HashMap<String, usize>,
) -> (FuncAnalysis, HashMap<String, String>) {
    let mut ctx = CtxRs {
        f,
        parsed,
        file_index,
        mod_index,
        model,
        summaries,
        qualname,
        types: pkg_types.cloned().unwrap_or_default(),
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
    // `self` receiver seeds the type env for method bodies.
    if let Some(info) = info {
        if info.is_method {
            if let Some(t) = &info.receiver_type {
                ctx.types.insert("self".to_string(), t.clone());
            }
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

    // Rust RAII closes resources at scope end, so an unreleased
    // acquisition is NOT a leak - local leak findings are disabled
    // for Rust (returns_unclosed still propagates for callers that
    // explicitly forget/leak). Documented blind spot: mem::forget
    // and Box::leak are not modeled.

    let mut summary = Summary {
        // `return expr` with expr state; bare `return`/fall-off
        // returns `()` which is not none-ish in the Option sense.
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

fn first_unclosed(ctx: &CtxRs) -> Option<String> {
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

fn budget(ctx: &mut CtxRs) -> bool {
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

fn walk_body(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    match node.kind() {
        "function_item" => {
            if let Some(b) = fn_body(node) {
                walk_stmt(b, ctx, env);
            }
        }
        _ => walk_stmt(node, ctx, env),
    }
}

fn walk_stmt(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    if budget(ctx) {
        return;
    }
    match node.kind() {
        "source_file" | "block" | "declaration_list" => {
            // A bare expression child (no semicolon) is the block's
            // tail value = implicit return. Walk statements first,
            // then eval the tail once into `ret`.
            let kids: Vec<Node> = node
                .children(&mut node.walk())
                .filter(|k| k.is_named())
                .collect();
            let tail = kids.iter().rev().find(|k| is_tail_expr(k.kind())).copied();
            for ch in &kids {
                if Some(*ch) == tail {
                    continue;
                }
                walk_stmt(*ch, ctx, env);
            }
            if let Some(t) = tail {
                let v = eval_expr(t, ctx, env);
                ctx.saw_return = true;
                ctx.ret.join(&v.state);
                if ctx.ret.taint.is_none() {
                    ctx.ret.taint = v.state.taint.clone();
                }
                if v.state.resource.is_some() && ctx.ret.resource.is_none() {
                    ctx.ret.resource = v.state.resource.clone();
                }
            }
        }
        "let_declaration" => walk_let(node, ctx, env),
        "expression_statement" => {
            // Compound exprs (if/match/...) need branch analysis;
            // plain exprs (calls etc.) go to eval_expr.
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    walk_dispatch(ch, ctx, env);
                }
            }
        }
        "if_expression" => walk_if(node, ctx, env),
        "for_expression" => walk_for(node, ctx, env),
        "while_expression" | "loop_expression" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                eval_expr(cond, ctx, env);
            }
            if let Some(body) = node.child_by_field_name("body") {
                walk_branch(body, ctx, env);
            }
        }
        "match_expression" => walk_match(node, ctx, env),
        "return_expression" | "yield_expression" | "break_expression"
        | "continue_expression" => {
            // return joins to ret; break/continue/yield eval inner.
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    if node.kind() == "return_expression" {
                        ctx.saw_return = true;
                        ctx.ret.join(&v.state);
                        if ctx.ret.taint.is_none() {
                            ctx.ret.taint = v.state.taint.clone();
                        }
                        if v.state.resource.is_some() && ctx.ret.resource.is_none() {
                            ctx.ret.resource = v.state.resource.clone();
                        }
                    }
                }
            }
        }
        "unsafe_block" | "async_block" | "const_block" | "try_block" => {
            if let Some(b) = node.child_by_field_name("body") {
                walk_stmt(b, ctx, env);
            } else {
                let mut c = node.walk();
                for ch in node.children(&mut c) {
                    if ch.is_named() {
                        walk_stmt(ch, ctx, env);
                    }
                }
            }
        }
        "macro_invocation" => {
            eval_macro(node, ctx, env);
        }
        "labeled_expression" | "block_expression" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    walk_dispatch(ch, ctx, env);
                }
            }
        }
        // Items and declarations carry no inline runtime effect for
        // the walker (nested fns are separate FuncRefs).
        "function_item"
        | "struct_item"
        | "enum_item"
        | "union_item"
        | "trait_item"
        | "impl_item"
        | "mod_item"
        | "type_item"
        | "const_item"
        | "static_item"
        | "use_declaration"
        | "extern_crate_declaration"
        | "foreign_mod_item"
        | "empty_statement"
        | "line_comment"
        | "block_comment" => {}
        _ => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    walk_dispatch(ch, ctx, env);
                }
            }
        }
    }
}

/// Dispatch a child node: statement/compound kinds get walk_stmt,
/// plain expressions get eval_expr.
fn walk_dispatch(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    if is_stmt_kind(node.kind()) || is_compound_expr(node.kind()) {
        walk_stmt(node, ctx, env);
    } else {
        eval_expr(node, ctx, env);
    }
}

/// Compound expressions that need statement-level branch analysis
/// when they appear as statements (if/match/loops/blocks).
fn is_compound_expr(kind: &str) -> bool {
    matches!(
        kind,
        "if_expression"
            | "match_expression"
            | "for_expression"
            | "while_expression"
            | "loop_expression"
            | "unsafe_block"
            | "async_block"
            | "const_block"
            | "try_block"
            | "block"
            | "labeled_expression"
    )
}

/// True if a node kind can be a block's tail expression (implicit
/// return value). Statements, declarations, items, and blocks are
/// not tail expressions.
fn is_tail_expr(kind: &str) -> bool {
    // Compound exprs are walked as statements; their branch tails
    // already join `ret` through the shared ctx, so they are not
    // treated as simple tail values here.
    if is_compound_expr(kind) {
        return false;
    }
    if kind.ends_with("_statement")
        || kind.ends_with("_declaration")
        || kind.ends_with("_item")
        || kind.ends_with("_block")
    {
        return false;
    }
    matches!(
        kind,
        "block"
            | "declaration_list"
            | "let_declaration"
            | "expression_statement"
            | "source_file"
            | "match_arm"
            | "else_clause"
            | "use_declaration"
            | "line_comment"
            | "block_comment"
            | "empty_statement"
            | "label"
    ) || kind.ends_with("_expression")
        || kind.ends_with("_literal")
        || matches!(
            kind,
            "identifier"
                | "scoped_identifier"
                | "self"
                | "crate"
                | "super"
                | "macro_invocation"
                | "field_identifier"
                | "type_identifier"
                | "self_parameter"
                | "negative_literal"
                | "unit_expression"
        )
}

/// Kinds walk_stmt handles as statements (default-arm dispatch).
fn is_stmt_kind(kind: &str) -> bool {
    kind.ends_with("_statement")
        || kind.ends_with("_declaration")
        || matches!(
            kind,
            "source_file"
                | "block"
                | "declaration_list"
                | "let_declaration"
                | "expression_statement"
                | "unsafe_block"
                | "async_block"
                | "const_block"
                | "try_block"
                | "match_arm"
                | "else_clause"
        )
}

/// `let pat = expr` / `let pat: T = expr` / `let pat = expr else {}`.
fn walk_let(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    let pat = node.child_by_field_name("pattern");
    let ty = node.child_by_field_name("type");
    let value = node.child_by_field_name("value");
    // Record declared type for method resolution.
    if let (Some(p), Some(tn)) = (pat, ty) {
        if let Some(t) = rust_deep::type_name_rs(tn, ctx.f.text.as_str()) {
            for k in pat_keys(p, ctx) {
                ctx.types.insert(k, t.clone());
            }
        }
    }
    match value {
        Some(v) => {
            let vv = eval_expr(v, ctx, env);
            if let Some(p) = pat {
                assign_pattern(p, &vv, node, ctx, env);
                // Composite literal / known call -> type env.
                if let Some(ty) = composite_type(v, ctx).or_else(|| call_ret_type(v, ctx)) {
                    for k in pat_keys(p, ctx) {
                        ctx.types.insert(k, ty.clone());
                    }
                }
            }
        }
        None => {
            // `let x;` - uninitialized; treat as none-ish? Rust
            // requires init before use; leave clean.
        }
    }
    // let-else: `else { diverge }` block.
    if let Some(alt) = node.child_by_field_name("alternative") {
        walk_stmt(alt, ctx, env);
    }
}

/// All binding identifiers in a pattern.
fn pat_keys(node: Node, ctx: &CtxRs) -> Vec<String> {
    let mut out = Vec::new();
    rust_deep::collect_pat_idents(node, ctx.f.text.as_str(), &mut out);
    out
}

/// Assign an evaluated value to a pattern target (identifier or
/// destructuring pattern - all bound vars get the joined state;
/// per-element precision for tuple/array/struct literals).
fn assign_pattern(
    target: Node,
    vv: &ExprVal,
    assign_node: Node,
    ctx: &mut CtxRs,
    env: &mut HashMap<String, VarState>,
) {
    let state = &vv.state;
    let source_label = &vv.source_label;
    match target.kind() {
        "identifier" => {
            let Ok(name) = target.utf8_text(ctx.f.text.as_bytes()) else {
                return;
            };
            let mut st = state.clone();
            if st.taint.is_none() {
                st.taint = source_label.clone();
            }
            if let Some(kind) = resource_kind_of(assign_node, ctx) {
                st.resource = Some(kind.clone());
                ctx.acquired
                    .push((name.to_string(), kind, line_of(assign_node)));
            }
            env.insert(name.to_string(), st);
            clear_element_states(env, name);
            if !vv.elems.is_empty() || !vv.fields.is_empty() {
                record_element_states(name, vv, ctx, env);
            }
        }
        "mut_pattern" | "ref_pattern" | "reference_pattern"
        | "parenthesized_pattern" => {
            let inner = target
                .children(&mut target.walk())
                .find(|k| k.is_named());
            if let Some(i) = inner {
                assign_pattern(i, vv, assign_node, ctx, env);
            }
        }
        "tuple_pattern" | "slice_pattern" | "or_pattern" | "tuple_struct_pattern"
        | "struct_pattern" | "generic_pattern" => {
            // Destructuring: distribute per-element for matching
            // tuple/array literal RHS; else join to all bindings.
            if !vv.elems.is_empty()
                && try_tuple_destructure(target, vv, ctx, env)
            {
                return;
            }
            for k in pat_keys(target, ctx) {
                let mut st = state.clone();
                if st.taint.is_none() {
                    st.taint = source_label.clone();
                }
                env.insert(k, st);
            }
        }
        "field_pattern" => {
            if let Some(p) = target.child_by_field_name("pattern") {
                assign_pattern(p, vv, assign_node, ctx, env);
            } else if let Some(name) = target.child_by_field_name("name") {
                if let Ok(n) = name.utf8_text(ctx.f.text.as_bytes()) {
                    let mut st = state.clone();
                    if st.taint.is_none() {
                        st.taint = source_label.clone();
                    }
                    env.insert(n.to_string(), st);
                }
            }
        }
        "shorthand_field_identifier" => {
            if let Ok(n) = target.utf8_text(ctx.f.text.as_bytes()) {
                let mut st = state.clone();
                if st.taint.is_none() {
                    st.taint = source_label.clone();
                }
                env.insert(n.to_string(), st);
            }
        }
        _ => {
            // Wildcard/literal patterns bind nothing.
            for k in pat_keys(target, ctx) {
                env.insert(k, state.clone());
            }
        }
    }
}

/// `let (a, b) = (x, y)` / `let [a, b] = [x, y]` distributing the
/// RHS's captured per-element states to pattern bindings.
fn try_tuple_destructure(
    pat: Node,
    vv: &ExprVal,
    ctx: &mut CtxRs,
    env: &mut HashMap<String, VarState>,
) -> bool {
    if vv.elems.is_empty() {
        return false;
    }
    let elems: Vec<Node> = pat
        .children(&mut pat.walk())
        .filter(|k| k.is_named() && !matches!(k.kind(), "tuple_pattern" | "slice_pattern"))
        .collect();
    if elems.len() != vv.elems.len() {
        return false;
    }
    for (t, (st, label)) in elems.iter().zip(vv.elems.iter()) {
        let ev = ExprVal {
            state: st.clone(),
            source_label: label.clone(),
            elems: Vec::new(),
            fields: Vec::new(),
            ..Default::default()
        };
        assign_pattern(*t, &ev, pat, ctx, env);
    }
    true
}

/// RHS expression node of an assignment-ish node.
fn rhs_node(node: Node) -> Option<Node> {
    match node.kind() {
        "let_declaration" => node.child_by_field_name("value"),
        "assignment_expression" | "compound_assignment_expr" => {
            node.child_by_field_name("right")
        }
        _ => None,
    }
}

/// Drop tracked `name[i]` / `name.key` entries (container rebound).
fn clear_element_states(env: &mut HashMap<String, VarState>, name: &str) {
    let pi = format!("{name}[");
    let pk = format!("{name}.");
    env.retain(|k, _| !k.starts_with(&pi) && !k.starts_with(&pk));
}

/// Record `name[i]` / `name.field` env entries from an evaluated
/// literal's captured per-element/per-field states.
fn record_element_states(
    name: &str,
    vv: &ExprVal,
    _ctx: &mut CtxRs,
    env: &mut HashMap<String, VarState>,
) {
    for (i, (st, label)) in vv.elems.iter().enumerate() {
        let mut est = st.clone();
        if est.taint.is_none() {
            est.taint = label.clone();
        }
        env.insert(format!("{name}[{i}]"), est);
    }
    for (key, st, label) in &vv.fields {
        let mut est = st.clone();
        if est.taint.is_none() {
            est.taint = label.clone();
        }
        env.insert(format!("{name}.{key}"), est);
    }
}

/// If this assignment's RHS is a resource-acquiring call, return kind.
fn resource_kind_of(assign_node: Node, ctx: &CtxRs) -> Option<String> {
    let r = rhs_node(assign_node)?;
    if r.kind() != "call_expression" {
        return None;
    }
    let dotted = dotted_callee(r, ctx)?;
    // Rust RAII closes on drop; only explicit-leak acquisitions are
    // interesting, but keep file/conn kinds for returns_unclosed.
    let kind = match dotted.as_str() {
        "std::fs::File::open" | "std::fs::File::create"
        | "std::fs::OpenOptions::open" => Some("file".to_string()),
        "std::net::TcpStream::connect" | "std::net::UdpSocket::bind" => {
            Some("conn".to_string())
        }
        _ => None,
    };
    kind
}

/// Dotted `::` name of a call's callee expression.
fn dotted_callee(call: Node, ctx: &CtxRs) -> Option<String> {
    let func = call.child_by_field_name("function")?;
    dotted_expr(func, ctx)
}

/// Dotted `::` name for identifier/scoped/field chains, resolving
/// heads through `use` imports to full paths.
fn dotted_expr(node: Node, ctx: &CtxRs) -> Option<String> {
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(text).ok()?;
            // `use` import -> full path.
            if let Some(path) = ctx.f.imports.get(name) {
                return Some(path.clone());
            }
            Some(name.to_string())
        }
        "self" | "crate" | "super" => {
            node.utf8_text(text).ok().map(str::to_string)
        }
        "scoped_identifier" => {
            let path = node.child_by_field_name("path")?;
            let name = node.child_by_field_name("name")?;
            let base = dotted_expr(path, ctx)?;
            // `use` alias on the path head: `env::var` where
            // `use std::env` binds env -> std::env.
            let base = resolve_path_head(&base, ctx);
            let n = name.utf8_text(text).ok()?;
            Some(format!("{base}::{n}"))
        }
        "field_expression" => {
            // `x.f` / `x.0` - receiver path + field.
            let val = node.child_by_field_name("value")?;
            let field = node.child_by_field_name("field")?;
            let base = dotted_expr(val, ctx)?;
            let p = field.utf8_text(text).ok()?;
            Some(format!("{base}::{p}"))
        }
        "generic_function" => {
            let func = node.child_by_field_name("function")?;
            dotted_expr(func, ctx)
        }
        "call_expression" | "index_expression" | "try_expression"
        | "await_expression" | "type_cast_expression" => {
            // `f().m()`, `x[i].m()`, `x?.m()`-ish chains: collapse to
            // the receiver's dotted name.
            let inner = if node.kind() == "field_expression" {
                node.child_by_field_name("value")?
            } else {
                node.child_by_field_name("function")
                    .or_else(|| node.child_by_field_name("value"))
                    .or_else(|| node.child_by_field_name("operand"))?
            };
            dotted_expr(inner, ctx)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            dotted_expr(inner, ctx)
        }
        _ => None,
    }
}

/// If `base`'s head segment is a `use` alias, expand it to the full
/// path (`env::var` with `use std::env` -> `std::env::var`).
fn resolve_path_head(base: &str, ctx: &CtxRs) -> String {
    let head = base.split("::").next().unwrap_or(base);
    if let Some(full) = ctx.f.imports.get(head) {
        if base == head {
            return full.clone();
        }
        let rest = &base[head.len()..];
        return format!("{full}{rest}");
    }
    base.to_string()
}

/// Environment key for an lvalue-ish expression.
fn expr_key(node: Node, ctx: &CtxRs, env: &HashMap<String, VarState>) -> Option<String> {
    let _ = env;
    expr_key_text(node, ctx.f.text.as_str())
}

/// Text-only variant for callee resolution.
fn expr_key_text(node: Node, text: &str) -> Option<String> {
    match node.kind() {
        "identifier" => node
            .utf8_text(text.as_bytes())
            .ok()
            .map(|s| s.to_string()),
        "field_expression" => {
            let val = node.child_by_field_name("value")?;
            let base = expr_key_text(val, text)?;
            let field = node.child_by_field_name("field")?;
            let p = field.utf8_text(text.as_bytes()).ok()?;
            Some(format!("{base}.{p}"))
        }
        "index_expression" => {
            // No fields: positional children - first named = value,
            // second = index.
            let named: Vec<Node> = node
                .children(&mut node.walk())
                .filter(|k| k.is_named())
                .collect();
            let base = expr_key_text(named.first().copied()?, text)?;
            if let Some(idx) = named.get(1) {
                if idx.kind() == "integer_literal" {
                    if let Ok(i) = idx.utf8_text(text.as_bytes()) {
                        if let Ok(n) = i.trim().parse::<i64>() {
                            return Some(format!("{base}[{n}]"));
                        }
                    }
                }
            }
            Some(base)
        }
        "parenthesized_expression" | "try_expression" | "await_expression" => {
            node.children(&mut node.walk())
                .find(|k| k.is_named())
                .and_then(|i| expr_key_text(i, text))
        }
        _ => None,
    }
}

/// Evaluate an expression to a VarState + optional source label.
fn eval_expr(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) -> ExprVal {
    if budget(ctx) {
        return ExprVal::default();
    }
    let text = ctx.f.text.as_bytes();
    match node.kind() {
        "string_literal"
        | "raw_string_literal"
        | "char_literal"
        | "integer_literal"
        | "float_literal"
        | "boolean_literal"
        | "unit_expression"
        | "line_comment"
        | "block_comment" => ExprVal::default(),
        "identifier" => {
            let name = node.utf8_text(text).unwrap_or("");
            // `None` literal -> may be absent.
            if name == "None" {
                return ExprVal {
                    state: VarState {
                        is_none: true,
                        ..Default::default()
                    },
                    source_label: None,
                    ..Default::default()
                };
            }
            ExprVal {
                state: env.get(name).cloned().unwrap_or_default(),
                source_label: None,
                ..Default::default()
            }
        }
        "field_expression" | "index_expression" => {
            // `x.f` / `x[i]`: source check, then env key lookup.
            // Field access can't be none in valid Rust - no
            // member-access deref finding (Option has no fields).
            if let Some(label) = source_label_of(node, ctx) {
                return ExprVal {
                    state: VarState {
                        taint: Some(label.clone()),
                        is_none: false,
                        resource: None,
                    },
                    source_label: Some(label),
                    ..Default::default()
                };
            }
            let mut st = VarState::default();
            if let Some(obj) = node.child_by_field_name("value") {
                let bv = eval_expr(obj, ctx, env);
                st = bv.state;
            }
            if let Some(key) = expr_key(node, ctx, env) {
                if env.contains_key(&key) {
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
                ..Default::default()
            }
        }
        "scoped_identifier" => {
            // `Option::None` / `Result::Err`-ish paths ending in a
            // known absent/present variant.
            let raw = node
                .utf8_text(text)
                .unwrap_or("");
            let last = raw.rsplit("::").next().unwrap_or(raw);
            if last == "None" {
                return ExprVal {
                    state: VarState {
                        is_none: true,
                        ..Default::default()
                    },
                    source_label: None,
                    ..Default::default()
                };
            }
            ExprVal {
                state: env.get(raw).cloned().unwrap_or_default(),
                source_label: None,
                ..Default::default()
            }
        }
        "call_expression" => eval_call(node, ctx, env),
        "macro_invocation" => eval_macro(node, ctx, env),
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
                ..Default::default()
            }
        }
        "unary_expression" | "reference_expression" => {
            // `*p`, `&x`, `!x`, `-x`: operand state propagates.
            // unary has no fields: first named child is the operand.
            let mut st = VarState::default();
            if let Some(arg) = node
                .child_by_field_name("value")
                .or_else(|| node.children(&mut node.walk()).find(|k| k.is_named()))
            {
                let v = eval_expr(arg, ctx, env);
                st = v.state;
            }
            ExprVal {
                state: st,
                source_label: None,
                ..Default::default()
            }
        }
        "try_expression" => {
            // `x?`: on None/Err the function returns early - the
            // function may return absent AND the unwrapped value is
            // not none. No fields: first named child is the operand.
            let arg = node.children(&mut node.walk()).find(|k| k.is_named());
            if let Some(arg) = arg {
                let v = eval_expr(arg, ctx, env);
                if v.state.is_none {
                    ctx.ret.is_none = true;
                }
                let mut st = v.state.clone();
                st.is_none = false;
                return ExprVal {
                    state: st,
                    source_label: v.source_label,
                    ..Default::default()
                };
            }
            ExprVal::default()
        }
        "await_expression" | "type_cast_expression" | "parenthesized_expression" => {
            let inner = node
                .child_by_field_name("value")
                .or_else(|| node.children(&mut node.walk()).find(|k| k.is_named()));
            match inner {
                Some(k) => eval_expr(k, ctx, env),
                None => ExprVal::default(),
            }
        }
        "array_expression" | "tuple_expression" => {
            let mut st = VarState::default();
            let mut label = None;
            let mut elems = Vec::new();
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    elems.push((v.state.clone(), v.source_label.clone()));
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
                elems,
                fields: Vec::new(),
                ..Default::default()
            }
        }
        "struct_expression" => {
            // `T{a: x, ..base}` - per-field states captured for
            // `x.a` tracking; joined state is the may-value.
            let mut st = VarState::default();
            let mut label = None;
            let mut fields = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let mut c = body.walk();
                for ch in body.children(&mut c) {
                    if !ch.is_named() {
                        continue;
                    }
                    match ch.kind() {
                        "field_initializer" => {
                            let fname = ch
                                .child_by_field_name("field")
                                .and_then(|f| f.utf8_text(text).ok())
                                .unwrap_or("")
                                .to_string();
                            if let Some(fv) = ch.child_by_field_name("value") {
                                let v = eval_expr(fv, ctx, env);
                                fields.push((
                                    fname,
                                    v.state.clone(),
                                    v.source_label.clone(),
                                ));
                                st.join(&v.state);
                                if label.is_none() {
                                    label = v.source_label;
                                }
                            }
                        }
                        "shorthand_field_initializer" => {
                            // `T{a}` - field `a` binds local `a`.
                            let fname = ch
                                .utf8_text(text)
                                .unwrap_or("")
                                .to_string();
                            if let Some(v) = env.get(&fname) {
                                fields.push((
                                    fname,
                                    v.clone(),
                                    v.taint.clone(),
                                ));
                                st.join(v);
                            }
                        }
                        "base_field_initializer" => {
                            // `..base` spreads base's state.
                            if let Some(b) = ch
                                .children(&mut ch.walk())
                                .find(|k| k.is_named())
                            {
                                let v = eval_expr(b, ctx, env);
                                st.join(&v.state);
                                if label.is_none() {
                                    label = v.source_label;
                                }
                            }
                        }
                        _ => {
                            let v = eval_expr(ch, ctx, env);
                            st.join(&v.state);
                            if label.is_none() {
                                label = v.source_label;
                            }
                        }
                    }
                }
            }
            st.is_none = false;
            ExprVal {
                state: st,
                source_label: label,
                elems: Vec::new(),
                fields,
                ..Default::default()
            }
        }
        "field_initializer_list" | "field_initializer" => {
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
                ..Default::default()
            }
        }
        "closure_expression" | "function_item" | "function_signature_item"
        | "struct_item" | "enum_item" | "impl_item" | "trait_item"
        | "mod_item" | "use_declaration" | "type_item" | "const_item"
        | "static_item" | "macro_definition" => ExprVal::default(),
        "assignment_expression" | "compound_assignment_expr" => {
            // Rust assignments are expressions: `x = f()`, `x += y`.
            let right = node.child_by_field_name("right");
            let left = node.child_by_field_name("left");
            if let (Some(l), Some(r)) = (left, right) {
                let is_aug = node.kind() == "compound_assignment_expr";
                let mut rv = eval_expr(r, ctx, env);
                if is_aug {
                    if let Some(key) = expr_key(l, ctx, env) {
                        if let Some(prev) = env.get(&key) {
                            let mut joined = prev.clone();
                            joined.join(&rv.state);
                            rv.state = joined;
                        }
                    }
                }
                assign_lvalue(l, &rv, node, ctx, env);
                return rv;
            }
            ExprVal::default()
        }
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
                ..Default::default()
            }
        }
    }
}

/// Assign to an lvalue expression (identifier/field/index).
fn assign_lvalue(
    target: Node,
    vv: &ExprVal,
    assign_node: Node,
    ctx: &mut CtxRs,
    env: &mut HashMap<String, VarState>,
) {
    let state = &vv.state;
    let source_label = &vv.source_label;
    match target.kind() {
        "identifier" => {
            let Ok(name) = target.utf8_text(ctx.f.text.as_bytes()) else {
                return;
            };
            let mut st = state.clone();
            if st.taint.is_none() {
                st.taint = source_label.clone();
            }
            if let Some(kind) = resource_kind_of(assign_node, ctx) {
                st.resource = Some(kind.clone());
                ctx.acquired
                    .push((name.to_string(), kind, line_of(assign_node)));
            }
            env.insert(name.to_string(), st);
            clear_element_states(env, name);
            if !vv.elems.is_empty() || !vv.fields.is_empty() {
                record_element_states(name, vv, ctx, env);
            }
        }
        "field_expression" | "index_expression" => {
            if let Some(key) = expr_key(target, ctx, env) {
                let mut st = state.clone();
                if st.taint.is_none() {
                    st.taint = source_label.clone();
                }
                env.insert(key, st);
            }
        }
        "parenthesized_expression" | "try_expression" | "await_expression" => {
            let inner = target
                .children(&mut target.walk())
                .find(|k| k.is_named());
            if let Some(i) = inner {
                assign_lvalue(i, vv, assign_node, ctx, env);
            }
        }
        _ => {}
    }
}

/// Is this expression a model source? Returns provenance label.
fn source_label_of(node: Node, ctx: &CtxRs) -> Option<String> {
    let dotted = dotted_expr(node, ctx)?;
    let kind = ctx.model.source_kind(&dotted)?;
    Some(format!("src:{kind:?}"))
}

/// Process a call: sinks, sources, sanitizers, resolved callees,
/// unknown-call taint propagation, receiver taint propagation, and
/// Option-unwrap panic checks.
fn eval_call(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) -> ExprVal {
    // Evaluate callee for side effects.
    if let Some(func) = node.child_by_field_name("function") {
        if matches!(
            func.kind(),
            "field_expression" | "scoped_identifier" | "call_expression"
                | "index_expression" | "generic_function"
        ) {
            eval_expr(func, ctx, env);
        }
    }
    let Some(mut dotted) = dotted_callee(node, ctx) else {
        ctx.touches_unknown = true;
        return ExprVal::default();
    };

    // `recv.m(...)` where recv is itself a call (`Command::new(..)
    // .arg(..)`): the syntactic dotted name embeds the callee
    // (`...::new::arg`), so resolve the receiver's return type and
    // rebuild `{RetType}::{method}` for sink/source matching.
    if let Some(func) = node.child_by_field_name("function") {
        if func.kind() == "field_expression" {
            if let Some(val) = func.child_by_field_name("value") {
                if val.kind() == "call_expression" {
                    if let Some(rt) = call_ret_type(val, ctx) {
                        if let Some(fname) = func.child_by_field_name("field") {
                            if let Ok(fn_) = fname.utf8_text(ctx.f.text.as_bytes()) {
                                dotted = format!("{rt}::{fn_}");
                            }
                        }
                    }
                }
            }
        }
    }

    let args = call_args(node, ctx, env);

    // Receiver value state for method calls (`x.m(...)`): used for
    // panic-method checks, sink checks on arg=None rules, and
    // receiver->result taint propagation.
    let recv = call_receiver(node, ctx, env);

    // Resource args may transfer ownership.
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

    // Panic-method check: `opt.unwrap()` / `.expect()` on a maybe-
    // None receiver -> NullDeref (panic) finding.
    if let Some(rv) = &recv {
        if rv.state.is_none {
            let last = dotted.rsplit("::").next().unwrap_or(&dotted);
            if PANIC_METHODS.contains(&last) {
                push_finding_at(ctx, SinkKind::NullDeref, "none", &dotted, node, 0.8);
            }
        }
    }

    // 1. Sink check by dotted name. arg=None rules check args AND
    // the receiver (method sinks like `conn.execute` have the sink
    // object as receiver but taint usually sits in args; unwrap
    // family handled above).
    let mut sink_hit: Vec<(SinkKind, usize)> = Vec::new();
    let mut sink_hit_recv = false;
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
                if recv.is_some() {
                    sink_hit_recv = true;
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

    // 3. Sanitizer (last-segment match).
    let is_sanitizer = ctx
        .model
        .sanitizer_names()
        .contains(dotted.rsplit("::").next().unwrap_or(&dotted));

    // 4. Apply sink rules to arg + receiver states.
    if !is_sanitizer {
        for (class, idx) in &sink_hit {
            let Some(av) = args.get(*idx) else { continue };
            if let Some(label) = &av.state.taint {
                handle_sink_taint(ctx, class.clone(), label.clone(), &dotted, node);
            }
        }
        if sink_hit_recv {
            if let Some(rv) = &recv {
                if let Some(label) = &rv.state.taint {
                    // Re-derive the class set for arg=None rules.
                    for rule in ctx.model.sinks_for(&dotted) {
                        if rule.arg.is_none() {
                            handle_sink_taint(
                                ctx,
                                rule.class.clone(),
                                label.clone(),
                                &dotted,
                                node,
                            );
                        }
                    }
                }
            }
        }
    }

    // 5. Callee resolution + summary application.
    if let Some((cm, cf)) = resolve_callee(
        node,
        ctx.f,
        ctx.parsed,
        ctx.file_index,
        ctx.mod_index,
        Some(&ctx.types),
    ) {
        let key = (cm.clone(), cf.clone());
        if let Some(sum) = ctx.summaries.get(&key) {
            apply_summary(node, ctx, &args, sum, &format!("{cm}::{cf}"));
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

    // Receiver taint propagation: `tainted.trim()`, `opt.unwrap()`,
    // `resp.text()` keep the receiver's taint when args are clean.
    // unwrap/expect on a none receiver already flagged above; the
    // result of unwrap is the payload (tainted if receiver was).
    if result.state.taint.is_none() {
        if let Some(rv) = &recv {
            if let Some(label) = &rv.state.taint {
                result.state.taint = Some(label.clone());
            }
        }
    }
    // unwrap-family clears none-ness on success path.
    let last = dotted.rsplit("::").next().unwrap_or(&dotted);
    if PANIC_METHODS.contains(&last) {
        result.state.is_none = false;
    }
    // `Some(x)`/`Ok(x)` constructors yield non-none.
    if OK_VARIANTS.contains(&last) {
        result.state.is_none = false;
    }

    // Model propagators.
    if result.state.taint.is_none()
        && ctx
            .model
            .propagators
            .iter()
            .any(|p| dotted == *p || dotted.ends_with(&format!("::{p}")) || dotted.ends_with(&format!(".{p}")))
    {
        if let Some(av) = args.iter().find(|a| a.state.taint.is_some()) {
            result.state.taint = av.state.taint.clone();
        } else if let Some(rv) = &recv {
            if let Some(label) = &rv.state.taint {
                result.state.taint = Some(label.clone());
            }
        }
    }

    if is_sanitizer {
        result.state.taint = None;
        result.source_label = None;
    }
    result
}

/// The receiver expression state of a method call
/// (`x.m(...)` -> state of `x`).
fn call_receiver(
    node: Node,
    ctx: &mut CtxRs,
    env: &mut HashMap<String, VarState>,
) -> Option<ExprVal> {
    let func = node.child_by_field_name("function")?;
    if func.kind() != "field_expression" {
        return None;
    }
    let val = func.child_by_field_name("value")?;
    Some(eval_expr(val, ctx, env))
}

/// Tainted arg reached a sink: concrete finding or param flow.
fn handle_sink_taint(ctx: &mut CtxRs, class: SinkKind, label: String, sink_name: &str, node: Node) {
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
    ctx: &mut CtxRs,
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
fn call_args(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) -> Vec<ExprVal> {
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

/// Evaluate a macro invocation: `format!`, `include_str!`, `vec!`,
/// custom macros. Token trees have no arg structure - scan for
/// identifier states and join (documented approximation). Known
/// compile-time file embeds become File sources.
fn eval_macro(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) -> ExprVal {
    let mac = node.child_by_field_name("macro");
    let name = mac
        .and_then(|m| {
            if m.kind() == "scoped_identifier" {
                m.child_by_field_name("name")
            } else {
                Some(m)
            }
        })
        .and_then(|n| n.utf8_text(ctx.f.text.as_bytes()).ok())
        .unwrap_or("");
    // include_str!/include_bytes! embed file content at compile
    // time - treat as a File source.
    if matches!(name, "include_str" | "include_bytes") {
        return ExprVal {
            state: VarState {
                taint: Some("src:File".to_string()),
                is_none: false,
                resource: None,
            },
            source_label: Some("src:File".to_string()),
            ..Default::default()
        };
    }
    // env!/option_env! are compile-time env reads - Env source.
    if name == "env" || name == "option_env" {
        return ExprVal {
            state: VarState {
                taint: Some("src:Env".to_string()),
                is_none: false,
                resource: None,
            },
            source_label: Some("src:Env".to_string()),
            ..Default::default()
        };
    }
    // Join taint of every identifier inside the token tree.
    let mut st = VarState::default();
    let mut label = None;
    let mut stack: Vec<Node> = node.children(&mut node.walk()).collect();
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                if let Ok(name) = n.utf8_text(ctx.f.text.as_bytes()) {
                    if let Some(v) = env.get(name) {
                        if v.taint.is_some() {
                            st.taint = v.taint.clone();
                            label = v.taint.clone();
                        }
                        st.is_none |= v.is_none;
                        if v.resource.is_some() {
                            st.resource = v.resource.clone();
                        }
                    }
                }
            }
            _ => {
                let mut c = n.walk();
                for ch in n.children(&mut c) {
                    if ch.is_named() {
                        stack.push(ch);
                    }
                }
            }
        }
    }
    st.is_none = false;
    ExprVal {
        state: st,
        source_label: label,
        ..Default::default()
    }
}

/// Branch bodies run on a cloned env, then join back (may-analysis).
/// `ctx.types` is shared (documented).
fn walk_branch(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    let mut env2 = env.clone();
    walk_dispatch(node, ctx, &mut env2);
    for (k, v) in env2 {
        env.entry(k).or_default().join(&v);
    }
}

type Narrows = (Vec<(String, bool)>, Vec<(String, bool)>);

/// Option-ness condition analysis: `x == None`, `x.is_none()`,
/// `x.is_some()`, `!`, `&&`/`||` recursion, `matches!` skipped.
fn null_checks(cond: Node, ctx: &CtxRs, env: &HashMap<String, VarState>) -> Narrows {
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
                if let Some(arg) = cond.child_by_field_name("value") {
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
        "call_expression" => {
            // `x.is_none()` / `x.is_some()` - method-call conditions.
            let func = cond.child_by_field_name("function");
            let dotted = func.and_then(|fn_| dotted_expr(fn_, ctx));
            match dotted.as_deref() {
                Some(d) if d.ends_with("::is_none") || d.ends_with(".is_none") => {
                    // Receiver is the `value` of the field_expression.
                    if let Some(f) = func {
                        if f.kind() == "field_expression" {
                            if let Some(v) = f.child_by_field_name("value") {
                                if let Some(key) = expr_key(v, ctx, env) {
                                    // is_none() true -> x is none.
                                    return (vec![(key.clone(), true)], vec![(key, false)]);
                                }
                            }
                        }
                    }
                }
                Some(d) if d.ends_with("::is_some") || d.ends_with(".is_some") => {
                    if let Some(f) = func {
                        if f.kind() == "field_expression" {
                            if let Some(v) = f.child_by_field_name("value") {
                                if let Some(key) = expr_key(v, ctx, env) {
                                    return (vec![(key.clone(), false)], vec![(key, true)]);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            (vec![], vec![])
        }
        _ => (vec![], vec![]),
    }
}

/// `x == None` / `x != None` (and swapped).
fn leaf_null_check(cond: Node, op: &str, ctx: &CtxRs, env: &HashMap<String, VarState>) -> Narrows {
    let l = cond.child_by_field_name("left");
    let r = cond.child_by_field_name("right");
    let (Some(left), Some(right)) = (l, r) else {
        return (vec![], vec![]);
    };
    let is_none_lit = |n: Node| n.kind() == "identifier"
        && n.utf8_text(ctx.f.text.as_bytes()).is_ok_and(|t| t == "None");
    let target = if is_none_lit(right) {
        left
    } else if is_none_lit(left) {
        right
    } else {
        return (vec![], vec![]);
    };
    let is_none_true = op == "==";
    match expr_key(target, ctx, env) {
        Some(key) => (
            vec![(key.clone(), is_none_true)],
            vec![(key, !is_none_true)],
        ),
        None => (vec![], vec![]),
    }
}

/// if/else with Option narrowing. Rust `if` is an expression; the
/// consequence/alternative are blocks.
fn walk_if(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    // `if let PAT = EXPR` conditions bind payload vars in the
    // consequence; handle let_condition/let_chain first.
    let cond = node.child_by_field_name("condition");
    let cons = node.child_by_field_name("consequence");
    let alt = node.child_by_field_name("alternative");
    let Some(cond) = cond else { return };

    // Collect let-bindings from the condition (`if let Some(x) = o`).
    let mut let_bindings: Vec<(Node, Node)> = Vec::new(); // (pattern, value)
    collect_let_conditions(cond, &mut let_bindings);
    for (pat, val) in &let_bindings {
        let mut vv = eval_expr(*val, ctx, env);
        // Payload binding: gets value state with none-ness cleared
        // (the pattern matched, so the payload exists).
        vv.state.is_none = false;
        assign_pattern(*pat, &vv, *val, ctx, env);
    }
    eval_expr(cond, ctx, env);
    let check = null_checks(cond, ctx, env);

    let mut clauses: Vec<(Narrows, Node, bool)> = Vec::new();
    if let Some(c) = cons {
        clauses.push((check, c, false));
    }
    if let Some(a) = alt {
        // else_clause wraps the else block or else-if.
        let inner = a.children(&mut a.walk()).find(|k| k.is_named());
        match inner {
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

    // Post-if narrowing (same shape as JS/Go).
    let n = clauses.len();
    if n == 0 {
        return;
    }
    let terms: Vec<bool> = clauses
        .iter()
        .map(|(_, s, _)| rs_block_terminal(*s, ctx.f.text.as_str()))
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

/// Collect (pattern, value) pairs from `if let`/`while let`/
/// `let_chain` conditions.
fn collect_let_conditions<'a>(cond: Node<'a>, out: &mut Vec<(Node<'a>, Node<'a>)>) {
    match cond.kind() {
        "let_condition" => {
            if let (Some(p), Some(v)) = (
                cond.child_by_field_name("pattern"),
                cond.child_by_field_name("value"),
            ) {
                out.push((p, v));
            }
        }
        "let_chain" => {
            let mut c = cond.walk();
            for ch in cond.children(&mut c) {
                if ch.is_named() {
                    collect_let_conditions(ch, out);
                }
            }
        }
        "binary_expression" => {
            // `let A = x && let B = y` may nest under binary &&.
            if let Some(l) = cond.child_by_field_name("left") {
                collect_let_conditions(l, out);
            }
            if let Some(r) = cond.child_by_field_name("right") {
                collect_let_conditions(r, out);
            }
        }
        "parenthesized_expression" => {
            let inner = cond.children(&mut cond.walk()).find(|k| k.is_named());
            if let Some(i) = inner {
                collect_let_conditions(i, out);
            }
        }
        _ => {}
    }
}

/// True if a Rust statement/block cannot complete normally.
fn rs_block_terminal(node: Node, text: &str) -> bool {
    match node.kind() {
        "return_expression" | "break_expression" | "continue_expression"
        | "yield_expression" => true,
        "block" | "declaration_list" => {
            let mut c = node.walk();
            node.children(&mut c)
                .filter(|k| k.is_named())
                .last()
                .map(|l| rs_block_terminal(l, text))
                .unwrap_or(false)
        }
        "expression_statement" => {
            // `panic!(...)` / `unreachable!()` / `todo!()` terminate.
            let mut stack = vec![node];
            while let Some(n) = stack.pop() {
                if n.kind() == "macro_invocation" {
                    if let Some(m) = n.child_by_field_name("macro") {
                        let name = if m.kind() == "scoped_identifier" {
                            m.child_by_field_name("name")
                        } else {
                            Some(m)
                        };
                        if let Some(nm) = name {
                            if nm
                                .utf8_text(text.as_bytes())
                                .is_ok_and(|t| matches!(t, "panic" | "unreachable" | "todo" | "unimplemented"))
                            {
                                return true;
                            }
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
        "if_expression" => {
            let cons = node.child_by_field_name("consequence");
            let alt = node.child_by_field_name("alternative");
            match (cons, alt) {
                (Some(c), Some(a)) => {
                    rs_block_terminal(c, text) && rs_block_terminal(a, text)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// for loop: pattern binding gets element taint; body as branch.
fn walk_for(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    if let Some(value) = node.child_by_field_name("value") {
        let rv = eval_expr(value, ctx, env);
        if let Some(pat) = node.child_by_field_name("pattern") {
            // Element state: taint propagates; none/resource don't.
            let mut st = VarState::default();
            st.taint = rv.state.taint.clone();
            for k in pat_keys(pat, ctx) {
                env.insert(k, st.clone());
            }
        }
    }
    if let Some(body) = node.child_by_field_name("body") {
        walk_branch(body, ctx, env);
    }
}

/// match: evaluate scrutinee; each arm binds pattern vars (payload
/// state = scrutinee state with none-ness cleared) and walks body.
fn walk_match(node: Node, ctx: &mut CtxRs, env: &mut HashMap<String, VarState>) {
    if let Some(v) = node.child_by_field_name("value") {
        eval_expr(v, ctx, env);
        let vv = eval_expr(v, ctx, env);
        if let Some(body) = node.child_by_field_name("body") {
            let mut c = body.walk();
            for arm in body.children(&mut c) {
                if arm.kind() != "match_arm" {
                    continue;
                }
                // Arm pattern bindings get payload state.
                if let Some(pat) = arm.child_by_field_name("pattern") {
                    let mut st = vv.state.clone();
                    st.is_none = false;
                    let mut env2 = env.clone();
                    for k in pat_keys(pat, ctx) {
                        env2.insert(k, st.clone());
                    }
                    if let Some(val) = arm.child_by_field_name("value") {
                        walk_dispatch(val, ctx, &mut env2);
                    }
                    for (k, v) in env2 {
                        env.entry(k).or_default().join(&v);
                    }
                } else if let Some(val) = arm.child_by_field_name("value") {
                    walk_dispatch(val, ctx, env);
                }
            }
        }
    }
}

/// Composite literal / struct expression type name.
fn composite_type(node: Node, ctx: &CtxRs) -> Option<String> {
    composite_type_text(node, ctx.f.text.as_str())
}

fn composite_type_text(node: Node, text: &str) -> Option<String> {
    let n = match node.kind() {
        "struct_expression" => node.child_by_field_name("name")?,
        "parenthesized_expression" | "try_expression" | "await_expression" => {
            node.children(&mut node.walk()).find(|k| k.is_named())?
        }
        _ => return None,
    };
    rust_deep::type_name_rs(n, text)
}

/// Known call return types: explicit table plus the `Type::new()` /
/// `Type::default()` convention (returns the type itself).
fn call_ret_type(node: Node, ctx: &CtxRs) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let dotted = dotted_callee(node, ctx)?;
    if let Some((_, t)) = CALL_RET_TYPES.iter().find(|(n, _)| {
        dotted == *n || dotted.ends_with(&format!("::{n}"))
    }) {
        return Some(t.to_string());
    }
    for suffix in ["::new", "::default"] {
        if let Some(t) = dotted.strip_suffix(suffix) {
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Resolve this call's callee to (file_rel, qualname).
pub fn resolve_callee(
    node: Node,
    f: &RsFile,
    parsed: &[RsFile],
    file_index: &HashMap<String, usize>,
    mod_index: &HashMap<String, usize>,
    types: Option<&HashMap<String, String>>,
) -> Option<NodeId> {
    let func = node.child_by_field_name("function")?;
    resolve_func_node(func, f, parsed, file_index, mod_index, types)
}

fn resolve_func_node(
    func: Node,
    f: &RsFile,
    parsed: &[RsFile],
    file_index: &HashMap<String, usize>,
    mod_index: &HashMap<String, usize>,
    types: Option<&HashMap<String, String>>,
) -> Option<NodeId> {
    let text = f.text.as_bytes();
    match func.kind() {
        "identifier" => {
            let name = func.utf8_text(text).ok()?;
            // `use`-imported callee: try project-path resolution
            // (`use crate::util::helper` -> util.rs::helper); external
            // paths (std::, crates.io) stay unresolved.
            if let Some(path) = f.imports.get(name) {
                return resolve_module_path(path, parsed, file_index, mod_index, f);
            }
            // Same-file function.
            local_qualname(f, name).map(|q| (f.rel.clone(), q))
        }
        "scoped_identifier" => {
            // `a::b::c(...)` - full path; project paths resolve via
            // module index, external paths stay unknown.
            let path = rust_deep_path(func, f);
            resolve_module_path(&path, parsed, file_index, mod_index, f)
        }
        "field_expression" => {
            // `recv.method(...)` - resolve via type env.
            let field = func.child_by_field_name("field")?;
            let fname = field.utf8_text(text).ok()?;
            let val = func.child_by_field_name("value")?;
            match val.kind() {
                "self" | "identifier" if val.kind() == "self" => {
                    // `self.m()` inside impl: receiver type is the
                    // impl type - find via enclosing impl? We stored
                    // receiver_type on the FUNC info, not here; use
                    // types env (seeded with self->Type).
                    let t = types.and_then(|t| t.get("self"))?;
                    let qual = format!("{t}::{fname}");
                    file_qualname(&f.rel, &qual, f).map(|q| (f.rel.clone(), q))
                }
                "identifier" => {
                    let vname = val.utf8_text(text).ok()?;
                    // `Type::method` style: val could be a type name
                    // (associated function) - check funcs for
                    // `Type::fname` qualname first.
                    let assoc = format!("{vname}::{fname}");
                    if file_has_qualname(&f.rel, &assoc, f) {
                        return Some((f.rel.clone(), assoc));
                    }
                    // Receiver method via type env.
                    let t = types.and_then(|t| t.get(vname))?;
                    let qual = format!("{t}::{fname}");
                    file_qualname(&f.rel, &qual, f).map(|q| (f.rel.clone(), q))
                }
                "field_expression" | "index_expression" | "call_expression"
                | "scoped_identifier" => {
                    // `x.f.m()` / `f().m()`: operand type if tracked.
                    if let Some(key) = expr_key_text(val, f.text.as_str()) {
                        if let Some(t) = types.and_then(|t| t.get(&key)) {
                            let qual = format!("{t}::{fname}");
                            return file_qualname(&f.rel, &qual, f)
                                .map(|q| (f.rel.clone(), q));
                        }
                    }
                    None
                }
                "parenthesized_expression" => {
                    let inner = val
                        .children(&mut val.walk())
                        .find(|k| k.is_named())?;
                    // Recurse treating inner as the receiver.
                    resolve_receiver(inner, fname, f, parsed, file_index, mod_index, types)
                }
                _ => None,
            }
        }
        "generic_function" => {
            let inner = func.child_by_field_name("function")?;
            resolve_func_node(inner, f, parsed, file_index, mod_index, types)
        }
        "parenthesized_expression" => {
            let inner = func
                .children(&mut func.walk())
                .find(|k| k.is_named())?;
            resolve_func_node(inner, f, parsed, file_index, mod_index, types)
        }
        _ => None,
    }
}

/// Resolve `recv.name(...)` where recv is an arbitrary expression -
/// shared tail for parenthesized/complex receivers.
fn resolve_receiver(
    val: Node,
    fname: &str,
    f: &RsFile,
    parsed: &[RsFile],
    file_index: &HashMap<String, usize>,
    mod_index: &HashMap<String, usize>,
    types: Option<&HashMap<String, String>>,
) -> Option<NodeId> {
    let _ = (parsed, file_index, mod_index);
    if let Some(key) = expr_key_text(val, f.text.as_str()) {
        if let Some(t) = types.and_then(|t| t.get(&key)) {
            let qual = format!("{t}::{fname}");
            return file_qualname(&f.rel, &qual, f).map(|q| (f.rel.clone(), q));
        }
    }
    None
}

/// Full `::` path text of a scoped_identifier (with `use` head
/// expansion).
fn rust_deep_path(node: Node, f: &RsFile) -> String {
    let text = f.text.as_str();
    // Rebuild path text manually (path_text is private in rust_deep).
    fn pt(n: Node, text: &str) -> String {
        match n.kind() {
            "identifier" | "self" | "super" | "crate" => {
                n.utf8_text(text.as_bytes()).unwrap_or("").to_string()
            }
            "scoped_identifier" => {
                let p = n.child_by_field_name("path");
                let nm = n.child_by_field_name("name");
                match (p, nm) {
                    (Some(p), Some(nm)) => {
                        let p = pt(p, text);
                        let nm = nm.utf8_text(text.as_bytes()).unwrap_or("");
                        if p.is_empty() { nm.to_string() } else { format!("{p}::{nm}") }
                    }
                    _ => n.utf8_text(text.as_bytes()).unwrap_or("").to_string(),
                }
            }
            _ => n.utf8_text(text.as_bytes()).unwrap_or("").to_string(),
        }
    }
    let raw = pt(node, text);
    // Expand `use` alias on head segment.
    let head = raw.split("::").next().unwrap_or(&raw);
    if let Some(full) = f.imports.get(head) {
        if raw == head {
            return full.clone();
        }
        let rest = &raw[head.len()..];
        return format!("{full}{rest}");
    }
    raw
}

/// Resolve a `::` path to a project file + qualname via the module
/// suffix index. `crate::`/`self::`/`super::` prefixes are stripped
/// heuristically (crate root unknown - suffix match covers it).
fn resolve_module_path(
    path: &str,
    parsed: &[RsFile],
    _file_index: &HashMap<String, usize>,
    mod_index: &HashMap<String, usize>,
    f: &RsFile,
) -> Option<NodeId> {
    // Strip crate/self/super prefixes for suffix matching.
    let mut p = path;
    for pre in ["crate::", "self::", "super::"] {
        if let Some(rest) = p.strip_prefix(pre) {
            p = rest;
            break;
        }
    }
    // External crates (std/core/alloc or unknown first seg that's
    // not a local module) stay unresolved.
    let first = p.split("::").next().unwrap_or(p);
    if matches!(first, "std" | "core" | "alloc") {
        return None;
    }
    // Try progressively shorter suffixes of the path against the
    // module index: `a::b::func` -> module `a::b` + func `func`,
    // or module `b` + `a::b::func`? The LAST segment is the item;
    // the rest is the module path.
    let segs: Vec<&str> = p.split("::").collect();
    if segs.len() < 2 {
        // Single segment - same-file or external; already handled
        // by identifier arm. Treat as same-file func.
        return local_qualname(f, p).map(|q| (f.rel.clone(), q));
    }
    let item = segs.last().unwrap();
    let mod_path = segs[..segs.len() - 1].join("::");
    // Longest module-path suffix match.
    let mut mp = mod_path.as_str();
    loop {
        if let Some(&fi) = mod_index.get(mp) {
            let tf = parsed.get(fi)?;
            // Item may itself be `Type::method` or plain func.
            if let Some(q) = file_qualname(&tf.rel, item, tf) {
                return Some((tf.rel.clone(), q));
            }
            // Item could be Type::assoc - try whole remaining path
            // as qualname in that file.
            let qual = format!("{}::{}", mp, item);
            if let Some(q) = file_qualname(&tf.rel, &qual, tf) {
                return Some((tf.rel.clone(), q));
            }
        }
        match mp.rsplit_once("::") {
            Some((rest, _)) => mp = rest,
            None => break,
        }
    }
    // Fallback: `use`-imported project path where head is a crate
    // name - try matching item name alone in likely files? Too
    // fuzzy; stay unresolved (honest).
    None
}

/// Best qualname for a short function name in the CURRENT file:
/// prefer non-method, last definition.
fn local_qualname(f: &RsFile, name: &str) -> Option<String> {
    f.funcs.get(name).and_then(|v| {
        v.iter()
            .rev()
            .find(|i| !i.is_method)
            .or_else(|| v.last())
            .map(|i| i.qualname.clone())
    })
}

/// Exact qualname match in a specific file.
fn file_qualname(rel: &str, qual: &str, f: &RsFile) -> Option<String> {
    let _ = rel;
    for infos in f.funcs.values() {
        for info in infos {
            if info.qualname == qual {
                return Some(info.qualname.clone());
            }
        }
    }
    None
}

fn file_has_qualname(rel: &str, qual: &str, f: &RsFile) -> bool {
    file_qualname(rel, qual, f).is_some()
}

/// Apply a resolved callee's summary to this call.
fn apply_summary(
    _node: Node,
    ctx: &mut CtxRs,
    args: &[ExprVal],
    sum: &Summary,
    callee_label: &str,
) {
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
        ..Default::default()
    });
}

/// Unresolvable/unknown callee: taint propagates arg->result
/// conservatively; flag touches_unknown.
fn unknown_call_result(args: &[ExprVal], result: &mut ExprVal, ctx: &mut CtxRs, dotted: &str) {
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
    use crate::models::rust_default;
    use crate::rust_deep::analyze_source;
    use crate::solver::SolveOutput;
    use std::collections::BTreeSet;

    fn run(files: &[(&str, &str)]) -> SolveOutput {
        let parsed: Vec<RsFile> = files
            .iter()
            .filter_map(|(rel, text)| analyze_source(rel, text))
            .collect();
        let _file_set: BTreeSet<String> =
            files.iter().map(|(k, _)| k.to_string()).collect();
        let model = rust_default().unwrap();
        crate::solver_rs::solve_rs(&parsed, &model)
    }

    #[test]
    fn taint_env_to_command_cross_function() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

fn run(cmd: String) {
    Command::new("sh").arg(cmd).spawn();
}

fn main() {
    let name = std::env::var("X").unwrap();
    run(name);
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| {
                f.class == SinkKind::Shell
                    && f.source.contains("Env")
                    && f.via.len() >= 1
            }),
            "expected shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn taint_cross_file_module() {
        let out = run(&[
            (
                "src/main.rs",
                r#"mod util;
use crate::util::helper;

fn main() {
    let x = helper();
    std::process::Command::new("sh").arg(&x).spawn();
}
"#,
            ),
            (
                "src/util.rs",
                r#"pub fn helper() -> String {
    std::env::var("TOKEN").unwrap()
}
"#,
            ),
        ]);
        assert!(
            out.findings.iter().any(|f| {
                f.class == SinkKind::Shell && f.file == "src/main.rs"
            }),
            "expected cross-file shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn unwrap_on_none_finding_unguarded_clean_guarded() {
        let out = run(&[(
            "src/lib.rs",
            r#"fn maybe() -> Option<i32> { None }

fn bad() {
    let x = maybe();
    x.unwrap();
}

fn good() {
    let y = maybe();
    if y.is_some() {
        y.unwrap();
    }
}
"#,
        )]);
        let derefs: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::NullDeref)
            .collect();
        assert_eq!(
            derefs.len(),
            1,
            "expected exactly one NullDeref (unguarded), got {:?}",
            out.findings
        );
        assert!(derefs[0].sink.contains("unwrap"));
    }

    #[test]
    fn sanitizer_parse_stops_taint() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

fn main() {
    let raw = std::env::var("X").unwrap();
    let n: i64 = raw.parse().unwrap();
    Command::new("sh").arg(n.to_string()).spawn();
}
"#,
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::Shell),
            "parse should sanitize, got {:?}",
            out.findings
        );
    }

    #[test]
    fn method_resolution_via_impl_type() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

struct Runner;

impl Runner {
    fn new() -> Runner { Runner }
    fn go(&self, cmd: String) {
        Command::new("sh").arg(cmd).spawn();
    }
}

fn main() {
    let r = Runner::new();
    let x = std::env::var("X").unwrap();
    r.go(x);
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| {
                f.class == SinkKind::Shell && f.source.contains("Env")
            }),
            "expected method shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn per_index_array_tracking() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

fn main() {
    let tainted = std::env::var("X").unwrap();
    let pair = [tainted, String::from("clean")];
    Command::new("sh").arg(&pair[0]).spawn();
    Command::new("sh").arg(&pair[1]).spawn();
}
"#,
        )]);
        let shells: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Shell)
            .collect();
        assert_eq!(
            shells.len(),
            1,
            "expected exactly one shell finding (pair[0] only), got {:?}",
            out.findings
        );
        assert_eq!(shells[0].line, 6);
    }

    #[test]
    fn struct_field_per_key_tracking() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

struct Pair { a: String, b: String }

fn main() {
    let tainted = std::env::var("X").unwrap();
    let p = Pair { a: tainted, b: String::from("clean") };
    Command::new("sh").arg(&p.a).spawn();
    Command::new("sh").arg(&p.b).spawn();
}
"#,
        )]);
        let shells: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Shell)
            .collect();
        assert_eq!(
            shells.len(),
            1,
            "expected exactly one shell finding (p.a only), got {:?}",
            out.findings
        );
        assert_eq!(shells[0].line, 8);
    }

    #[test]
    fn format_macro_propagates_taint() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

fn main() {
    let x = std::env::var("X").unwrap();
    let msg = format!("run {}", x);
    Command::new("sh").arg(msg).spawn();
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell),
            "format! should propagate taint, got {:?}",
            out.findings
        );
    }

    #[test]
    fn include_str_is_file_source() {
        let out = run(&[(
            "src/main.rs",
            r#"use std::process::Command;

fn main() {
    let data = include_str!("secret.txt");
    Command::new("sh").arg(data).spawn();
}
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| {
                f.class == SinkKind::Shell && f.source.contains("File")
            }),
            "include_str! should be a file source, got {:?}",
            out.findings
        );
    }
}
