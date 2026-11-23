//! Interprocedural analysis for JS/TS dynamic `import(expr)` and
//! `require(expr)` - the ECMAScript mirror of `ipa.rs`.
//!
//! Same honesty contract: inferred edges are `EdgeKind::Heuristic`,
//! unresolved sites are reported, never guessed. Module identity is
//! the project-relative file path, so candidates resolve straight
//! into the scanned file set (no dotted-module layer needed).
//!
//! v1 scope: single-parameter specifiers, literal/const call-site
//! arguments, positional params only (no destructured signatures),
//! CommonJS `require` + ES `import` bindings, relative and
//! root-relative specifiers (bare package specifiers stay external).

use std::collections::{BTreeSet, HashMap};

use strand_core::EdgeKind;
use rayon::prelude::*;
use tree_sitter::{Node, Tree};

use crate::deep::ipa::{FuncInfo, IpaOutput};

const MAX_CALL_SITES: usize = 64;
const MAX_STRINGS: usize = 64;

/// One JS/TS file's parsed view.
pub(crate) struct JsFile {
    /// Project-root-relative path (`/`-separated).
    pub(crate) rel: String,
    pub(crate) tree: Tree,
    pub(crate) text: String,
    /// Local name -> (module spec, member). `member=None` means the
    /// local name is the whole module (`import * as ns`,
    /// `const m = require('x')`); `member=Some(f)` is a named import,
    /// destructured require member, or the `"default"` export.
    /// Specs stay unresolved here; `call_targets` maps them through
    /// the scanned file set.
    pub(crate) bindings: HashMap<String, (String, Option<String>)>,
    /// `const NAME = "literal"` style constants.
    pub(crate) consts: HashMap<String, String>,
    /// Function short name -> info (declarations, arrows/functions
    /// bound by declarator, methods).
    pub(crate) funcs: HashMap<String, Vec<FuncInfo>>,
}

fn parse_js(text: &str, rel: &str) -> Option<Tree> {
    thread_local! {
        static PARSERS: std::cell::RefCell<
            Vec<(tree_sitter::Language, tree_sitter::Parser)>,
        > = std::cell::RefCell::new(Vec::new());
    }
    let lang = strand_import::scan::js_language_for(rel);
    PARSERS.with(|cell| {
        let mut parsers = cell.borrow_mut();
        let idx = parsers.iter().position(|(l, _)| *l == lang);
        let p = match idx {
            Some(i) => &mut parsers[i].1,
            None => {
                let mut p = tree_sitter::Parser::new();
                p.set_language(&lang).ok()?;
                parsers.push((lang, p));
                &mut parsers.last_mut().unwrap().1
            }
        };
        p.parse(text, None)
    })
}

/// All `call_expression` nodes via a tree-sitter query compiled for
/// the file's own grammar (JS vs TS vs TSX node ids differ).
pub(crate) fn call_nodes<'a>(f: &'a JsFile) -> Vec<Node<'a>> {
    use tree_sitter::StreamingIterator;
    let q = call_query(f);
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut out = Vec::new();
    let mut matches = cursor.matches(q, f.tree.root_node(), f.text.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures() {
            out.push(cap.node);
        }
    }
    out
}

fn call_query(f: &JsFile) -> &'static tree_sitter::Query {
    use std::sync::OnceLock;
    static JS_Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    static TS_Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    static TSX_Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    let lower = f.rel.to_lowercase();
    if lower.ends_with(".tsx") {
        TSX_Q.get_or_init(|| {
            tree_sitter::Query::new(
                &tree_sitter_typescript::LANGUAGE_TSX.into(),
                "(call_expression) @call",
            )
            .expect("tsx call query")
        })
    } else if lower.ends_with(".ts") || lower.ends_with(".mts") || lower.ends_with(".cts") {
        TS_Q.get_or_init(|| {
            tree_sitter::Query::new(
                &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                "(call_expression) @call",
            )
            .expect("ts call query")
        })
    } else {
        JS_Q.get_or_init(|| {
            tree_sitter::Query::new(
                &tree_sitter_javascript::LANGUAGE.into(),
                "(call_expression) @call",
            )
            .expect("js call query")
        })
    }
}

fn analyze_file_tree(rel: &str, text: String, tree: Tree) -> JsFile {
    let (mut bindings, mut consts, mut funcs) =
        (HashMap::new(), HashMap::new(), HashMap::new());
    collect_facts(tree.root_node(), &text, &mut bindings, &mut consts, &mut funcs, rel);
    JsFile {
        rel: rel.to_string(),
        tree,
        text,
        bindings,
        consts,
        funcs,
    }
}

/// Build a `JsFile` from source text (parses internally).
pub(crate) fn analyze_source(rel: &str, text: &str) -> Option<JsFile> {
    let tree = parse_js(text, rel)?;
    Some(analyze_file_tree(rel, text.to_string(), tree))
}

/// Build `JsFile`s from `(rel, abs)` paths in parallel.
pub(crate) fn analyze_files(
    files: &[(String, std::path::PathBuf)],
) -> Vec<(String, Option<JsFile>)> {
    files
        .par_iter()
        .map(|(rel, abs)| {
            let text = std::fs::read(abs)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            (rel.clone(), analyze_source(rel, &text))
        })
        .collect()
}

fn collect_facts(
    root: Node,
    text: &str,
    bindings: &mut HashMap<String, (String, Option<String>)>,
    consts: &mut HashMap<String, String>,
    funcs: &mut HashMap<String, Vec<FuncInfo>>,
    rel: &str,
) {
    let query = facts_query_rel(rel);
    let mut qcursor = tree_sitter::QueryCursor::new();
    let mut matches = qcursor.matches(query, root, text.as_bytes());
    use tree_sitter::StreamingIterator as _;
    let mut nodes: Vec<Node> = Vec::new();
    while let Some(m) = matches.next() {
        for cap in m.captures() {
            nodes.push(cap.node);
        }
    }
    for node in nodes {
        match node.kind() {
            "import_statement" => collect_import(node, text, bindings),
            "variable_declarator" => collect_declarator(node, text, bindings, consts, funcs),
            "function_declaration" => collect_func_decl(node, text, funcs),
            "method_definition" => collect_method(node, text, funcs),
            "arrow_function" | "function_expression" => {
                // Named only via an enclosing declarator/pair - handled
                // there; skip standalone expressions for v1.
            }
            _ => {}
        }
    }
}

fn facts_query_rel(rel: &str) -> &'static tree_sitter::Query {
    use std::sync::OnceLock;
    static JS_Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    static TS_Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    static TSX_Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    const SRC: &str = "(import_statement) @n (variable_declarator) @n (function_declaration) @n (method_definition) @n";
    let lower = rel.to_lowercase();
    let init = |lang: tree_sitter::Language| {
        tree_sitter::Query::new(&lang, SRC).expect("js facts query")
    };
    if lower.ends_with(".tsx") {
        TSX_Q.get_or_init(|| init(tree_sitter_typescript::LANGUAGE_TSX.into()))
    } else if lower.ends_with(".ts") || lower.ends_with(".mts") || lower.ends_with(".cts") {
        TS_Q.get_or_init(|| init(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()))
    } else {
        JS_Q.get_or_init(|| init(tree_sitter_javascript::LANGUAGE.into()))
    }
}

pub(crate) fn spec_string(node: Node, text: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = node.utf8_text(text.as_bytes()).ok()?;
    let inner = raw
        .strip_prefix('"')
        .or_else(|| raw.strip_prefix('\''))
        .and_then(|s| {
            s.strip_suffix('"')
                .or_else(|| s.strip_suffix('\''))
        })?;
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

fn collect_import(
    node: Node,
    text: &str,
    bindings: &mut HashMap<String, (String, Option<String>)>,
) {
    let Some(src) = node
        .child_by_field_name("source")
        .and_then(|s| spec_string(s, text))
    else {
        return;
    };
    // import_clause children: identifier (default), namespace_import,
    // named_imports > import_specifier.
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "import_clause" => {
                let mut c = n.walk();
                for ch in n.children(&mut c) {
                    match ch.kind() {
                        "identifier" => {
                            // Default import: `import def from 'm'`.
                            if let Ok(t) = ch.utf8_text(text.as_bytes()) {
                                bindings.insert(
                                    t.to_string(),
                                    (src.clone(), Some("default".to_string())),
                                );
                            }
                        }
                        "namespace_import" => {
                            // `import * as ns` - whole module.
                            if let Some(id) = ch
                                .children(&mut ch.walk())
                                .find(|k| k.kind() == "identifier")
                            {
                                if let Ok(t) = id.utf8_text(text.as_bytes()) {
                                    bindings
                                        .insert(t.to_string(), (src.clone(), None));
                                }
                            }
                        }
                        "named_imports" => {
                            let mut nc = ch.walk();
                            for spec in ch.children(&mut nc) {
                                if spec.kind() != "import_specifier" {
                                    continue;
                                }
                                let imported = spec
                                    .child_by_field_name("name")
                                    .map(|nm| match nm.kind() {
                                        "identifier" => nm
                                            .utf8_text(text.as_bytes())
                                            .unwrap_or("")
                                            .to_string(),
                                        "string" => spec_string(nm, text)
                                            .unwrap_or_default(),
                                        _ => "default".to_string(),
                                    })
                                    .unwrap_or_default();
                                let local = spec
                                    .child_by_field_name("alias")
                                    .or_else(|| spec.child_by_field_name("name"))
                                    .and_then(|a| a.utf8_text(text.as_bytes()).ok())
                                    .map(str::to_string)
                                    .unwrap_or_default();
                                if !local.is_empty() && !imported.is_empty() {
                                    bindings.insert(
                                        local,
                                        (src.clone(), Some(imported)),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                let mut c = n.walk();
                stack.extend(n.children(&mut c));
            }
        }
    }
}

pub(crate) fn is_require_call(node: Node, text: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if func.kind() != "identifier" || func.utf8_text(text.as_bytes()).ok()? != "require" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut c = args.walk();
    let first = args
        .children(&mut c)
        .find(|ch| ch.is_named())?;
    spec_string(first, text)
}

fn collect_declarator(
    node: Node,
    text: &str,
    bindings: &mut HashMap<String, (String, Option<String>)>,
    consts: &mut HashMap<String, String>,
    funcs: &mut HashMap<String, Vec<FuncInfo>>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };

    // `const {a, b: c} = require('m')` - destructured members.
    if name.kind() == "object_pattern" {
        if let Some(spec) = is_require_call(value, text) {
            bind_object_pattern(name, &spec, text, bindings);
        }
        return;
    }
    if name.kind() != "identifier" {
        return;
    }
    let Ok(local) = name.utf8_text(text.as_bytes()) else {
        return;
    };
    let local = local.to_string();

    // `const x = require('m')` -> whole-module binding.
    if let Some(spec) = is_require_call(value, text) {
        bindings.insert(local.clone(), (spec, None));
        return;
    }
    // `const x = require('m').member` -> member binding.
    if value.kind() == "member_expression" {
        if let Some(obj) = value.child_by_field_name("object") {
            if let Some(spec) = is_require_call(obj, text) {
                if let Some(prop) = value.child_by_field_name("property") {
                    if let Ok(p) = prop.utf8_text(text.as_bytes()) {
                        bindings.insert(local.clone(), (spec, Some(p.to_string())));
                        return;
                    }
                }
            }
        }
    }
    // `const NAME = "lit"`.
    if let Some(s) = spec_string(value, text) {
        consts.insert(local.clone(), s);
        return;
    }
    // `const f = (a, b) => ...` / `const f = function(a,b) {...}`.
    if matches!(value.kind(), "arrow_function" | "function_expression") {
        let params = fn_params(value, text);
        let entry = FuncInfo {
            params,
            start: value.start_byte(),
            end: value.end_byte(),
            qualname: local.clone(),
            is_method: false,
            is_stub: false,
        };
        funcs.entry(local).or_default().push(entry);
    }
}

fn bind_object_pattern(
    pat: Node,
    spec: &str,
    text: &str,
    bindings: &mut HashMap<String, (String, Option<String>)>,
) {
    let mut c = pat.walk();
    for ch in pat.children(&mut c) {
        match ch.kind() {
            // `{a}` -> a is member "a".
            "shorthand_property_identifier_pattern" => {
                if let Ok(t) = ch.utf8_text(text.as_bytes()) {
                    bindings.insert(t.to_string(), (spec.to_string(), Some(t.to_string())));
                }
            }
            // `{key: local}` / `{key: local = def}` - member is the key.
            "pair_pattern" => {
                let key = ch.child_by_field_name("key");
                let val = ch.child_by_field_name("value");
                let (Some(k), Some(v)) = (key, val) else { continue };
                let member = match k.kind() {
                    "property_identifier" | "identifier" => {
                        k.utf8_text(text.as_bytes()).unwrap_or("").to_string()
                    }
                    "string" => spec_string(k, text).unwrap_or_default(),
                    _ => String::new(),
                };
                // value may be assignment_pattern wrapping identifier.
                let local_node = if v.kind() == "assignment_pattern" {
                    v.children(&mut v.walk())
                        .find(|x| x.kind() == "identifier")
                } else {
                    Some(v)
                };
                if let Some(ln) = local_node {
                    if ln.kind() == "identifier" {
                        if let (Ok(l), true) = (
                            ln.utf8_text(text.as_bytes()),
                            !member.is_empty(),
                        ) {
                            bindings.insert(
                                l.to_string(),
                                (spec.to_string(), Some(member)),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Params of a function-ish node: identifiers plus the first
/// identifier inside TS `required_parameter`/`optional_parameter`.
pub(crate) fn fn_params(node: Node, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pn) = node.child_by_field_name("parameters") else {
        return out;
    };
    let mut c = pn.walk();
    for p in pn.children(&mut c) {
        match p.kind() {
            "identifier" => {
                if let Ok(t) = p.utf8_text(text.as_bytes()) {
                    out.push(t.to_string());
                }
            }
            "required_parameter" | "optional_parameter" | "assignment_pattern" => {
                let mut sc = p.walk();
                for d in p.children(&mut sc) {
                    if d.kind() == "identifier" {
                        if let Ok(t) = d.utf8_text(text.as_bytes()) {
                            out.push(t.to_string());
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn collect_func_decl(node: Node, text: &str, funcs: &mut HashMap<String, Vec<FuncInfo>>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Ok(name) = name_node.utf8_text(text.as_bytes()) else {
        return;
    };
    let params = fn_params(node, text);
    // Qualified name via enclosing class for methods-as-declarations
    // is rare in JS; function_declaration is always top-level or
    // nested - qualname = name for v1.
    funcs.entry(name.to_string()).or_default().push(FuncInfo {
        params,
        start: node.start_byte(),
        end: node.end_byte(),
        qualname: name.to_string(),
        is_method: false,
        is_stub: false,
    });
}

fn collect_method(node: Node, text: &str, funcs: &mut HashMap<String, Vec<FuncInfo>>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Ok(name) = name_node.utf8_text(text.as_bytes()) else {
        return;
    };
    // Enclosing class name for qualname.
    let mut class_name = String::new();
    let mut anc = node.parent();
    while let Some(a) = anc {
        if a.kind() == "class_declaration" || a.kind() == "class" {
            if let Some(cn) = a
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(text.as_bytes()).ok())
            {
                class_name = cn.to_string();
            }
            break;
        }
        anc = a.parent();
    }
    let params = fn_params(node, text);
    let qualname = if class_name.is_empty() {
        name.to_string()
    } else {
        format!("{class_name}.{name}")
    };
    funcs.entry(name.to_string()).or_default().push(FuncInfo {
        params,
        start: node.start_byte(),
        end: node.end_byte(),
        qualname,
        is_method: true,
        is_stub: false,
    });
}

// ---------- specifier template evaluation ----------

enum Part {
    Lit(String),
    /// Identifier that is NOT a module const - could be a parameter.
    Name(String),
}

fn string_content(node: Node, text: &str) -> Option<String> {
    spec_string(node, text)
}

/// Ordered literal/name parts of an expression: strings, const
/// identifiers, `+` concatenation, and all-literal template strings.
fn expr_parts(node: Node, text: &str, f: &JsFile, depth: usize) -> Option<Vec<Part>> {
    if depth > 8 {
        return None;
    }
    if let Some(s) = string_content(node, text) {
        return Some(vec![Part::Lit(s)]);
    }
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            if let Some(v) = f.consts.get(name) {
                return Some(vec![Part::Lit(v.clone())]);
            }
            Some(vec![Part::Name(name.to_string())])
        }
        "binary_expression" | "concatenation" => {
            // tree-sitter-javascript uses binary_expression with
            // operator "+".
            let is_plus = node
                .children(&mut node.walk())
                .any(|c| c.kind() == "+");
            if !is_plus {
                return None;
            }
            let l = node.child_by_field_name("left")?;
            let r = node.child_by_field_name("right")?;
            let mut out = expr_parts(l, text, f, depth + 1)?;
            out.extend(expr_parts(r, text, f, depth + 1)?);
            Some(out)
        }
        "template_string" => template_parts(node, text, f, depth),
        "parenthesized_expression" => {
            let inner = node
                .children(&mut node.walk())
                .find(|c| c.is_named())?;
            expr_parts(inner, text, f, depth + 1)
        }
        _ => None,
    }
}

/// Template string -> parts; every substitution must itself reduce
/// to Lit or a single Name (mixed templates stay unresolved).
fn template_parts(node: Node, text: &str, f: &JsFile, depth: usize) -> Option<Vec<Part>> {
    let mut out = Vec::new();
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        match ch.kind() {
            "string_fragment" => {
                if let Ok(t) = ch.utf8_text(text.as_bytes()) {
                    out.push(Part::Lit(t.to_string()));
                }
            }
            "template_substitution" => {
                let inner = ch
                    .children(&mut ch.walk())
                    .find(|x| x.is_named())?;
                let parts = expr_parts(inner, text, f, depth + 1)?;
                out.extend(parts);
            }
            _ => {}
        }
    }
    Some(out)
}

/// Evaluate an expression to a set of constant strings.
fn eval_strset(node: Node, text: &str, f: &JsFile, depth: usize) -> Option<BTreeSet<String>> {
    if depth > 8 {
        return None;
    }
    if let Some(s) = string_content(node, text) {
        return Some(BTreeSet::from([s]));
    }
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            f.consts.get(name).map(|s| BTreeSet::from([s.clone()]))
        }
        "binary_expression" => {
            let is_plus = node
                .children(&mut node.walk())
                .any(|c| c.kind() == "+");
            if !is_plus {
                return None;
            }
            let l = node.child_by_field_name("left")?;
            let r = node.child_by_field_name("right")?;
            let lv = eval_strset(l, text, f, depth + 1)?;
            let rv = eval_strset(r, text, f, depth + 1)?;
            let mut out = BTreeSet::new();
            for a in &lv {
                for b in &rv {
                    out.insert(format!("{a}{b}"));
                    if out.len() > MAX_STRINGS {
                        return None;
                    }
                }
            }
            Some(out)
        }
        "template_string" => {
            let mut acc = String::new();
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                match ch.kind() {
                    "string_fragment" => {
                        acc.push_str(ch.utf8_text(text.as_bytes()).ok()?);
                    }
                    "template_substitution" => {
                        let inner = ch
                            .children(&mut ch.walk())
                            .find(|x| x.is_named())?;
                        let vals = eval_strset(inner, text, f, depth + 1)?;
                        if vals.len() != 1 {
                            return None;
                        }
                        acc.push_str(vals.iter().next()?);
                    }
                    _ => {}
                }
            }
            Some(BTreeSet::from([acc]))
        }
        "parenthesized_expression" => {
            let inner = node
                .children(&mut node.walk())
                .find(|c| c.is_named())?;
            eval_strset(inner, text, f, depth + 1)
        }
        _ => None,
    }
}

/// `lit* + param + lit*` with exactly one non-const identifier that
/// is a parameter of the enclosing function.
fn specifier_template(
    arg: Node,
    text: &str,
    f: &JsFile,
    params: &[String],
) -> Option<(String, String, String)> {
    let parts = expr_parts(arg, text, f, 0)?;
    let names: Vec<&Part> = parts
        .iter()
        .filter(|p| matches!(p, Part::Name(_)))
        .collect();
    if names.len() != 1 {
        return None;
    }
    let Part::Name(pname) = names[0] else {
        return None;
    };
    if !params.iter().any(|p| p == pname) {
        return None;
    }
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut seen_name = false;
    for p in &parts {
        match p {
            Part::Lit(s) => {
                if seen_name {
                    suffix.push_str(s);
                } else {
                    prefix.push_str(s);
                }
            }
            Part::Name(_) => seen_name = true,
        }
    }
    Some((pname.clone(), prefix, suffix))
}

// ---------- dyn sites ----------

struct DynSite {
    file_rel: String,
    /// Module key = the file's own rel path.
    module: String,
    func: String,
    param: String,
    prefix: String,
    suffix: String,
}

fn is_dyn_call(call: Node, text: &str) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    // `import(expr)`: function is the anonymous `import` keyword.
    if func.kind() == "import" {
        return true;
    }
    // `require(expr)`.
    func.kind() == "identifier"
        && func.utf8_text(text.as_bytes()).is_ok_and(|t| t == "require")
}

fn first_arg(call: Node) -> Option<Node> {
    let args = call.child_by_field_name("arguments")?;
    let mut c = args.walk();
    let found = args.children(&mut c).find(|ch| ch.is_named());
    found
}

/// Enclosing function of a node -> (name, info). JS functions get
/// names from declarations, declarator-bound arrows/functions, and
/// method definitions; anonymous/nested expressions are skipped.
pub(crate) fn enclosing_func<'t>(node: Node<'t>, f: &'t JsFile) -> Option<(String, FuncInfo)> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        match n.kind() {
            "function_declaration" | "method_definition" => {
                let name = n
                    .child_by_field_name("name")
                    .and_then(|x| x.utf8_text(f.text.as_bytes()).ok())?
                    .to_string();
                return f
                    .funcs
                    .get(&name)
                    .and_then(|v| {
                        v.iter()
                            .rev()
                            .find(|i| {
                                i.start <= n.start_byte() && n.end_byte() <= i.end
                            })
                            .or_else(|| v.last())
                            .cloned()
                    })
                    .map(|info| (name, info));
            }
            "arrow_function" | "function_expression" => {
                // Name comes from an enclosing variable_declarator or
                // pair; walk up to find it.
                let mut up = n.parent();
                while let Some(u) = up {
                    match u.kind() {
                        "variable_declarator" => {
                            if let Some(nm) = u.child_by_field_name("name") {
                                if nm.kind() == "identifier" {
                                    if let Ok(name) =
                                        nm.utf8_text(f.text.as_bytes())
                                    {
                                        let name = name.to_string();
                                        return f
                                            .funcs
                                            .get(&name)
                                            .and_then(|v| v.last().cloned())
                                            .map(|info| (name, info));
                                    }
                                }
                            }
                            return None;
                        }
                        "pair" => {
                            if let Some(k) = u.child_by_field_name("key") {
                                if let Ok(name) =
                                    k.utf8_text(f.text.as_bytes())
                                {
                                    return f
                                        .funcs
                                        .get(name)
                                        .and_then(|v| v.last().cloned())
                                        .map(|i| (name.to_string(), i));
                                }
                            }
                            return None;
                        }
                        "function_declaration" | "method_definition"
                        | "statement_block" | "program" => break,
                        _ => up = u.parent(),
                    }
                }
                return None;
            }
            _ => {}
        }
        anc = n.parent();
    }
    None
}

fn dyn_sites(f: &JsFile) -> Vec<DynSite> {
    // `import(`/`require(` must appear literally for a site to exist.
    if !f.text.contains("import(") && !f.text.contains("require(") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for node in call_nodes(f) {
        if !is_dyn_call(node, &f.text) {
            continue;
        }
        let Some(arg) = first_arg(node) else {
            continue;
        };
        if arg.kind() == "string" {
            continue;
        }
        let Some((func, info)) = enclosing_func(node, f) else {
            continue;
        };
        if let Some((param, prefix, suffix)) =
            specifier_template(arg, &f.text, f, &info.params)
        {
            out.push(DynSite {
                file_rel: f.rel.clone(),
                module: f.rel.clone(),
                func,
                param,
                prefix,
                suffix,
            });
        }
    }
    out
}

// ---------- call index ----------

/// Resolve a module spec to a project file rel path, or `None` for
/// bare/external specs. Mirrors strand-import's JS resolution:
/// `./`,`../` resolve against the importer's dir; other path-like
/// specs try project-root relative.
pub(crate) fn resolve_spec(importer_rel: &str, spec: &str, names: &BTreeSet<String>) -> Option<String> {
    use strand_import::scan::{normalize_rel, resolve_js};
    let parent = importer_rel
        .rsplit_once('/')
        .map(|(d, _)| d)
        .unwrap_or("");
    if spec.starts_with('.') {
        let norm = normalize_rel(parent, spec)?;
        return resolve_js(names, &norm);
    }
    // Path-like non-relative spec: try root-relative.
    if spec.contains('/') || spec.ends_with(".json") {
        return resolve_js(names, spec);
    }
    None
}

/// (module_rel, func) candidates a call's callee may invoke.
pub(crate) fn call_targets(
    func_node: Node,
    rbind: &HashMap<String, (String, Option<String>)>,
    f: &JsFile,
    names: &BTreeSet<String>,
) -> Vec<(String, String)> {
    match func_node.kind() {
        "identifier" => {
            let Ok(name) = func_node.utf8_text(f.text.as_bytes()) else {
                return Vec::new();
            };
            match rbind.get(name) {
                // `import {f} from 'm'` / `const {f} = require('m')`
                // -> f(...) invokes m.f.
                Some((spec, Some(member))) => resolve_spec(&f.rel, spec, names)
                    .map(|m| vec![(m, member.clone())])
                    .unwrap_or_default(),
                _ => Vec::new(),
            }
        }
        "member_expression" => {
            let Some(prop) = func_node.child_by_field_name("property") else {
                return Vec::new();
            };
            let Some(obj) = func_node.child_by_field_name("object") else {
                return Vec::new();
            };
            let Ok(fname) = prop.utf8_text(f.text.as_bytes()) else {
                return Vec::new();
            };
            object_module(obj, rbind, f, names)
                .map(|m| vec![(m, fname.to_string())])
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Module file a member-expression object refers to.
pub(crate) fn object_module(
    obj: Node,
    rbind: &HashMap<String, (String, Option<String>)>,
    f: &JsFile,
    names: &BTreeSet<String>,
) -> Option<String> {
    match obj.kind() {
        "identifier" => {
            let name = obj.utf8_text(f.text.as_bytes()).ok()?;
            match rbind.get(name) {
                // `const m = require('x')` / `import * as m` -> m IS x.
                Some((spec, None)) => resolve_spec(&f.rel, spec, names),
                // `import {u} from 'x'` -> u is an export object;
                // its module is still x's file.
                Some((spec, Some(_))) => resolve_spec(&f.rel, spec, names),
                None => None,
            }
        }
        "member_expression" => {
            // Dotted chain a.b.c - resolve the head, keep the tail as
            // part of the module path is meaningless for file modules;
            // the file is what matters, so resolve the root object.
            let inner = obj.child_by_field_name("object")?;
            object_module(inner, rbind, f, names)
        }
        "this" => None,
        _ => None,
    }
}

struct CallRec {
    file: usize,
    start: usize,
    end: usize,
}

/// Positional argument for `param` (JS has no keyword args; destructured
/// params aren't collected so `position` misses -> unresolved, honest).
fn callsite_param_arg<'t>(
    call: Node<'t>,
    _caller: &JsFile,
    func_params: &[String],
    param: &str,
) -> Option<Node<'t>> {
    let idx = func_params.iter().position(|p| p == param)?;
    let args = call.child_by_field_name("arguments")?;
    let mut positional: Vec<Node> = Vec::new();
    let mut c = args.walk();
    for ch in args.children(&mut c) {
        if ch.is_named() {
            positional.push(ch);
        }
    }
    positional.get(idx).copied()
}

// ---------- driver ----------

/// Analyze pre-parsed JS files. `file_set` = known project rel paths.
pub fn analyze_js_parsed(parsed: &[JsFile], file_set: &BTreeSet<String>) -> IpaOutput {
    let prof = std::env::var("STRAND_PROFILE").is_ok();
    let t_all = std::time::Instant::now();

    let sites: Vec<DynSite> = parsed.par_iter().flat_map_iter(dyn_sites).collect();
    if prof {
        eprintln!("js ipa dyn_sites: {:?} ({} sites)", t_all.elapsed(), sites.len());
    }

    let needed: std::collections::HashSet<&str> =
        sites.iter().map(|s| s.func.as_str()).collect();
    let per_file: Vec<Vec<((String, String), usize, usize)>> = if needed.is_empty() {
        Vec::new()
    } else {
        parsed
            .par_iter()
            .enumerate()
            .map(|(fi, f)| {
                // A call can only target a needed function if the name
                // literally appears in this file's text (identifier,
                // property, or import source).
                let file_needed: Vec<&str> = needed
                    .iter()
                    .copied()
                    .filter(|n| f.text.contains(*n))
                    .collect();
                if file_needed.is_empty() {
                    return Vec::new();
                }
                let mut rbind: HashMap<String, (String, Option<String>)> =
                    HashMap::new();
                for (local, (spec, member)) in &f.bindings {
                    rbind.insert(local.clone(), (spec.clone(), member.clone()));
                }
                let mut out = Vec::new();
                for node in call_nodes(f) {
                    let Some(func_node) = node.child_by_field_name("function") else {
                        continue;
                    };
                    let keep = match func_node.kind() {
                        "identifier" => func_node
                            .utf8_text(f.text.as_bytes())
                            .ok()
                            .and_then(|n| rbind.get(n))
                            .and_then(|(_, mem)| mem.as_ref())
                            .is_some_and(|mem| file_needed.contains(&mem.as_str())),
                        "member_expression" => func_node
                            .child_by_field_name("property")
                            .and_then(|a| a.utf8_text(f.text.as_bytes()).ok())
                            .is_some_and(|a| file_needed.contains(&a)),
                        _ => false,
                    };
                    if !keep {
                        continue;
                    }
                    for target in call_targets(func_node, &rbind, f, file_set) {
                        out.push((target, node.start_byte(), node.end_byte()));
                    }
                }
                let _ = fi;
                out
            })
            .collect()
    };
    if prof {
        eprintln!("js ipa call_index: {:?}", t_all.elapsed());
    }
    let mut calls: Vec<CallRec> = Vec::new();
    let mut index: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (fi, recs) in per_file.into_iter().enumerate() {
        for (target, start, end) in recs {
            let ci = calls.len();
            calls.push(CallRec { file: fi, start, end });
            index.entry(target).or_default().push(ci);
        }
    }

    let mut edges: Vec<(String, String, EdgeKind)> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    let mut resolved = 0usize;
    let mut seen_edges: BTreeSet<(String, String)> = BTreeSet::new();

    for site in &sites {
        let site_file = parsed
            .iter()
            .find(|f| f.rel == site.file_rel)
            .expect("site file was parsed");
        let Some(func_params) = site_file
            .funcs
            .get(&site.func)
            .and_then(|v| {
                v.iter()
                    .rev()
                    .find(|i| !i.is_stub)
                    .or_else(|| v.last())
            })
            .map(|i| &i.params)
        else {
            unresolved.push(format!("{}:{} (no signature)", site.file_rel, site.func));
            continue;
        };

        let key = (site.module.clone(), site.func.clone());
        let Some(rec_ids) = index.get(&key) else {
            unresolved.push(format!("{}:{} (no call sites)", site.file_rel, site.func));
            continue;
        };

        let mut candidates: BTreeSet<String> = BTreeSet::new();
        let mut n_calls = 0usize;
        let mut call_failed = false;

        for &ci in rec_ids {
            n_calls += 1;
            if n_calls > MAX_CALL_SITES {
                call_failed = true;
                break;
            }
            let rec = &calls[ci];
            let caller = &parsed[rec.file];
            let Some(call_node) = caller
                .tree
                .root_node()
                .descendant_for_byte_range(rec.start, rec.end)
            else {
                continue;
            };
            if call_node.kind() != "call_expression" {
                continue;
            }
            match callsite_param_arg(call_node, caller, func_params, &site.param) {
                Some(arg_node) => match eval_strset(arg_node, &caller.text, caller, 0) {
                    Some(vals) => {
                        for v in vals {
                            candidates.insert(format!(
                                "{}{}{}",
                                site.prefix, v, site.suffix
                            ));
                            if candidates.len() > MAX_STRINGS {
                                call_failed = true;
                                break;
                            }
                        }
                    }
                    None => call_failed = true,
                },
                None => call_failed = true,
            }
            if call_failed {
                break;
            }
        }

        if candidates.is_empty() {
            unresolved.push(format!(
                "{}:{} ({})",
                site.file_rel,
                site.func,
                if call_failed { "unresolved call sites" } else { "no call sites" }
            ));
            continue;
        }

        let mut any = false;
        for cand in candidates {
            if let Some(dst) = resolve_candidate(&site.file_rel, &cand, file_set) {
                if dst != site.file_rel
                    && seen_edges.insert((site.file_rel.clone(), dst.clone()))
                {
                    edges.push((site.file_rel.clone(), dst, EdgeKind::Heuristic));
                    any = true;
                }
            }
        }
        if any {
            resolved += 1;
        } else {
            unresolved.push(format!("{}:{} (no matching module)", site.file_rel, site.func));
        }
    }

    if prof {
        eprintln!("js ipa sites_resolve: {:?}", t_all.elapsed());
    }
    IpaOutput {
        edges,
        unresolved,
        resolved,
    }
}

/// Candidate specifier -> project file, relative to the site file.
fn resolve_candidate(site_rel: &str, cand: &str, names: &BTreeSet<String>) -> Option<String> {
    resolve_spec(site_rel, cand, names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn analyze(pairs: &[(&str, &str)]) -> (IpaOutput, BTreeSet<String>) {
        let file_set: BTreeSet<String> = pairs.iter().map(|(k, _)| k.to_string()).collect();
        let parsed: Vec<JsFile> = pairs
            .iter()
            .filter_map(|(rel, text)| analyze_source(rel, text))
            .collect();
        let out = analyze_js_parsed(&parsed, &file_set);
        (out, file_set)
    }

    #[test]
    fn cjs_require_positional() {
        let (out, _) = analyze(&[
            ("loader.js", "const {import_module} = require('importlib');\nfunction load(name){\n  return require('./plugins/' + name);\n}\n"),
            ("app.js", "const {load} = require('./loader');\nload('ldap');\nload('sql');\n"),
            ("plugins/ldap.js", ""),
            ("plugins/sql.js", ""),
        ]);
        assert_eq!(out.edges.len(), 2, "edges: {:?} unres: {:?}", out.edges, out.unresolved);
        assert!(out.edges.iter().all(|(_, _, k)| *k == EdgeKind::Heuristic));
    }

    #[test]
    fn es_dynamic_import_template() {
        let (out, _) = analyze(&[
            ("loader.js", "export function load(name){\n  return import(`./plugins/${name}.js`);\n}\n"),
            ("app.js", "import {load} from './loader.js';\nload('ldap');\n"),
            ("plugins/ldap.js", ""),
        ]);
        assert_eq!(out.edges.len(), 1, "edges: {:?} unres: {:?}", out.edges, out.unresolved);
        assert_eq!(out.edges[0].1, "plugins/ldap.js");
    }

    #[test]
    fn namespace_member_call() {
        let (out, _) = analyze(&[
            ("loader.js", "export function load(name){\n  return import('./plugins/' + name);\n}\n"),
            ("app.js", "import * as l from './loader.js';\nl.load('ldap');\n"),
            ("plugins/ldap.js", ""),
        ]);
        assert_eq!(out.edges.len(), 1, "edges: {:?} unres: {:?}", out.edges, out.unresolved);
    }

    #[test]
    fn ts_file_and_arrow() {
        let (out, _) = analyze(&[
            ("src/loader.ts", "export const load = (name: string) => import('./plugins/' + name);\n"),
            ("src/app.ts", "import {load} from './loader';\nload('ldap');\n"),
            ("src/plugins/ldap.ts", ""),
        ]);
        assert_eq!(out.edges.len(), 1, "edges: {:?} unres: {:?}", out.edges, out.unresolved);
        assert_eq!(out.edges[0].1, "src/plugins/ldap.ts");
    }

    #[test]
    fn unresolved_variable_callsite() {
        let (out, _) = analyze(&[
            ("loader.js", "function load(name){\n  return require('./plugins/' + name);\n}\nmodule.exports = {load};\n"),
            ("app.js", "const {load} = require('./loader');\nconst x = getName();\nload(x);\n"),
            ("plugins/ldap.js", ""),
        ]);
        assert!(out.edges.is_empty());
        assert_eq!(out.unresolved.len(), 1);
    }

    #[test]
    fn function_expression_declarator() {
        // `const f = function(){}` must register as a callable func
        // (tree-sitter names it function_expression, not "function").
        let (out, _) = analyze(&[
            ("loader.js", "const load = function(name){\n  return require('./plugins/' + name);\n};\nmodule.exports = {load};\n"),
            ("app.js", "const {load} = require('./loader');\nload('ldap');\n"),
            ("plugins/ldap.js", ""),
        ]);
        assert_eq!(out.edges.len(), 1, "edges: {:?} unres: {:?}", out.edges, out.unresolved);
        assert_eq!(out.edges[0].1, "plugins/ldap.js");
    }

    #[test]
    fn no_call_sites() {
        let (out, _) = analyze(&[
            ("loader.js", "function load(name){\n  return require('./plugins/' + name);\n}\n"),
            ("plugins/ldap.js", ""),
        ]);
        assert!(out.edges.is_empty());
        assert!(out.unresolved.iter().any(|u| u.contains("no call sites")));
    }
}
