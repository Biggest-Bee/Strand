//! Rust file representation for deep analysis: parsed tree, `use`
//! import bindings (local name -> full `::` path), and function/
//! method metadata. Module identity is the file path (Rust modules
//! are file-scoped); cross-file resolution uses a module-path suffix
//! index built from file locations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use rayon::prelude::*;
use tree_sitter::{Node, Tree};
use tree_sitter::StreamingIterator;

/// One Rust file's parsed view.
pub(crate) struct RsFile {
    /// Project-root-relative path (`/`-separated).
    pub(crate) rel: String,
    pub(crate) tree: Tree,
    pub(crate) text: String,
    /// Local binding name -> full `::` path (`use std::env::var`
    /// binds `var` -> `std::env::var`; `use x as y` binds `y` -> `x`).
    /// Wildcard imports (`use x::*`) are not modeled.
    pub(crate) imports: HashMap<String, String>,
    /// Function/method short name -> info (methods key by method
    /// name; qualname is `f`, `Type::f`, or `mod::f`).
    pub(crate) funcs: HashMap<String, Vec<RsFuncInfo>>,
}

/// Rust function metadata.
#[derive(Debug, Clone)]
pub(crate) struct RsFuncInfo {
    pub params: Vec<String>,
    pub start: usize,
    pub end: usize,
    /// `f`, `Type::f` (inherent/trait impl method), or `m::f`
    /// (function inside an inline `mod`).
    pub qualname: String,
    pub is_method: bool,
    /// Impl self type for methods (`self`/`&self` receiver).
    pub receiver_type: Option<String>,
}

fn parse_rs(text: &str) -> Option<Tree> {
    thread_local! {
        static PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> =
            const { std::cell::RefCell::new(None) };
    }
    PARSER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let mut p = tree_sitter::Parser::new();
            p.set_language(&tree_sitter_rust::LANGUAGE.into()).ok()?;
            *slot = Some(p);
        }
        slot.as_mut().unwrap().parse(text, None)
    })
}

static CALL_Q: OnceLock<tree_sitter::Query> = OnceLock::new();

fn call_query() -> &'static tree_sitter::Query {
    CALL_Q.get_or_init(|| {
        tree_sitter::Query::new(
            &tree_sitter_rust::LANGUAGE.into(),
            "(call_expression) @call",
        )
        .expect("rust call query")
    })
}

/// All `call_expression` nodes via query.
pub(crate) fn call_nodes<'a>(f: &'a RsFile) -> Vec<Node<'a>> {
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut out = Vec::new();
    let mut matches = cursor.matches(call_query(), f.tree.root_node(), f.text.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures() {
            out.push(cap.node);
        }
    }
    out
}

fn short_name(qual: &str) -> String {
    qual.rsplit("::").next().unwrap_or(qual).to_string()
}

/// Build an `RsFile` from source text.
pub(crate) fn analyze_source(rel: &str, text: &str) -> Option<RsFile> {
    let tree = parse_rs(text)?;
    let mut imports = HashMap::new();
    let mut funcs: HashMap<String, Vec<RsFuncInfo>> = HashMap::new();
    collect_top(tree.root_node(), text, "", &mut imports, &mut funcs, None);
    Some(RsFile {
        rel: rel.to_string(),
        tree,
        text: text.to_string(),
        imports,
        funcs,
    })
}

/// Build `RsFile`s from `(rel, abs)` paths in parallel.
pub(crate) fn analyze_files(files: &[(String, PathBuf)]) -> Vec<(String, Option<RsFile>)> {
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

/// `_type` node -> short type name for impl/receiver tracking.
pub(crate) fn type_name_rs(node: Node, text: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" => node
            .utf8_text(text.as_bytes())
            .ok()
            .map(str::to_string),
        "scoped_type_identifier" | "scoped_identifier" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(text.as_bytes()).ok())
            .map(str::to_string),
        "generic_type" | "generic_type_with_turbofish" => {
            let inner = node.child_by_field_name("type")?;
            type_name_rs(inner, text)
        }
        "reference_type" | "pointer_type" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            type_name_rs(inner, text)
        }
        "parenthesized_type" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            type_name_rs(inner, text)
        }
        _ => None,
    }
}

/// Collect use-declarations and function items via controlled
/// recursion (a flat query would visit impl/mod bodies twice and
/// lose context). `mod_prefix` is the inline-module path
/// (`m::inner`); `impl_type` is Some when inside an impl block
/// (methods get `Type::name` qualnames). Function bodies are NOT
/// entered: `use` inside a fn is block-scoped and nested items are
/// rare; trait items are skipped (method signatures have no
/// analyzable body for v1).
fn collect_top(
    node: Node,
    text: &str,
    mod_prefix: &str,
    imports: &mut HashMap<String, String>,
    funcs: &mut HashMap<String, Vec<RsFuncInfo>>,
    impl_type: Option<&str>,
) {
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if !ch.is_named() {
            continue;
        }
        match ch.kind() {
            "use_declaration" => collect_use(ch, text, imports),
            "function_item" => {
                if let Some(info) = func_info(ch, text, mod_prefix, impl_type) {
                    funcs
                        .entry(short_name(&info.qualname))
                        .or_default()
                        .push(info);
                }
            }
            "impl_item" => {
                let ty = ch
                    .child_by_field_name("type")
                    .and_then(|t| type_name_rs(t, text));
                if let Some(body) = ch.child_by_field_name("body") {
                    collect_top(body, text, mod_prefix, imports, funcs, ty.as_deref());
                }
            }
            "mod_item" => {
                let name = ch
                    .child_by_field_name("name")
                    .and_then(|x| x.utf8_text(text.as_bytes()).ok())
                    .unwrap_or("");
                let prefix = if mod_prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{mod_prefix}::{name}")
                };
                if let Some(body) = ch.child_by_field_name("body") {
                    collect_top(body, text, &prefix, imports, funcs, None);
                }
            }
            // Items whose children can't contain functions we model.
            "trait_item" | "struct_item" | "enum_item" | "union_item"
            | "type_item" | "const_item" | "static_item" | "extern_crate_declaration"
            | "foreign_mod_item" | "macro_definition" => {}
            _ => {
                // declaration_list / source_file wrappers: recurse.
                if matches!(ch.kind(), "declaration_list" | "source_file" | "block") {
                    collect_top(ch, text, mod_prefix, imports, funcs, impl_type);
                }
            }
        }
    }
}

/// Parameter binding names of a `parameters` node: pattern
/// identifiers (through mut/ref/tuple wrappers) plus `self`.
fn param_names(node: Option<Node>, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pn) = node else { return out };
    let mut c = pn.walk();
    for p in pn.children(&mut c) {
        match p.kind() {
            // `self`/`&self` is the receiver, not an argument - it
            // must NOT occupy a param index (call args exclude it).
            "self_parameter" => {}
            "parameter" => {
                let pat = p.child_by_field_name("pattern");
                match pat {
                    Some(pat) if pat.kind() == "self" => {}
                    Some(pat) => collect_pat_idents(pat, text, &mut out),
                    None => {}
                }
            }
            _ => {}
        }
    }
    out
}

/// All binding identifiers inside a pattern (identifier, mut_pattern,
/// ref_pattern, tuple_pattern, struct_pattern field patterns, etc.).
pub(crate) fn collect_pat_idents(node: Node, text: &str, out: &mut Vec<String>) {
    match node.kind() {
        "identifier" | "shorthand_field_identifier" => {
            if let Ok(t) = node.utf8_text(text.as_bytes()) {
                out.push(t.to_string());
            }
        }
        "self" | "self_parameter" | "crate" | "super" => {}
        _ => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    collect_pat_idents(ch, text, out);
                }
            }
        }
    }
}

fn func_info(
    node: Node,
    text: &str,
    mod_prefix: &str,
    impl_type: Option<&str>,
) -> Option<RsFuncInfo> {
    let name = node.child_by_field_name("name")?;
    let name = name.utf8_text(text.as_bytes()).ok()?;
    let params = param_names(node.child_by_field_name("parameters"), text);
    let qualname = match (mod_prefix.is_empty(), impl_type) {
        (false, _) => format!("{mod_prefix}::{name}"),
        (true, Some(t)) => format!("{t}::{name}"),
        (true, None) => name.to_string(),
    };
    Some(RsFuncInfo {
        params,
        start: node.start_byte(),
        end: node.end_byte(),
        qualname,
        is_method: impl_type.is_some(),
        receiver_type: impl_type.map(str::to_string),
    })
}

/// `use` declaration -> import bindings. Handles plain paths
/// (`use a::b::c`), `as` aliases, braced lists (`use a::{b, c as d}`),
/// `self` in lists, and `*` (skipped - unbounded).
fn collect_use(node: Node, text: &str, imports: &mut HashMap<String, String>) {
    let Some(arg) = node.child_by_field_name("argument") else {
        return;
    };
    collect_use_path(arg, "", text, imports);
}

fn collect_use_path(node: Node, prefix: &str, text: &str, imports: &mut HashMap<String, String>) {
    match node.kind() {
        "use_wildcard" => {}
        "use_as_clause" => {
            // `path as alias`
            let path = node
                .children(&mut node.walk())
                .find(|k| {
                    k.is_named()
                        && matches!(
                            k.kind(),
                            "identifier" | "scoped_identifier" | "crate" | "self" | "super"
                        )
                })
                .map(|n| path_text(n, text))
                .unwrap_or_default();
            let alias = node
                .children(&mut node.walk())
                .filter(|k| k.is_named() && k.kind() == "identifier")
                .last()
                .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                .unwrap_or("");
            if !path.is_empty() && !alias.is_empty() {
                imports.insert(alias.to_string(), join_path(prefix, &path));
            }
        }
        "scoped_use_list" => {
            // `path::{list}` - path field + list field.
            let path = node
                .child_by_field_name("path")
                .map(|p| path_text(p, text))
                .unwrap_or_default();
            let list = node.child_by_field_name("list");
            if let Some(list) = list {
                collect_use_list(list, &join_path(prefix, &path), text, imports);
            }
        }
        "use_list" => collect_use_list(node, prefix, text, imports),
        "identifier" | "scoped_identifier" | "crate" | "self" | "super" => {
            let p = path_text(node, text);
            if p.is_empty() {
                return;
            }
            let full = join_path(prefix, &p);
            let local = full.rsplit("::").next().unwrap_or(&full).to_string();
            imports.insert(local, full);
        }
        _ => {}
    }
}

fn collect_use_list(node: Node, prefix: &str, text: &str, imports: &mut HashMap<String, String>) {
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if !ch.is_named() {
            continue;
        }
        match ch.kind() {
            "use_as_clause" | "scoped_use_list" | "use_list" | "use_wildcard" => {
                collect_use_path(ch, prefix, text, imports)
            }
            "identifier" | "self" | "crate" | "super" => {
                let name = ch.utf8_text(text.as_bytes()).unwrap_or("");
                if name == "self" {
                    // `use a::{self}` binds `a`'s last segment.
                    if !prefix.is_empty() {
                        let local = prefix.rsplit("::").next().unwrap_or(prefix);
                        imports.insert(local.to_string(), prefix.to_string());
                    }
                } else {
                    imports.insert(
                        name.to_string(),
                        join_path(prefix, name),
                    );
                }
            }
            _ => {}
        }
    }
}

/// Full `::` path text of an identifier/scoped_identifier/crate/self/
/// super node.
fn path_text(node: Node, text: &str) -> String {
    match node.kind() {
        "identifier" | "self" | "super" | "crate" => {
            node.utf8_text(text.as_bytes())
                .unwrap_or("")
                .to_string()
        }
        "scoped_identifier" => {
            let path = node.child_by_field_name("path");
            let name = node.child_by_field_name("name");
            match (path, name) {
                (Some(p), Some(n)) => {
                    let p = path_text(p, text);
                    let n = n.utf8_text(text.as_bytes()).unwrap_or("");
                    if p.is_empty() {
                        n.to_string()
                    } else {
                        format!("{p}::{n}")
                    }
                }
                _ => node
                    .utf8_text(text.as_bytes())
                    .unwrap_or("")
                    .to_string(),
            }
        }
        _ => node
            .utf8_text(text.as_bytes())
            .unwrap_or("")
            .to_string(),
    }
}

fn join_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.to_string()
    } else if path.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}::{path}")
    }
}

/// Enclosing function of a node -> (qualname, info). Methods and
/// nested-fn items both resolve through the file's funcs map by
/// byte range.
pub(crate) fn enclosing_func<'t>(
    node: Node<'t>,
    f: &'t RsFile,
) -> Option<(String, RsFuncInfo)> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if n.kind() == "function_item" {
            // Find the func info covering this node's range.
            for infos in f.funcs.values() {
                for info in infos {
                    if info.start <= n.start_byte() && n.end_byte() <= info.end {
                        return Some((info.qualname.clone(), info.clone()));
                    }
                }
            }
            return None;
        }
        anc = n.parent();
    }
    None
}

/// Syntactic seed types for callgraph resolution: `let x = T{..}`,
/// `let x = T::new()/T::default()`, `let x: T = ..` map binding ->
/// type name. No dataflow - first binding wins; used only to order
/// SCCs (the facts walk rebuilds precise types itself).
pub(crate) fn seed_types(f: &RsFile) -> HashMap<String, String> {
    let mut out = HashMap::new();
    seed_walk(f.tree.root_node(), f, &mut out);
    out
}

fn seed_walk(node: Node, f: &RsFile, out: &mut HashMap<String, String>) {
    if node.kind() == "let_declaration" {
        if let Some(t) = let_decl_type(node, f) {
            if let Some(pat) = node.child_by_field_name("pattern") {
                let mut names = Vec::new();
                collect_pat_idents(pat, &f.text, &mut names);
                for n in names {
                    out.entry(n).or_insert_with(|| t.clone());
                }
            }
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        if ch.is_named() {
            seed_walk(ch, f, out);
        }
    }
}

fn let_decl_type(node: Node, f: &RsFile) -> Option<String> {
    let text = f.text.as_str();
    // Explicit annotation wins.
    if let Some(t) = node
        .child_by_field_name("type")
        .and_then(|t| type_name_rs(t, text))
    {
        return Some(t);
    }
    let v = node.child_by_field_name("value")?;
    match v.kind() {
        "struct_expression" => v
            .child_by_field_name("name")
            .and_then(|n| type_name_rs(n, text)),
        "call_expression" => {
            // `T::new()` / `T::default()` convention.
            let func = v.child_by_field_name("function")?;
            let dotted = path_text(func, text);
            for suffix in ["::new", "::default"] {
                if let Some(t) = dotted.strip_suffix(suffix) {
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                }
            }
            None
        }
        "parenthesized_expression" | "try_expression" | "await_expression" => {
            v.children(&mut v.walk())
                .find(|k| k.is_named())
                .and_then(|inner| {
                    if inner.kind() == "call_expression" {
                        let func = inner.child_by_field_name("function")?;
                        let dotted = path_text(func, text);
                        for suffix in ["::new", "::default"] {
                            if let Some(t) = dotted.strip_suffix(suffix) {
                                if !t.is_empty() {
                                    return Some(t.to_string());
                                }
                            }
                        }
                        None
                    } else {
                        None
                    }
                })
        }
        _ => None,
    }
}

/// Module-path index: maps every plausible `::` path suffix of each
/// file to the file index, for cross-file call resolution.
/// `src/util/helper.rs` yields `src::util::helper`, `util::helper`,
/// `helper`; `a/b/mod.rs` yields `a::b`, `b`.
pub(crate) fn module_index(parsed: &[RsFile]) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for (i, f) in parsed.iter().enumerate() {
        let rel = f.rel.strip_suffix(".rs").unwrap_or(&f.rel);
        let rel = rel.replace('/', "::");
        let rel = rel.strip_suffix("::mod").unwrap_or(&rel).to_string();
        // All suffixes: full path plus each tail segment chain.
        let segs: Vec<&str> = rel.split("::").collect();
        for start in 0..segs.len() {
            let key = segs[start..].join("::");
            // Shorter suffixes are ambiguous; prefer the longest
            // (insert only if absent so earlier=fuller paths win).
            out.entry(key).or_insert(i);
        }
    }
    out
}
