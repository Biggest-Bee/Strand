//! Go file representation for deep analysis: parsed tree, package
//! clause, import bindings (local name -> canonical package + path),
//! and function/method metadata. Module identity for the solver is
//! the package directory (Go scopes calls per package, not per file).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use tree_sitter::{Node, Tree};

/// One Go file's parsed view.
pub struct GoFile {
    /// Project-root-relative path (`/`-separated).
    pub rel: String,
    /// Directory of `rel` - the package key ("." for root files).
    pub dir: String,
    /// Package clause name.
    pub package: String,
    pub tree: Tree,
    pub text: String,
    /// Local binding name -> (canonical package name, import path).
    /// Canonical name = target package clause for project imports,
    /// else last path element with `.vN` suffix stripped.
    pub imports: HashMap<String, (String, String)>,
    /// Function/method short name -> info. Methods key by method
    /// name; qualname is "Func" or "Type.Method".
    pub funcs: HashMap<String, Vec<GoFuncInfo>>,
}

/// Go function metadata (extends the shared FuncInfo shape with the
/// receiver for `recv.Method()` resolution).
#[derive(Debug, Clone)]
pub struct GoFuncInfo {
    pub params: Vec<String>,
    pub start: usize,
    pub end: usize,
    pub qualname: String,
    pub is_method: bool,
    /// `(receiver_name, receiver_type)` for method_declaration.
    pub receiver: Option<(String, String)>,
    /// Result types are nilable (pointer/slice/map/chan/interface/
    /// func/error) - bare `return` may yield nil.
    pub nilable_results: bool,
}

fn parse_go(text: &str) -> Option<Tree> {
    thread_local! {
        static PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> =
            const { std::cell::RefCell::new(None) };
    }
    PARSER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let mut p = tree_sitter::Parser::new();
            p.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
            *slot = Some(p);
        }
        slot.as_mut().unwrap().parse(text, None)
    })
}

/// All `call_expression` nodes via query.
pub fn call_nodes<'a>(f: &'a GoFile) -> Vec<Node<'a>> {
    use std::sync::OnceLock;
    use tree_sitter::StreamingIterator;
    static Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    let q = Q.get_or_init(|| {
        tree_sitter::Query::new(
            &tree_sitter_go::LANGUAGE.into(),
            "(call_expression) @call",
        )
        .expect("go call query")
    });
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

fn dir_of(rel: &str) -> String {
    rel.rsplit_once('/')
        .map(|(d, _)| d.to_string())
        .unwrap_or_else(|| ".".to_string())
}

fn analyze_file_tree(rel: &str, text: String, tree: Tree) -> Option<GoFile> {
    let root = tree.root_node();
    let package = package_name(root, &text).unwrap_or_default();
    if package.is_empty() {
        return None;
    }
    let mut imports = HashMap::new();
    let mut funcs: HashMap<String, Vec<GoFuncInfo>> = HashMap::new();
    collect_top(root, &text, &mut imports, &mut funcs);
    Some(GoFile {
        rel: rel.to_string(),
        dir: dir_of(rel),
        package,
        tree,
        text,
        imports,
        funcs,
    })
}

/// Syntactic seed types for callgraph resolution: `s := &Server{}`,
/// `var s Server`, `s := new(Server)` map binding -> type name.
/// Returns `(file_local, package_level)`: package_level only holds
/// top-level `var` declarations (no enclosing function), which are
/// safe to merge across a package's files; file_local may contain
/// function-scoped vars and must only apply to that file.
/// No dataflow - used only to order SCCs (the facts walk rebuilds
/// precise types itself).
pub fn seed_types(f: &GoFile) -> (HashMap<String, String>, HashMap<String, String>) {
    let mut local = HashMap::new();
    let mut pkg = HashMap::new();
    use std::sync::OnceLock;
    use tree_sitter::StreamingIterator;
    static Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    let q = Q.get_or_init(|| {
        tree_sitter::Query::new(
            &tree_sitter_go::LANGUAGE.into(),
            "(short_var_declaration) @d (var_spec) @d",
        )
        .expect("go seed query")
    });
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(q, f.tree.root_node(), f.text.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures() {
            let n = cap.node;
            match n.kind() {
                "var_spec" => {
                    let ty = n
                        .child_by_field_name("type")
                        .and_then(|t| type_name_pub(t, &f.text))
                        .or_else(|| {
                            n.child_by_field_name("value")
                                .and_then(|v| rhs_seed_type(v, &f.text))
                        });
                    if let Some(t) = ty {
                        let at_pkg_level = !inside_func(n);
                        if let Some(names) = n.child_by_field_name("name") {
                            for nm in left_names(names, &f.text) {
                                local.entry(nm.clone()).or_insert_with(|| t.clone());
                                if at_pkg_level {
                                    pkg.entry(nm).or_insert_with(|| t.clone());
                                }
                            }
                        }
                    }
                }
                "short_var_declaration" => {
                    let (Some(left), Some(right)) = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("right"),
                    ) else {
                        continue;
                    };
                    let lefts = left_names(left, &f.text);
                    let rights = expr_nodes(right);
                    if lefts.is_empty() || lefts.len() != rights.len() {
                        continue;
                    }
                    for (l, r) in lefts.iter().zip(rights.iter()) {
                        if let Some(t) = rhs_seed_type(*r, &f.text) {
                            local.entry(l.clone()).or_insert(t);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (local, pkg)
}

/// True if `node` sits inside a function/method/func_literal body.
fn inside_func(node: Node) -> bool {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if matches!(
            n.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return true;
        }
        cur = n.parent();
    }
    false
}

/// Direct expression children: unwraps expression_list/argument_list/
/// parenthesized_expression one level; otherwise returns the node.
fn expr_nodes(node: Node) -> Vec<Node> {
    if matches!(
        node.kind(),
        "expression_list" | "argument_list" | "parenthesized_expression"
    ) {
        let mut c = node.walk();
        node.children(&mut c)
            .filter(|ch| ch.is_named())
            .collect()
    } else {
        vec![node]
    }
}

/// Identifier names among expr_nodes (for `:=` / `var` left sides).
fn left_names(node: Node, text: &str) -> Vec<String> {
    expr_nodes(node)
        .iter()
        .filter(|n| n.kind() == "identifier")
        .filter_map(|n| n.utf8_text(text.as_bytes()).ok().map(str::to_string))
        .collect()
}

/// RHS type for `s := &T{}` / `s := T{}` / `s := new(T)`.
fn rhs_seed_type(node: Node, text: &str) -> Option<String> {
    match node.kind() {
        "composite_literal" => node
            .child_by_field_name("type")
            .and_then(|t| type_name_pub(t, text)),
        "unary_expression" => {
            // `&T{}` - find composite literal child.
            let mut c = node.walk();
            let found = node
                .children(&mut c)
                .find(|k| k.is_named() && k.kind() == "composite_literal");
            found
                .and_then(|cl| cl.child_by_field_name("type"))
                .and_then(|t| type_name_pub(t, text))
        }
        "call_expression" => {
            // `new(T)` -> T.
            let func = node.child_by_field_name("function")?;
            if func.kind() == "identifier"
                && func.utf8_text(text.as_bytes()).ok() == Some("new")
            {
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut c = args.walk();
                    let arg = args.children(&mut c).find(|k| k.is_named());
                    if let Some(arg) = arg {
                        return type_name_pub(arg, text);
                    }
                }
            }
            None
        }
        "parenthesized_expression" => node
            .children(&mut node.walk())
            .find(|k| k.is_named())
            .and_then(|i| rhs_seed_type(i, text)),
        _ => None,
    }
}

/// Parse a `package x` clause name.
fn package_name(root: Node, text: &str) -> Option<String> {
    let mut c = root.walk();
    for ch in root.children(&mut c) {
        if ch.kind() == "package_clause" {
            let name = ch
                .children(&mut ch.walk())
                .find(|k| k.kind() == "package_identifier")?;
            return name.utf8_text(text.as_bytes()).ok().map(str::to_string);
        }
    }
    None
}

/// Import path string literal -> contents.
fn path_string(node: Node, text: &str) -> Option<String> {
    let raw = node.utf8_text(text.as_bytes()).ok()?;
    raw.strip_prefix('"')
        .or_else(|| raw.strip_prefix('`'))
        .and_then(|s| s.strip_suffix('"').or_else(|| s.strip_suffix('`')))
        .map(str::to_string)
}

/// Last path element with a trailing `.vN` version stripped
/// (`gopkg.in/yaml.v2` -> `yaml`).
pub fn canonical_external(path: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or(path);
    if let Some((base, ver)) = last.rsplit_once('.') {
        if ver.len() <= 3 && ver.chars().all(|c| c.is_ascii_digit()) && !base.is_empty() {
            return base.to_string();
        }
    }
    last.to_string()
}

/// Collect imports and top-level functions via a query (document
/// order irrelevant - all outputs are maps).
fn collect_top(
    root: Node,
    text: &str,
    imports: &mut HashMap<String, (String, String)>,
    funcs: &mut HashMap<String, Vec<GoFuncInfo>>,
) {
    use std::sync::OnceLock;
    use tree_sitter::StreamingIterator;
    static Q: OnceLock<tree_sitter::Query> = OnceLock::new();
    let q = Q.get_or_init(|| {
        tree_sitter::Query::new(
            &tree_sitter_go::LANGUAGE.into(),
            "(import_spec) @imp (function_declaration) @fn (method_declaration) @fn (short_var_declaration) @d (var_spec) @d",
        )
        .expect("go facts query")
    });
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(q, root, text.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures() {
            let n = cap.node;
            match n.kind() {
                "import_spec" => collect_import_spec(n, text, imports),
                "function_declaration" => {
                    if let Some(info) = func_info(n, text, None, None) {
                        funcs.entry(short_name(&info.qualname)).or_default().push(info);
                    }
                }
                "method_declaration" => {
                    if let Some(info) = method_info(n, text) {
                        funcs.entry(short_name(&info.qualname)).or_default().push(info);
                    }
                }
                // `f := func(){...}` / `var f = func(){...}` register
                // the literal as a named function.
                "short_var_declaration" | "var_spec" => {
                    collect_func_literal_decl(n, text, funcs);
                }
                _ => {}
            }
        }
    }
}

/// `name := func(...)` / `var name = func(...)` -> func entry.
fn collect_func_literal_decl(
    node: Node,
    text: &str,
    funcs: &mut HashMap<String, Vec<GoFuncInfo>>,
) {
    // Find a func_literal on the right side.
    let right = if node.kind() == "var_spec" {
        node.child_by_field_name("value")
    } else {
        node.child_by_field_name("right")
    };
    let Some(right) = right else { return };
    let lit = if right.kind() == "func_literal" {
        Some(right)
    } else {
        // expression_list may wrap it.
        let mut c = right.walk();
        let found = right
            .children(&mut c)
            .find(|ch| ch.kind() == "func_literal");
        found
    };
    let Some(lit) = lit else { return };
    // Only single-name bindings (multi-name `a, b := f(), func(){}`
    // is rare; take first left ident anyway - approximation).
    let Some(name) = first_left_ident(node, text) else {
        return;
    };
    if let Some(info) = func_info_named(lit, text, &name) {
        funcs.entry(name).or_default().push(info);
    }
}

fn short_name(qual: &str) -> String {
    qual.rsplit('.').next().unwrap_or(qual).to_string()
}

fn collect_import_spec(
    node: Node,
    text: &str,
    imports: &mut HashMap<String, (String, String)>,
) {
    let path = node
        .child_by_field_name("path")
        .and_then(|p| path_string(p, text));
    let Some(path) = path else { return };
    let alias = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(text.as_bytes()).ok())
        .map(str::to_string);
    let local = match alias.as_deref() {
        Some("_") => return,          // blank import: side effects only
        Some(".") => return,          // dot import: names enter scope unqualified - not modeled
        Some(a) => a.to_string(),
        None => canonical_external(&path),
    };
    // Canonical package name refined later for project imports (the
    // solver's package index knows target package clauses); for now
    // external-style canonical.
    imports.insert(local, (canonical_external(&path), path));
}

/// Parameter names of a parameter_list: all identifier children of
/// each parameter_declaration (covers `a, b int` via multiple decls
/// or repeated names - tree-sitter emits one decl per name group).
fn param_names(node: Option<Node>, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pn) = node else { return out };
    let mut c = pn.walk();
    for p in pn.children(&mut c) {
        if p.kind() != "parameter_declaration" {
            continue;
        }
        let mut pc = p.walk();
        for ch in p.children(&mut pc) {
            if ch.kind() == "identifier" {
                if let Ok(t) = ch.utf8_text(text.as_bytes()) {
                    out.push(t.to_string());
                }
            }
        }
    }
    out
}

/// `_type` node -> dotted type name for var_types seeding.
pub fn type_name_pub(node: Node, text: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" => node
            .utf8_text(text.as_bytes())
            .ok()
            .map(str::to_string),
        "qualified_type" => {
            let pkg = node.child_by_field_name("package")?;
            let name = node.child_by_field_name("name")?;
            let p = pkg.utf8_text(text.as_bytes()).ok()?;
            let n = name.utf8_text(text.as_bytes()).ok()?;
            Some(format!("{p}.{n}"))
        }
        "pointer_type" | "slice_type" | "array_type" | "map_type"
        | "channel_type" | "function_type" => {
            // Recurse into the element/value type where present.
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() && ch.kind() != node.kind() {
                    if let Some(t) = type_name_pub(ch, text) {
                        return Some(t);
                    }
                }
            }
            None
        }
        "generic_type" => {
            let inner = node.child_by_field_name("type")?;
            type_name_pub(inner, text)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|k| k.is_named())?;
            type_name_pub(inner, text)
        }
        _ => None,
    }
}

/// Nilable result types: pointer/slice/map/chan/interface/func and
/// `error` (an interface). Named types are conservatively non-nil.
pub fn type_nilable_pub(node: Node, text: &str) -> bool {
    match node.kind() {
        "pointer_type" | "slice_type" | "map_type" | "channel_type"
        | "interface_type" | "function_type" => true,
        "type_identifier" => {
            node.utf8_text(text.as_bytes()).is_ok_and(|t| t == "error")
        }
        "qualified_type" | "generic_type" => false,
        "parameter_list" => {
            // `(a, b T)` result list: nilable if ANY element nilable.
            let mut c = node.walk();
            let kids: Vec<Node> = node.children(&mut c).collect();
            kids.iter().any(|ch| {
                ch.kind() == "parameter_declaration"
                    && ch
                        .children(&mut ch.walk())
                        .any(|k| k.is_named() && type_nilable_pub(k, text))
            })
        }
        _ => false,
    }
}

fn func_info(
    node: Node,
    text: &str,
    receiver: Option<(String, String)>,
    name_override: Option<&str>,
) -> Option<GoFuncInfo> {
    let name = match name_override {
        Some(n) => n.to_string(),
        None => {
            let name = node.child_by_field_name("name")?;
            name.utf8_text(text.as_bytes()).ok()?.to_string()
        }
    };
    let params = param_names(node.child_by_field_name("parameters"), text);
    let _ = &name;
    let result = node.child_by_field_name("result");
    let nilable = match result {
        Some(r) => {
            type_nilable_pub(r, text)
                || (r.kind() == "parameter_list"
                    && r
                        .children(&mut r.walk())
                        .any(|ch| ch.is_named() && type_nilable_pub(ch, text)))
        }
        None => false,
    };
    let qualname = match &receiver {
        Some((_, t)) => format!("{t}.{name}"),
        None => name.to_string(),
    };
    Some(GoFuncInfo {
        params,
        start: node.start_byte(),
        end: node.end_byte(),
        qualname,
        is_method: receiver.is_some(),
        receiver,
        nilable_results: nilable,
    })
}

/// func_info for func_literal nodes bound to `name`.
fn func_info_named(node: Node, text: &str, name: &str) -> Option<GoFuncInfo> {
    func_info(node, text, None, Some(name))
}

fn method_info(node: Node, text: &str) -> Option<GoFuncInfo> {
    let recv = node.child_by_field_name("receiver")?;
    // receiver parameter_list -> first parameter_declaration ->
    // (name identifier, type node).
    let mut rc = recv.walk();
    let decl = recv
        .children(&mut rc)
        .find(|c| c.kind() == "parameter_declaration")?;
    let mut dc = decl.walk();
    let mut name = String::new();
    let mut ty = String::new();
    for ch in decl.children(&mut dc) {
        match ch.kind() {
            "identifier" => {
                name = ch.utf8_text(text.as_bytes()).ok()?.to_string();
            }
            _ => {
                if ty.is_empty() {
                    if let Some(t) = type_name_pub(ch, text) {
                        ty = t;
                    }
                }
            }
        }
    }
    if name.is_empty() || ty.is_empty() {
        return None;
    }
    func_info(node, text, Some((name, ty)), None)
}

/// Build a `GoFile` from source text.
pub fn analyze_source(rel: &str, text: &str) -> Option<GoFile> {
    let tree = parse_go(text)?;
    analyze_file_tree(rel, text.to_string(), tree)
}

/// Build `GoFile`s from `(rel, abs)` paths in parallel.
pub fn analyze_files(
    files: &[(String, PathBuf)],
) -> Vec<(String, Option<GoFile>)> {
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

/// Project module prefixes discovered from go.mod files: longest
/// module path wins when resolving an import path to a directory.
pub struct GoModules {
    /// (module_path, dir_rel) sorted by path length desc at use site.
    pub prefixes: Vec<(String, String)>,
}

/// Discover go.mod files under `root` (bounded walk) and parse their
/// `module` directives.
pub fn discover_modules(root: &Path) -> GoModules {
    let mut prefixes = Vec::new();
    // go.mod files may not be in file_set (scanner nodes differ);
    // walk the tree shallowly for them.
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        visited += 1;
        if visited > 4000 {
            break;
        }
        let gomod = dir.join("go.mod");
        if gomod.is_file() {
            if let Ok(text) = std::fs::read_to_string(&gomod) {
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("module") {
                        let path = rest.trim().trim_matches('"');
                        if !path.is_empty() {
                            let rel = dir
                                .strip_prefix(root)
                                .unwrap_or_else(|_| dir.as_path())
                                .to_string_lossy()
                                .replace('\\', "/");
                            let dir_rel = if rel.is_empty() { ".".into() } else { rel };
                            prefixes.push((path.to_string(), dir_rel));
                        }
                        break;
                    }
                }
            }
        }
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if matches!(
                        name.as_str(),
                        "vendor" | "node_modules" | ".git" | "testdata"
                    ) {
                        continue;
                    }
                    stack.push(p);
                }
            }
        }
    }
    prefixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    GoModules { prefixes }
}

/// Resolve an import path to a project package dir, if any.
pub fn resolve_import(mods: &GoModules, path: &str) -> Option<String> {
    for (mpath, mdir) in &mods.prefixes {
        if path == mpath {
            return Some(mdir.clone());
        }
        if let Some(rest) = path.strip_prefix(&format!("{mpath}/")) {
            let dir = if mdir == "." {
                rest.to_string()
            } else {
                format!("{mdir}/{rest}")
            };
            return Some(dir);
        }
    }
    None
}

/// Enclosing function of a node -> GoFuncInfo (methods/functions/
/// func literals bound by name). Returns qualname + info.
pub fn enclosing_func<'t>(
    node: Node<'t>,
    f: &'t GoFile,
) -> Option<(String, GoFuncInfo)> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        match n.kind() {
            "function_declaration" => {
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
                            .find(|i| i.start <= n.start_byte() && n.end_byte() <= i.end)
                            .or_else(|| v.last())
                            .cloned()
                    })
                    .map(|info| (name, info));
            }
            "method_declaration" => {
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
                            .find(|i| i.start <= n.start_byte() && n.end_byte() <= i.end)
                            .or_else(|| v.last())
                            .cloned()
                    })
                    .map(|info| (name, info));
            }
            "func_literal" => {
                // Named via enclosing short_var_declaration/var_spec.
                let mut up = n.parent();
                while let Some(u) = up {
                    match u.kind() {
                        "short_var_declaration" | "var_spec" => {
                            if let Some(left) = first_left_ident(u, &f.text) {
                                return f
                                    .funcs
                                    .get(&left)
                                    .and_then(|v| v.last().cloned())
                                    .map(|info| (left, info));
                            }
                            return None;
                        }
                        "function_declaration" | "function_body" | "block"
                        | "source_file" => break,
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

fn first_left_ident(decl: Node, text: &str) -> Option<String> {
    let left = decl.child_by_field_name("left").or_else(|| {
        // var_spec uses `name` field
        decl.child_by_field_name("name")
    })?;
    // left may be expression_list; take first identifier.
    let mut stack = vec![left];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                return n.utf8_text(text.as_bytes()).ok().map(str::to_string);
            }
            _ => {
                let mut c = n.walk();
                stack.extend(n.children(&mut c));
            }
        }
    }
    None
}

// Func-literal-valued declarations register via collect_func_literal_decl;
// anonymous literals stay unresolved (honest).
