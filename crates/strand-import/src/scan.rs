//! Rust source scanner: walks a directory tree, resolves `mod` and `use`
//! statements to files, and emits an [`EdgeList`] where `A -> B` means
//! "file A depends on file B".
//!
//! Node names are root-relative paths with forward slashes
//! (e.g. `crates/strand-core/src/graph.rs`), which keeps builds
//! deterministic across platforms and names unique.
//!
//! All three languages are parsed with real parsers: `syn` for Rust,
//! tree-sitter for Python and JS/TS - comments, string literals, and
//! broken-code recovery are handled by the grammars, not text matching.
//! `#[path]` attributes, `include!("...")`, `tsconfig`/`jsconfig`
//! aliases, and `package.json` `"imports"` are resolved on top.
//! Macros that expand to modules are not followed. External crates and
//! node_modules packages are ignored.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use strand_core::{Error, Result};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};

use crate::EdgeList;

/// Directories never descended into: VCS internals, dependency dirs,
/// and conventional build/tooling output (`.next`, `dist`, `out`,
/// `coverage`, framework caches). `build` is deliberately absent -
/// some projects keep real sources there.
const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    ".next",
    "dist",
    "out",
    "coverage",
    ".turbo",
    ".cache",
    ".vercel",
    ".netlify",
    ".firebase",
];

/// Output of a scan: edges plus every source file found (so files
/// with no dependencies still become nodes in the graph).
pub struct ScanOutput {
    pub edges: EdgeList,
    /// All discovered source files as root-relative `/` paths, sorted.
    pub nodes: Vec<String>,
    /// Non-fatal problems (e.g. files that failed to parse). The graph
    /// may be incomplete when this is non-empty.
    pub warnings: Vec<String>,
}

/// Languages the scanner supports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Rust,
    Python,
    Js,
}

/// Scan `root` for Rust sources and resolve intra-project dependencies.
pub fn scan_rust(root: &Path) -> Result<ScanOutput> {
    scan_lang(root, Lang::Rust)
}

/// Dispatch to the per-language scanner.
pub fn scan_lang(root: &Path, lang: Lang) -> Result<ScanOutput> {
    match lang {
        Lang::Rust => scan_rust_impl(root),
        Lang::Python => scan_python_impl(root),
        Lang::Js => scan_js_impl(root),
    }
}

/// Scan `root` for all supported languages and merge the results.
/// Edges only form within a language (a `.rs` file can't depend on a
/// `.py` file), but node sets are unioned.
pub fn scan_project(root: &Path, langs: &[Lang]) -> Result<ScanOutput> {
    let mut edges = EdgeList::new();
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    for &lang in langs {
        let out = scan_lang(root, lang)?;
        edges.extend(out.edges);
        nodes.extend(out.nodes);
        warnings.extend(out.warnings);
    }
    nodes.sort();
    nodes.dedup();
    Ok(ScanOutput {
        edges,
        nodes,
        warnings,
    })
}

fn scan_rust_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["rs"], &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let crates = crate_map(root, &names);
    let mut edges: EdgeList = Vec::new();
    let mut warnings = Vec::new();

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
        // Real parse via syn: comments, string/char/raw literals, and
        // grouped `use` trees are handled by the grammar, not text
        // matching. A file that fails to parse contributes no edges and
        // is reported in `warnings` - the graph may be incomplete.
        let refs = match parse_rs_refs(&text) {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                let first = msg.lines().next().unwrap_or(&msg);
                warnings.push(format!("{rel}: {first}"));
                continue;
            }
        };
        let mut deps: BTreeSet<String> = BTreeSet::new();

        // `mod foo;` declarations -> foo.rs or foo/mod.rs under this
        // file's module directory. `#[path = "..."]` comes straight from
        // the item's attributes - no proximity guessing.
        let mdir = module_dir_rel(rel);
        for (seg, custom) in &refs.mods {
            let dep = match custom {
                Some(p) => normalize_rel(&mdir, p).filter(|c| names.contains(c)),
                None => resolve(&names, &mdir, std::slice::from_ref(seg)),
            };
            if let Some(dep) = dep {
                if dep != *rel {
                    deps.insert(dep);
                }
            }
        }

        // `include!("file.rs")` pulls the file's contents into this one.
        let parent = parent_rel(rel);
        for inc in &refs.includes {
            if let Some(dep) = normalize_rel(parent, inc).filter(|c| names.contains(c)) {
                if dep != *rel {
                    deps.insert(dep);
                }
            }
        }

        // `use` paths (flattened: `use a::{b, c::d}` yields both tails).
        for segments in &refs.uses {
            let Some((first, rest)) = segments.split_first() else {
                continue;
            };
            // `use other_workspace_crate::...` resolves into that crate;
            // unresolved tails fall back to the crate's root file.
            if let Some((src_rel, root_file)) = crates.get(first.as_str()) {
                let dep = if rest.is_empty() {
                    Some(root_file.clone())
                } else {
                    resolve(&names, src_rel, rest).or_else(|| Some(root_file.clone()))
                };
                if let Some(dep) = dep {
                    if dep != *rel {
                        deps.insert(dep);
                    }
                }
                continue;
            }
            let Some((base, rest)) = resolve_use_base(rel, root, abs, &segments) else {
                continue; // external crate or unresolvable
            };
            if rest.is_empty() {
                continue;
            }
            if let Some(dep) = resolve(&names, &base, &rest) {
                if dep != *rel {
                    deps.insert(dep);
                }
            }
        }

        for dep in deps {
            edges.push((rel.clone(), dep, None));
        }
    }

    let nodes = names.into_iter().collect();
    Ok(ScanOutput {
        edges,
        nodes,
        warnings,
    })
}

// ---------- Rust reference extraction (syn) ----------

/// Everything the resolver needs from one parsed `.rs` file.
#[derive(Default)]
struct RustRefs {
    /// `mod name;` declarations: `(ident, #[path] value if present)`.
    mods: Vec<(String, Option<String>)>,
    /// `use` paths flattened to segment lists (`use a::{b, c::d}`
    /// yields `["a","b"]` and `["a","c","d"]`).
    uses: Vec<Vec<String>>,
    /// String literals inside `include!(...)` calls.
    includes: Vec<String>,
}

fn parse_rs_refs(text: &str) -> std::result::Result<RustRefs, syn::Error> {
    let file = syn::parse_file(text)?;
    let mut v = RustRefVisitor::default();
    v.visit_file(&file);
    Ok(v.refs)
}

#[derive(Default)]
struct RustRefVisitor {
    refs: RustRefs,
}

impl<'ast> Visit<'ast> for RustRefVisitor {
    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        // `mod foo;` (no inline body) declares a child module file.
        // `mod foo { ... }` still gets visited for nested items.
        if i.content.is_none() {
            let custom = i.attrs.iter().find_map(path_attr_value);
            self.refs
                .mods
                .push((i.ident.unraw().to_string(), custom));
        }
        visit::visit_item_mod(self, i);
    }

    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        flatten_use(&i.tree, &mut prefix, &mut self.refs.uses);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if i.path
            .segments
            .last()
            .is_some_and(|s| s.ident == "include")
        {
            if let Ok(lit) = syn::parse2::<syn::LitStr>(i.tokens.clone()) {
                self.refs.includes.push(lit.value());
            }
        }
        visit::visit_macro(self, i);
    }
}

/// `#[path = "..."]` -> the literal value, for `mod` items only.
fn path_attr_value(attr: &syn::Attribute) -> Option<String> {
    if !attr.path().is_ident("path") {
        return None;
    }
    if let syn::Meta::NameValue(nv) = &attr.meta {
        if let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = &nv.value
        {
            return Some(s.value());
        }
    }
    None
}

/// Flatten a `use` tree into full segment paths. `self`/`super`/`crate`
/// are ordinary idents here - the resolver interprets them.
fn flatten_use(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.unraw().to_string());
            flatten_use(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            prefix.push(n.ident.unraw().to_string());
            out.push(prefix.clone());
            prefix.pop();
        }
        // `use a::b as c` depends on `a::b`, not the rename.
        syn::UseTree::Rename(r) => {
            prefix.push(r.ident.unraw().to_string());
            out.push(prefix.clone());
            prefix.pop();
        }
        // `use a::*` refers to module `a` itself.
        syn::UseTree::Glob(_) => out.push(prefix.clone()),
        syn::UseTree::Group(g) => {
            for t in &g.items {
                flatten_use(t, prefix, out);
            }
        }
    }
}

// ---------- filesystem walk ----------

fn walk_ext(
    dir: &Path,
    root: &Path,
    exts: &[&str],
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            walk_ext(&path, root, exts, out)?;
        } else if ft.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.contains(&e))
        {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

// ---------- path math (all in root-relative "/" space) ----------

/// Parent directory of `rel` ("" for top-level files).
fn parent_rel(rel: &str) -> &str {
    rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

/// The directory that contains this file's *child* modules:
/// `foo.rs` -> `foo/`, `mod.rs`/`lib.rs`/`main.rs` -> own directory.
fn module_dir_rel(rel: &str) -> String {
    let parent = parent_rel(rel);
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let stem = name.strip_suffix(".rs").unwrap_or(name);
    if matches!(stem, "mod" | "lib" | "main") {
        parent.to_string()
    } else if parent.is_empty() {
        stem.to_string()
    } else {
        format!("{parent}/{stem}")
    }
}

fn join_rel(base: &str, segs: &[String]) -> String {
    let tail = segs.join("/");
    if base.is_empty() {
        tail
    } else {
        format!("{base}/{tail}")
    }
}

/// Longest-prefix resolution: for k from `segs.len()` down to 1, try
/// `base/s0/.../sk.rs` then `base/s0/.../sk/mod.rs`. Returns the first
/// match - so `use crate::a::b::Item` resolves to `a/b.rs` if it exists,
/// else to `a.rs`/`a/mod.rs` (treating `b` as an item inside module `a`).
fn resolve(names: &BTreeSet<String>, base: &str, segs: &[String]) -> Option<String> {
    for k in (1..=segs.len()).rev() {
        let p = join_rel(base, &segs[..k]);
        for cand in [format!("{p}.rs"), format!("{p}/mod.rs")] {
            if names.contains(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

/// Map the first segment of a `use` path to a base directory (rel) plus
/// the remaining segments. Returns `None` for external crates.
fn resolve_use_base(
    rel: &str,
    root: &Path,
    abs: &Path,
    segs: &[String],
) -> Option<(String, Vec<String>)> {
    let (first, rest) = segs.split_first()?;
    match first.as_str() {
        "crate" => {
            let base = crate_src_rel(abs, root)?;
            Some((base, rest.to_vec()))
        }
        "self" => Some((module_dir_rel(rel), rest.to_vec())),
        "super" => {
            // The first `super` pops one level from the file's module
            // directory; each additional leading `super` pops another.
            let mut base = parent_rel(&module_dir_rel(rel)).to_string();
            let mut rest: Vec<String> = rest.to_vec();
            let mut i = 0;
            while i < rest.len() && rest[i] == "super" {
                base = parent_rel(&base).to_string();
                i += 1;
            }
            rest.drain(..i);
            Some((base, rest))
        }
        _ => None, // external crate (2018+ edition) -> ignore
    }
}

/// Map of importable crate names (both `foo-bar` and `foo_bar` forms) to
/// `(src_dir_rel, root_file_rel)` for every `Cargo.toml` under `root`.
/// Crude `[package] name` parsing - first `name = "..."` wins.
fn crate_map(root: &Path, names: &BTreeSet<String>) -> BTreeMap<String, (String, String)> {
    let mut manifests = Vec::new();
    collect_manifests(root, root, &mut manifests);
    let mut map = BTreeMap::new();
    for (dir_abs, dir_rel) in manifests {
        let Ok(text) = fs::read_to_string(dir_abs.join("Cargo.toml")) else {
            continue;
        };
        let Some(name) = parse_package_name(&text) else {
            continue;
        };
        // src/ dir if present, else the manifest dir itself.
        let src_abs = dir_abs.join("src");
        let src_rel = if src_abs.is_dir() {
            format!("{dir_rel}/src")
        } else {
            dir_rel.clone()
        };
        // Crate root file for fallback edges.
        let root_file = ["lib.rs", "main.rs"]
            .iter()
            .map(|f| format!("{src_rel}/{f}"))
            .find(|c| names.contains(c))
            .unwrap_or_else(|| format!("{src_rel}/lib.rs"));
        for key in [name.clone(), name.replace('-', "_")] {
            map.insert(key, (src_rel.clone(), root_file.clone()));
        }
    }
    map
}

fn collect_manifests(dir: &Path, root: &Path, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            collect_manifests(&path, root, out);
        } else if ft.is_file() && entry.file_name() == "Cargo.toml" {
            let rel = path
                .parent()
                .and_then(|p| p.strip_prefix(root).ok())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            out.push((path.parent().unwrap().to_path_buf(), rel));
        }
    }
}

/// First `name = "..."` in the file (the `[package]` name in practice).
fn parse_package_name(toml: &str) -> Option<String> {
    for line in toml.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let v = rest.trim().trim_matches('"');
                if !v.is_empty() && !v.contains(' ') {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Find the `src/` dir (root-relative) of the crate this file belongs
/// to: nearest ancestor containing `Cargo.toml`, plus `/src` when present.
/// Falls back to the scan root when no Cargo.toml is found.
fn crate_src_rel(abs: &Path, root: &Path) -> Option<String> {
    for dir in abs.ancestors().skip(1) {
        if dir.join("Cargo.toml").is_file() {
            let src = dir.join("src");
            if src.is_dir() {
                let rel = src.strip_prefix(root).ok()?.to_string_lossy().replace('\\', "/");
                return Some(rel);
            }
            let rel = dir.strip_prefix(root).ok()?.to_string_lossy().replace('\\', "/");
            return Some(rel);
        }
        if !dir.starts_with(root) {
            break;
        }
    }
    // No Cargo.toml under the scan root: treat the root itself as crate
    // root, using `src/` if it exists there.
    let src = root.join("src");
    if src.is_dir() {
        Some("src".to_string())
    } else {
        Some(String::new())
    }
}

// ---------- source scanning ----------

/// Join `base` (a `/`-separated rel dir) with `p`, resolving `.` and `..`.
/// Returns `None` if the result escapes the scan root.
fn normalize_rel(base: &str, p: &str) -> Option<String> {
    let mut segs: Vec<&str> = if base.is_empty() {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for s in p.split('/') {
        match s {
            "" | "." => {}
            ".." => {
                segs.pop()?;
            }
            x => segs.push(x),
        }
    }
    Some(segs.join("/"))
}

// ---------- tree-sitter extraction ----------
//
// Python and JS/TS imports are found by walking the concrete syntax
// tree, so comments, strings, and template literals can't create phantom
// edges and broken code degrades to ERROR nodes instead of wrong guesses.

/// Parse `text` with `lang`; returns the root node's sexp-visible tree.
/// `None` only if the parser itself fails (tree-sitter is error-tolerant,
/// so syntax errors still produce a usable tree).
fn parse_ts(text: &str, lang: tree_sitter::Language) -> Option<tree_sitter::Tree> {
    let mut p = tree_sitter::Parser::new();
    p.set_language(&lang).ok()?;
    p.parse(text, None)
}

/// Text of a string-ish node (`string`, `template_string`) with its
/// surrounding quotes/backticks stripped. `None` for empty specs.
fn spec_text(node: tree_sitter::Node, src: &str) -> Option<String> {
    let text = node.utf8_text(src.as_bytes()).ok()?;
    let inner = text
        .strip_prefix(|c| matches!(c, '\'' | '"' | '`'))
        .and_then(|s| s.strip_suffix(|c| matches!(c, '\'' | '"' | '`')))
        .unwrap_or(text);
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

/// Module specifier of an `import`/`export ... from` statement:
/// the `source` field's string content.
fn ts_source_spec(stmt: tree_sitter::Node, src: &str) -> Option<String> {
    spec_text(stmt.child_by_field_name("source")?, src)
}

/// Specifier of `require('x')` / `import('x')` call arguments.
fn ts_call_spec(call: tree_sitter::Node, src: &str) -> Option<String> {
    let func = call.child_by_field_name("function")?;
    let func_text = func.utf8_text(src.as_bytes()).ok()?;
    let is_require = func.kind() == "identifier" && func_text == "require";
    let is_dyn_import = func.kind() == "import";
    if !is_require && !is_dyn_import {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    // First string-ish argument.
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if matches!(child.kind(), "string" | "template_string") {
            return spec_text(child, src);
        }
    }
    None
}

/// All module specifiers in JS/TS source, via tree-sitter.
/// Returns `(specs, had_error)` - `had_error` means the tree contains
/// ERROR nodes, so the spec list may be incomplete.
fn js_import_specs_ts(text: &str, lang: tree_sitter::Language) -> (Vec<String>, bool) {
    let mut specs = Vec::new();
    let Some(tree) = parse_ts(text, lang) else {
        return (specs, true);
    };
    let had_error = tree.root_node().has_error();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "export_statement" => {
                if let Some(s) = ts_source_spec(node, text) {
                    specs.push(s);
                }
            }
            "call_expression" => {
                if let Some(s) = ts_call_spec(node, text) {
                    specs.push(s);
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    (specs, had_error)
}

// ---------- Python scanner ----------

const PY_EXTS: &[&str] = &["py"];

/// One import found by the tree-sitter Python parse.
enum PyRef {
    /// `import a.b.c` - full dotted path segments.
    Import(Vec<String>),
    /// `from <dots><mod> import <names>`: leading-dot count (0 =
    /// absolute), module segments (empty for `from . import x`), and
    /// imported names.
    From {
        level: usize,
        segs: Vec<String>,
        names: Vec<String>,
    },
}

/// All imports in Python source, via tree-sitter. Docstrings, comments,
/// and string contents can't produce phantom imports; syntax errors
/// degrade to ERROR nodes rather than wrong guesses.
fn py_import_refs(text: &str) -> (Vec<PyRef>, bool) {
    let mut out = Vec::new();
    let Some(tree) = parse_ts(text, tree_sitter_python::LANGUAGE.into()) else {
        return (out, true);
    };
    let had_error = tree.root_node().has_error();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" => {
                let mut cursor = node.walk();
                for name in node.children_by_field_name("name", &mut cursor) {
                    // `import a.b` or `import a.b as c`.
                    let dotted = if name.kind() == "aliased_import" {
                        name.child_by_field_name("name")
                    } else {
                        Some(name)
                    };
                    if let Some(d) = dotted {
                        if let Some(segs) = dotted_segs(d, text) {
                            out.push(PyRef::Import(segs));
                        }
                    }
                }
            }
            "import_from_statement" => {
                let level_segs = node
                    .child_by_field_name("module_name")
                    .and_then(|m| rel_mod_segs(m, text));
                let mut names = Vec::new();
                let mut cursor = node.walk();
                for name in node.children_by_field_name("name", &mut cursor) {
                    // dotted_name, aliased_import, or wildcard_import.
                    let dotted = if name.kind() == "aliased_import" {
                        name.child_by_field_name("name")
                    } else if name.kind() == "dotted_name" {
                        Some(name)
                    } else {
                        None
                    };
                    if let Some(d) = dotted {
                        if let Ok(t) = d.utf8_text(text.as_bytes()) {
                            let t = t.trim();
                            // Import names are single identifiers;
                            // anything dotted isn't a real name.
                            if !t.is_empty()
                                && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                            {
                                names.push(t.to_string());
                            }
                        }
                    }
                }
                if let Some((level, segs)) = level_segs {
                    out.push(PyRef::From { level, segs, names });
                }
            }
            "call" => {
                // Dynamic imports with literal arguments:
                // `import_module("a.b")`, `importlib.import_module("a.b")`,
                // `__import__("a.b")`. Non-literal args stay invisible.
                if let Some(segs) = py_dyn_import_segs(node, text) {
                    out.push(PyRef::Import(segs));
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    (out, had_error)
}

/// `a.b.c` node text -> segments, or `None` if not a plain dotted path.
fn dotted_segs(node: tree_sitter::Node, text: &str) -> Option<Vec<String>> {
    let t = node.utf8_text(text.as_bytes()).ok()?;
    let segs: Vec<String> = t
        .split('.')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if segs.is_empty() {
        None
    } else {
        Some(segs)
    }
}

/// `module_name` of a `from` import -> (leading-dot count, segments).
/// `from . import x` gives `(1, [])`; `from ..pkg.mod import y` gives
/// `(2, ["pkg","mod"])`; absolute gives `(0, [...])`.
fn rel_mod_segs(node: tree_sitter::Node, text: &str) -> Option<(usize, Vec<String>)> {
    let t = node.utf8_text(text.as_bytes()).ok()?;
    let level = t.chars().take_while(|&c| c == '.').count();
    let dotted = t[level..].trim();
    let segs: Vec<String> = if dotted.is_empty() {
        Vec::new()
    } else {
        dotted
            .split('.')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    Some((level, segs))
}

/// Dotted module path from a dynamic-import call:
/// `import_module("a.b")`, `importlib.import_module("a.b")`,
/// `__import__("a.b")`. Returns `None` for non-literal or
/// non-module-looking arguments.
fn py_dyn_import_segs(call: tree_sitter::Node, text: &str) -> Option<Vec<String>> {
    let func = call.child_by_field_name("function")?;
    let func_text = func.utf8_text(text.as_bytes()).ok()?;
    let is_dyn = func_text == "__import__"
        || func_text == "import_module"
        || func_text.ends_with(".import_module")
        || func_text.ends_with(".__import__");
    if !is_dyn {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() != "string" {
            continue;
        }
        let inner = py_string_inner(arg, text)?;
        // f-strings interpolate; a "{" means the path isn't literal.
        if inner.contains('{') {
            return None;
        }
        let segs: Vec<String> = inner
            .split('.')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let valid = !segs.is_empty()
            && segs
                .iter()
                .all(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        return valid.then_some(segs);
    }
    None
}

/// String literal content without quotes or prefix (`r"x"`, `'''x'''`).
fn py_string_inner(node: tree_sitter::Node, text: &str) -> Option<String> {
    let raw = node.utf8_text(text.as_bytes()).ok()?;
    let bytes = raw.as_bytes();
    let mut i = 0;
    // Skip string prefix chars (r, b, f, u and uppercase combos).
    while i < bytes.len() && matches!(bytes[i], b'r' | b'R' | b'b' | b'B' | b'f' | b'F' | b'u' | b'U') {
        i += 1;
    }
    let rest = &raw[i..];
    let quote_len = if rest.starts_with("'''") || rest.starts_with("\"\"\"") {
        3
    } else if rest.starts_with('\'') || rest.starts_with('"') {
        1
    } else {
        return None;
    };
    let inner = &rest[quote_len..];
    inner
        .get(..inner.len().saturating_sub(quote_len))
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn scan_python_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, PY_EXTS, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let mut edges: EdgeList = Vec::new();
    let mut warnings = Vec::new();

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
        let (refs, had_error) = py_import_refs(&text);
        if had_error {
            warnings.push(format!("{rel}: parse errors (partial scan)"));
        }
        let mut deps: BTreeSet<String> = BTreeSet::new();
        let parent = parent_rel(rel);

        for r in refs {
            match r {
                PyRef::Import(segs) => {
                    // `import a.b.c` needs the full path to resolve; try
                    // each ancestor dir as a package root (sys.path
                    // heuristic).
                    for b in ancestor_bases(rel) {
                        if let Some(dep) = resolve_py_exact(&names, &b, &segs) {
                            if dep != *rel {
                                deps.insert(dep);
                            }
                            break;
                        }
                    }
                }
                PyRef::From { level, segs, names: imps } => {
                    add_py_from(&names, rel, parent, level, &segs, &imps, &mut deps);
                }
            }
        }

        for dep in deps {
            edges.push((rel.clone(), dep, None));
        }
    }
    let nodes = names.into_iter().collect();
    Ok(ScanOutput { edges, nodes, warnings })
}

/// Resolve a `from <dots><mod> import <names>` against the file set.
/// `level` is the count of leading dots (0 = absolute import, which
/// tries every ancestor dir as a package root like `sys.path`).
fn add_py_from(
    names: &BTreeSet<String>,
    rel: &str,
    parent: &str,
    level: usize,
    segs: &[String],
    imps: &[String],
    deps: &mut BTreeSet<String>,
) {
    let mut base = parent.to_string();
    for _ in 1..level {
        base = parent_rel(&base).to_string();
    }
    // Absolute imports (`from x.y import`, level 0) resolve against
    // every ancestor dir of this file, like Python's sys.path -
    // the package root may be a subdirectory (e.g. `repo/pkg/pkg/`).
    // Relative imports keep their computed base only.
    let bases: Vec<String> = if level == 0 {
        ancestor_bases(rel)
    } else {
        vec![base]
    };
    // Module file for `from X import ...`.
    if !segs.is_empty() {
        for b in &bases {
            if let Some(dep) = resolve_py(names, b, segs) {
                if dep != rel {
                    deps.insert(dep);
                }
                break;
            }
        }
        // `from pkg import sub` may pull pkg/sub.py too.
        for name in imps {
            let mut ns = segs.to_vec();
            ns.push(name.clone());
            for b in &bases {
                if let Some(dep) = resolve_py(names, b, &ns) {
                    if dep != rel {
                        deps.insert(dep);
                    }
                    break;
                }
            }
        }
    } else {
        // `from . import x, y` - names are modules under base.
        for name in imps {
            for b in &bases {
                if let Some(dep) = resolve_py(names, b, std::slice::from_ref(name)) {
                    if dep != rel {
                        deps.insert(dep);
                    }
                    break;
                }
            }
        }
    }
}

/// Ancestor directories of `rel` (root-relative file path), deepest
/// first, ending with `""` (the scan root). Candidate package roots for
/// absolute Python imports - mirrors how `sys.path` can contain any
/// ancestor of the importing file (e.g. `repo/pkg/pkg/` layouts where
/// the top-level package lives one level down).
fn ancestor_bases(rel: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut dir = parent_rel(rel).to_string();
    loop {
        out.push(dir.clone());
        if dir.is_empty() {
            break;
        }
        dir = parent_rel(&dir).to_string();
    }
    out
}

/// Resolve a dotted Python module path under `base` ("" = root), trying
/// the longest prefix first: `a/b/c.py`, `a/b/c/__init__.py`, then
/// shorter prefixes ending at a `.py` or `__init__.py`.
fn resolve_py(names: &BTreeSet<String>, base: &str, segs: &[String]) -> Option<String> {
    for k in (1..=segs.len()).rev() {
        let p = join_rel(base, &segs[..k]);
        for cand in [format!("{p}.py"), format!("{p}/__init__.py")] {
            if names.contains(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

/// Exact full-path resolution for `import a.b.c` statements.
fn resolve_py_exact(names: &BTreeSet<String>, base: &str, segs: &[String]) -> Option<String> {
    let p = join_rel(base, segs);
    for cand in [format!("{p}.py"), format!("{p}/__init__.py")] {
        if names.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

// ---------- JS/TS scanner ----------

const JS_EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

fn scan_js_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, JS_EXTS, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let mut edges: EdgeList = Vec::new();
    let mut warnings = Vec::new();
    let mut alias_cache = JsAliasCache::new(root);

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
        let (specs, had_error) = js_import_specs_ts(&text, js_language_for(rel));
        if had_error {
            warnings.push(format!("{rel}: parse errors (partial scan)"));
        }
        let mut deps: BTreeSet<String> = BTreeSet::new();
        let parent = parent_rel(rel);
        let resolver = alias_cache.for_dir(parent);

        for spec in specs {
            // Relative specs ('./x', '../x') are always intra-project.
            if spec.starts_with(".") {
                let Some(norm) = normalize_rel(parent, &spec) else {
                    continue;
                };
                if let Some(dep) = resolve_js(&names, &norm) {
                    if dep != *rel {
                        deps.insert(dep);
                    }
                }
                continue;
            }
            // Bare specifiers: package.json `imports`, tsconfig `paths`
            // aliases and `baseUrl` resolve intra-project; anything
            // else is node_modules.
            if let Some(dep) = resolve_js_alias(&resolver, &names, &spec) {
                if dep != *rel {
                    deps.insert(dep);
                }
            }
        }

        for dep in deps {
            edges.push((rel.clone(), dep, None));
        }
    }
    let nodes = names.into_iter().collect();
    Ok(ScanOutput { edges, nodes, warnings })
}

/// tree-sitter grammar for a JS/TS file extension.
fn js_language_for(rel: &str) -> tree_sitter::Language {
    match rel.rsplit('.').next() {
        Some("ts") => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Some("tsx") => tree_sitter_typescript::LANGUAGE_TSX.into(),
        _ => tree_sitter_javascript::LANGUAGE.into(),
    }
}

/// Resolve a normalized relative JS spec to a file: exact, +ext, /index+ext.
fn resolve_js(names: &BTreeSet<String>, norm: &str) -> Option<String> {
    if names.contains(norm) {
        return Some(norm.to_string());
    }
    for ext in JS_EXTS {
        let cand = format!("{norm}.{ext}");
        if names.contains(&cand) {
            return Some(cand);
        }
    }
    for ext in JS_EXTS {
        let cand = format!("{norm}/index.{ext}");
        if names.contains(&cand) {
            return Some(cand);
        }
    }
    None
}



// ---------- JS/TS alias resolution ----------
//
// Bare import specifiers (`@/foo`, `#alias`) resolve intra-project via
// `tsconfig.json`/`jsconfig.json` `compilerOptions.paths` + `baseUrl`
// and `package.json` `"imports"`. Configs are looked up per file: the
// nearest ancestor directory wins (monorepo support), `extends` chains
// are followed, and tsconfig's JSONC syntax (comments, trailing
// commas) is tolerated.

/// One `paths`/`imports` pattern: literal `prefix` + optional `*` +
/// literal `suffix`. `star = false` means exact-match only.
#[derive(Clone)]
struct PathPattern {
    prefix: String,
    suffix: String,
    star: bool,
    targets: Vec<String>,
}

/// If `spec` matches `pat`, return the text captured by `*`
/// (empty string for exact patterns).
fn pattern_star_text(pat: &PathPattern, spec: &str) -> Option<String> {
    if pat.star {
        if !spec.starts_with(&pat.prefix) || !spec.ends_with(&pat.suffix) {
            return None;
        }
        let end = spec.len() - pat.suffix.len();
        if end < pat.prefix.len() {
            return None;
        }
        Some(spec[pat.prefix.len()..end].to_string())
    } else if spec == pat.prefix {
        Some(String::new())
    } else {
        None
    }
}

/// Effective tsconfig/jsconfig aliases for one directory scope.
#[derive(Clone, Default)]
struct TsAliases {
    /// Root-relative dir that `paths` targets and `baseUrl`-relative
    /// bare specifiers resolve against.
    base: String,
    /// `baseUrl` was explicitly set - unmatched bare specifiers fall
    /// back to `base/spec` (classic baseUrl resolution).
    has_base_url: bool,
    patterns: Vec<PathPattern>,
}

/// `package.json` `"imports"` aliases; targets resolve against `base`
/// (the package.json's directory).
#[derive(Clone, Default)]
struct PkgImports {
    base: String,
    patterns: Vec<PathPattern>,
}

/// Per-directory resolver: nearest tsconfig aliases + nearest
/// package.json imports, found by walking up to the scan root.
#[derive(Clone, Default)]
struct JsResolver {
    ts: Option<TsAliases>,
    pkg: Option<PkgImports>,
}

/// Cache of resolvers keyed by root-relative directory ("" = root).
struct JsAliasCache<'a> {
    root: &'a Path,
    map: std::collections::HashMap<String, std::rc::Rc<JsResolver>>,
}

impl<'a> JsAliasCache<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            map: std::collections::HashMap::new(),
        }
    }

    /// Resolver for a file living in root-relative dir `dir`.
    fn for_dir(&mut self, dir: &str) -> std::rc::Rc<JsResolver> {
        if let Some(r) = self.map.get(dir) {
            return r.clone();
        }
        let r = std::rc::Rc::new(self.resolve_for(dir));
        self.map.insert(dir.to_string(), r.clone());
        r
    }

    fn resolve_for(&self, dir: &str) -> JsResolver {
        let mut ts = None;
        let mut pkg = None;
        for anc in ancestors(dir) {
            if ts.is_none() {
                ts = self.load_tsconfig(&anc);
            }
            if pkg.is_none() {
                pkg = self.load_pkg_imports(&anc);
            }
            if ts.is_some() && pkg.is_some() {
                break;
            }
        }
        JsResolver { ts, pkg }
    }

    /// Nearest `tsconfig.json`/`jsconfig.json` at or above `dir`.
    fn load_tsconfig(&self, dir: &str) -> Option<TsAliases> {
        for name in ["tsconfig.json", "jsconfig.json"] {
            let p = self.root.join(dir).join(name);
            if p.is_file() {
                let mut seen = BTreeSet::new();
                let merged = read_tsconfig(self.root, &p, dir, 0, &mut seen)?;
                return merged.into_aliases();
            }
        }
        None
    }

    /// Nearest `package.json` with an `"imports"` field at or above `dir`.
    fn load_pkg_imports(&self, dir: &str) -> Option<PkgImports> {
        let p = self.root.join(dir).join("package.json");
        if !p.is_file() {
            return None;
        }
        let text = fs::read_to_string(&p).ok()?;
        let json: serde_json::Value = serde_json::from_str(&jsonc(&text)).ok()?;
        let imports = json.get("imports")?.as_object()?;
        if imports.is_empty() {
            return None;
        }
        let mut patterns = Vec::new();
        for (key, val) in imports {
            let target = pkg_import_target(val)?;
            patterns.push(path_pattern(key.clone(), vec![target]));
        }
        Some(PkgImports {
            base: dir.to_string(),
            patterns,
        })
    }
}

/// `dir` and each ancestor up to "" (inclusive), nearest first.
fn ancestors(dir: &str) -> Vec<&str> {
    let mut out = vec![dir];
    let mut cur = dir;
    while let Some((parent, _)) = cur.rsplit_once('/') {
        out.push(parent);
        cur = parent;
    }
    if !dir.is_empty() {
        out.push("");
    }
    out
}

/// Extract the resolution target from a package.json `imports` value:
/// a plain string, or a conditions object (`import`/`require`/`node`/
/// `default` preferred, then any string value, one nesting level deep).
fn pkg_import_target(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => {
            for key in ["import", "require", "node", "default"] {
                if let Some(t) = map.get(key).and_then(pkg_import_target) {
                    return Some(t);
                }
            }
            map.values().find_map(pkg_import_target)
        }
        _ => None,
    }
}

/// Build a [`PathPattern`] from a `paths`/`imports` key and targets.
fn path_pattern(key: String, targets: Vec<String>) -> PathPattern {
    if let Some(star) = key.find('*') {
        PathPattern {
            prefix: key[..star].to_string(),
            suffix: key[star + 1..].to_string(),
            star: true,
            targets,
        }
    } else {
        PathPattern {
            prefix: key,
            suffix: String::new(),
            star: false,
            targets,
        }
    }
}

/// One level of a tsconfig `extends` chain.
struct TsConfig {
    base_url: Option<(String, String)>, // (declaring dir, value)
    paths: Option<(String, Vec<(String, Vec<String>)>)>, // (declaring dir, entries)
}

fn read_tsconfig(
    root: &Path,
    abs: &Path,
    dir_rel: &str,
    depth: u8,
    seen: &mut BTreeSet<PathBuf>,
) -> Option<TsConfig> {
    if depth > 8 || !seen.insert(abs.to_path_buf()) {
        return None;
    }
    let text = fs::read_to_string(abs).ok()?;
    let json: serde_json::Value = serde_json::from_str(&jsonc(&text)).ok()?;
    let empty = serde_json::Value::Null;
    let opts = json.get("compilerOptions").unwrap_or(&empty);

    // `extends` first: parent values apply unless the child overrides.
    let mut merged = TsConfig {
        base_url: None,
        paths: None,
    };
    if let Some(ext) = json.get("extends").and_then(|e| e.as_str()) {
        if let Some(parent_abs) = resolve_extends(root, abs, dir_rel, ext) {
            let parent_dir = parent_abs
                .parent()
                .and_then(|p| p.strip_prefix(root).ok())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            if let Some(parent) =
                read_tsconfig(root, &parent_abs, &parent_dir, depth + 1, seen)
            {
                merged = parent;
            }
        }
    }

    if let Some(v) = opts.get("baseUrl").and_then(|v| v.as_str()) {
        merged.base_url = Some((dir_rel.to_string(), v.to_string()));
    }
    if let Some(map) = opts.get("paths").and_then(|v| v.as_object()) {
        let entries: Vec<(String, Vec<String>)> = map
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|t| t.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                )
            })
            .collect();
        merged.paths = Some((dir_rel.to_string(), entries));
    }
    Some(merged)
}

/// Resolve an `extends` value to a file: relative to the config's dir,
/// with or without a `.json` suffix, or under `node_modules`.
fn resolve_extends(
    root: &Path,
    cfg_abs: &Path,
    dir_rel: &str,
    ext: &str,
) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if ext.starts_with('.') {
        let base = cfg_abs.parent()?;
        for suffix in ["", ".json", "/tsconfig.json"] {
            candidates.push(base.join(format!("{ext}{suffix}")));
        }
    } else {
        for suffix in ["", ".json"] {
            candidates.push(root.join("node_modules").join(format!("{ext}{suffix}")));
        }
        let _ = dir_rel;
    }
    candidates.into_iter().find(|p| p.is_file())
}

impl TsConfig {
    fn into_aliases(self) -> Option<TsAliases> {
        // Effective base dir: declaring config's dir + its baseUrl
        // (baseUrl defaults to the declaring config's dir when only
        // `paths` is set, per TS >= 4.1).
        let (base, has_base_url) = match &self.base_url {
            Some((dir, url)) => {
                let joined = normalize_rel(dir, url).unwrap_or_else(|| dir.clone());
                (joined, true)
            }
            None => match &self.paths {
                Some((dir, _)) => (dir.clone(), false),
                None => return None,
            },
        };
        let patterns = self
            .paths
            .map(|(_, entries)| {
                entries
                    .into_iter()
                    .map(|(key, targets)| path_pattern(key, targets))
                    .collect()
            })
            .unwrap_or_default();
        Some(TsAliases {
            base,
            has_base_url,
            patterns,
        })
    }
}

/// Resolve a bare (non-relative) specifier: package.json `"imports"`
/// for `#`-prefixed specs first, then tsconfig `paths` (longest
/// matching prefix wins, TypeScript semantics), then `baseUrl`
/// fallback for unmatched specifiers.
fn resolve_js_alias(
    resolver: &JsResolver,
    names: &BTreeSet<String>,
    spec: &str,
) -> Option<String> {
    if spec.starts_with('#') {
        if let Some(pkg) = &resolver.pkg {
            if let Some(dep) = resolve_patterns(&pkg.patterns, &pkg.base, names, spec) {
                return Some(dep);
            }
        }
    }
    if let Some(ts) = &resolver.ts {
        if let Some(dep) = resolve_patterns(&ts.patterns, &ts.base, names, spec) {
            return Some(dep);
        }
        // baseUrl fallback applies only to specifiers no pattern matched.
        let matched = ts.patterns.iter().any(|p| pattern_star_text(p, spec).is_some());
        if ts.has_base_url && !matched {
            if let Some(norm) = normalize_rel(&ts.base, spec.trim_start_matches('/')) {
                return resolve_js(names, &norm);
            }
        }
    }
    None
}

/// Try patterns by longest matching prefix (TS semantics): collect all
/// matches, pick the longest prefix, try its targets in order.
fn resolve_patterns(
    patterns: &[PathPattern],
    base: &str,
    names: &BTreeSet<String>,
    spec: &str,
) -> Option<String> {
    let mut best: Option<(&PathPattern, String)> = None;
    for pat in patterns {
        let Some(star_text) = pattern_star_text(pat, spec) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some((bp, _)) => pat.prefix.len() > bp.prefix.len(),
        };
        if better {
            best = Some((pat, star_text));
        }
    }
    let (pat, star_text) = best?;
    for target in &pat.targets {
        let t = if pat.star {
            target.replacen('*', &star_text, 1)
        } else {
            target.clone()
        };
        let t = t.trim_start_matches('/');
        if let Some(norm) = normalize_rel(base, t) {
            if let Some(dep) = resolve_js(names, &norm) {
                return Some(dep);
            }
        }
    }
    None
}

/// Strip JSONC-only syntax (line/block comments, trailing commas)
/// outside string literals so `serde_json` can parse tsconfig files.
fn jsonc(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
                i += 1;
            }
            '/' if i + 1 < b.len() && b[i + 1] == '/' => {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < b.len() && b[i + 1] == '*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            ',' => {
                // Drop the comma if the next significant token is } or ]
                // (skipping whitespace and comments).
                let mut j = i + 1;
                loop {
                    while j < b.len() && b[j].is_whitespace() {
                        j += 1;
                    }
                    if j + 1 < b.len() && b[j] == '/' && b[j + 1] == '/' {
                        while j < b.len() && b[j] != '\n' {
                            j += 1;
                        }
                        continue;
                    }
                    if j + 1 < b.len() && b[j] == '/' && b[j + 1] == '*' {
                        j += 2;
                        while j + 1 < b.len() && !(b[j] == '*' && b[j + 1] == '/') {
                            j += 1;
                        }
                        j = (j + 2).min(b.len());
                        continue;
                    }
                    break;
                }
                if j < b.len() && (b[j] == '}' || b[j] == ']') {
                    i += 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}
