//! Rust source scanner: walks a directory tree, resolves `mod` and `use`
//! statements to files, and emits an [`EdgeList`] where `A -> B` means
//! "file A depends on file B".
//!
//! Node names are root-relative paths with forward slashes
//! (e.g. `crates/strand-core/src/graph.rs`), which keeps builds
//! deterministic across platforms and names unique.
//!
//! This is deliberately a pattern-matching scanner, not a full Rust
//! parser: it strips comments, finds `mod foo;` declarations and `use`
//! paths, and resolves them with Rust 2018 path rules. `#[path]`
//! attributes, macros that expand to modules, and `include!` are not
//! followed. External crates (`use serde::...`) are ignored.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use strand_core::{Error, Result};

use crate::EdgeList;

/// Directories never descended into.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Output of a scan: edges plus every source file found (so files
/// with no dependencies still become nodes in the graph).
pub struct ScanOutput {
    pub edges: EdgeList,
    /// All discovered source files as root-relative `/` paths, sorted.
    pub nodes: Vec<String>,
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
    for &lang in langs {
        let out = scan_lang(root, lang)?;
        edges.extend(out.edges);
        nodes.extend(out.nodes);
    }
    nodes.sort();
    nodes.dedup();
    Ok(ScanOutput { edges, nodes })
}

fn scan_rust_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["rs"], &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let crates = crate_map(root, &names);
    let mut edges: EdgeList = Vec::new();

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
        // `lex_rs` produces two views: `clean` (comments stripped, string
        // contents kept for `#[path]`/`include!`) and `masked` (string
        // contents blanked, positions preserved) for `mod`/`use` scanning
        // so tokens inside literals can't create phantom edges.
        let (clean, masked) = lex_rs(&text);
        let mut deps: BTreeSet<String> = BTreeSet::new();

        // `mod foo;` declarations -> foo.rs or foo/mod.rs under this
        // file's module directory. A preceding `#[path = "..."]`
        // attribute overrides the location.
        let mdir = module_dir_rel(rel);
        let attrs = path_attrs(&clean);
        for (idx, seg) in mod_decls(&masked) {
            // The attribute applies only if nothing item-like sits
            // between it and this `mod` (no `;`, `{`, `}`).
            let custom = attrs
                .iter()
                .rev()
                .find(|(_, ae, _)| {
                    *ae < idx
                        && !masked
                            .chars()
                            .skip(*ae)
                            .take(idx - ae)
                            .any(|c| matches!(c, ';' | '{' | '}'))
                })
                .map(|(_, _, p)| p.as_str());
            let dep = match custom {
                Some(p) => normalize_rel(&mdir, p).filter(|c| names.contains(c)),
                None => resolve(&names, &mdir, std::slice::from_ref(&seg)),
            };
            if let Some(dep) = dep {
                if dep != *rel {
                    deps.insert(dep);
                }
            }
        }

        // `include!("file.rs")` pulls the file's contents into this one.
        let parent = parent_rel(rel);
        for inc in include_paths(&clean) {
            if let Some(dep) = normalize_rel(parent, &inc).filter(|c| names.contains(c)) {
                if dep != *rel {
                    deps.insert(dep);
                }
            }
        }

        // `use` paths.
        for segments in use_paths(&masked) {
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
    Ok(ScanOutput { edges, nodes })
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
/// match — so `use crate::a::b::Item` resolves to `a/b.rs` if it exists,
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
/// Crude `[package] name` parsing — first `name = "..."` wins.
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

/// Remove `//` line comments and `/* */` block comments. Char-based so
/// non-ASCII source survives intact; string literals are not understood
/// — a known limitation of the pattern approach.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Lex Rust source into two aligned views:
///
/// - `clean`: comments removed, everything else verbatim (string contents
///   kept — `#[path]`/`include!` extraction needs them).
/// - `masked`: identical to `clean` except string/raw-string *contents*
///   are blanked to spaces (length and char positions preserved), so
///   `mod`/`use` scanning can't see tokens inside literals.
///
/// Handles line comments, nested block comments, normal strings with
/// escapes, byte strings (`b".."` — the `b` is just a normal char), raw
/// strings (`r".."`, `r#".."#`, `br#".."#`), char literals vs lifetimes
/// (`'x'` vs `'a`), and non-ASCII text (char-based, not bytes).
fn lex_rs(src: &str) -> (String, String) {
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let mut clean = String::with_capacity(src.len());
    let mut masked = String::with_capacity(src.len());
    let mut i = 0;
    while i < n {
        let c = b[i];
        // Line comment: dropped from both views.
        if c == '/' && i + 1 < n && b[i + 1] == '/' {
            while i < n && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // Block comment (Rust nests them): dropped from both views.
        if c == '/' && i + 1 < n && b[i + 1] == '*' {
            let mut depth = 1usize;
            i += 2;
            while i < n && depth > 0 {
                if i + 1 < n && b[i] == '/' && b[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < n && b[i] == '*' && b[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // Raw string: r"..", r#".."#, r##".."##, or br".."/br#".."#.
        if let Some(end) = raw_string_end(&b, i) {
            let lit: String = b[i..end].iter().collect();
            clean.push_str(&lit);
            masked.push_str(&blank_literal(&lit));
            i = end;
            continue;
        }
        // Normal string literal (also covers b".." — `b` is emitted as a
        // normal char on the previous iteration).
        if c == '"' {
            let start = i;
            i += 1;
            while i < n {
                if b[i] == '\\' {
                    i = (i + 2).min(n);
                    continue;
                }
                if b[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let lit: String = b[start..i.min(n)].iter().collect();
            clean.push_str(&lit);
            masked.push_str(&blank_literal(&lit));
            continue;
        }
        // Char literal ('x', '\n', '\'', '"') vs lifetime ('a, 'static).
        if c == '\'' {
            if let Some(end) = char_literal_end(&b, i) {
                let lit: String = b[i..end].iter().collect();
                clean.push_str(&lit);
                masked.push_str(&lit);
                i = end;
                continue;
            }
            clean.push('\'');
            masked.push('\'');
            i += 1;
            continue;
        }
        clean.push(c);
        masked.push(c);
        i += 1;
    }
    (clean, masked)
}

/// `lit` with its interior blanked to spaces (quotes/delimiters kept,
/// newlines preserved). Used for the `masked` view of string literals.
fn blank_literal(lit: &str) -> String {
    let chars: Vec<char> = lit.chars().collect();
    if chars.len() <= 2 {
        return lit.to_string();
    }
    let mut out = String::with_capacity(lit.len());
    out.push(chars[0]);
    for &ch in &chars[1..chars.len() - 1] {
        out.push(if ch == '\n' { '\n' } else { ' ' });
    }
    out.push(chars[chars.len() - 1]);
    out
}

/// If a raw string starts at `b[i]` (`r"`, `r#"`, `r##"`, ..., or the
/// `br` byte-string variants), return the index just past its closing
/// `"` + `#`s. Requires a non-identifier char before `r`/`b` so `parser`
/// or `foobar` can't fake one.
fn raw_string_end(b: &[char], i: usize) -> Option<usize> {
    let n = b.len();
    let mut j = i;
    // Optional `b` prefix for byte raw strings.
    if j < n && b[j] == 'b' && j + 1 < n && b[j + 1] == 'r' {
        j += 1;
    }
    if j >= n || b[j] != 'r' {
        return None;
    }
    // Boundary: the `r` (or `b`) must not continue an identifier.
    if i > 0 && is_ident(b[i - 1]) {
        return None;
    }
    j += 1;
    let mut hashes = 0usize;
    while j < n && b[j] == '#' {
        hashes += 1;
        j += 1;
    }
    if j >= n || b[j] != '"' {
        return None;
    }
    // Find closing `"` followed by exactly `hashes` '#'s.
    let mut k = j + 1;
    while k < n {
        if b[k] == '"'
            && k + 1 + hashes <= n
            && b[k + 1..k + 1 + hashes].iter().all(|&c| c == '#')
        {
            return Some(k + 1 + hashes);
        }
        k += 1;
    }
    None // unterminated: treat rest of file as not-a-string
}

/// If a char literal starts at `b[i]` (`'x'`, `'\n'`, `'\''`, `'"'`,
/// `'\u{..}'`), return the index just past the closing `'`. Anything
/// else starting with `'` is treated as a lifetime/label and returns
/// `None` so the `'` is emitted as a normal char.
fn char_literal_end(b: &[char], i: usize) -> Option<usize> {
    let n = b.len();
    if i + 1 >= n {
        return None;
    }
    if b[i + 1] == '\\' {
        // Escape form: '\<stuff>' — find the closing quote soon after.
        let mut j = i + 2;
        while j < n && j <= i + 14 {
            if b[j] == '\'' {
                return Some(j + 1);
            }
            j += 1;
        }
        return None;
    }
    // Simple form: '<one char>' — exactly one char between the quotes.
    if i + 2 < n && b[i + 2] == '\'' {
        return Some(i + 3);
    }
    None
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// All `mod name;` declarations as `(char_index, name)` pairs
/// (skips inline `mod name { ... }`).
fn mod_decls(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let mut i = 0;
    while i < n {
        // word "mod" at a boundary
        if b[i] == 'm'
            && (i == 0 || !is_ident(b[i - 1]))
            && i + 3 <= n
            && b[i..i + 3] == ['m', 'o', 'd']
            && (i + 3 >= n || !is_ident(b[i + 3]))
        {
            let mut j = i + 3;
            while j < n && b[j].is_whitespace() {
                j += 1;
            }
            let start = j;
            while j < n && is_ident(b[j]) {
                j += 1;
            }
            if j > start {
                let mut k = j;
                while k < n && b[k].is_whitespace() {
                    k += 1;
                }
                if k < n && b[k] == ';' {
                    out.push((i, b[start..j].iter().collect()));
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

/// All `use` paths as segment lists (`use a::b::{c}` yields `["a","b"]`).
fn use_paths(src: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let mut i = 0;
    while i < n {
        if b[i] == 'u'
            && (i == 0 || !is_ident(b[i - 1]))
            && i + 3 <= n
            && b[i..i + 3] == ['u', 's', 'e']
            && (i + 3 >= n || b[i + 3].is_whitespace())
        {
            let mut j = i + 3;
            while j < n && b[j].is_whitespace() {
                j += 1;
            }
            // Collect path chars: idents, '_', and ':'.
            let start = j;
            while j < n && (is_ident(b[j]) || b[j] == ':') {
                j += 1;
            }
            let raw: String = b[start..j].iter().collect();
            let segs: Vec<String> = raw
                .split("::")
                .filter(|s| !s.is_empty())
                .map(|s| s.trim_start_matches(':').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !segs.is_empty() {
                out.push(segs);
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}


/// `#[path = "..."]` attributes as `(start, end, path)` triples; `end` is
/// the char index just past the closing quote.
fn path_attrs(src: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let mut i = 0;
    while i + 6 < n {
        if b[i] == '#' && b[i + 1] == '[' {
            // Look for `path` then `=` then a quoted string before `]`.
            let mut j = i + 2;
            while j < n && b[j].is_whitespace() {
                j += 1;
            }
            if j + 4 <= n && b[j..j + 4].iter().collect::<String>() == "path" {
                j += 4;
                while j < n && (b[j].is_whitespace() || b[j] == '=') {
                    j += 1;
                }
                if j < n && (b[j] == '"' || b[j] == '\'') {
                    let q = b[j];
                    let start = j + 1;
                    let mut k = start;
                    while k < n && b[k] != q {
                        k += 1;
                    }
                    if k < n {
                        out.push((i, k + 1, b[start..k].iter().collect()));
                        i = k;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

/// Paths inside `include!("...")` macro calls.
fn include_paths(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let needle = ['i', 'n', 'c', 'l', 'u', 'd', 'e', '!'];
    let mut i = 0;
    while i + needle.len() < n {
        if (i == 0 || !is_ident(b[i - 1]))
            && b[i..i + needle.len()] == needle
            && (i + needle.len() >= n || !is_ident(b[i + needle.len()]))
        {
            let mut j = i + needle.len();
            while j < n && b[j].is_whitespace() {
                j += 1;
            }
            if j < n && b[j] == '(' {
                j += 1;
                while j < n && b[j].is_whitespace() {
                    j += 1;
                }
                if j < n && (b[j] == '"' || b[j] == '\'') {
                    let q = b[j];
                    let start = j + 1;
                    let mut k = start;
                    while k < n && b[k] != q {
                        k += 1;
                    }
                    if k < n {
                        out.push(b[start..k].iter().collect());
                        i = k;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

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

// ---------- Python scanner ----------

const PY_EXTS: &[&str] = &["py"];

fn scan_python_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, PY_EXTS, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let mut edges: EdgeList = Vec::new();

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
        let clean = strip_hash_comments(&text);
        let mut deps: BTreeSet<String> = BTreeSet::new();
        let parent = parent_rel(rel);

        for line in clean.lines() {
            let line = line.trim();
            // `from <dots><mod> import <names>` (also `from x import (a,b)`).
            if let Some(rest) = line.strip_prefix("from ") {
                let Some((mod_part, names_part)) = rest.split_once(" import") else {
                    continue;
                };
                let level = mod_part.chars().take_while(|&c| c == '.').count();
                let dotted = mod_part[level..].trim();
                let mut base = parent.to_string();
                for _ in 1..level {
                    base = parent_rel(&base).to_string();
                }
                let segs: Vec<String> = dotted
                    .split('.')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                // Module file for `from X import ...`.
                if !segs.is_empty() {
                    if let Some(dep) = resolve_py(&names, &base, &segs) {
                        if dep != *rel {
                            deps.insert(dep);
                        }
                    }
                    // `from pkg import sub` may pull pkg/sub.py too.
                    for name in import_names(names_part) {
                        let mut ns = segs.clone();
                        ns.push(name);
                        if let Some(dep) = resolve_py(&names, &base, &ns) {
                            if dep != *rel {
                                deps.insert(dep);
                            }
                        }
                    }
                } else {
                    // `from . import x, y` — names are modules under base.
                    for name in import_names(names_part) {
                        if let Some(dep) = resolve_py(&names, &base, &[name]) {
                            if dep != *rel {
                                deps.insert(dep);
                            }
                        }
                    }
                }
                continue;
            }
            // `import a.b.c` (possibly comma-separated list).
            if let Some(rest) = line.strip_prefix("import ") {
                for item in rest.split(',') {
                    let item = item.trim();
                    let dotted = item.split(" as ").next().unwrap_or(item).trim();
                    if dotted.is_empty() || dotted.starts_with('.') {
                        continue; // relative `import .x` is invalid syntax anyway
                    }
                    let segs: Vec<String> = dotted
                        .split('.')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    if segs.is_empty() {
                        continue;
                    }
                    // `import a.b.c` needs the full path to resolve.
                    if let Some(dep) = resolve_py_exact(&names, "", &segs) {
                        if dep != *rel {
                            deps.insert(dep);
                        }
                    }
                }
            }
        }

        for dep in deps {
            edges.push((rel.clone(), dep, None));
        }
    }
    let nodes = names.into_iter().collect();
    Ok(ScanOutput { edges, nodes })
}

/// Names in a `from X import ...` clause: `a, b as c, (d, e)`.
fn import_names(s: &str) -> Vec<String> {
    s.trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(',')
        .filter_map(|part| {
            let name = part.split(" as ").next().unwrap_or(part).trim();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
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

/// Strip `#` line comments (naive: `#` inside strings is not understood).
fn strip_hash_comments(src: &str) -> String {
    src.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------- JS/TS scanner ----------

const JS_EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

fn scan_js_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, JS_EXTS, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let mut edges: EdgeList = Vec::new();
    let mut alias_cache = JsAliasCache::new(root);

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
        let clean = strip_comments(&text);
        let mut deps: BTreeSet<String> = BTreeSet::new();
        let parent = parent_rel(rel);
        let resolver = alias_cache.for_dir(parent);

        for spec in js_import_specs(&clean) {
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
    Ok(ScanOutput { edges, nodes })
}

/// All module specifiers in `import ... from 'x'`, `import 'x'`,
/// `import('x')`, `export ... from 'x'`, and `require('x')`.
fn js_import_specs(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let mut i = 0;
    while i < n {
        for kw in ["from", "import", "require"] {
            let klen = kw.len();
            if i + klen > n
                || (i > 0 && is_ident(b[i - 1]))
                || b[i..i + klen].iter().collect::<String>() != kw
                || (i + klen < n && is_ident(b[i + klen]))
            {
                continue;
            }
            let mut j = i + klen;
            while j < n && b[j].is_whitespace() {
                j += 1;
            }
            // Skip an optional `(` (dynamic import / require call).
            if j < n && b[j] == '(' {
                j += 1;
                while j < n && b[j].is_whitespace() {
                    j += 1;
                }
            }
            if j < n && (b[j] == '\'' || b[j] == '"') {
                let q = b[j];
                let start = j + 1;
                let mut k = start;
                while k < n && b[k] != q && b[k] != '\n' {
                    k += 1;
                }
                if k < n && b[k] == q {
                    out.push(b[start..k].iter().collect());
                    i = k;
                }
            }
            break; // matched a keyword; move on regardless
        }
        i += 1;
    }
    out
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
    /// `baseUrl` was explicitly set — unmatched bare specifiers fall
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
