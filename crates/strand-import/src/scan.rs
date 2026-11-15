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
            .map_err(|e| Error::Invalid(format!("{}: {e}", abs.display())))?;
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

/// Remove `//` line comments and `/* */` block comments (string literals
/// are not understood — a known limitation of the pattern approach).
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i] as char;
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
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
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
            .map_err(|e| Error::Invalid(format!("{}: {e}", abs.display())))?;
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

    for (rel, abs) in &files {
        let text = fs::read_to_string(abs)
            .map_err(|e| Error::Invalid(format!("{}: {e}", abs.display())))?;
        let clean = strip_comments(&text);
        let mut deps: BTreeSet<String> = BTreeSet::new();
        let parent = parent_rel(rel);

        for spec in js_import_specs(&clean) {
            // Only relative specs ('./x', '../x') are intra-project;
            // bare specifiers resolve to node_modules.
            if !spec.starts_with(".") {
                continue;
            }
            let Some(norm) = normalize_rel(parent, &spec) else {
                continue;
            };
            if let Some(dep) = resolve_js(&names, &norm) {
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

