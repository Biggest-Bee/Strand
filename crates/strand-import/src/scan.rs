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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use strand_core::{EdgeKind, Error, Result};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};

use crate::EdgeList;

/// Record `dep` with `kind`, keeping the highest-confidence tag when
/// several refs resolve to the same file.
fn note_dep(deps: &mut BTreeMap<String, EdgeKind>, dep: String, kind: EdgeKind) {
    deps.entry(dep)
        .and_modify(|k| *k = (*k).max(kind))
        .or_insert(kind);
}

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
    // Manifest deps (requirements.txt, package.json, Cargo.toml,
    // pyproject.toml, ...) are language-agnostic: run once. Edges are
    // held back so lockfile-pinned versions can replace bare dep
    // names below (manifest -> name@version -> transitive).
    let mut manifest_edges: EdgeList = Vec::new();
    if !langs.is_empty() {
        let m = crate::manifests::scan_manifests(root)?;
        manifest_edges = m.edges;
        nodes.extend(m.nodes);
        warnings.extend(m.warnings);
    }
    // Lockfiles anywhere in the tree: full transitive dep chains.
    const LOCK_NAMES: &[&str] = &[
        "cargo.lock",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "poetry.lock",
        "uv.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "composer.lock",
        "gemfile.lock",
        "packages.lock.json",
        "package.resolved",
        "pubspec.lock",
        "podfile.lock",
        "paket.lock",
        "stack.yaml.lock",
        "mix.lock",
        "cartfile.resolved",
        "deno.lock",
        "conan.lock",
        "flake.lock",
    ];
    let mut lock_files: Vec<(String, PathBuf)> = Vec::new();
    walk_files(root, root, &mut |rel, abs| {
        if abs
            .file_name()
            .map(|n| {
                LOCK_NAMES.contains(&n.to_string_lossy().to_lowercase().as_str())
            })
            .unwrap_or(false)
        {
            lock_files.push((rel, abs));
        }
    });
    lock_files.sort_by(|a, b| a.0.cmp(&b.0));
    // group -> dep name -> pinned node ids, for manifest bridging.
    let mut lock_nodes: HashMap<&'static str, HashMap<String, Vec<String>>> =
        HashMap::new();
    for (rel, abs) in &lock_files {
        // bun.lockb is binary: parse it from raw bytes instead of
        // the text path used by every other lockfile.
        if abs
            .file_name()
            .map(|n| n.to_string_lossy().ends_with(".lockb"))
            .unwrap_or(false)
        {
            match fs::read(abs).map(|b| crate::locks::bun_lockb(&b)) {
                Ok(Ok(es)) => ingest_lock_edges(
                    rel,
                    es,
                    Some("npm"),
                    false,
                    &mut nodes,
                    &mut edges,
                    &mut lock_nodes,
                ),
                Ok(Err(e)) => warnings.push(format!("{rel}: bun.lockb parse: {e}")),
                Err(e) => warnings.push(format!("{rel}: bun.lockb read: {e}")),
            }
            continue;
        }
        let Ok(text) = fs::read_to_string(abs) else {
            continue;
        };
        let fmt = crate::detect_format(abs, &text);
        match crate::parse(&text, fmt) {
            Ok(es) => ingest_lock_edges(
                rel,
                es,
                lock_group(fmt),
                is_flat_lock(fmt),
                &mut nodes,
                &mut edges,
                &mut lock_nodes,
            ),
            Err(e) => warnings.push(format!("{rel}: lockfile parse: {e}")),
        }
    }
    // Bridge: manifest `package.json -> my-app` becomes
    // `package.json -> my-app@1.2.0` when a lockfile pins it, so
    // `deps` walks manifest -> pinned -> full transitive chain.
    let mut bridged: EdgeList = Vec::new();
    let mut seen_bridge: BTreeSet<(String, String)> = BTreeSet::new();
    for (src, dst, w, kind) in manifest_edges {
        let pinned = manifest_group(&src)
            .and_then(|g| lock_nodes.get(g))
            .and_then(|m| {
                // Case-insensitive: Podfile/pod names and NuGet ids
                // vary in case between manifest and lock.
                m.get(&dst.to_lowercase())
                    .or_else(|| m.get(&lock_node_name(&dst).to_lowercase()))
            });
        match pinned {
            Some(nodes_for) if !nodes_for.is_empty() => {
                // A manifest dep that already carries `@version`
                // (e.g. requirements.txt `==` pins) prefers the
                // exact locked node over every version of the name.
                let exact: Vec<String> = if dst.contains('@') {
                    nodes_for
                        .iter()
                        .filter(|n| n.as_str() == dst)
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                let targets = if exact.is_empty() {
                    nodes_for.as_slice()
                } else {
                    exact.as_slice()
                };
                for n in targets {
                    if seen_bridge.insert((src.clone(), n.clone())) {
                        bridged.push((src.clone(), n.clone(), w, kind));
                    }
                }
            }
            _ => {
                if seen_bridge.insert((src.clone(), dst.clone())) {
                    bridged.push((src, dst, w, kind));
                }
            }
        }
    }
    edges.extend(bridged);
    nodes.sort();
    nodes.dedup();
    Ok(ScanOutput {
        edges,
        nodes,
        warnings,
    })
}

/// Merge parsed lockfile edges into the scan: rewrite flat
/// `(lockfile)` srcs to the lockfile's rel path, register nodes,
/// and index `name@version` ids for manifest bridging.
#[allow(clippy::too_many_arguments)]
fn ingest_lock_edges(
    rel: &str,
    mut es: EdgeList,
    group: Option<&'static str>,
    flat: bool,
    nodes: &mut Vec<String>,
    edges: &mut EdgeList,
    lock_nodes: &mut HashMap<&'static str, HashMap<String, Vec<String>>>,
) {
    if flat {
        for e in &mut es {
            if e.0 == crate::locks::FLAT_SRC {
                e.0 = rel.to_string();
            }
        }
    }
    for (s, d, _, _) in &es {
        nodes.push(s.clone());
        nodes.push(d.clone());
        if let Some(g) = group {
            for n in [s, d] {
                lock_nodes
                    .entry(g)
                    .or_default()
                    .entry(lock_node_name(n).to_lowercase())
                    .or_default()
                    .push(n.clone());
            }
        }
    }
    edges.extend(es);
}

/// Ecosystem group a lockfile format feeds manifest bridging.
fn lock_group(fmt: crate::Format) -> Option<&'static str> {
    use crate::Format::*;
    match fmt {
        NpmLock | YarnLock | PnpmLock | BunLock => Some("npm"),
        CargoLock | Cargo => Some("cargo"),
        PoetryLock | UvLock => Some("python"),
        ComposerLock => Some("php"),
        GemfileLock => Some("ruby"),
        NugetLock => Some("nuget"),
        SwiftResolved => Some("swift"),
        PubspecLock => Some("pub"),
        PodfileLock => Some("cocoapods"),
        PaketLock => Some("jvm"),
        StackLock => Some("haskell"),
        MixLock => Some("elixir"),
        CartfileResolved => Some("carthage"),
        DenoLock => Some("deno"),
        ConanLock => Some("conan"),
        GradleVerification => Some("gradle"),
        GoMod | GoSum => Some("go"),
        _ => None,
    }
}

/// Lockfile formats whose parsers emit `(lockfile) -> pkg` edges
/// (no recorded inter-package edges in the format itself).
fn is_flat_lock(fmt: crate::Format) -> bool {
    use crate::Format::*;
    matches!(
        fmt,
        SwiftResolved | PubspecLock | StackLock | MixLock | CartfileResolved
            | DenoLock | GradleVerification
    )
}

/// Ecosystem group a manifest edge source belongs to.
fn manifest_group(src: &str) -> Option<&'static str> {
    let f = src.rsplit('/').next()?.to_lowercase();
    match f.as_str() {
        "package.json" => Some("npm"),
        "cargo.toml" => Some("cargo"),
        "pyproject.toml" | "pipfile" | "setup.cfg" | "environment.yml"
        | "environment.yaml" => Some("python"),
        "composer.json" => Some("php"),
        "gemfile" => Some("ruby"),
        "pubspec.yaml" => Some("pub"),
        "podfile" => Some("cocoapods"),
        "package.swift" => Some("swift"),
        "directory.packages.props" | "packages.config" => Some("nuget"),
        "paket.dependencies" => Some("jvm"),
        "stack.yaml" => Some("haskell"),
        "mix.exs" => Some("elixir"),
        "cartfile" => Some("carthage"),
        "conanfile.txt" => Some("conan"),
        "pubspec_overrides.yaml" => Some("pub"),
        "deno.json" | "deno.jsonc" => Some("deno"),
        _ if f.ends_with(".csproj") => Some("nuget"),
        _ if f.ends_with(".gradle") || f.ends_with(".gradle.kts")
            || f == "libs.versions.toml" => Some("gradle"),
        _ if f == "setup.py" => Some("python"),
        _ if f.starts_with("requirements") && f.ends_with(".txt") => Some("python"),
        _ => None,
    }
}

/// Package name part of a lockfile node id: strips a trailing
/// `@version` or ` version` suffix (`name@1.2.3` -> `name`,
/// `@scope/name@1.2.3` -> `@scope/name`).
fn lock_node_name(node: &str) -> &str {
    if let Some(i) = node.rfind('@') {
        if i > 0 {
            let rest = &node[i + 1..];
            let first = rest.chars().next().unwrap_or('\0');
            // Semver pin: `name@1.2.3`.
            if first.is_ascii_digit() {
                return &node[..i];
            }
            // Non-semver source specs: `name@workspace:path`,
            // `name@github:o/r#sha`, `name@git+https://...`.
            // Package names never contain these prefixes, so the
            // `@` here separates name from source, not scope.
            const SRC_PREFIXES: [&str; 11] = [
                "workspace:", "git+", "git:", "github:", "gitlab:",
                "http://", "https://", "link:", "file:", "portal:",
                "npm:",
            ];
            if SRC_PREFIXES.iter().any(|p| rest.starts_with(p)) {
                return &node[..i];
            }
        }
    }
    // Space-separated `name version (source)` forms: name is first.
    if let Some(i) = node.find(' ') {
        return &node[..i];
    }
    node
}

fn scan_rust_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["rs"], &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let crates = crate_map(root, &names);
    let mut edges: EdgeList = Vec::new();
    let mut warnings = Vec::new();

    // Parse all files in parallel (rayon); resolution below stays
    // sequential so edge order is deterministic. Read errors abort
    // (as before); parse errors become per-file warnings.
    let extracted: Vec<std::result::Result<(RustRefs, Vec<String>), String>> = files
        .par_iter()
        .map(|(_rel, abs)| {
            let text = fs::read_to_string(abs)
                .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
            let inner = parse_rs_refs(&text)
                .map(|r| (r, manual_dep_specs(&text)))
                .map_err(|e| {
                    let msg = e.to_string();
                    msg.lines().next().unwrap_or(&msg).to_string()
                });
            Ok(inner)
        })
        .collect::<Result<Vec<_>>>()?;

    for ((rel, abs), inner) in files.iter().zip(extracted) {
        let (refs, manual) = match inner {
            Ok(v) => v,
            Err(msg) => {
                warnings.push(format!("{rel}: {msg}"));
                continue;
            }
        };
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();

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
                    note_dep(&mut deps, dep, EdgeKind::Static);
                }
            }
        }

        // `include!("file.rs")` pulls the file's contents into this one.
        let parent = parent_rel(rel);
        for inc in &refs.includes {
            if let Some(dep) = normalize_rel(parent, inc).filter(|c| names.contains(c)) {
                if dep != *rel {
                    note_dep(&mut deps, dep, EdgeKind::Static);
                }
            }
        }

        // `// strand: depends-on path` manual edges. Paths resolve
        // relative to the file's dir, then project root.
        for spec in manual {
            let dep = [parent, ""]
                .iter()
                .filter_map(|b| normalize_rel(b, &spec))
                .find(|c| names.contains(c));
            if let Some(dep) = dep {
                if dep != *rel {
                    note_dep(&mut deps, dep, EdgeKind::Declared);
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
                        note_dep(&mut deps, dep, EdgeKind::Static);
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
                    note_dep(&mut deps, dep, EdgeKind::Static);
                }
            }
        }

        for (dep, kind) in deps {
            edges.push((rel.clone(), dep, None, kind));
        }
    }

    // Cross-check against rustc dep-info: `cargo check`/`build` writes
    // `.d` files listing every source file the compiler actually read.
    // Two gap classes are worth a warning:
    //  - files rustc saw that the walk didn't reach at all
    //  - files the walk saw, rustc compiled, but no `mod`/`#[path]`
    //    edge points at - the signature of a macro-emitted module.
    let depinfo = depinfo_rs_files(root);
    if !depinfo.is_empty() {
        let missed: Vec<&String> = depinfo.difference(&names).collect();
        if !missed.is_empty() {
            let shown: Vec<&str> = missed.iter().take(10).map(|s| s.as_str()).collect();
            let suffix = if missed.len() > shown.len() {
                format!(", +{} more", missed.len() - shown.len())
            } else {
                String::new()
            };
            warnings.push(format!(
                "rustc dep-info lists {} source file(s) the scanner did not reach: {}{}",
                missed.len(),
                shown.join(", "),
                suffix
            ));
        }

        let targets: BTreeSet<&str> = edges.iter().map(|(_, d, _, _)| d.as_str()).collect();
        let edgeless: Vec<&String> = depinfo
            .intersection(&names)
            .filter(|f| !targets.contains(f.as_str()) && !is_probable_crate_root(f))
            .collect();
        // Rust's module-to-file layout is deterministic, so an
        // edgeless compiled file almost always has an inferable
        // parent: `a/b/c.rs` is declared by `a/b.rs` or `a/b/mod.rs`,
        // `a/b/mod.rs` by `a.rs`/`a/mod.rs`, and `src/x.rs` by the
        // crate root. Add the edge rather than only warning; files
        // with no existing candidate stay warnings.
        let mut unresolved: Vec<&String> = Vec::new();
        for f in edgeless {
            match infer_rs_parent(&names, f) {
                Some(parent) => edges.push((parent, f.clone(), None, EdgeKind::Heuristic)),
                None => unresolved.push(f),
            }
        }
        if !unresolved.is_empty() {
            let shown: Vec<&str> = unresolved.iter().take(10).map(|s| s.as_str()).collect();
            let suffix = if unresolved.len() > shown.len() {
                format!(", +{} more", unresolved.len() - shown.len())
            } else {
                String::new()
            };
            warnings.push(format!(
                "rustc compiled {} file(s) with no incoming module edge and no inferable parent (possible macro-generated modules): {}{}",
                unresolved.len(),
                shown.join(", "),
                suffix
            ));
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
            self.refs.mods.push((i.ident.unraw().to_string(), custom));
        }
        visit::visit_item_mod(self, i);
    }

    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        flatten_use(&i.tree, &mut prefix, &mut self.refs.uses);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if i.path.segments.last().is_some_and(|s| s.ident == "include") {
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

/// Manual escape hatch: `# strand: depends-on <path>` /
/// `// strand: depends-on <path>` comment directives. Each occurrence
/// yields one target path, resolved relative to the file's directory.
/// For edges the scanner can't see (runtime wiring, computed names).
fn manual_dep_specs(text: &str) -> Vec<String> {
    const MARKER: &str = "strand: depends-on";
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(pos) = line.find(MARKER) else {
            continue;
        };
        let rest = line[pos + MARKER.len()..]
            .trim()
            .trim_end_matches("*/")
            .trim();
        if !rest.is_empty() {
            out.push(rest.to_string());
        }
    }
    out
}

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

/// Visit every file under `root` (respecting [`SKIP_DIRS`]) with its
/// root-relative `/` path and absolute path. Used by the manifest
/// scanner, which matches on file names rather than extensions.
pub(crate) fn walk_files(
    dir: &Path,
    root: &Path,
    f: &mut dyn FnMut(String, PathBuf),
) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            walk_files(&path, root, f);
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            f(rel, path);
        }
    }
}

/// Drop a Windows `\\?\` verbatim prefix from a path string.
fn strip_verbatim(s: &str) -> String {
    s.strip_prefix("\\\\?\\").unwrap_or(s).to_string()
}

/// All `.rs` paths (root-relative, "/" separated) that rustc read per
/// `target/**` dep-info `.d` files. Empty when no dep-info exists - a
/// missing `target/` just means cargo hasn't run, not a coverage gap.
fn depinfo_rs_files(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let target = root.join("target");
    if !target.is_dir() {
        return out;
    }
    let Ok(root_canon) = root.canonicalize() else {
        return out;
    };
    // Normalize both sides to '/'-joined strings without a verbatim
    // `\\?\` prefix so `.d` paths (plain `C:\...`) compare cleanly.
    let root_norm = strip_verbatim(&root_canon.to_string_lossy()).replace('\\', "/");
    let root_prefix = format!("{root_norm}/");
    let mut d_files = Vec::new();
    collect_depinfo(&target, 0, &mut d_files);

    for d in d_files {
        let Ok(text) = fs::read_to_string(&d) else {
            continue;
        };
        for dep in depinfo_deps(&text) {
            let dep = dep.replace("\\ ", " ");
            if !dep.ends_with(".rs") {
                continue;
            }
            let dep_norm = strip_verbatim(&dep).replace('\\', "/");
            let Some(rel) = dep_norm.strip_prefix(&root_prefix) else {
                continue; // outside the project (path deps, sysroot)
            };
            let rel = rel.to_string();
            // Skip anything under an intentionally-skipped dir (target/
            // itself holds OUT_DIR-generated sources rustc legitimately
            // reads but the scanner deliberately ignores).
            if rel.split('/').any(|s| SKIP_DIRS.contains(&s)) {
                continue;
            }
            out.insert(rel);
        }
    }
    out
}

/// Files that legitimately have no incoming `mod` edge: crate roots
/// (`lib.rs`/`main.rs`/`build.rs`), cargo auto-discovered target roots
/// (`tests/`, `examples/`, `benches/`, `src/bin/`).
fn is_probable_crate_root(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if matches!(name, "lib.rs" | "main.rs" | "build.rs") {
        return true;
    }
    let segs: Vec<&str> = rel.split('/').collect();
    // Any tests/examples/benches dir component, or src/bin/ prefix.
    segs.iter()
        .any(|s| matches!(*s, "tests" | "examples" | "benches"))
        || rel.starts_with("src/bin/")
}

/// Infer the module file that would declare `rel` per Rust's
/// layout rules, returning it only if it exists in `names`.
/// `a/b/c.rs` -> `a/b.rs` or `a/b/mod.rs`; `a/b/mod.rs` -> `a.rs` or
/// `a/mod.rs`; `src/x.rs` -> `src/lib.rs`/`src/main.rs` (crate root).
fn infer_rs_parent(names: &BTreeSet<String>, rel: &str) -> Option<String> {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let parent_dir = parent_rel(rel);
    // `mod.rs` files *are* the directory's module - the parent is one
    // level up.
    let container = if base == "mod.rs" {
        parent_rel(parent_dir).to_string()
    } else {
        parent_dir.to_string()
    };
    if container.is_empty() {
        return None;
    }
    let mut candidates = vec![format!("{container}.rs"), format!("{container}/mod.rs")];
    // Files directly under a `src/` dir are declared by the crate
    // root, not by `src.rs`.
    if container.rsplit('/').next() == Some("src") {
        candidates.push(format!("{container}/lib.rs"));
        candidates.push(format!("{container}/main.rs"));
    }
    candidates.into_iter().find(|c| names.contains(c))
}

/// Collect `*.d` dep-info files under `target/`, bounded in depth and
/// count so huge target dirs stay cheap.
fn collect_depinfo(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 5 || out.len() > 5000 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            collect_depinfo(&path, depth + 1, out);
        } else if ft.is_file() && path.extension().and_then(|e| e.to_str()) == Some("d") {
            out.push(path);
        }
    }
}

/// Dependency paths from a Makefile-style `.d` file: `target: dep dep
/// \`-continued lines, `\ `-escaped spaces. Returns raw dep strings.
fn depinfo_deps(text: &str) -> Vec<String> {
    // Join `\`-newline continuations, then take everything after the
    // first ':' on each logical rule line.
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    let mut out = Vec::new();
    for line in joined.lines() {
        // Rule colon is the first ':' followed by whitespace or EOL -
        // `C:\` drive prefixes have ':' followed by '\'.
        let bytes = line.as_bytes();
        let mut split_at = None;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b':' && (i + 1 == bytes.len() || bytes[i + 1].is_ascii_whitespace()) {
                split_at = Some(i);
                break;
            }
        }
        let Some(i) = split_at else {
            continue;
        };
        let deps = &line[i + 1..];
        // Split on whitespace but keep `\ `-escaped spaces inside tokens.
        let mut cur = String::new();
        let mut chars = deps.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&' ') {
                cur.push('\\');
                cur.push(' ');
                chars.next();
            } else if c.is_whitespace() {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(c);
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
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
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
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
                let rel = src
                    .strip_prefix(root)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                return Some(rel);
            }
            let rel = dir
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
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
/// Returns `(specs, globs, had_error, dynamic)` - `had_error` means the
/// tree contains ERROR nodes; `dynamic` counts `import(expr)`/`require(expr)`
/// calls with non-literal args (invisible edges); `globs` holds bundler-style
/// patterns (`require.context`, `import.meta.glob`, template/concat dynamic
/// imports) expanded against the scanned file set by the caller.
fn js_import_specs_ts(
    text: &str,
    lang: tree_sitter::Language,
) -> (Vec<String>, Vec<String>, bool, usize) {
    let mut specs = Vec::new();
    let mut globs = Vec::new();
    let mut dynamic = 0usize;
    let Some(tree) = parse_ts(text, lang) else {
        return (specs, globs, true, dynamic);
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
                } else {
                    match ts_glob_spec(node, text) {
                        TsGlob::Patterns(p) => globs.extend(p),
                        TsGlob::Dynamic => dynamic += 1,
                        TsGlob::NotGlob => {
                            if ts_is_dynamic_call(node, text) {
                                dynamic += 1;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    (specs, globs, had_error, dynamic)
}

/// Outcome of checking a call for bundler-style glob loading.
enum TsGlob {
    /// Resolved glob patterns to expand against the file set.
    Patterns(Vec<String>),
    /// A glob-shaped call whose pattern can't be statically resolved.
    Dynamic,
    /// Not a glob-loading call at all.
    NotGlob,
}

/// `require.context(dir, ...)`, `import.meta.glob(pat | [pats])`, and
/// `import()`/`require()` with a template or `+`-concatenated spec that
/// has a static directory anchor - the cases bundlers turn into
/// context modules.
fn ts_glob_spec(call: tree_sitter::Node, src: &str) -> TsGlob {
    let Some(func) = call.child_by_field_name("function") else {
        return TsGlob::NotGlob;
    };
    let Ok(ft) = func.utf8_text(src.as_bytes()) else {
        return TsGlob::NotGlob;
    };
    let Some(args) = call.child_by_field_name("arguments") else {
        return TsGlob::NotGlob;
    };

    if ft == "require.context" {
        // require.context('./dir', recursive?, regex?) - the regex is
        // approximated away: `names` only holds JS/TS files anyway.
        let dir = {
            let mut c = args.walk();
            let found = args
                .children(&mut c)
                .find(|c| !matches!(c.kind(), "(" | ")" | ","))
                .and_then(|a| ts_string_literal(a, src));
            found
        };
        return match dir {
            Some(d) => {
                // Second arg `false` means non-recursive.
                let recursive = {
                    let mut c = args.walk();
                    let second = args
                        .children(&mut c)
                        .filter(|c| !matches!(c.kind(), "(" | ")" | ","))
                        .nth(1);
                    second.map(|n| n.kind() != "false").unwrap_or(true)
                };
                let pat = if recursive {
                    format!("{d}/**/*")
                } else {
                    format!("{d}/*")
                };
                TsGlob::Patterns(vec![pat])
            }
            None => TsGlob::Dynamic,
        };
    }

    if ft == "import.meta.glob" {
        // import.meta.glob('./a/*.ts') or an array of patterns.
        let mut pats = Vec::new();
        let mut dyn_seen = false;
        {
            let mut c = args.walk();
            for a in args
                .children(&mut c)
                .filter(|c| !matches!(c.kind(), "(" | ")" | ","))
            {
                collect_glob_arg(a, src, &mut pats, &mut dyn_seen);
            }
        }
        if dyn_seen && pats.is_empty() {
            return TsGlob::Dynamic;
        }
        return if pats.is_empty() {
            TsGlob::Dynamic
        } else {
            TsGlob::Patterns(pats)
        };
    }

    // import()/require() with a non-plain-literal spec: template with
    // substitution or `+` concatenation.
    let is_require = func.kind() == "identifier" && ft == "require";
    let is_dyn_import = func.kind() == "import";
    if !is_require && !is_dyn_import {
        return TsGlob::NotGlob;
    }
    let arg = {
        let mut c = args.walk();
        let found = args
            .children(&mut c)
            .find(|c| !matches!(c.kind(), "(" | ")" | ","));
        found
    };
    let Some(arg) = arg else {
        return TsGlob::Dynamic;
    };
    match ts_spec_pattern(arg, src) {
        Some(pat) => {
            // Needs a directory anchor - `*.js` alone would match
            // every sibling file.
            if pat.contains('/') {
                TsGlob::Patterns(vec![pat])
            } else {
                TsGlob::Dynamic
            }
        }
        None => TsGlob::Dynamic,
    }
}

/// String literal text of a `string` node (quotes stripped), or a
/// `template_string` with no substitutions.
fn ts_string_literal(node: tree_sitter::Node, src: &str) -> Option<String> {
    match node.kind() {
        "string" => spec_text(node, src),
        "template_string" => {
            let has_sub = {
                let mut c = node.walk();
                let found = node
                    .children(&mut c)
                    .any(|ch| ch.kind() == "template_substitution");
                found
            };
            if has_sub {
                None
            } else {
                spec_text(node, src)
            }
        }
        _ => None,
    }
}

/// Collect glob patterns from an `import.meta.glob` argument: a
/// string/template, or an array of them.
fn collect_glob_arg(
    node: tree_sitter::Node,
    src: &str,
    pats: &mut Vec<String>,
    dyn_seen: &mut bool,
) {
    match node.kind() {
        "string" | "template_string" => {
            if let Some(s) = ts_string_literal(node, src) {
                pats.push(s);
            } else {
                // Template with substitution inside glob() - treat
                // interpolation as `*`.
                if node.kind() == "template_string" {
                    if let Some(p) = ts_template_pattern(node, src) {
                        pats.push(p);
                        return;
                    }
                }
                *dyn_seen = true;
            }
        }
        "array" => {
            let mut c = node.walk();
            for ch in node
                .children(&mut c)
                .filter(|c| !matches!(c.kind(), "[" | "]" | ","))
            {
                collect_glob_arg(ch, src, pats, dyn_seen);
            }
        }
        _ => *dyn_seen = true,
    }
}

/// A dynamic-import spec argument -> glob pattern, or `None` when it
/// has no static anchor at all. Template substitutions and non-literal
/// `+` operands become `*`.
fn ts_spec_pattern(node: tree_sitter::Node, src: &str) -> Option<String> {
    match node.kind() {
        "template_string" => ts_template_pattern(node, src),
        "binary_expression" => ts_concat_pattern(node, src),
        _ => None,
    }
}

/// `` `./x/${n}.ts` `` -> `./x/*.ts` (one `*` per substitution).
fn ts_template_pattern(node: tree_sitter::Node, src: &str) -> Option<String> {
    let mut out = String::new();
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        match ch.kind() {
            "string_fragment" => {
                out.push_str(ch.utf8_text(src.as_bytes()).ok()?);
            }
            "template_substitution" => out.push('*'),
            _ => {}
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `'./x/' + n + '.ts'` -> `./x/*.ts`. Returns `None` when no string
/// literal participates (nothing to anchor the pattern).
fn ts_concat_pattern(node: tree_sitter::Node, src: &str) -> Option<String> {
    // Flatten `a + b + c` left-associative tree.
    fn flat(node: tree_sitter::Node, src: &str, parts: &mut Vec<String>) -> bool {
        if node.kind() == "binary_expression" {
            // Only `+` concatenation - other operators aren't specs.
            let is_plus = {
                let mut c = node.walk();
                let found = node.children(&mut c).any(|ch| ch.kind() == "+");
                found
            };
            if !is_plus {
                return false;
            }
            // binary_expression children: left, "+", right - take the
            // first two operand nodes.
            let mut c = node.walk();
            let mut exprs = node
                .children(&mut c)
                .filter(|ch| !matches!(ch.kind(), "+" | "(" | ")" | ","));
            let (Some(l), Some(r)) = (exprs.next(), exprs.next()) else {
                return false;
            };
            return flat(l, src, parts) && flat(r, src, parts);
        }
        match node.kind() {
            "string" => {
                if let Some(s) = spec_text(node, src) {
                    parts.push(s);
                    true
                } else {
                    false
                }
            }
            "template_string" => {
                if let Some(p) = ts_template_pattern(node, src) {
                    parts.push(p);
                    true
                } else {
                    false
                }
            }
            // Non-literal operand -> wildcard.
            "identifier"
            | "member_expression"
            | "call_expression"
            | "number"
            | "parenthesized_expression" => {
                parts.push("*".to_string());
                true
            }
            _ => false,
        }
    }
    let mut parts = Vec::new();
    if !flat(node, src, &mut parts) || parts.is_empty() {
        return None;
    }
    // Require at least one literal (non-`*`) part to anchor.
    if parts.iter().all(|p| p == "*") {
        return None;
    }
    Some(parts.concat())
}

/// `require(x)` / `import(x)` where the first arg isn't a string or
/// template literal - a dynamic site the scanner can't resolve.
fn ts_is_dynamic_call(call: tree_sitter::Node, src: &str) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let is_require =
        func.kind() == "identifier" && func.utf8_text(src.as_bytes()).is_ok_and(|t| t == "require");
    let is_dyn_import = func.kind() == "import";
    if !is_require && !is_dyn_import {
        return false;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return true;
    };
    let arg_kind = {
        let mut cursor = args.walk();
        // First real argument - skip "(", ",", ")" punctuation.
        let found = args
            .children(&mut cursor)
            .find(|c| !matches!(c.kind(), "(" | ")" | ","))
            .map(|c| c.kind().to_string());
        found
    };
    match arg_kind.as_deref() {
        Some("string" | "template_string") => false,
        Some(_) => true,
        None => true,
    }
}

// ---------- Python scanner ----------

const PY_EXTS: &[&str] = &["py", "pyi"];

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
    /// `glob.glob("pat")`/`iglob`/`Path.glob` literal patterns -
    /// resolved against the scanned file set by the caller.
    Glob(Vec<String>),
    /// Framework convention lists (`pytest_plugins`,
    /// `INSTALLED_APPS`): dotted strings resolved as module paths,
    /// dropping trailing segments for `module:Class`-style entries.
    Convention(Vec<String>),
    /// `entry_points(group="x")` consumer lookups - group names
    /// resolved via const-prop; empty vec means "all groups".
    EpGroup(Vec<String>),
    /// `runpy.run_path("script.py")` - a file path (not a module
    /// path) resolved file-dir relative, then project-root relative.
    PathDep(String),
}

// ---------- Python constant propagation ----------
//
// Flow-insensitive, per-file "set of possible strings" domain. A name
// maps to every literal-derived value it could hold; any unresolvable
// assignment makes the name unknown. Used to resolve computed dynamic
// imports (`import_module("pkg." + NAME)`) that would otherwise be
// invisible. Deliberately shallow: no control flow, no calls, no
// cross-module constants.

/// Cap on set sizes - beyond this a site is treated as dynamic.
const PY_MAX_STRSET: usize = 64;
/// Recursion cap for const lookups (cycles, deep chains).
const PY_MAX_EVAL_DEPTH: u8 = 12;

/// Mutating method names that invalidate a container constant.
const PY_MUTATORS: &[&str] = &[
    "append",
    "extend",
    "update",
    "add",
    "setdefault",
    "pop",
    "clear",
    "remove",
    "insert",
    "sort",
    "reverse",
];

/// Collected bindings and invalidations for one Python file.
struct PyEnv<'t> {
    /// `name = <expr>` right-hand sides (all assignments unioned).
    assigns: HashMap<String, Vec<tree_sitter::Node<'t>>>,
    /// `for name in <expr>` iterable expressions.
    verbind: HashMap<String, Vec<tree_sitter::Node<'t>>>,
    /// Names that can't be trusted: mutated containers, function
    /// parameters (shadowing), destructured targets.
    bad: BTreeSet<String>,
    memo: std::cell::RefCell<HashMap<String, Option<BTreeSet<String>>>>,
    visiting: std::cell::RefCell<BTreeSet<String>>,
}

impl<'t> PyEnv<'t> {
    fn lookup(&self, name: &str, text: &str) -> Option<BTreeSet<String>> {
        if self.bad.contains(name) {
            return None;
        }
        if let Some(v) = self.memo.borrow().get(name) {
            return v.clone();
        }
        if !self.visiting.borrow_mut().insert(name.to_string()) {
            return None; // cycle
        }
        let mut out: Option<BTreeSet<String>> = Some(BTreeSet::new());
        // Every binding source must resolve, or the name is unknown.
        for expr in self.assigns.get(name).into_iter().flatten() {
            match py_eval_strset(self, *expr, text, 0) {
                Some(s) => {
                    if let Some(o) = out.as_mut() {
                        o.extend(s);
                        if o.len() > PY_MAX_STRSET {
                            out = None;
                            break;
                        }
                    }
                }
                None => {
                    out = None;
                    break;
                }
            }
        }
        if out.is_some() {
            for expr in self.verbind.get(name).into_iter().flatten() {
                match py_eval_strlist(self, *expr, text, 0) {
                    Some(items) => {
                        if let Some(o) = out.as_mut() {
                            for item in items {
                                o.extend(item);
                                if o.len() > PY_MAX_STRSET {
                                    out = None;
                                    break;
                                }
                            }
                        }
                    }
                    None => {
                        out = None;
                        break;
                    }
                }
            }
        }
        self.visiting.borrow_mut().remove(name);
        let result = out.filter(|s| !s.is_empty());
        self.memo
            .borrow_mut()
            .insert(name.to_string(), result.clone());
        result
    }
}

/// Walk the tree once collecting assignments, for-bindings, and
/// invalidations for the const-prop environment.
fn build_py_env<'t>(tree: &'t tree_sitter::Tree, text: &str) -> PyEnv<'t> {
    let _ = text;
    let mut env = PyEnv {
        assigns: HashMap::new(),
        verbind: HashMap::new(),
        bad: BTreeSet::new(),
        memo: std::cell::RefCell::new(HashMap::new()),
        visiting: std::cell::RefCell::new(BTreeSet::new()),
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "assignment" => {
                if let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if l.kind() == "identifier" {
                        if let Ok(name) = l.utf8_text(text.as_bytes()) {
                            env.assigns.entry(name.to_string()).or_default().push(r);
                        }
                    } else {
                        poison_target(&mut env.bad, l, text);
                    }
                }
            }
            "augmented_assignment" => {
                if let Some(l) = node.child_by_field_name("left") {
                    poison_target(&mut env.bad, l, text);
                }
            }
            "for_statement" => {
                if let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if l.kind() == "identifier" {
                        if let Ok(name) = l.utf8_text(text.as_bytes()) {
                            env.verbind.entry(name.to_string()).or_default().push(r);
                        }
                    } else {
                        poison_target(&mut env.bad, l, text);
                    }
                }
            }
            "call" => {
                // `X.append(...)`/`D.update(...)` etc. invalidate X.
                if let Some(func) = node.child_by_field_name("function") {
                    if func.kind() == "attribute" {
                        let attr = func
                            .child_by_field_name("attribute")
                            .and_then(|a| a.utf8_text(text.as_bytes()).ok())
                            .unwrap_or("");
                        if PY_MUTATORS.contains(&attr) {
                            if let Some(obj) = func.child_by_field_name("object") {
                                if obj.kind() == "identifier" {
                                    if let Ok(name) = obj.utf8_text(text.as_bytes()) {
                                        env.bad.insert(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "parameters" | "lambda_parameters" => {
                poison_params(&mut env.bad, node, text);
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    env
}

/// Mark every identifier bound by a non-simple assignment target
/// (subscripts, attributes, destructuring) as unknown.
fn poison_target(bad: &mut BTreeSet<String>, node: tree_sitter::Node, text: &str) {
    // `D["k"] = v` / `O.x = v` poison the base object; `a, b = v`
    // poisons each destructured name.
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == "identifier" {
            if let Ok(name) = n.utf8_text(text.as_bytes()) {
                bad.insert(name.to_string());
            }
            continue; // don't descend into the identifier itself
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            stack.push(child);
        }
    }
}

/// Function/lambda parameter names shadow outer constants - mark
/// them unknown so a param named like a const can't fake-resolve.
fn poison_params(bad: &mut BTreeSet<String>, params: tree_sitter::Node, text: &str) {
    let mut c = params.walk();
    for child in params.children(&mut c) {
        match child.kind() {
            "identifier" => {
                if let Ok(n) = child.utf8_text(text.as_bytes()) {
                    bad.insert(n.to_string());
                }
            }
            "keyword_parameter"
            | "typed_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => {
                // First identifier descendant is the bound name.
                let mut stack = vec![child];
                while let Some(n) = stack.pop() {
                    if n.kind() == "identifier" {
                        if let Ok(name) = n.utf8_text(text.as_bytes()) {
                            bad.insert(name.to_string());
                        }
                        break;
                    }
                    let mut cc = n.walk();
                    for ch in n.children(&mut cc) {
                        stack.push(ch);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Evaluate an expression to a set of possible string values.
/// `None` = unknown (dynamic). Depth-capped; identifiers resolve
/// through the env with cycle protection.
fn py_eval_strset(
    env: &PyEnv,
    node: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    if depth > PY_MAX_EVAL_DEPTH {
        return None;
    }
    match node.kind() {
        "string" => py_eval_string(node, env, text, depth),
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            env.lookup(name, text)
        }
        "binary_operator" => py_eval_binary(env, node, text, depth),
        "call" => py_eval_call_str(env, node, text, depth),
        "conditional_expression" => {
            // `A if cond else B` - union of both arms.
            let a = node.child_by_field_name("consequence");
            let b = node.child_by_field_name("alternative");
            let (a, b) = match (a, b) {
                (Some(x), Some(y)) => (x, y),
                _ => {
                    // Field names vary; fall back to first/last child.
                    let mut named = Vec::new();
                    let mut wc = node.walk();
                    for c in node.children(&mut wc) {
                        if c.is_named() {
                            named.push(c);
                        }
                    }
                    let first = *named.first()?;
                    let last = *named.last().unwrap_or(&first);
                    (first, last)
                }
            };
            let mut out = py_eval_strset(env, a, text, depth + 1)?;
            out.extend(py_eval_strset(env, b, text, depth + 1)?);
            (out.len() <= PY_MAX_STRSET).then_some(out)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|c| c.is_named())?;
            py_eval_strset(env, inner, text, depth + 1)
        }
        "subscript" => py_eval_subscript(env, node, text, depth),
        _ => None,
    }
}

/// String literal, possibly an f-string with interpolations.
/// Returns the cartesian product of all interpolated values.
fn py_eval_string(
    node: tree_sitter::Node,
    env: &PyEnv,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    // Collect parts: literal string_content vs interpolation exprs.
    enum Part<'n> {
        Lit(String),
        Expr(tree_sitter::Node<'n>),
    }
    let mut parts: Vec<Part> = Vec::new();
    let mut has_interp = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_content" | "escape_sequence" => {
                if let Ok(t) = child.utf8_text(text.as_bytes()) {
                    parts.push(Part::Lit(t.to_string()));
                }
            }
            "interpolation" => {
                has_interp = true;
                // Only a bare `{expr}` interpolates cleanly; format
                // specs/conversions make the value untrustworthy.
                let expr = child.child_by_field_name("expression")?;
                let extra = child
                    .children(&mut child.walk())
                    .filter(|c| c.is_named() && c.id() != expr.id())
                    .count();
                if extra > 0 {
                    return None;
                }
                parts.push(Part::Expr(expr));
            }
            _ => {}
        }
    }
    if !has_interp {
        return py_string_inner(node, text).map(|s| BTreeSet::from([s]));
    }
    // Cartesian product over interpolation values, literals spliced in.
    let mut acc: BTreeSet<String> = BTreeSet::from([String::new()]);
    for part in parts {
        match part {
            Part::Lit(lit) => {
                acc = acc.iter().map(|s| format!("{s}{lit}")).collect();
            }
            Part::Expr(expr) => {
                let vals = py_eval_strset(env, expr, text, depth + 1)?;
                let mut next: BTreeSet<String> = BTreeSet::new();
                for prefix in &acc {
                    for v in &vals {
                        next.insert(format!("{prefix}{v}"));
                        if next.len() > PY_MAX_STRSET {
                            return None;
                        }
                    }
                }
                acc = next;
            }
        }
    }
    Some(acc)
}

/// `+` concatenation and `%` formatting over evaluated operands.
fn py_eval_binary(
    env: &PyEnv,
    node: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    // Operator is the anonymous child between them.
    let mut op = "";
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            if let Ok(t) = child.utf8_text(text.as_bytes()) {
                op = t;
            }
        }
    }
    match op {
        "+" => {
            let ls = py_eval_strset(env, left, text, depth + 1)?;
            let rs = py_eval_strset(env, right, text, depth + 1)?;
            let mut out = BTreeSet::new();
            for a in &ls {
                for b in &rs {
                    out.insert(format!("{a}{b}"));
                    if out.len() > PY_MAX_STRSET {
                        return None;
                    }
                }
            }
            Some(out)
        }
        "%" => py_eval_percent(env, left, right, text, depth),
        _ => None,
    }
}

/// `"fmt %s %s" % (a, b)` - sequential %-specifiers filled from the
/// right operand (tuple elements in order, or a single value).
fn py_eval_percent(
    env: &PyEnv,
    left: tree_sitter::Node,
    right: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    let fmts = py_eval_strset(env, left, text, depth + 1)?;
    // Right operand values: tuple -> elements, else single set.
    let rsets: Vec<BTreeSet<String>> = if matches!(right.kind(), "tuple" | "list" | "set") {
        py_eval_strlist(env, right, text, depth + 1)?
    } else {
        vec![py_eval_strset(env, right, text, depth + 1)?]
    };
    let mut out = BTreeSet::new();
    'outer: for fmt in &fmts {
        // Split fmt into literal segments and % specifiers.
        let specs = py_percent_specs(fmt)?;
        if specs != rsets.len() {
            continue 'outer; // arity mismatch - try other fmt candidates
        }
        // Cartesian product over right values.
        let mut combos: Vec<Vec<String>> = vec![vec![String::new()]];
        for rs in &rsets {
            let mut next = Vec::new();
            for combo in &combos {
                for v in rs {
                    let mut c = combo.clone();
                    c.push(v.clone());
                    next.push(c);
                    if next.len() > PY_MAX_STRSET {
                        return None;
                    }
                }
            }
            combos = next;
        }
        for combo in combos {
            let mut result = String::new();
            let bytes = fmt.as_bytes();
            let mut i = 0;
            let mut vi = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
                        result.push('%');
                        i += 2;
                        continue;
                    }
                    // %(name)s unsupported.
                    if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                        return None;
                    }
                    let mut j = i + 1;
                    while j < bytes.len()
                        && !matches!(bytes[j], b'd' | b's' | b'r' | b'i' | b'f' | b'g')
                    {
                        j += 1;
                    }
                    if j >= bytes.len() || vi >= combo.len() {
                        return None;
                    }
                    result.push_str(&combo[vi]);
                    vi += 1;
                    i = j + 1;
                } else {
                    // Copy one UTF-8 char.
                    let ch_len = utf8_len(bytes[i]);
                    result.push_str(&fmt[i..i + ch_len]);
                    i += ch_len;
                }
            }
            out.insert(result);
            if out.len() > PY_MAX_STRSET {
                return None;
            }
        }
    }
    Some(out)
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

/// Count %-conversion specifiers in a format string (%% excluded,
/// %(name)s unsupported -> None).
fn py_percent_specs(fmt: &str) -> Option<usize> {
    let b = fmt.as_bytes();
    let mut i = 0;
    let mut n = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 1 < b.len() && b[i + 1] == b'%' {
                i += 2;
                continue;
            }
            if i + 1 < b.len() && b[i + 1] == b'(' {
                return None;
            }
            let mut j = i + 1;
            while j < b.len() && !matches!(b[j], b'd' | b's' | b'r' | b'i' | b'f' | b'g') {
                j += 1;
            }
            if j >= b.len() {
                return None;
            }
            n += 1;
            i = j + 1;
        } else {
            i += 1;
        }
    }
    Some(n)
}

/// `sep.join(iterable)` and `"...".format(args)` - the two call forms
/// worth resolving. Everything else is unknown.
fn py_eval_call_str(
    env: &PyEnv,
    node: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    let func = node.child_by_field_name("function")?;
    if func.kind() != "attribute" {
        return None;
    }
    let attr = func
        .child_by_field_name("attribute")
        .and_then(|a| a.utf8_text(text.as_bytes()).ok())?;
    let obj = func.child_by_field_name("object")?;
    let args = node.child_by_field_name("arguments")?;
    // Positional args only (skip keywords/starred).
    let mut arg_nodes = Vec::new();
    let mut cursor = args.walk();
    for c in args.children(&mut cursor) {
        if c.is_named()
            && !matches!(
                c.kind(),
                "keyword_argument" | "dictionary_splat" | "list_splat" | "parenthesized_list_splat"
            )
        {
            arg_nodes.push(c);
        }
    }
    match attr {
        "join" => {
            let seps = py_eval_strset(env, obj, text, depth + 1)?;
            let items = arg_nodes
                .first()
                .and_then(|a| py_eval_strlist(env, *a, text, depth + 1))?;
            py_join_strs(&seps, &items)
        }
        "format" => {
            let fmts = py_eval_strset(env, obj, text, depth + 1)?;
            let argsets: Option<Vec<BTreeSet<String>>> = arg_nodes
                .iter()
                .map(|a| py_eval_strset(env, *a, text, depth + 1))
                .collect();
            py_format_strs(&fmts, &argsets?)
        }
        _ => None,
    }
}

/// Cartesian join of element string-sets with each separator.
fn py_join_strs(seps: &BTreeSet<String>, items: &[BTreeSet<String>]) -> Option<BTreeSet<String>> {
    // Cartesian product over items (order preserved).
    let mut combos: Vec<Vec<String>> = vec![Vec::new()];
    for item in items {
        let mut next = Vec::new();
        for combo in &combos {
            for v in item {
                let mut c = combo.clone();
                c.push(v.clone());
                next.push(c);
                if next.len() > PY_MAX_STRSET {
                    return None;
                }
            }
        }
        combos = next;
    }
    let mut out = BTreeSet::new();
    for sep in seps {
        for combo in &combos {
            out.insert(combo.join(sep));
            if out.len() > PY_MAX_STRSET {
                return None;
            }
        }
    }
    Some(out)
}

/// `"...{}...".format(a, b)` - supports auto `{}` and explicit `{N}`
/// positional fields only.
fn py_format_strs(fmts: &BTreeSet<String>, args: &[BTreeSet<String>]) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for fmt in fmts {
        // Extract field specs in order.
        let fields: Option<Vec<Option<usize>>> = py_format_fields(fmt);
        let Some(fields) = fields else { continue };
        // Map each field to an arg index; auto fields consume args
        // sequentially, explicit {N} index directly.
        let mut arg_idx: Vec<usize> = Vec::new();
        let mut auto = 0usize;
        let mut ok = true;
        for f in &fields {
            match f {
                None => {
                    if auto >= args.len() {
                        ok = false;
                        break;
                    }
                    arg_idx.push(auto);
                    auto += 1;
                }
                Some(n) => {
                    if *n >= args.len() {
                        ok = false;
                        break;
                    }
                    arg_idx.push(*n);
                }
            }
        }
        if !ok {
            continue;
        }
        // Cartesian product over the referenced arg sets.
        let mut combos: Vec<Vec<String>> = vec![Vec::new()];
        for &ai in &arg_idx {
            let mut next = Vec::new();
            for combo in &combos {
                for v in &args[ai] {
                    let mut c = combo.clone();
                    c.push(v.clone());
                    next.push(c);
                    if next.len() > PY_MAX_STRSET {
                        return None;
                    }
                }
            }
            combos = next;
        }
        for combo in combos {
            out.insert(py_format_apply(fmt, &combo)?);
            if out.len() > PY_MAX_STRSET {
                return None;
            }
        }
    }
    Some(out)
}

/// Parse `{...}` fields: None = auto `{}`, Some(n) = `{n}`.
/// Returns None if any field is named/complex.
fn py_format_fields(fmt: &str) -> Option<Vec<Option<usize>>> {
    let mut out = Vec::new();
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if i + 1 < b.len() && b[i + 1] == b'{' {
                i += 2;
                continue;
            }
            let mut j = i + 1;
            while j < b.len() && b[j] != b'}' {
                j += 1;
            }
            if j >= b.len() {
                return None;
            }
            let inner = &fmt[i + 1..j];
            if inner.is_empty() {
                out.push(None);
            } else if inner.chars().all(|c| c.is_ascii_digit()) {
                out.push(Some(inner.parse().ok()?));
            } else {
                return None; // {name}, {x!r}, {x:>5} unsupported
            }
            i = j + 1;
        } else if b[i] == b'}' {
            if i + 1 < b.len() && b[i + 1] == b'}' {
                i += 2;
                continue;
            }
            return None;
        } else {
            i += 1;
        }
    }
    Some(out)
}

/// Substitute already-computed field values into a format string.
/// `values` are in placeholder-occurrence order.
fn py_format_apply(fmt: &str, values: &[String]) -> Option<String> {
    // fields[i] corresponds to the i-th placeholder occurrence;
    // values are in field order.
    let mut out = String::new();
    let b = fmt.as_bytes();
    let mut i = 0;
    let mut fi = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if i + 1 < b.len() && b[i + 1] == b'{' {
                out.push('{');
                i += 2;
                continue;
            }
            let mut j = i + 1;
            while j < b.len() && b[j] != b'}' {
                j += 1;
            }
            if j >= b.len() || fi >= values.len() {
                return None;
            }
            out.push_str(&values[fi]);
            fi += 1;
            i = j + 1;
        } else if b[i] == b'}' {
            if i + 1 < b.len() && b[i + 1] == b'}' {
                out.push('}');
                i += 2;
            } else {
                return None;
            }
        } else {
            let l = utf8_len(b[i]);
            out.push_str(&fmt[i..i + l]);
            i += l;
        }
    }
    Some(out)
}

/// Evaluate an iterable expression to per-element string sets.
fn py_eval_strlist(
    env: &PyEnv,
    node: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<Vec<BTreeSet<String>>> {
    if depth > PY_MAX_EVAL_DEPTH {
        return None;
    }
    match node.kind() {
        "list" | "tuple" | "set" => {
            let mut out = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if !child.is_named() {
                    continue;
                }
                out.push(py_eval_strset(env, child, text, depth + 1)?);
            }
            Some(out)
        }
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            if env.bad.contains(name) {
                return None;
            }
            // Resolve through assignments: each RHS may itself be a
            // list literal or another name.
            let exprs = env.assigns.get(name)?;
            let mut out = Vec::new();
            for e in exprs {
                if let Some(items) = py_eval_strlist(env, *e, text, depth + 1) {
                    out.extend(items);
                } else if let Some(s) = py_eval_strset(env, *e, text, depth + 1) {
                    // `X = "abc"` iterated gives chars - useless; bail.
                    let _ = s;
                    return None;
                } else {
                    return None;
                }
            }
            Some(out)
        }
        "parenthesized_expression" => {
            let inner = node.children(&mut node.walk()).find(|c| c.is_named())?;
            py_eval_strlist(env, inner, text, depth + 1)
        }
        _ => None,
    }
}

/// `D["key"]` where D is a dict literal (or name bound to one):
/// over-approximate as the union of all values - the key is data,
/// not structure we can trust.
fn py_eval_subscript(
    env: &PyEnv,
    node: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    let obj = node.child_by_field_name("object")?;
    match obj.kind() {
        "dictionary" => py_dict_values(env, obj, text, depth),
        "identifier" => {
            let name = obj.utf8_text(text.as_bytes()).ok()?;
            if env.bad.contains(name) {
                return None;
            }
            let exprs = env.assigns.get(name)?;
            let mut out = BTreeSet::new();
            for e in exprs {
                if let Some(v) = py_dict_values(env, *e, text, depth + 1) {
                    out.extend(v);
                }
            }
            (!out.is_empty() && out.len() <= PY_MAX_STRSET).then_some(out)
        }
        _ => None,
    }
}

/// Union of all values in a dict literal (keys ignored).
fn py_dict_values(
    env: &PyEnv,
    node: tree_sitter::Node,
    text: &str,
    depth: u8,
) -> Option<BTreeSet<String>> {
    if node.kind() != "dictionary" {
        return None;
    }
    let mut out = BTreeSet::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        if let Some(v) = child.child_by_field_name("value") {
            if let Some(s) = py_eval_strset(env, v, text, depth + 1) {
                out.extend(s);
            }
        }
    }
    (!out.is_empty() && out.len() <= PY_MAX_STRSET).then_some(out)
}

/// All imports in Python source, via tree-sitter. Docstrings, comments,
/// and string contents can't produce phantom imports; syntax errors
/// degrade to ERROR nodes rather than wrong guesses. The third return
/// value counts dynamic import sites (non-literal `import_module` /
/// `__import__` args) so callers can warn that edges may be incomplete.
fn py_import_refs(text: &str) -> (Vec<PyRef>, bool, usize, usize) {
    let mut out = Vec::new();
    let mut dynamic = 0usize;
    // Subset of `dynamic` whose argument reads env vars or config -
    // reported separately so warnings can say *why* it's invisible.
    let mut env_cfg = 0usize;
    let Some(tree) = parse_ts(text, tree_sitter_python::LANGUAGE.into()) else {
        return (out, true, dynamic, env_cfg);
    };
    let had_error = tree.root_node().has_error();
    // Const-prop environment for computed dynamic imports - built in
    // a pre-pass so bindings are order-independent.
    let env = build_py_env(&tree, text);
    // Names bound by import statements - `getattr` on one of these is
    // dynamic dispatch (module __getattr__ can lazily import, so the
    // edge is invisible). Collected in the same walk; getattr calls
    // are resolved against the set after the walk since imports may
    // appear textually after the call.
    let mut bound: BTreeSet<String> = BTreeSet::new();
    let mut getattr_objs: Vec<String> = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" => {
                let mut cursor = node.walk();
                for name in node.children_by_field_name("name", &mut cursor) {
                    // `import a.b` binds `a`; `import a.b as c` binds `c`.
                    if name.kind() == "aliased_import" {
                        if let Some(alias) = name.child_by_field_name("alias") {
                            if let Ok(t) = alias.utf8_text(text.as_bytes()) {
                                bound.insert(t.to_string());
                            }
                        }
                        if let Some(d) = name.child_by_field_name("name") {
                            if let Some(segs) = dotted_segs(d, text) {
                                out.push(PyRef::Import(segs));
                            }
                        }
                    } else if let Some(segs) = dotted_segs(name, text) {
                        bound.insert(segs[0].clone());
                        out.push(PyRef::Import(segs));
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
                    if name.kind() == "aliased_import" {
                        if let Some(alias) = name.child_by_field_name("alias") {
                            if let Ok(t) = alias.utf8_text(text.as_bytes()) {
                                bound.insert(t.to_string());
                            }
                        }
                    }
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
                                bound.insert(t.to_string());
                            }
                        }
                    }
                }
                if let Some((level, segs)) = level_segs {
                    out.push(PyRef::From { level, segs, names });
                }
            }
            "assignment" => {
                // Framework convention lists: `pytest_plugins = [...]`,
                // `INSTALLED_APPS = [...]` - literal dotted strings the
                // frameworks import on our behalf.
                if let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if l.kind() == "identifier" {
                        if let Ok(name) = l.utf8_text(text.as_bytes()) {
                            if matches!(name, "pytest_plugins" | "INSTALLED_APPS") {
                                if let Some(strings) = py_convention_strings(&env, r, text) {
                                    if !strings.is_empty() {
                                        out.push(PyRef::Convention(strings));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "call" => {
                // Dynamic imports with literal arguments:
                // `import_module("a.b")`, `importlib.import_module("a.b")`,
                // `__import__("a.b")`. Non-literal args are counted as
                // dynamic sites (invisible edges) for the warning.
                match py_dyn_call_kind(node, text, &env) {
                    PyDynCall::Literal(paths) => {
                        for segs in paths {
                            out.push(PyRef::Import(segs));
                        }
                    }
                    PyDynCall::Dynamic => {
                        // Same-file call-site propagation: `def f(n):
                        // import_module(n)` called with literals
                        // resolves through the parameter.
                        let resolved = py_first_arg(node).and_then(|arg| {
                            py_dyn_callsite_paths(tree.root_node(), arg, text, &env)
                        });
                        match resolved {
                            Some((paths, unresolved)) => {
                                for segs in paths {
                                    out.push(PyRef::Import(segs));
                                }
                                if unresolved {
                                    dynamic += 1;
                                }
                            }
                            None => {
                                dynamic += 1;
                                if py_first_arg(node).is_some_and(|a| py_source_hint(a, text)) {
                                    env_cfg += 1;
                                }
                            }
                        }
                    }
                    PyDynCall::NotDynamic => {}
                }
                // `runpy.run_path("script.py")` - literal/const file
                // path dep (module path handled above via run_module).
                if let Some(func) = node.child_by_field_name("function") {
                    if let Ok(ft) = func.utf8_text(text.as_bytes()) {
                        if ft == "run_path" || ft.ends_with(".run_path") {
                            match py_first_arg(node)
                                .and_then(|a| py_eval_strset(&env, a, text, 0))
                            {
                                Some(vals) => {
                                    for v in vals {
                                        out.push(PyRef::PathDep(v));
                                    }
                                }
                                None => dynamic += 1,
                            }
                        }
                        // `importlib.util.spec_from_file_location("n",
                        // "path.py")` - second arg is the file path.
                        if ft == "spec_from_file_location"
                            || ft.ends_with(".spec_from_file_location")
                        {
                            let path_arg = node
                                .child_by_field_name("arguments")
                                .map(|args| {
                                    let mut c = args.walk();
                                    let kids: Vec<_> = args
                                        .children(&mut c)
                                        .filter(|k| {
                                            !matches!(k.kind(), "(" | ")" | ",")
                                        })
                                        .collect();
                                    kids.into_iter().nth(1)
                                })
                                .flatten();
                            match path_arg
                                .and_then(|a| py_eval_strset(&env, a, text, 0))
                            {
                                Some(vals) => {
                                    for v in vals {
                                        out.push(PyRef::PathDep(v));
                                    }
                                }
                                None => dynamic += 1,
                            }
                        }
                    }
                }
                // glob.glob/iglob/Path.glob with a literal or
                // const-derived pattern - matched against the file set.
                if let Some(func) = node.child_by_field_name("function") {
                    if let Ok(ft) = func.utf8_text(text.as_bytes()) {
                        let is_glob = ft == "glob"
                            || ft == "iglob"
                            || ft.ends_with(".glob")
                            || ft.ends_with(".iglob");
                        if is_glob {
                            if let Some(args) = node.child_by_field_name("arguments") {
                                let evaluated = {
                                    let mut c = args.walk();
                                    let found = args
                                        .children(&mut c)
                                        .find(|c| !matches!(c.kind(), "(" | ")" | ","))
                                        .and_then(|arg| py_eval_strset(&env, arg, text, 0));
                                    found
                                };
                                match evaluated {
                                    // Literal/const-derived pattern -
                                    // expand against the scanned files.
                                    // Non-wildcard patterns are exact
                                    // matches, which is correct.
                                    Some(vals) => {
                                        let pats: Vec<String> = vals.into_iter().collect();
                                        if !pats.is_empty() {
                                            out.push(PyRef::Glob(pats));
                                        }
                                    }
                                    // Computed pattern - invisible
                                    // edges, count for the warning.
                                    None => dynamic += 1,
                                }
                            } else {
                                dynamic += 1;
                            }
                        }
                    }
                }
                // `entry_points(group="x")` and
                // `entry_points().select(group="x")` - consumer side
                // of declared entry points; resolved by the caller
                // once the group->targets map is known. No `group`
                // kwarg selects all groups (empty vec). `.select`
                // only counts when it has a group kwarg - a bare
                // `entry_points().select(name=...)` selects by entry
                // name, not group, and stays unresolved.
                if let Some(func) = node.child_by_field_name("function") {
                    let is_ep_call = func
                        .utf8_text(text.as_bytes())
                        .is_ok_and(|t| t == "entry_points" || t.ends_with(".entry_points"));
                    let is_ep_select = func
                        .utf8_text(text.as_bytes())
                        .is_ok_and(|t| t.ends_with(".select"));
                    if is_ep_call || is_ep_select {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let groups = {
                                let mut c = args.walk();
                                let found = args
                                    .children(&mut c)
                                    .filter(|ch| ch.kind() == "keyword_argument")
                                    .find_map(|kw| {
                                        let name = kw
                                            .child_by_field_name("name")
                                            .and_then(|n| n.utf8_text(text.as_bytes()).ok())?;
                                        if name != "group" {
                                            return None;
                                        }
                                        let value = kw.child_by_field_name("value")?;
                                        Some(value)
                                    })
                                    .map(|v| {
                                        py_eval_strset(&env, v, text, 0)
                                            .map(|s| s.into_iter().collect::<Vec<_>>())
                                    });
                                found
                            };
                            match groups {
                                // group= literal/const -> those groups.
                                Some(Some(gs)) => out.push(PyRef::EpGroup(gs)),
                                // group= computed -> dynamic site.
                                Some(None) => dynamic += 1,
                                // entry_points() with no group -> all
                                // groups; bare .select() has no group
                                // semantics - ignore it.
                                None => {
                                    if is_ep_call {
                                        out.push(PyRef::EpGroup(Vec::new()));
                                    }
                                }
                            }
                        }
                    }
                }
                // `getattr(<imported-name>, ...)` - dynamic attribute
                // dispatch; module __getattr__ may lazily import, so
                // edges can be invisible. First arg must be a bare
                // identifier; resolved against `bound` after the walk.
                if let Some(func) = node.child_by_field_name("function") {
                    if func
                        .utf8_text(text.as_bytes())
                        .is_ok_and(|t| t == "getattr")
                    {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let first_ident = {
                                let mut c = args.walk();
                                let found = args
                                    .children(&mut c)
                                    .find(|c| !matches!(c.kind(), "(" | ")" | ","))
                                    .filter(|a| a.kind() == "identifier")
                                    .and_then(|a| a.utf8_text(text.as_bytes()).ok())
                                    .map(|t| t.to_string());
                                found
                            };
                            if let Some(t) = first_ident {
                                getattr_objs.push(t);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    dynamic += getattr_objs.iter().filter(|o| bound.contains(*o)).count();
    (out, had_error, dynamic, env_cfg)
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

/// What a `call` node turned out to be for dynamic-import purposes.
enum PyDynCall {
    /// `import_module("a.b")` etc. resolving to one or more valid
    /// module paths (literal or const-propagated).
    Literal(Vec<Vec<String>>),
    /// Dyn-import-shaped call whose module path isn't resolvable -
    /// invisible edge.
    Dynamic,
    /// Not a dynamic-import call, or a literal that isn't a valid
    /// module path (unresolvable, not "dynamic").
    NotDynamic,
}

/// Classify a call as a dynamic-import site: `import_module`,
/// `importlib.import_module`, `__import__` and attribute variants.
/// `env` is the file's const-prop environment - computed arguments
/// like `"pkg." + NAME` resolve when every piece is literal-derived.
fn py_dyn_call_kind(call: tree_sitter::Node, text: &str, env: &PyEnv) -> PyDynCall {
    let Some(func) = call.child_by_field_name("function") else {
        return PyDynCall::NotDynamic;
    };
    let Ok(func_text) = func.utf8_text(text.as_bytes()) else {
        return PyDynCall::NotDynamic;
    };
    let is_dyn = func_text == "__import__"
        || func_text == "import_module"
        || func_text.ends_with(".import_module")
        || func_text.ends_with(".__import__")
        || func_text == "run_module"
        || func_text.ends_with(".run_module");
    if !is_dyn {
        return PyDynCall::NotDynamic;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return PyDynCall::Dynamic;
    };
    let mut cursor = args.walk();
    // First real argument - skip "(", ",", ")" punctuation nodes.
    let Some(arg) = args
        .children(&mut cursor)
        .find(|c| !matches!(c.kind(), "(" | ")" | ","))
    else {
        return PyDynCall::Dynamic;
    };
    // Plain literal string: fast path, no env needed.
    if arg.kind() == "string" {
        if let Some(inner) = py_string_inner(arg, text) {
            if !inner.contains('{') {
                return py_module_path_call(inner);
            }
        }
        // f-string or unparseable - fall through to const-prop, which
        // handles interpolations over known constants.
    }
    // Computed argument: evaluate to a set of possible module paths.
    let Some(vals) = py_eval_strset(env, arg, text, 0) else {
        return PyDynCall::Dynamic;
    };
    let mut paths = Vec::new();
    for v in &vals {
        if let PyDynCall::Literal(mut p) = py_module_path_call(v.clone()) {
            paths.append(&mut p);
        }
    }
    if paths.is_empty() {
        PyDynCall::Dynamic
    } else {
        PyDynCall::Literal(paths)
    }
}

/// First real argument of a call - skips "(", ",", ")" punctuation.
fn py_first_arg(call: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let found = args
        .children(&mut cursor)
        .find(|c| !matches!(c.kind(), "(" | ")" | ","));
    found
}

/// Heuristic: does this dynamic-import argument read from the
/// environment or a config file? Substring scan of the arg's source -
/// good enough for a warning hint, not for resolution.
fn py_source_hint(arg: tree_sitter::Node, text: &str) -> bool {
    let Ok(src) = arg.utf8_text(text.as_bytes()) else {
        return false;
    };
    let s = src.to_lowercase();
    [
        "environ",
        "getenv",
        "config",
        "setting",
        "dotenv",
        "configparser",
        "json.load",
        "yaml",
        "toml",
        "argv",
        "secret",
    ]
    .iter()
    .any(|k| s.contains(k))
}

/// Same-file call-site propagation for `def load(name): import_module(name)`.
/// When a dynamic-import argument references parameters of the
/// enclosing function, literal arguments at call sites of that
/// function (same file) are overlaid onto a cloned const-prop env as
/// synthetic assignments, then the argument is re-evaluated - so
/// `'plugins.' + name` resolves through `load('ldap')`.
/// Returns `(module paths, had_unresolved_callsite)` or `None` when
/// the pattern doesn't apply (arg isn't inside a function, or no
/// parameter of that function has any call site).
fn py_dyn_callsite_paths(
    root: tree_sitter::Node,
    arg: tree_sitter::Node,
    text: &str,
    env: &PyEnv,
) -> Option<(Vec<Vec<String>>, bool)> {
    // Enclosing function definition.
    let mut anc = arg.parent();
    let fdef = loop {
        match anc {
            Some(n) if n.kind() == "function_definition" => break n,
            Some(n) => anc = n.parent(),
            None => return None,
        }
    };
    let func_name = fdef
        .child_by_field_name("name")?
        .utf8_text(text.as_bytes())
        .ok()?
        .to_string();
    // Ordered parameters: (name, default value node).
    let params_node = fdef.child_by_field_name("parameters")?;
    let mut params: Vec<(String, Option<tree_sitter::Node>)> = Vec::new();
    let mut pc = params_node.walk();
    for p in params_node.children(&mut pc) {
        match p.kind() {
            "identifier" => {
                if let Ok(t) = p.utf8_text(text.as_bytes()) {
                    params.push((t.to_string(), None));
                }
            }
            "default_parameter" => {
                let name = p
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                    .unwrap_or("")
                    .to_string();
                let default = p.child_by_field_name("value");
                if !name.is_empty() {
                    params.push((name, default));
                }
            }
            "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
                let mut sc = p.walk();
                for d in p.children(&mut sc) {
                    if d.kind() == "identifier" {
                        if let Ok(t) = d.utf8_text(text.as_bytes()) {
                            params.push((t.to_string(), None));
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    if params.is_empty() {
        return None;
    }
    // Only parameters the argument expression actually references
    // need call-site coverage - unrelated params can't affect it.
    let mut used: BTreeSet<String> = BTreeSet::new();
    {
        let mut st = vec![arg];
        while let Some(n) = st.pop() {
            if n.kind() == "identifier" {
                if let Ok(t) = n.utf8_text(text.as_bytes()) {
                    used.insert(t.to_string());
                }
            }
            let mut c = n.walk();
            st.extend(n.children(&mut c));
        }
    }
    let needed: Vec<usize> = params
        .iter()
        .enumerate()
        .filter(|(_, (p, _))| used.contains(p))
        .map(|(i, _)| i)
        .collect();
    if needed.is_empty() {
        return None;
    }

    // Collect call-site argument nodes per parameter. A call site
    // that omits the parameter falls back to its default; one that
    // can't supply it at all marks the result unresolved.
    let mut site_args: Vec<Vec<tree_sitter::Node>> = vec![Vec::new(); params.len()];
    let mut unresolved = false;
    let mut any_site = false;
    let mut sites = 0usize;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            let is_target = node
                .child_by_field_name("function")
                .filter(|f| f.kind() == "identifier")
                .and_then(|f| f.utf8_text(text.as_bytes()).ok())
                == Some(func_name.as_str());
            if is_target {
                sites += 1;
                if sites > 64 {
                    unresolved = true;
                    break;
                }
                any_site = true;
                let Some(args) = node.child_by_field_name("arguments") else {
                    unresolved = true;
                    continue;
                };
                let mut positional: Vec<tree_sitter::Node> = Vec::new();
                let mut keywords: Vec<(String, tree_sitter::Node)> = Vec::new();
                let mut ac = args.walk();
                for ch in args.children(&mut ac) {
                    match ch.kind() {
                        "keyword_argument" => {
                            if let (Some(n), Some(v)) = (
                                ch.child_by_field_name("name"),
                                ch.child_by_field_name("value"),
                            ) {
                                if let Ok(t) = n.utf8_text(text.as_bytes()) {
                                    keywords.push((t.to_string(), v));
                                }
                            }
                        }
                        "(" | ")" | "," => {}
                        _ => positional.push(ch),
                    }
                }
                for i in &needed {
                    let (pname, default) = &params[*i];
                    let supplied = keywords
                        .iter()
                        .find(|(n, _)| n == pname)
                        .map(|(_, v)| *v)
                        .or_else(|| positional.get(*i).copied());
                    match supplied {
                        Some(v) => site_args[*i].push(v),
                        None => match default {
                            Some(d) => site_args[*i].push(*d),
                            None => unresolved = true,
                        },
                    }
                }
            }
        }
        let mut c = node.walk();
        stack.extend(node.children(&mut c));
    }
    if !any_site {
        return None;
    }

    // Overlay: clone the env, bind each parameter to its call-site
    // argument expressions, and un-mark it as a function parameter.
    let mut env2 = PyEnv {
        assigns: env.assigns.clone(),
        verbind: env.verbind.clone(),
        bad: env.bad.clone(),
        memo: std::cell::RefCell::new(HashMap::new()),
        visiting: std::cell::RefCell::new(BTreeSet::new()),
    };
    for (i, (pname, _)) in params.iter().enumerate() {
        if !site_args[i].is_empty() {
            env2.bad.remove(pname);
            env2.assigns.insert(pname.clone(), site_args[i].clone());
        }
    }

    // Re-evaluate the import argument under the overlaid env.
    let Some(vals) = py_eval_strset(&env2, arg, text, 0) else {
        return Some((Vec::new(), true));
    };
    let mut paths = Vec::new();
    for v in &vals {
        if let PyDynCall::Literal(mut p) = py_module_path_call(v.clone()) {
            paths.append(&mut p);
        }
    }
    Some((paths, unresolved))
}

/// Validate a dotted module string -> segment list (single path).
fn py_module_path_call(module: String) -> PyDynCall {
    let segs: Vec<String> = module
        .split('.')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    let valid = !segs.is_empty()
        && segs
            .iter()
            .all(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    if valid {
        PyDynCall::Literal(vec![segs])
    } else {
        PyDynCall::NotDynamic
    }
}

/// String literal content without quotes or prefix (`r"x"`, `'''x'''`).
fn py_string_inner(node: tree_sitter::Node, text: &str) -> Option<String> {
    let raw = node.utf8_text(text.as_bytes()).ok()?;
    let bytes = raw.as_bytes();
    let mut i = 0;
    // Skip string prefix chars (r, b, f, u and uppercase combos).
    while i < bytes.len()
        && matches!(
            bytes[i],
            b'r' | b'R' | b'b' | b'B' | b'f' | b'F' | b'u' | b'U'
        )
    {
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
    // `entry_points(group=...)` consumer lookups, resolved after the
    // config files below build the group -> targets map.
    let mut ep_lookups: Vec<(String, Vec<String>)> = Vec::new();

    // Parse all files in parallel (rayon); resolution below stays
    // sequential so edge order is deterministic.
    let extracted = files
        .par_iter()
        .map(|(rel, abs)| {
            let text = fs::read_to_string(abs)
                .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
            let (refs, had_error, dynamic, env_cfg) = py_import_refs(&text);
            Ok((
                rel.clone(),
                refs,
                had_error,
                dynamic,
                env_cfg,
                manual_dep_specs(&text),
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    for (rel_s, refs, had_error, dynamic, env_cfg, manual) in extracted {
        let rel = &rel_s;
        if had_error {
            warnings.push(format!("{rel}: parse errors (partial scan)"));
        }
        if dynamic > 0 {
            let hint = if env_cfg > 0 {
                format!(" ({env_cfg} read env vars/config)")
            } else {
                String::new()
            };
            warnings.push(format!(
                "{rel}: {dynamic} dynamic import site(s){hint} - edges may be incomplete"
            ));
        }
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();
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
                                note_dep(&mut deps, dep, EdgeKind::Static);
                            }
                            break;
                        }
                    }
                }
                PyRef::From {
                    level,
                    segs,
                    names: imps,
                } => {
                    add_py_from(&names, rel, parent, level, &segs, &imps, &mut deps);
                }
                PyRef::Glob(patterns) => {
                    for pat in patterns {
                        for dep in py_glob_expand(&names, &[parent, ""], &pat) {
                            if dep != *rel {
                                note_dep(&mut deps, dep, EdgeKind::Resolved);
                            }
                        }
                    }
                }
                PyRef::Convention(strings) => {
                    for s in strings {
                        let segs: Vec<String> = s.split('.').map(str::to_string).collect();
                        // Try longest prefix first - `myapp.apps.MyConfig`
                        // resolves `myapp.apps` (the module), not the
                        // class attribute.
                        'outer: for end in (1..=segs.len()).rev() {
                            for b in ancestor_bases(rel) {
                                if let Some(dep) = resolve_py_exact(&names, &b, &segs[..end]) {
                                    if dep != *rel {
                                        note_dep(&mut deps, dep, EdgeKind::Declared);
                                    }
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
                PyRef::PathDep(spec) => {
                    // File path: file-dir relative, then project-root
                    // relative - same rule as `# strand: depends-on`.
                    if let Some(dep) = [parent, ""]
                        .iter()
                        .filter_map(|b| normalize_rel(b, &spec))
                        .find(|c| names.contains(c))
                    {
                        if dep != *rel {
                            note_dep(&mut deps, dep, EdgeKind::Static);
                        }
                    }
                }
                PyRef::EpGroup(groups) => {
                    ep_lookups.push((rel.clone(), groups));
                }
            }
        }

        // `# strand: depends-on path` manual edges - file path relative
        // to this file's dir, or a dotted module path.
        for spec in manual {
            let dep = if spec.contains('/') || spec.ends_with(".py") {
                // Path form: file-dir relative, then project-root relative.
                [parent, ""]
                    .iter()
                    .filter_map(|b| normalize_rel(b, &spec))
                    .find(|c| names.contains(c))
            } else {
                let segs: Vec<String> = spec.split('.').map(str::to_string).collect();
                ancestor_bases(rel)
                    .iter()
                    .find_map(|b| resolve_py_exact(&names, b, &segs))
            };
            if let Some(dep) = dep {
                if dep != *rel {
                    note_dep(&mut deps, dep, EdgeKind::Declared);
                }
            }
        }

        for (dep, kind) in deps {
            edges.push((rel.clone(), dep, None, kind));
        }
    }

    // pytest auto-loads every ancestor `conftest.py` for each test
    // module - an implicit framework edge the imports never show.
    // Restricted to test-looking files: `test_*.py`/`*_test.py`
    // basenames or anything under a `test`/`tests` directory.
    for (rel, _) in &files {
        let base = rel.rsplit('/').next().unwrap_or(rel);
        let under_test_dir = rel.split('/').any(|seg| seg == "test" || seg == "tests");
        let test_named = base.starts_with("test_") || base.ends_with("_test.py");
        if !under_test_dir && !test_named {
            continue;
        }
        let mut dir = parent_rel(rel);
        loop {
            let conf = if dir.is_empty() {
                "conftest.py".to_string()
            } else {
                format!("{dir}/conftest.py")
            };
            if names.contains(&conf) && conf != *rel {
                edges.push((rel.clone(), conf, None, EdgeKind::Declared));
            }
            if dir.is_empty() {
                break;
            }
            dir = parent_rel(dir);
        }
    }

    // `pyproject.toml` [project.entry-points] registers plugins at
    // runtime. The config file becomes the edge source so impact
    // analysis can see entry-point targets; the group -> targets map
    // also resolves `entry_points(group=...)` consumer lookups below.
    let mut ep_targets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut tomls: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["toml"], &mut tomls)?;
    let mut nodes: BTreeSet<String> = names.iter().cloned().collect();
    for (rel, abs) in tomls {
        if Path::new(&rel).file_name().and_then(|s| s.to_str()) != Some("pyproject.toml") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&abs) else {
            continue;
        };
        let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        let Some(eps) = doc
            .get("project")
            .and_then(|p| p.get("entry-points"))
            .and_then(|e| e.as_table())
        else {
            continue;
        };
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();
        for (group, specs) in eps {
            let Some(specs) = specs.as_table() else {
                continue;
            };
            let mut group_deps: BTreeSet<String> = BTreeSet::new();
            for (_name, spec) in specs {
                let Some(spec) = spec.as_str() else {
                    continue;
                };
                // Entry-point spec is "module.path:attr [extras]".
                let module = spec.split(':').next().unwrap_or(spec).trim();
                let segs: Vec<String> = module
                    .split('.')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let valid = !segs.is_empty()
                    && segs
                        .iter()
                        .all(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
                if !valid {
                    continue;
                }
                for base in entry_bases(&rel) {
                    if let Some(dep) = resolve_py_exact(&names, &base, &segs) {
                        if dep != rel {
                            note_dep(&mut deps, dep.clone(), EdgeKind::Declared);
                            group_deps.insert(dep);
                        }
                        break;
                    }
                }
            }
            if !group_deps.is_empty() {
                ep_targets
                    .entry(group.to_string())
                    .or_default()
                    .extend(group_deps);
            }
        }
        if !deps.is_empty() {
            for (dep, kind) in deps {
                edges.push((rel.clone(), dep, None, kind));
            }
            nodes.insert(rel);
        }
    }

    // `setup.cfg` [options.entry_points] - the setuptools-era
    // equivalent of pyproject entry points.
    let mut cfgs: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["cfg"], &mut cfgs)?;
    for (rel, abs) in cfgs {
        if Path::new(&rel).file_name().and_then(|s| s.to_str()) != Some("setup.cfg") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&abs) else {
            continue;
        };
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();
        for (group, module) in setup_cfg_entry_groups(&text) {
            let segs: Vec<String> = module.split('.').map(str::to_string).collect();
            for base in entry_bases(&rel) {
                if let Some(dep) = resolve_py_exact(&names, &base, &segs) {
                    if dep != rel {
                        note_dep(&mut deps, dep.clone(), EdgeKind::Declared);
                        ep_targets.entry(group.clone()).or_default().insert(dep);
                    }
                    break;
                }
            }
        }
        if !deps.is_empty() {
            for (dep, kind) in deps {
                edges.push((rel.clone(), dep, None, kind));
            }
            nodes.insert(rel);
        }
    }

    // `setup.py` `entry_points={...}` dict literals.
    for (rel, abs) in &files {
        if Path::new(rel).file_name().and_then(|s| s.to_str()) != Some("setup.py") {
            continue;
        }
        let Ok(text) = fs::read_to_string(abs) else {
            continue;
        };
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();
        let (specs, dynamic) = setup_py_entry_groups(&text);
        if dynamic > 0 {
            warnings.push(format!(
                "{rel}: {dynamic} computed entry_points value(s) - edges may be incomplete"
            ));
        }
        for (group, module) in specs {
            let segs: Vec<String> = module.split('.').map(str::to_string).collect();
            for base in entry_bases(rel) {
                if let Some(dep) = resolve_py_exact(&names, &base, &segs) {
                    if dep != *rel {
                        note_dep(&mut deps, dep.clone(), EdgeKind::Declared);
                        ep_targets.entry(group.clone()).or_default().insert(dep);
                    }
                    break;
                }
            }
        }
        for (dep, kind) in deps {
            edges.push((rel.clone(), dep, None, kind));
        }
    }

    // `entry_points(group="x")` callers depend on every target
    // declared in that group; no group selects all declared targets.
    if !ep_lookups.is_empty() && !ep_targets.is_empty() {
        for (rel, groups) in ep_lookups {
            let mut targets: BTreeSet<String> = BTreeSet::new();
            if groups.is_empty() {
                for t in ep_targets.values() {
                    targets.extend(t.iter().cloned());
                }
            } else {
                for g in &groups {
                    if let Some(t) = ep_targets.get(g) {
                        targets.extend(t.iter().cloned());
                    }
                }
            }
            targets.remove(&rel);
            for dep in targets {
                edges.push((rel.clone(), dep, None, EdgeKind::Resolved));
            }
        }
    }
    Ok(ScanOutput {
        edges,
        nodes: nodes.into_iter().collect(),
        warnings,
    })
}

/// `name = module.path:attr` spec -> `module.path`, or `None`.
/// Validates every segment is an identifier.
fn entry_spec_module(spec: &str) -> Option<String> {
    let rhs = spec.split_once('=')?.1.trim();
    let module = rhs.split(':').next()?.trim();
    let valid = !module.is_empty()
        && module
            .split('.')
            .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    valid.then(|| module.to_string())
}

/// `setup.cfg` `[options.entry_points]` section -> `(group, module)`
/// pairs. Group headers (`group =` with empty value) set the current
/// group; spec lines are `name = module.path:attr`.
fn setup_cfg_entry_groups(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_section = false;
    let mut cur_group = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t.eq_ignore_ascii_case("[options.entry_points]");
            continue;
        }
        if !in_section || t.is_empty() || t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        // `group =` (empty RHS) opens a group; `name = module:attr`
        // lines belong to it.
        if let Some((lhs, rhs)) = t.split_once('=') {
            if rhs.trim().is_empty() {
                cur_group = lhs.trim().to_string();
                continue;
            }
            if let Some(m) = entry_spec_module(t) {
                out.push((cur_group.clone(), m));
            }
        }
    }
    out
}

/// `setup.py` `entry_points={...}` dict literal -> `(group, module)`
/// pairs. Also returns a count of `entry_points=` values resolved to a
/// function call (e.g. `build_eps()`) - computed dicts stay invisible.
fn setup_py_entry_groups(text: &str) -> (Vec<(String, String)>, usize) {
    let mut out = Vec::new();
    let mut dynamic = 0usize;
    let Some(tree) = parse_ts(text, tree_sitter_python::LANGUAGE.into()) else {
        return (out, dynamic);
    };
    // Alias map: `NAME = <expr>` assignments, so
    // `setup(entry_points=NAME)` resolves to the assigned dict.
    let mut aliases: Vec<(String, tree_sitter::Node)> = Vec::new();
    {
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "assignment" {
                if let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if l.kind() == "identifier" {
                        if let Ok(name) = l.utf8_text(text.as_bytes()) {
                            aliases.push((name.to_string(), r));
                        }
                    }
                }
            }
            let mut c = node.walk();
            for child in node.children(&mut c) {
                stack.push(child);
            }
        }
    }
    let mut resolve_expr = |expr: tree_sitter::Node, out: &mut Vec<(String, String)>| {
        // Follow identifier aliases (bounded) then read group -> specs
        // pairs from whatever dict expression remains.
        let mut cur = expr;
        for _ in 0..8 {
            if cur.kind() != "identifier" {
                break;
            }
            let Ok(name) = cur.utf8_text(text.as_bytes()) else {
                break;
            };
            match aliases.iter().find(|(n, _)| n == name) {
                Some((_, rhs)) => cur = *rhs,
                None => return,
            }
        }
        // A non-`dict(...)` call means the dict is computed - count it
        // as a dynamic site so the scan can warn.
        let mut is_dict_call = false;
        if cur.kind() == "call" {
            let fname = cur
                .child_by_field_name("function")
                .and_then(|f| f.utf8_text(text.as_bytes()).ok())
                .unwrap_or("");
            if fname.ends_with("dict") {
                is_dict_call = true;
            } else {
                dynamic += 1;
            }
        }
        if cur.kind() != "dictionary" {
            // `dict(...)` calls can't be grouped reliably - keep the
            // config->target edges under an empty group.
            if is_dict_call {
                let mut mods = Vec::new();
                collect_entry_strings(cur, text, &mut mods);
                for m in mods {
                    out.push((String::new(), m));
                }
            }
            return;
        }
        // Top-level pairs are group -> specs; each value may be a
        // dict of name->spec, a list, or a bare spec string.
        let mut c = cur.walk();
        for pair in cur.children(&mut c).filter(|ch| ch.kind() == "pair") {
            let Some(group) = pair
                .child_by_field_name("key")
                .and_then(|k| py_string_inner(k, text))
            else {
                continue;
            };
            let Some(value) = pair.child_by_field_name("value") else {
                continue;
            };
            let mut mods = Vec::new();
            collect_entry_strings(value, text, &mut mods);
            for m in mods {
                out.push((group.clone(), m));
            }
        }
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            let is_setup = node
                .child_by_field_name("function")
                .and_then(|f| f.utf8_text(text.as_bytes()).ok())
                .is_some_and(|t| t == "setup");
            if is_setup {
                // keyword_argument nodes live inside argument_list.
                let mut inner = vec![node];
                while let Some(n) = inner.pop() {
                    if n.kind() == "keyword_argument" {
                        let named = n
                            .child_by_field_name("name")
                            .and_then(|x| x.utf8_text(text.as_bytes()).ok())
                            .is_some_and(|x| x == "entry_points");
                        if named {
                            if let Some(value) = n.child_by_field_name("value") {
                                resolve_expr(value, &mut out);
                            }
                        }
                    }
                    let mut c = n.walk();
                    for child in n.children(&mut c) {
                        inner.push(child);
                    }
                }
            }
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    (out, dynamic)
}

/// Collect `"name = module.path:attr"` strings anywhere inside a node
/// (dict values, lists, nested groups).
fn collect_entry_strings(node: tree_sitter::Node, text: &str, out: &mut Vec<String>) {
    if node.kind() == "string" {
        if let Some(inner) = py_string_inner(node, text) {
            if let Some(m) = entry_spec_module(&inner) {
                out.push(m);
            }
        }
        return;
    }
    let mut c = node.walk();
    for child in node.children(&mut c) {
        collect_entry_strings(child, text, out);
    }
}

/// Candidate package roots for entry-point module resolution:
/// ancestor dirs of the pyproject plus their `src/` subdirs
/// (src-layout projects).
fn entry_bases(rel: &str) -> Vec<String> {
    ancestor_bases(rel)
        .into_iter()
        .flat_map(|b| {
            let src = if b.is_empty() {
                "src".to_string()
            } else {
                format!("{b}/src")
            };
            [b, src]
        })
        .collect()
}

/// Resolve a `from <dots><mod> import <names>` against the file set.
/// `level` is the count of leading dots (0 = absolute import, which
/// tries every ancestor dir as a package root like `sys.path`).
/// `pytest_plugins`/`INSTALLED_APPS` RHS -> dotted module strings.
/// Handles list/tuple literals and single strings via const-prop.
fn py_convention_strings(env: &PyEnv, node: tree_sitter::Node, text: &str) -> Option<Vec<String>> {
    // List/tuple/set of strings.
    if matches!(node.kind(), "list" | "tuple" | "set") {
        let items = py_eval_strlist(env, node, text, 0)?;
        let mut out = Vec::new();
        for item in items {
            if item.len() == 1 {
                out.extend(item);
            } else {
                return None; // multi-valued element - too fuzzy
            }
        }
        return Some(out);
    }
    // Single string or name.
    py_eval_strset(env, node, text, 0).map(|s| s.into_iter().collect())
}

/// Expand a glob pattern against scanned file names. Tried relative
/// to each base dir (file's dir, then project root). Supports `*`,
/// `?`, and `**` path segments.
fn py_glob_expand(names: &BTreeSet<String>, bases: &[&str], pattern: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for base in bases {
        let Some(norm) = normalize_rel(base, pattern) else {
            continue;
        };
        // normalize_rel treats `*`/`?` as ordinary segment chars -
        // they survive as literal text for the matcher.
        for name in names {
            if glob_match(&norm, name) {
                out.insert(name.clone());
            }
        }
    }
    out.into_iter().collect()
}

/// Match a `/`-separated glob pattern against a `/`-separated path.
/// `**` matches zero or more whole segments; `*`/`?` work inside a
/// segment.
fn glob_match(pat: &str, path: &str) -> bool {
    let p: Vec<&str> = pat.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    glob_match_segs(&p, &s)
}

fn glob_match_segs(pat: &[&str], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        // `**` matches zero or more segments.
        for skip in 0..=path.len() {
            if glob_match_segs(&pat[1..], &path[skip..]) {
                return true;
            }
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    wild_match(pat[0], path[0]) && glob_match_segs(&pat[1..], &path[1..])
}

/// `*`/`?` wildcard match within one path segment.
fn wild_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    // Iterative two-pointer with backtracking on '*'.
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_p, mut star_s) = (usize::MAX, 0usize);
    while si < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = pi;
            star_s = si;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_s += 1;
            si = star_s;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn add_py_from(
    names: &BTreeSet<String>,
    rel: &str,
    parent: &str,
    level: usize,
    segs: &[String],
    imps: &[String],
    deps: &mut BTreeMap<String, EdgeKind>,
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
                    note_dep(deps, dep, EdgeKind::Static);
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
                        note_dep(deps, dep, EdgeKind::Static);
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
                        note_dep(deps, dep, EdgeKind::Static);
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
        // .py before .pyi: the implementation wins over the stub.
        for cand in [
            format!("{p}.py"),
            format!("{p}.pyi"),
            format!("{p}/__init__.py"),
            format!("{p}/__init__.pyi"),
        ] {
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
    for cand in [
        format!("{p}.py"),
        format!("{p}.pyi"),
        format!("{p}/__init__.py"),
        format!("{p}/__init__.pyi"),
    ] {
        if names.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

// ---------- JS/TS scanner ----------

const JS_EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];

fn scan_js_impl(root: &Path) -> Result<ScanOutput> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, JS_EXTS, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    // `.json` files are resolvable import targets (`import data from
    // './x.json'`) but are not themselves import-scanned.
    let mut json_files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["json"], &mut json_files)?;
    let mut names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    names.extend(json_files.iter().map(|(n, _)| n.clone()));
    let mut edges: EdgeList = Vec::new();
    let mut warnings = Vec::new();
    let mut alias_cache = JsAliasCache::new(root);

    // Parse all files in parallel (rayon); alias resolution below
    // stays sequential (shared config cache) so edge order is
    // deterministic.
    let extracted = files
        .par_iter()
        .map(|(rel, abs)| {
            let text = fs::read_to_string(abs)
                .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
            let (specs, globs, had_error, dynamic) =
                js_import_specs_ts(&text, js_language_for(rel));
            Ok((
                rel.clone(),
                specs,
                globs,
                had_error,
                dynamic,
                manual_dep_specs(&text),
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    for (rel_s, specs, globs, had_error, dynamic, manual) in extracted {
        let rel = &rel_s;
        if had_error {
            warnings.push(format!("{rel}: parse errors (partial scan)"));
        }
        if dynamic > 0 {
            warnings.push(format!(
                "{rel}: {dynamic} dynamic import site(s) - edges may be incomplete"
            ));
        }
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();
        let parent = parent_rel(rel);
        let resolver = alias_cache.for_dir(parent);

        for spec in specs {
            // Relative specs ('./x', '../x') are always intra-project.
            if spec.starts_with(".") {
                let Some(norm) = normalize_rel(parent, &spec) else {
                    continue;
                };
                let dep = resolve_js(&names, &norm).or_else(|| resolve_json(&names, &norm));
                if let Some(dep) = dep {
                    if dep != *rel {
                        note_dep(&mut deps, dep, EdgeKind::Static);
                    }
                }
                continue;
            }
            // Bare specifiers: package.json `imports`, tsconfig `paths`
            // aliases and `baseUrl` resolve intra-project; anything
            // else is node_modules.
            if let Some(dep) = resolve_js_alias(&resolver, &names, &spec) {
                if dep != *rel {
                    note_dep(&mut deps, dep, EdgeKind::Static);
                }
            }
        }

        // Bundler-style glob patterns (`require.context`,
        // `import.meta.glob`, template/concat dynamic imports) expand
        // against the scanned JS/TS file set.
        for pat in globs {
            for dep in js_glob_expand(&names, &[parent, ""], &pat) {
                if dep != *rel {
                    note_dep(&mut deps, dep, EdgeKind::Resolved);
                }
            }
        }

        // `// strand: depends-on spec` manual edges - relative paths
        // or bare specifiers resolved like normal imports.
        for spec in manual {
            // Path-like specs resolve file-dir relative, then
            // project-root relative; bare specs go through aliases.
            let path_dep = |s: &str| {
                [parent, ""]
                    .iter()
                    .filter_map(|b| normalize_rel(b, s))
                    .find_map(|n| resolve_js(&names, &n))
            };
            let dep = if spec.starts_with(".") {
                path_dep(&spec)
            } else if spec.contains('/')
                || spec.ends_with(".ts")
                || spec.ends_with(".tsx")
                || spec.ends_with(".js")
                || spec.ends_with(".jsx")
                || spec.ends_with(".mjs")
                || spec.ends_with(".cjs")
            {
                path_dep(&spec)
            } else {
                resolve_js_alias(&resolver, &names, &spec)
            };
            if let Some(dep) = dep {
                if dep != *rel {
                    note_dep(&mut deps, dep, EdgeKind::Declared);
                }
            }
        }

        for (dep, kind) in deps {
            edges.push((rel.clone(), dep, None, kind));
        }
    }
    let nodes = names.into_iter().collect();
    Ok(ScanOutput {
        edges,
        nodes,
        warnings,
    })
}

/// tree-sitter grammar for a JS/TS file extension.
fn js_language_for(rel: &str) -> tree_sitter::Language {
    let lower = rel.to_lowercase();
    if lower.ends_with(".tsx") {
        return tree_sitter_typescript::LANGUAGE_TSX.into();
    }
    // .ts, .d.ts, .mts, .cts all parse under the TS grammar.
    if lower.ends_with(".ts") || lower.ends_with(".mts") || lower.ends_with(".cts") {
        return tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
    }
    tree_sitter_javascript::LANGUAGE.into()
}

/// Expand a JS glob pattern against scanned file names, relative to
/// each base dir. A pattern whose last segment has no `.` also tries
/// `+ext` variants so `import('./x/' + n)` reaches `x/a.ts` etc.
fn js_glob_expand(names: &BTreeSet<String>, bases: &[&str], pattern: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for base in bases {
        let Some(norm) = normalize_rel(base, pattern) else {
            continue;
        };
        let mut pats = vec![norm.clone()];
        let last = norm.rsplit('/').next().unwrap_or("");
        if !last.contains('.') {
            for ext in JS_EXTS {
                pats.push(format!("{norm}.{ext}"));
            }
        }
        for name in names {
            if pats.iter().any(|p| glob_match(p, name)) {
                out.insert(name.clone());
            }
        }
    }
    out.into_iter().collect()
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
    // `./x` -> `x.d.ts` declaration files.
    let cand = format!("{norm}.d.ts");
    if names.contains(&cand) {
        return Some(cand);
    }
    for ext in JS_EXTS {
        let cand = format!("{norm}/index.{ext}");
        if names.contains(&cand) {
            return Some(cand);
        }
    }
    // NodeNext / bundler convention: `./x.js` resolves to `x.ts` or
    // `x.tsx`, `.mjs` -> `.mts`, `.cjs` -> `.cts`, `.jsx` -> `.tsx`.
    // Try the extensionless stem against every script extension.
    for script_ext in [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"] {
        let Some(stem) = norm.strip_suffix(script_ext) else {
            continue;
        };
        for ext in JS_EXTS {
            let cand = format!("{stem}.{ext}");
            if names.contains(&cand) {
                return Some(cand);
            }
        }
        let cand = format!("{stem}.d.ts");
        if names.contains(&cand) {
            return Some(cand);
        }
        break;
    }
    None
}

/// JSON module resolution: `./data.json` exact, `./data` ->
/// `data.json`, `./dir` -> `dir/index.json`? (no - JSON has no
/// index convention; exact + `.json` suffix only).
fn resolve_json(names: &BTreeSet<String>, norm: &str) -> Option<String> {
    if names.contains(norm) && norm.ends_with(".json") {
        return Some(norm.to_string());
    }
    let cand = format!("{norm}.json");
    if names.contains(&cand) {
        return Some(cand);
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
            if let Some(parent) = read_tsconfig(root, &parent_abs, &parent_dir, depth + 1, seen) {
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
fn resolve_extends(root: &Path, cfg_abs: &Path, dir_rel: &str, ext: &str) -> Option<PathBuf> {
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
fn resolve_js_alias(resolver: &JsResolver, names: &BTreeSet<String>, spec: &str) -> Option<String> {
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
        let matched = ts
            .patterns
            .iter()
            .any(|p| pattern_star_text(p, spec).is_some());
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
