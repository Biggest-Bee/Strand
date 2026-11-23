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
    Go,
}

/// A Python source file's text plus its tree-sitter tree, handed back
/// by [`scan_project_with_py`] so callers doing their own per-file
/// analysis (strand-deep) can reuse the parse instead of paying for a
/// second tree-sitter parse of every file.
pub struct PySource {
    pub text: String,
    pub tree: tree_sitter::Tree,
}

/// Scan `root` for Rust sources and resolve intra-project dependencies.
pub fn scan_rust(root: &Path) -> Result<ScanOutput> {
    scan_lang(root, Lang::Rust)
}

/// Dispatch to the per-language scanner.
pub fn scan_lang(root: &Path, lang: Lang) -> Result<ScanOutput> {
    scan_lang_inner(root, lang, None)
}

fn scan_lang_inner(
    root: &Path,
    lang: Lang,
    mut py_sink: Option<&mut BTreeMap<String, PySource>>,
) -> Result<ScanOutput> {
    match lang {
        Lang::Rust => scan_rust_impl(root),
        Lang::Python => scan_python_impl(root, py_sink.as_deref_mut()),
        Lang::Js => scan_js_impl(root),
        Lang::Go => scan_go_impl(root),
    }
}

/// Scan `root` for all supported languages and merge the results.
/// Edges only form within a language (a `.rs` file can't depend on a
/// `.py` file), but node sets are unioned.
pub fn scan_project(root: &Path, langs: &[Lang]) -> Result<ScanOutput> {
    scan_project_inner(root, langs, None)
}

/// Like [`scan_project`], but also returns every scanned Python file's
/// text and tree-sitter tree so the caller can analyze them without
/// re-reading or re-parsing. Only populated when `Lang::Python` is in
/// `langs`.
pub fn scan_project_with_py(
    root: &Path,
    langs: &[Lang],
) -> Result<(ScanOutput, BTreeMap<String, PySource>)> {
    let mut py_sources = BTreeMap::new();
    let out = scan_project_inner(root, langs, Some(&mut py_sources))?;
    Ok((out, py_sources))
}

fn scan_project_inner(
    root: &Path,
    langs: &[Lang],
    mut py_sink: Option<&mut BTreeMap<String, PySource>>,
) -> Result<ScanOutput> {
    let mut edges = EdgeList::new();
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    for &lang in langs {
        let out = scan_lang_inner(root, lang, py_sink.as_deref_mut())?;
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
        "gradle.lockfile",
        "verification-metadata.xml",
        "pdm.lock",
        "conda-lock.yml",
        "conda-lock.yaml",
        "manifest.toml",
        "rebar.lock",
        "renv.lock",
        "go.work.sum",
    ];
    let mut lock_files: Vec<(String, PathBuf)> = Vec::new();
    walk_files(root, root, &mut |rel, abs| {
        if abs
            .file_name()
            .map(|n| {
                let n = n.to_string_lossy().to_lowercase();
                LOCK_NAMES.contains(&n.as_str())
                    || (n.starts_with("package@swift-") && n.ends_with(".resolved"))
            })
            .unwrap_or(false)
        {
            lock_files.push((rel, abs));
        }
    });
    lock_files.sort_by(|a, b| a.0.cmp(&b.0));
    // group -> dep name -> pinned node ids, for manifest bridging.
    let mut lock_nodes: HashMap<&'static str, HashMap<String, Vec<String>>> = HashMap::new();
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
    // Gradle module cache: verification-metadata/gradle.lockfile are
    // flat inventories, but ~/.gradle/caches/modules-2/files-2.1
    // holds each component's .module/.pom with real dependency
    // edges. Probe it when a gradle project is present.
    {
        let gradle_engaged = lock_nodes.get("gradle").is_some_and(|m| !m.is_empty())
            || manifest_edges
                .iter()
                .any(|(s, ..)| manifest_group(s) == Some("gradle"));
        if gradle_engaged {
            let mut coords: BTreeSet<String> = BTreeSet::new();
            if let Some(m) = lock_nodes.get("gradle") {
                for ids in m.values() {
                    coords.extend(ids.iter().cloned());
                }
            }
            // Manifest-declared `group:name` deps without a locked
            // version cannot locate cache dirs; skip them.
            if !coords.is_empty() {
                let ces = gradle_cache_edges(&coords);
                if !ces.is_empty() {
                    ingest_lock_edges(
                        "(gradle-cache)",
                        ces,
                        Some("gradle"),
                        false,
                        &mut nodes,
                        &mut edges,
                        &mut lock_nodes,
                    );
                }
            }
        }
    }
    // Local package caches: flat lockfiles (pubspec.lock,
    // Package.resolved, mix.lock, Cartfile.resolved, go.sum,
    // paket.lock, packages.config/lock.json) record pins but no dep
    // relations; ecosystem caches and project checkouts hold real
    // metadata, so BFS them for component->component edges.
    {
        let coords_of = |g: &str| -> BTreeSet<String> {
            lock_nodes
                .get(g)
                .map(|m| m.values().flatten().cloned().collect())
                .unwrap_or_default()
        };
        // (ecosystem group, seed coords, cache-derived edges)
        let mut probes: Vec<(&'static str, EdgeList)> = Vec::new();
        let pub_c = coords_of("pub");
        if !pub_c.is_empty() {
            if let Some(root) = crate::caches::pub_cache_root() {
                probes.push(("pub", crate::caches::pub_cache_edges(&pub_c, &root)));
            }
        }
        let go_c = coords_of("go");
        if !go_c.is_empty() {
            if let Some(root) = crate::caches::go_mod_cache_root() {
                probes.push(("go", crate::caches::go_cache_edges(&go_c, &root)));
            }
        }
        // NuGet seeds also come from packages.config manifest deps
        // (`id@version` dsts only; bare ids can't locate cache dirs).
        let mut nuget_seed = coords_of("nuget");
        for (s, d, ..) in &manifest_edges {
            if manifest_group(s) == Some("nuget") && d.contains('@') {
                nuget_seed.insert(d.clone());
            }
        }
        if !nuget_seed.is_empty() {
            if let Some(root) = crate::caches::nuget_cache_root() {
                probes.push((
                    "nuget",
                    crate::caches::nuget_cache_edges(&nuget_seed, &root),
                ));
            }
        }
        let jvm_c = coords_of("jvm");
        if !jvm_c.is_empty() {
            if let Some(root) = crate::caches::maven_repo_root() {
                probes.push(("jvm", crate::caches::maven_cache_edges(&jvm_c, &root)));
            }
        }
        // Python pins come from pdm.lock (lock_nodes) plus exact
        // `==` pins in requirements/setup.py manifest edges.
        let mut py_seed = coords_of("python");
        for (s, d, ..) in &manifest_edges {
            if manifest_group(s) == Some("python") && d.contains('@') {
                py_seed.insert(d.clone());
            }
        }
        let proj = PathBuf::from(root);
        if !py_seed.is_empty() {
            probes.push((
                "python",
                crate::caches::pip_site_packages_edges(&py_seed, &proj),
            ));
        }
        // Stack pkgdb: ~/.stack snapshots + project .stack-work.
        let haskell_c = coords_of("haskell");
        if !haskell_c.is_empty() {
            let stack_home = crate::caches::home_dir_public()
                .map(|h| h.join(".stack"))
                .unwrap_or_else(|| PathBuf::from("/nonexistent"));
            probes.push((
                "haskell",
                crate::caches::stack_pkgdb_edges(&haskell_c, &stack_home, &proj),
            ));
        }
        // Project-local checkouts/installs.
        let mix_c = coords_of("elixir");
        if !mix_c.is_empty() {
            probes.push(("elixir", crate::caches::mix_deps_edges(&mix_c, &proj)));
        }
        let erlang_c = coords_of("erlang");
        if !erlang_c.is_empty() {
            probes.push(("erlang", crate::caches::erlang_app_edges(&erlang_c, &proj)));
        }
        let r_c = coords_of("r");
        if !r_c.is_empty() {
            probes.push(("r", crate::caches::renv_library_edges(&r_c, &proj)));
        }
        let swift_c = coords_of("swift");
        if !swift_c.is_empty() {
            probes.push((
                "swift",
                crate::caches::swift_checkout_edges(&swift_c, &proj),
            ));
        }
        let carthage_c = coords_of("carthage");
        if !carthage_c.is_empty() {
            probes.push((
                "carthage",
                crate::caches::carthage_checkout_edges(&carthage_c, &proj),
            ));
        }
        for (group, edges_out) in probes {
            if edges_out.is_empty() {
                continue;
            }
            ingest_lock_edges(
                "(cache)",
                edges_out,
                Some(group),
                false,
                &mut nodes,
                &mut edges,
                &mut lock_nodes,
            );
        }
    }
    // Lockfile drift: a manifest `name@version` pin (requirements
    // `==`, package.json exact versions, cargo `=x`) that matches no
    // locked version of the same package is what `npm ci` / a frozen
    // install would reject - manifest and lockfile disagree about
    // what actually resolves.
    {
        let mut drift: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (src, dst, ..) in &manifest_edges {
            let Some(g) = manifest_group(src) else {
                continue;
            };
            // Only exact pins carry `@`+digit; bare/range specs skip.
            let Some(i) = dst.rfind('@') else {
                continue;
            };
            if i == 0
                || !dst[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
            {
                continue;
            }
            let bare = lock_node_name(dst).to_lowercase();
            let Some(locked) = lock_nodes.get(g).and_then(|m| m.get(&bare)) else {
                continue;
            };
            if locked.is_empty() || locked.iter().any(|n| n == dst) {
                continue;
            }
            // Version-tolerant compare: `1.0` vs `1.0.0` are the same
            // pin in most ecosystems.
            let mv = ver_key(&dst[i + 1..]);
            if locked.iter().any(|n| {
                n.rfind('@').is_some_and(|j| {
                    j > 0
                        && n[j + 1..]
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_digit())
                        && ver_key(&n[j + 1..]) == mv
                })
            }) {
                continue;
            }
            drift.entry(src.clone()).or_default().insert(dst.clone());
        }
        let total: usize = drift.values().map(|s| s.len()).sum();
        let mut shown = 0usize;
        'outer: for (src, dsts) in &drift {
            for d in dsts {
                if shown >= 20 {
                    break 'outer;
                }
                warnings.push(format!(
                    "{src}: {d} pinned in manifest but no lockfile agrees - possible drift"
                ));
                shown += 1;
            }
        }
        if total > shown {
            warnings.push(format!(
                "lockfile drift check truncated at {shown} of {total} pins"
            ));
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

/// Version compare key for drift checks: strip trailing `.0`
/// segments so `1.0`, `1.0.0`, `1` compare equal (version padding
/// tolerance across ecosystems).
fn ver_key(v: &str) -> String {
    let mut s = v.trim();
    while let Some(stripped) = s.strip_suffix(".0") {
        s = stripped;
    }
    s.to_string()
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
        GradleVerification | GradleLockfile => Some("gradle"),
        GoMod | GoSum => Some("go"),
        PdmLock => Some("python"),
        CondaLock => Some("conda"),
        JuliaManifest => Some("julia"),
        RebarLock => Some("erlang"),
        RenvLock => Some("r"),
        _ => None,
    }
}

/// Lockfile formats whose parsers emit `(lockfile) -> pkg` edges
/// (no recorded inter-package edges in the format itself).
fn is_flat_lock(fmt: crate::Format) -> bool {
    use crate::Format::*;
    matches!(
        fmt,
        SwiftResolved
            | PubspecLock
            | StackLock
            | MixLock
            | CartfileResolved
            | DenoLock
            | GradleVerification
            | GradleLockfile
            | RebarLock
            | RenvLock
    )
}

/// Ecosystem group a manifest edge source belongs to.
fn manifest_group(src: &str) -> Option<&'static str> {
    let f = src.rsplit('/').next()?.to_lowercase();
    match f.as_str() {
        "package.json" => Some("npm"),
        "cargo.toml" => Some("cargo"),
        "pyproject.toml" | "pipfile" | "setup.cfg" | "environment.yml" | "environment.yaml" => {
            Some("python")
        }
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
        _ if f.ends_with(".gradle") || f.ends_with(".gradle.kts") || f == "libs.versions.toml" => {
            Some("gradle")
        }
        _ if f == "setup.py" => Some("python"),
        _ if f.starts_with("requirements") && f.ends_with(".txt") => Some("python"),
        "pdm.lock" => Some("python"),
        "project.toml" => Some("julia"),
        "deps.edn" | "bb.edn" | "project.clj" => Some("jvm"),
        _ if f.ends_with(".sbt") => Some("jvm"),
        "rebar.config" => Some("erlang"),
        _ if f.ends_with(".cabal") || f == "stack.yaml" => Some("haskell"),
        "manifest.toml" => Some("julia"),
        "renv.lock" => Some("r"),
        "description" => Some("r"),
        "conanfile.py" => Some("conan"),
        _ if f.ends_with(".fsproj") || f.ends_with(".vbproj") || f.ends_with(".props") => {
            Some("nuget")
        }
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
                "workspace:",
                "git+",
                "git:",
                "github:",
                "gitlab:",
                "http://",
                "https://",
                "link:",
                "file:",
                "portal:",
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
            // Lossy decode: non-UTF-8 source files (legacy encodings,
            // mislabeled binaries) must not abort the whole scan.
            let text = fs::read(abs)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
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

        // `#[link(name = "foo")]` / `cargo:rustc-link-lib` - native
        // library deps; internals stay opaque.
        for lib in &refs.link_libs {
            if !lib.is_empty() {
                note_dep(&mut deps, format!("native:{lib}"), EdgeKind::Resolved);
            }
        }
        // `include_str!`/`include_bytes!` - compile-time file reads.
        // Edge only when the path exists on disk.
        for inc in &refs.data_includes {
            if let Some(dep) = normalize_rel(parent, inc)
                .filter(|c| root.join(c.as_str()).is_file() && c.as_str() != rel.as_str())
            {
                note_dep(&mut deps, dep, EdgeKind::Resolved);
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
    /// `#[link(name = "foo")]` on extern blocks/items - native libs.
    link_libs: Vec<String>,
    /// `include_str!("x")`/`include_bytes!("x")` literals - data
    /// files pulled into the binary at compile time.
    data_includes: Vec<String>,
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

    fn visit_item_foreign_mod(&mut self, i: &'ast syn::ItemForeignMod) {
        // `#[link(name = "foo", kind = "dylib")] extern "C" { ... }` -
        // the native library this block binds against.
        for attr in &i.attrs {
            if let Some(name) = link_attr_name(attr) {
                self.refs.link_libs.push(name);
            }
        }
        visit::visit_item_foreign_mod(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let last = i.path.segments.last().map(|s| s.ident.to_string());
        match last.as_deref() {
            Some("include") => {
                if let Ok(lit) = syn::parse2::<syn::LitStr>(i.tokens.clone()) {
                    self.refs.includes.push(lit.value());
                }
            }
            Some("include_str") | Some("include_bytes") => {
                if let Ok(lit) = syn::parse2::<syn::LitStr>(i.tokens.clone()) {
                    self.refs.data_includes.push(lit.value());
                }
            }
            _ => {}
        }
        // build.rs `println!("cargo:rustc-link-lib=dylib=foo")` -
        // linker directives embedded in string literals.
        self.refs.link_libs.extend(cargo_link_libs(i));
        visit::visit_macro(self, i);
    }
}

/// `#[link(name = "foo")]` -> `"foo"`.
fn link_attr_name(attr: &syn::Attribute) -> Option<String> {
    if !attr.path().is_ident("link") {
        return None;
    }
    let nested = attr
        .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .ok()?;
    for m in nested {
        if let syn::Meta::NameValue(nv) = m {
            if nv.path.is_ident("name") {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) = nv.value
                {
                    return Some(s.value());
                }
            }
        }
    }
    None
}

/// `cargo:rustc-link-lib=[KIND=]NAME` inside macro string literals
/// (build.rs link directives). `KIND` is one of static/dylib/
/// framework. Token text is inspected via `Display` so no
/// proc-macro2 dependency is needed.
fn cargo_link_libs(mac: &syn::Macro) -> Vec<String> {
    let mut out = Vec::new();
    for tt in mac.tokens.clone() {
        let s = tt.to_string();
        let s = s.trim();
        if !s.starts_with('"') {
            continue;
        }
        let s = s.trim_matches('"');
        let Some(rest) = s.strip_prefix("cargo:rustc-link-lib=") else {
            continue;
        };
        // `dylib=foo` / `static=foo` -> `foo`; bare `foo` stays.
        let name = match rest.split_once('=') {
            Some((kind, n)) if matches!(kind, "static" | "dylib" | "framework") => n,
            _ => rest,
        };
        if !name.is_empty() {
            out.push(name.to_string());
        }
    }
    out
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
pub(crate) fn walk_files(dir: &Path, root: &Path, f: &mut dyn FnMut(String, PathBuf)) {
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
    // Parser setup (lexer alloc + language bind) costs more than a
    // trivial parse, and scans parse thousands of files - keep one
    // parser per language per thread instead of rebuilding it.
    thread_local! {
        static PARSERS: std::cell::RefCell<
            Vec<(tree_sitter::Language, tree_sitter::Parser)>,
        > = std::cell::RefCell::new(Vec::new());
    }
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

/// Native-library and data-file specs in JS/TS call expressions:
/// `bindings("name")` (node-gyp addons), `process.dlopen(m, "x.node")`,
/// and the `fs` read family (`readFileSync`, `fs.readFile`,
/// `createReadStream`, `readdir`). Returns `(native_names,
/// file_paths)`; literal args only - computed args are ignored (the
/// file existence check filters noise anyway).
fn js_native_file_specs(text: &str, lang: tree_sitter::Language) -> (Vec<String>, Vec<String>) {
    let mut natives = Vec::new();
    let mut files = Vec::new();
    let Some(tree) = parse_ts(text, lang) else {
        return (natives, files);
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(ft) = func.utf8_text(text.as_bytes()) {
                    let args = node.child_by_field_name("arguments");
                    let arg_str =
                        |idx: usize| -> Option<String> { js_call_arg_str(args, idx, text) };
                    if ft == "bindings" || ft.ends_with(".bindings") {
                        if let Some(n) = arg_str(0) {
                            natives.push(n);
                        }
                    } else if ft == "process.dlopen" || ft.ends_with(".dlopen") {
                        // dlopen(module, path) - path is arg 1.
                        if let Some(n) = arg_str(1).or_else(|| arg_str(0)) {
                            natives.push(n);
                        }
                    } else {
                        let is_fs = matches!(
                            ft,
                            "readFileSync"
                                | "readFile"
                                | "createReadStream"
                                | "readdirSync"
                                | "readdir"
                        ) || ft.ends_with(".readFileSync")
                            || ft.ends_with(".readFile")
                            || ft.ends_with(".createReadStream")
                            || ft.ends_with(".readdirSync")
                            || ft.ends_with(".readdir");
                        if is_fs {
                            if let Some(p) = arg_str(0) {
                                files.push(p);
                            }
                        }
                    }
                }
            }
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    (natives, files)
}

/// Nth non-punctuation call argument as a string literal.
fn js_call_arg_str(args: Option<tree_sitter::Node>, idx: usize, text: &str) -> Option<String> {
    let args = args?;
    let mut c = args.walk();
    let found = args
        .children(&mut c)
        .filter(|c| !matches!(c.kind(), "(" | ")" | ","))
        .nth(idx)
        .and_then(|a| ts_string_literal(a, text));
    found
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
    /// `ctypes.CDLL("libfoo.so")` / `ctypes.windll.kernel32` -
    /// native library load with a literal name. Emitted as a
    /// `native:<name>` node; the library's internals stay opaque.
    NativeLib(String),
    /// `open("cfg.yaml")`, `Path("data/x")`, `pd.read_csv("t.csv")`
    /// - literal file path; caller emits an edge only when the path
    /// exists on disk (data-only coupling).
    DataFile(String),
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
    fn empty() -> Self {
        Self {
            assigns: HashMap::new(),
            verbind: HashMap::new(),
            bad: BTreeSet::new(),
            memo: std::cell::RefCell::new(HashMap::new()),
            visiting: std::cell::RefCell::new(BTreeSet::new()),
        }
    }

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
/// The fifth element counts dynamic native-library loads
/// (`ctypes.CDLL(var)`) - reported separately since they aren't
/// import sites.
/// Substrings whose presence means `build_py_env`'s const-prop table
/// can be consulted: dynamic-import machinery, entry-point/glob
/// evaluators, native-library loaders, and the convention-setting
/// names. File-call args (`open`, `Path`, `read_*`) are handled by
/// deferred re-evaluation instead, so they need no trigger.
const PY_ENV_TRIGGERS: &[&str] = &[
    "import_module",
    "__import__",
    "importlib",
    "run_module",
    "run_path",
    "spec_from_file_location",
    "entry_points",
    "glob",
    "CDLL",
    "PyDLL",
    "WinDLL",
    "LoadLibrary",
    "windll",
    "cdll",
    "oledll",
    "pydll",
    "pytest_plugins",
    "INSTALLED_APPS",
    "CELERY_IMPORTS",
    "STATICFILES_DIRS",
    "MEDIA_ROOT",
    "STATIC_ROOT",
];

fn py_import_refs<'t>(
    tree: &'t tree_sitter::Tree,
    text: &str,
) -> (Vec<PyRef>, bool, usize, usize, usize) {
    let mut out = Vec::new();
    let mut dynamic = 0usize;
    // Subset of `dynamic` whose argument reads env vars or config -
    // reported separately so warnings can say *why* it's invisible.
    let mut env_cfg = 0usize;
    // Non-literal native lib loads (`ctypes.CDLL(name)`).
    let mut native_dyn = 0usize;
    let had_error = tree.root_node().has_error();
    // Const-prop environment for computed dynamic imports - built in
    // a pre-pass so bindings are order-independent. The pre-pass is a
    // full extra tree walk, so it is gated: files without any feature
    // that can consume the env skip it entirely (plain string literals
    // evaluate without it). File/native call args that fail to
    // evaluate are deferred and re-tried once below if needed.
    let needs_env = PY_ENV_TRIGGERS.iter().any(|t| text.contains(t));
    let env = if needs_env {
        build_py_env(tree, text)
    } else {
        PyEnv::empty()
    };
    // (arg node, is_native_lib) pairs whose eval failed under the
    // possibly-empty env.
    let mut deferred: Vec<(tree_sitter::Node, bool)> = Vec::new();
    // Names bound by import statements - `getattr` on one of these is
    // dynamic dispatch (module __getattr__ can lazily import, so the
    // edge is invisible). Collected in the same walk; getattr calls
    // are resolved against the set after the walk since imports may
    // appear textually after the call.
    let mut bound: BTreeSet<String> = BTreeSet::new();
    let mut getattr_objs: Vec<String> = Vec::new();
    // File-level gates for the rare node kinds: `attribute` nodes are
    // the most numerous in a typical tree but only matter for
    // `ctypes.windll.X` loads, and `assignment` nodes only matter for
    // the convention/settings names below. Skipping their queries on
    // files that cannot contain them avoids hundreds of thousands of
    // capture callbacks per scan. Ref order within a file is
    // irrelevant downstream (deps collect into a BTreeMap keyed by
    // name with max-kind merge; dynamic/native counts are sums).
    let want_assign = [
        "pytest_plugins",
        "INSTALLED_APPS",
        "CELERY_IMPORTS",
        "STATICFILES_DIRS",
        "MEDIA_ROOT",
        "STATIC_ROOT",
    ]
    .iter()
    .any(|n| text.contains(n));
    let want_attr = text.contains("ctypes.");
    static MAIN_QUERY: std::sync::OnceLock<tree_sitter::Query> = std::sync::OnceLock::new();
    static ASSIGN_QUERY: std::sync::OnceLock<tree_sitter::Query> = std::sync::OnceLock::new();
    static ATTR_QUERY: std::sync::OnceLock<tree_sitter::Query> = std::sync::OnceLock::new();
    let lang = tree_sitter_python::LANGUAGE.into();
    let main_query = MAIN_QUERY.get_or_init(|| {
        tree_sitter::Query::new(
            &lang,
            "(import_statement) @n (import_from_statement) @n (call) @n",
        )
        .expect("python main query")
    });
    let queries: Vec<&tree_sitter::Query> = {
        let mut v = vec![main_query];
        if want_assign {
            v.push(ASSIGN_QUERY.get_or_init(|| {
                tree_sitter::Query::new(&lang, "(assignment) @n").expect("python assign query")
            }));
        }
        if want_attr {
            v.push(ATTR_QUERY.get_or_init(|| {
                tree_sitter::Query::new(&lang, "(attribute) @n").expect("python attr query")
            }));
        }
        v
    };
    let mut qcursor = tree_sitter::QueryCursor::new();
    for query in queries {
        let mut matches = qcursor.matches(query, tree.root_node(), text.as_bytes());
        use tree_sitter::StreamingIterator as _;
        while let Some(m) = matches.next() {
            for cap in m.captures() {
                let node = cap.node;
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
                                if matches!(
                                    name,
                                    "pytest_plugins" | "INSTALLED_APPS" | "CELERY_IMPORTS"
                                ) {
                                    if let Some(strings) = py_convention_strings(&env, r, text) {
                                        if !strings.is_empty() {
                                            out.push(PyRef::Convention(strings));
                                        }
                                    }
                                } else if matches!(
                                    name,
                                    "STATICFILES_DIRS" | "MEDIA_ROOT" | "STATIC_ROOT"
                                ) {
                                    // Django path-valued settings - data
                                    // coupling, resolved against disk.
                                    if let Some(strings) = py_convention_strings(&env, r, text) {
                                        for s in strings {
                                            out.push(PyRef::DataFile(s));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                "call" => {
                    // Callee text, extracted once and shared by every
                    // feature check below (dyn import, run_path,
                    // spec_from_file_location, native loads, file
                    // reads, glob, entry_points, getattr).
                    let call_ft = node
                        .child_by_field_name("function")
                        .and_then(|f| f.utf8_text(text.as_bytes()).ok());
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
                    if let Some(ft) = call_ft {
                        if ft == "run_path" || ft.ends_with(".run_path") {
                            match py_first_arg(node).and_then(|a| py_eval_strset(&env, a, text, 0))
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
                                        .filter(|k| !matches!(k.kind(), "(" | ")" | ","))
                                        .collect();
                                    kids.into_iter().nth(1)
                                })
                                .flatten();
                            match path_arg.and_then(|a| py_eval_strset(&env, a, text, 0)) {
                                Some(vals) => {
                                    for v in vals {
                                        out.push(PyRef::PathDep(v));
                                    }
                                }
                                None => dynamic += 1,
                            }
                        }
                        // Native library loads: `ctypes.CDLL("x.so")`,
                        // `ctypes.PyDLL`, `ctypes.WinDLL`,
                        // `ctypes.*.LoadLibrary("x.dll")` - literal
                        // names become `native:` edges; computed names
                        // are invisible edges worth a warning.
                        // `CDLL(None)` is the main-program handle, not
                        // a library - skipped entirely.
                        let is_lib_load = ft == "CDLL"
                            || ft == "PyDLL"
                            || ft == "WinDLL"
                            || ft == "LoadLibrary"
                            || ft.ends_with(".CDLL")
                            || ft.ends_with(".PyDLL")
                            || ft.ends_with(".WinDLL")
                            || ft.ends_with(".LoadLibrary");
                        if is_lib_load {
                            let arg = py_first_arg(node);
                            let is_none = arg.is_some_and(|a| a.kind() == "none");
                            match arg.and_then(|a| py_eval_strset(&env, a, text, 0)) {
                                Some(vals) => {
                                    for v in vals {
                                        out.push(PyRef::NativeLib(v));
                                    }
                                }
                                None if !is_none => {
                                    if needs_env {
                                        native_dyn += 1;
                                    } else if let Some(a) = arg {
                                        deferred.push((a, true));
                                    } else {
                                        native_dyn += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                        // File reads: `open`/`io.open`/`*.open`,
                        // `Path(...)`, `os.open`, and the
                        // `read_csv`/`read_excel`/`*.load` family.
                        // Literal paths become data-file edges only
                        // when the file exists on disk.
                        let is_file_call = ft == "open"
                            || ft == "Path"
                            || ft.ends_with(".open")
                            || ft.ends_with(".Path")
                            || matches!(
                                ft,
                                "read_csv"
                                    | "read_excel"
                                    | "read_json"
                                    | "read_parquet"
                                    | "read_table"
                                    | "read_feather"
                                    | "read_hdf"
                                    | "read_stata"
                                    | "read_sas"
                                    | "read_spss"
                                    | "read_html"
                                    | "read_xml"
                                    | "read_sql"
                                    | "read_clipboard"
                            )
                            || (ft.contains('.')
                                && (ft.ends_with(".read_csv")
                                    || ft.ends_with(".read_excel")
                                    || ft.ends_with(".read_json")
                                    || ft.ends_with(".read_parquet")
                                    || ft.ends_with(".read_table")
                                    || ft.ends_with(".load")
                                    || ft.ends_with(".imread")));
                        if is_file_call {
                            if let Some(arg) = py_first_arg(node) {
                                match py_eval_strset(&env, arg, text, 0) {
                                    Some(vals) => {
                                        for v in vals {
                                            out.push(PyRef::DataFile(v));
                                        }
                                    }
                                    None if !needs_env => deferred.push((arg, false)),
                                    None => {}
                                }
                            }
                        }
                    }
                    // glob.glob/iglob/Path.glob with a literal or
                    // const-derived pattern - matched against the file set.
                    if let Some(ft) = call_ft {
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
                    // `entry_points(group="x")` and
                    // `entry_points().select(group="x")` - consumer side
                    // of declared entry points; resolved by the caller
                    // once the group->targets map is known. No `group`
                    // kwarg selects all groups (empty vec). `.select`
                    // only counts when it has a group kwarg - a bare
                    // `entry_points().select(name=...)` selects by entry
                    // name, not group, and stays unresolved.
                    if let Some(ft) = call_ft {
                        let is_ep_call = ft == "entry_points" || ft.ends_with(".entry_points");
                        let is_ep_select = ft.ends_with(".select");
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
                    if call_ft == Some("getattr") {
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
                "attribute" => {
                    // `ctypes.windll.kernel32` / `ctypes.cdll.msvcrt` /
                    // `ctypes.oledll.X` / `ctypes.pydll.X` - attribute
                    // access itself performs the library load (unlike
                    // `cdll.LoadLibrary`, a method needing a call).
                    if let Ok(t) = node.utf8_text(text.as_bytes()) {
                        if let Some(rest) = t.strip_prefix("ctypes.") {
                            let segs: Vec<&str> = rest.split('.').collect();
                            if segs.len() == 2
                                && matches!(segs[0], "windll" | "cdll" | "oledll" | "pydll")
                                && segs[1] != "LoadLibrary"
                                && !segs[1].is_empty()
                            {
                                out.push(PyRef::NativeLib(segs[1].to_string()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        }
    }
    dynamic += getattr_objs.iter().filter(|o| bound.contains(*o)).count();
    // Deferred file/native args: the env was skipped up front, so
    // build it now (once) and re-evaluate only those args. Literal
    // args never land here, and files with env triggers already ran
    // the full env during the walk.
    if !needs_env && !deferred.is_empty() {
        let env = build_py_env(tree, text);
        for (arg, is_lib) in deferred {
            match py_eval_strset(&env, arg, text, 0) {
                Some(vals) => {
                    for v in vals {
                        out.push(if is_lib {
                            PyRef::NativeLib(v)
                        } else {
                            PyRef::DataFile(v)
                        });
                    }
                }
                None if is_lib => native_dyn += 1,
                None => {}
            }
        }
    }
    (out, had_error, dynamic, env_cfg, native_dyn)
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

/// Per-file resolution for `scan_python_impl`, extracted so the
/// caller can run it under rayon. Returns (edge triples,
/// warnings, entry-point lookups); edge order inside a file is
/// BTreeMap-deterministic and the caller preserves file order.
fn resolve_py_file(
    rel_s: String,
    refs: Vec<PyRef>,
    had_error: bool,
    dynamic: usize,
    env_cfg: usize,
    native_dyn: usize,
    manual: Vec<String>,
    names: &BTreeSet<String>,
    root: &Path,
) -> (
    Vec<(String, String, EdgeKind)>,
    Vec<String>,
    Vec<(String, Vec<String>)>,
) {
    let mut warns = Vec::new();
    let mut eps = Vec::new();
    let mut edge_triples: Vec<(String, String, EdgeKind)> = Vec::new();
    let rel = &rel_s;
    if had_error {
        warns.push(format!("{rel}: parse errors (partial scan)"));
    }
    if dynamic > 0 {
        let hint = if env_cfg > 0 {
            format!(" ({env_cfg} read env vars/config)")
        } else {
            String::new()
        };
        warns.push(format!(
            "{rel}: {dynamic} dynamic import site(s){hint} - edges may be incomplete"
        ));
    }
    if native_dyn > 0 {
        warns.push(format!(
            "{rel}: {native_dyn} dynamic native-library load(s) - edges may be incomplete"
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
            PyRef::NativeLib(name) => {
                // `ctypes.CDLL("/usr/lib/libfoo.so.1")` -> the
                // basename is the loadable name; the library's
                // internals stay opaque (honest edge, no
                // fabrication of function-level links).
                let base = name.rsplit(['/', '\\']).next().unwrap_or(name.as_str());
                if !base.is_empty() {
                    note_dep(&mut deps, format!("native:{base}"), EdgeKind::Resolved);
                }
            }
            PyRef::DataFile(spec) => {
                // Data coupling: the literal path must exist on
                // disk or the edge would be invented. Resolved
                // file-dir relative, then project-root relative.
                for cand in [parent, ""].iter().filter_map(|b| normalize_rel(b, &spec)) {
                    if root.join(&cand).is_file() {
                        if cand != *rel {
                            note_dep(&mut deps, cand, EdgeKind::Resolved);
                        }
                        break;
                    }
                }
            }
            PyRef::EpGroup(groups) => {
                eps.push((rel.clone(), groups));
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
        edge_triples.push((rel.clone(), dep, kind));
    }
    (edge_triples, warns, eps)
}

// ---------- Go ----------

/// Minimal `go.mod` view for source scanning: module path plus
/// `require` path->version pairs. `replace`/`exclude` are ignored -
/// the require path still names the module an import resolves
/// through, which is what edge targets need.
struct GoModInfo {
    module: String,
    requires: Vec<(String, String)>,
}

/// Parse `module X` and `require` lines/blocks out of a go.mod.
fn parse_go_mod_info(text: &str) -> Option<GoModInfo> {
    let mut module: Option<String> = None;
    let mut requires: Vec<(String, String)> = Vec::new();
    let mut in_block = false;
    for raw in text.lines() {
        let line = strip_go_line_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            let mut it = line.split_whitespace();
            if let (Some(p), Some(v)) = (it.next(), it.next()) {
                requires.push((p.to_string(), v.to_string()));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("module") {
            let rest = rest.trim_start();
            if !rest.is_empty() && !rest.starts_with('(') {
                module = rest.split_whitespace().next().map(str::to_string);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim_start();
            if rest.is_empty() || rest.starts_with('(') {
                in_block = true;
            } else {
                let mut it = rest.split_whitespace();
                if let (Some(p), Some(v)) = (it.next(), it.next()) {
                    requires.push((p.to_string(), v.to_string()));
                }
            }
            continue;
        }
    }
    module.map(|m| GoModInfo { module: m, requires })
}

/// Strip a trailing `//` comment without touching `//` inside string
/// literals (import paths never contain `//`, and directive values
/// that do are not parsed here).
fn strip_go_line_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        match b[i] {
            b'"' | b'`' | b'\'' => in_str = !in_str,
            b'/' if !in_str && i + 1 < b.len() && b[i + 1] == b'/' => {
                return &line[..i];
            }
            _ => {}
        }
        i += 1;
    }
    line
}

/// One source line split into code and comment parts.
struct GoLine {
    /// Code with comments removed (whitespace preserved).
    code: String,
    /// Comment text on this line, delimiters stripped. For `//`
    /// comments this is the rest of the line; for `/* */` blocks it
    /// is the inner text (possibly empty on delimiter-only lines).
    comment: String,
    /// True when the line carries comment syntax and no code tokens -
    /// i.e. it can be part of a doc/preamble comment group.
    comment_only: bool,
}

/// Split one line into code and comment, tracking `/* */` state
/// across lines. Byte-wise so UTF-8 content survives.
fn go_scan_line(raw: &str, in_comment: &mut bool) -> GoLine {
    let b = raw.as_bytes();
    let mut code: Vec<u8> = Vec::with_capacity(b.len());
    let mut comment: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut saw_comment = false;
    let mut saw_code = false;
    while i < b.len() {
        if *in_comment {
            saw_comment = true;
            if b[i..].starts_with(b"*/") {
                *in_comment = false;
                i += 2;
            } else {
                comment.push(b[i]);
                i += 1;
            }
        } else if b[i..].starts_with(b"//") {
            saw_comment = true;
            comment.extend_from_slice(&b[i + 2..]);
            break;
        } else if b[i..].starts_with(b"/*") {
            saw_comment = true;
            *in_comment = true;
            i += 2;
        } else {
            if !b[i].is_ascii_whitespace() {
                saw_code = true;
            }
            code.push(b[i]);
            i += 1;
        }
    }
    GoLine {
        code: String::from_utf8_lossy(&code).into_owned(),
        comment: String::from_utf8_lossy(&comment).into_owned(),
        comment_only: saw_comment && !saw_code,
    }
}

/// Quoted string literals in a line of Go code.
fn go_quoted(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i < b.len() {
                out.push(s[start..i].to_string());
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

/// One import spec found in a .go file.
#[derive(Debug)]
struct GoSpec {
    /// Import path as written (`"fmt"`, `"github.com/x/y"`, `"C"`).
    path: String,
}

/// Imports plus cgo facts extracted from one .go file's text.
#[derive(Default)]
struct GoRefs {
    specs: Vec<GoSpec>,
    /// `-l<name>` flags and pkg-config names from `#cgo` directives.
    cgo_libs: Vec<String>,
    /// `#include "local.h"` paths from the cgo preamble.
    cgo_includes: Vec<String>,
}

/// Extract import specs and cgo preamble facts with a line scanner.
/// Import declarations only appear at top level in Go, and `import`
/// inside a comment or string is already stripped, so any remaining
/// `import` line is a real declaration.
fn go_file_refs(text: &str) -> GoRefs {
    let mut out = GoRefs::default();
    let mut in_comment = false;
    let mut in_block = false;
    let mut cgo_lines: Vec<usize> = Vec::new();
    let mut scanned: Vec<GoLine> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let gl = go_scan_line(raw, &mut in_comment);
        let line = gl.code.trim().to_string();
        scanned.push(gl);
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            for p in go_quoted(&line) {
                if p == "C" {
                    cgo_lines.push(i);
                }
                out.specs.push(GoSpec { path: p });
            }
            continue;
        }
        if line == "import (" {
            in_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("import") {
            let rest = rest.trim_start();
            if rest.starts_with('(') {
                let inner = &rest[1..];
                if inner.contains(')') {
                    // `import("a" "b")` - inline parenthesized specs.
                    for p in go_quoted(inner) {
                        if p == "C" {
                            cgo_lines.push(i);
                        }
                        out.specs.push(GoSpec { path: p });
                    }
                } else {
                    in_block = true;
                }
                continue;
            }
            for p in go_quoted(rest) {
                if p == "C" {
                    cgo_lines.push(i);
                }
                out.specs.push(GoSpec { path: p });
            }
        }
    }
    // cgo preamble: the comment group immediately above each `import
    // "C"` spec/declaration carries `#cgo` flags and `#include`s.
    // Works for both // line comments and /* */ block preambles.
    for &i in &cgo_lines {
        let mut j = i;
        let mut comments: Vec<&str> = Vec::new();
        while j > 0 {
            j -= 1;
            let gl = &scanned[j];
            if gl.comment_only {
                comments.push(gl.comment.as_str());
            } else {
                break;
            }
        }
        for c in comments.iter().rev() {
            let c = c.trim();
            if c.is_empty() {
                continue;
            }
            if let Some(directive) = c.strip_prefix("#cgo") {
                for tok in directive.split_whitespace() {
                    if let Some(lib) = tok.strip_prefix("-l") {
                        if !lib.is_empty() {
                            out.cgo_libs.push(lib.to_string());
                        }
                    }
                }
                // `pkg-config: foo bar` names real native deps too.
                if let Some(pc) = directive.split("pkg-config:").nth(1) {
                    for name in pc.split(|c: char| c.is_whitespace() || c == ',') {
                        let name = name.trim();
                        if !name.is_empty() && !name.starts_with('-') {
                            out.cgo_libs.push(format!("pkg-config:{name}"));
                        }
                    }
                }
            } else if let Some(inc) = c
                .strip_prefix("#include")
                .map(str::trim)
            {
                // Only quoted includes are project-local files;
                // <...> are system headers.
                if let Some(inner) = inc
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                {
                    out.cgo_includes.push(inner.to_string());
                }
            }
        }
    }
    out
}

/// Resolve one import path against a file's module context.
/// Returns the edge target node name, or None for stdlib imports
/// (no edge - the standard library is not a dependency).
fn go_import_target(
    path: &str,
    module: Option<&GoModInfo>,
) -> Option<String> {
    let Some(mi) = module else {
        // No go.mod in scope: still record the declared import as a
        // bare node (version unknowable), unless it is clearly
        // standard library.
        let first = path.split('/').next().unwrap_or(path);
        if !first.contains('.') {
            return None;
        }
        return Some(path.to_string());
    };
    // Local package: the main module itself or a subpackage of it.
    if path == mi.module || path.starts_with(&format!("{}/", mi.module)) {
        return Some(format!("gopkg:{path}"));
    }
    // External: longest require-prefix wins, same rule the go tool
    // uses to map an import path to its providing module. The bare
    // module path is the target so the edge lands on the same node
    // go.mod/go.sum edges already produce.
    let mut best: Option<&str> = None;
    for (req, _) in &mi.requires {
        if path == req || path.starts_with(&format!("{req}/")) {
            if best.is_none_or(|b| req.len() > b.len()) {
                best = Some(req);
            }
        }
    }
    if let Some(req) = best {
        return Some(req.to_string());
    }
    // Standard library: first path element has no dot ("fmt",
    // "net/http", "encoding/json"). Everything else is an external
    // import we could not pin to a require - still a declared dep.
    let first = path.split('/').next().unwrap_or(path);
    if !first.contains('.') {
        return None;
    }
    Some(path.to_string())
}

fn scan_go_impl(root: &Path) -> Result<ScanOutput> {
    // Collect go.mod files first - they define module context for
    // every .go file beneath them (nearest ancestor wins, matching
    // the go tool's nested-module rule).
    let mut gomod_files: Vec<(String, PathBuf)> = Vec::new();
    walk_files(root, root, &mut |rel, abs| {
        if rel == "go.mod" || rel.ends_with("/go.mod") {
            gomod_files.push((rel, abs));
        }
    });
    gomod_files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut mod_by_dir: BTreeMap<String, GoModInfo> = BTreeMap::new();
    for (rel, abs) in &gomod_files {
        let Ok(bytes) = fs::read(abs) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if let Some(info) = parse_go_mod_info(&text) {
            // "a/b/go.mod" -> module root dir "a/b"; "go.mod" -> "".
            let dir = rel
                .strip_suffix("/go.mod")
                .map(str::to_string)
                .unwrap_or_default();
            mod_by_dir.insert(dir, info);
        }
    }

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, &["go"], &mut files)?;
    // vendor/ trees are vendored copies of external modules - their
    // imports are already represented by the parent's go.mod.
    files.retain(|(rel, _)| !rel.split('/').any(|s| s == "vendor"));
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let extracted = files
        .par_iter()
        .map(|(rel, abs)| {
            let bytes = fs::read(abs)
                .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            Ok((rel.clone(), go_file_refs(&text)))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut edges: EdgeList = Vec::new();
    let mut nodes: Vec<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let mut dep_nodes: BTreeSet<String> = BTreeSet::new();

    for ((rel, _abs), (_rel2, refs)) in files.iter().zip(extracted) {
        // Nearest ancestor go.mod = this file's module.
        let mut module: Option<&GoModInfo> = None;
        let mut dir = parent_rel(rel).to_string();
        loop {
            if let Some(mi) = mod_by_dir.get(&dir) {
                module = Some(mi);
                break;
            }
            if dir.is_empty() {
                break;
            }
            dir = parent_rel(&dir).to_string();
        }

        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();

        // Package membership: every .go file belongs to the package
        // at its directory. Convention-derived, so Heuristic.
        if let Some(mi) = module {
            let mod_dir = mod_dir_of(rel, &mod_by_dir);
            let pkg = go_package_path(mi, rel, mod_dir.as_deref());
            if !pkg.is_empty() {
                let node = format!("gopkg:{pkg}");
                note_dep(&mut deps, node.clone(), EdgeKind::Heuristic);
                dep_nodes.insert(node);
            }
        }

        for spec in &refs.specs {
            if spec.path == "C" {
                note_dep(&mut deps, "native:cgo".to_string(), EdgeKind::Resolved);
                dep_nodes.insert("native:cgo".to_string());
                continue;
            }
            if let Some(target) = go_import_target(&spec.path, module) {
                note_dep(&mut deps, target.clone(), EdgeKind::Declared);
                dep_nodes.insert(target);
            }
        }

        // cgo preamble facts: `-l` libs and pkg-config names are
        // native deps; quoted #includes are project files.
        for lib in &refs.cgo_libs {
            let node = format!("native:{lib}");
            note_dep(&mut deps, node.clone(), EdgeKind::Resolved);
            dep_nodes.insert(node);
        }
        let parent = parent_rel(rel);
        for inc in &refs.cgo_includes {
            if let Some(dep) = normalize_rel(parent, inc)
                .filter(|c| root.join(c.as_str()).is_file() && c.as_str() != rel.as_str())
            {
                note_dep(&mut deps, dep, EdgeKind::Resolved);
            }
        }

        for (dep, kind) in deps {
            edges.push((rel.clone(), dep, None, kind));
        }
    }
    nodes.extend(dep_nodes);
    nodes.sort();
    nodes.dedup();
    Ok(ScanOutput {
        edges,
        nodes,
        warnings: Vec::new(),
    })
}

/// Directory (root-relative) of the go.mod governing `rel`, found by
/// walking ancestors - mirrors the module lookup in `scan_go_impl`.
fn mod_dir_of<'a>(
    rel: &str,
    mod_by_dir: &'a BTreeMap<String, GoModInfo>,
) -> Option<String> {
    let mut dir = parent_rel(rel).to_string();
    loop {
        if mod_by_dir.contains_key(&dir) {
            return Some(dir);
        }
        if dir.is_empty() {
            return None;
        }
        dir = parent_rel(&dir).to_string();
    }
}

/// Import-path form of the package containing `rel`: the module path
/// plus the file's directory relative to the module root.
fn go_package_path(mi: &GoModInfo, rel: &str, mod_dir: Option<&str>) -> String {
    let dir = parent_rel(rel);
    match mod_dir {
        Some("") | None => {
            if dir.is_empty() {
                mi.module.clone()
            } else {
                // File is outside the module root (shouldn't happen -
                // mod_dir was found as an ancestor) - fall back to
                // module + dir anyway for a stable node name.
                format!("{}/{}", mi.module, dir)
            }
        }
        Some(md) => {
            if dir == md {
                mi.module.clone()
            } else {
                // dir is md + "/" + sub by construction.
                let sub = dir.strip_prefix(md).unwrap_or(dir);
                let sub = sub.trim_start_matches('/');
                if sub.is_empty() {
                    mi.module.clone()
                } else {
                    format!("{}/{sub}", mi.module)
                }
            }
        }
    }
}

/// Per-file extraction result carried from the parallel parse phase
/// into resolution; `tree`/`text` are only consumed when the caller
/// asked for [`PySource`]s via `scan_project_with_py`.
struct PyExtract {
    rel: String,
    refs: Vec<PyRef>,
    had_error: bool,
    dynamic: usize,
    env_cfg: usize,
    native_dyn: usize,
    manual: Vec<String>,
    tree: Option<tree_sitter::Tree>,
    text: String,
}

fn scan_python_impl(
    root: &Path,
    mut py_sink: Option<&mut BTreeMap<String, PySource>>,
) -> Result<ScanOutput> {
    let prof = std::env::var_os("STRAND_PROFILE").is_some();
    let t_all = std::time::Instant::now();
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_ext(root, root, PY_EXTS, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if prof {
        eprintln!("py walk: {:?} ({} files)", t_all.elapsed(), files.len());
    }
    let names: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let mut edges: EdgeList = Vec::new();
    let mut warnings = Vec::new();
    // `entry_points(group=...)` consumer lookups, resolved after the
    // config files below build the group -> targets map.
    let mut ep_lookups: Vec<(String, Vec<String>)> = Vec::new();

    // Parse all files in parallel (rayon); resolution below stays
    // sequential so edge order is deterministic.
    let parse_ns = std::sync::atomic::AtomicU64::new(0);
    let refs_ns = std::sync::atomic::AtomicU64::new(0);
    let extracted = files
        .par_iter()
        .map(|(rel, abs)| {
            // Lossy decode: non-UTF-8 source files (legacy encodings,
            // mislabeled binaries) must not abort the whole scan.
            let text = fs::read(abs)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
            let tp = std::time::Instant::now();
            let tree = parse_ts(&text, tree_sitter_python::LANGUAGE.into());
            parse_ns.fetch_add(tp.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            let tr = std::time::Instant::now();
            let (refs, had_error, dynamic, env_cfg, native_dyn) = match &tree {
                Some(t) => py_import_refs(t, &text),
                None => (Vec::new(), true, 0, 0, 0),
            };
            refs_ns.fetch_add(tr.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(PyExtract {
                rel: rel.clone(),
                refs,
                had_error,
                dynamic,
                env_cfg,
                native_dyn,
                manual: manual_dep_specs(&text),
                tree,
                text,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if prof {
        eprintln!(
            "py extract: {:?} (parse {:.1?}, refs {:.1?})",
            t_all.elapsed(),
            std::time::Duration::from_nanos(parse_ns.load(std::sync::atomic::Ordering::Relaxed)),
            std::time::Duration::from_nanos(refs_ns.load(std::sync::atomic::Ordering::Relaxed))
        );
    }

    // Resolution is per-file independent (read-only shared state),
    // so it parallelizes; collect preserves file order so edge and
    // warning order stay deterministic.
    let resolved = extracted
        .into_par_iter()
        .map(|ex| {
            let PyExtract {
                rel,
                refs,
                had_error,
                dynamic,
                env_cfg,
                native_dyn,
                manual,
                tree,
                text,
            } = ex;
            let r = resolve_py_file(
                rel.clone(),
                refs,
                had_error,
                dynamic,
                env_cfg,
                native_dyn,
                manual,
                &names,
                root,
            );
            (r, tree, text, rel)
        })
        .collect::<Vec<_>>();
    for (r, tree, text, rel) in resolved {
        let (triples, warns, eps) = r;
        warnings.extend(warns);
        edges.extend(triples.into_iter().map(|(s, d, k)| (s, d, None, k)));
        ep_lookups.extend(eps);
        if let (Some(sink), Some(tree)) = (py_sink.as_mut(), tree) {
            sink.insert(rel, PySource { text, tree });
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
    // Installed distributions' `entry_points.txt` files declare the
    // same groups from the provider side - consumer -> `name@version`
    // edges bridge plugin use into the lockfile dep graph.
    if !ep_lookups.is_empty() {
        let providers = crate::caches::entry_point_providers(root);
        let mut prov_by_group: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (g, n) in &providers {
            prov_by_group
                .entry(g.as_str())
                .or_default()
                .insert(n.as_str());
        }
        for (rel, groups) in ep_lookups {
            let mut targets: BTreeSet<String> = BTreeSet::new();
            if !ep_targets.is_empty() {
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
            }
            if !providers.is_empty() {
                if groups.is_empty() {
                    for t in prov_by_group.values() {
                        for n in t {
                            targets.insert((*n).to_string());
                        }
                    }
                } else {
                    for g in &groups {
                        if let Some(t) = prov_by_group.get(g.as_str()) {
                            for n in t {
                                targets.insert((*n).to_string());
                            }
                        }
                    }
                }
            }
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
            // Lossy decode: non-UTF-8 source files (legacy encodings,
            // mislabeled binaries) must not abort the whole scan.
            let text = fs::read(abs)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| Error::Usage(format!("{}: {e}", abs.display())))?;
            let (specs, globs, had_error, dynamic) =
                js_import_specs_ts(&text, js_language_for(rel));
            let (natives, data_files) = js_native_file_specs(&text, js_language_for(rel));
            Ok((
                rel.clone(),
                specs,
                globs,
                had_error,
                dynamic,
                natives,
                data_files,
                manual_dep_specs(&text),
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    for (rel_s, specs, globs, had_error, dynamic, natives, data_files, manual) in extracted {
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
            // `require("./addon.node")` / `import("x.node")` -
            // native addons aren't JS modules; emit a `native:` edge
            // instead of letting the spec drop silently.
            if spec.ends_with(".node") && (spec.starts_with(".") || spec.contains('/')) {
                let base = spec.rsplit('/').next().unwrap_or(spec.as_str());
                if !base.is_empty() {
                    note_dep(&mut deps, format!("native:{base}"), EdgeKind::Resolved);
                }
                continue;
            }
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

        // Native addons (`bindings`, `process.dlopen`) and fs reads
        // (`readFileSync`, `createReadStream`) - literal args only.
        for n in &natives {
            let base = n.rsplit(['/', '\\']).next().unwrap_or(n.as_str());
            if !base.is_empty() {
                note_dep(&mut deps, format!("native:{base}"), EdgeKind::Resolved);
            }
        }
        for p in &data_files {
            for cand in [parent, ""].iter().filter_map(|b| normalize_rel(b, p)) {
                if root.join(&cand).is_file() {
                    if cand != *rel {
                        note_dep(&mut deps, cand, EdgeKind::Resolved);
                    }
                    break;
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

// ---------- gradle module cache ----------

/// Split a `group:name@version` lock node into its Maven
/// coordinates. Returns None for nodes without a pinned version.
fn gradle_coord_parts(node: &str) -> Option<(String, String, String)> {
    let bytes = node.as_bytes();
    let mut cut = None;
    for (i, &c) in bytes.iter().enumerate().skip(1) {
        if c == b'@' && bytes.get(i + 1).is_some_and(|d| d.is_ascii_digit()) {
            cut = Some(i);
        }
    }
    let i = cut?;
    let ver = node[i + 1..].to_string();
    let ga = &node[..i];
    let (g, a) = ga.split_once(':')?;
    if g.is_empty() || a.is_empty() || ver.is_empty() {
        return None;
    }
    Some((g.to_string(), a.to_string(), ver))
}

/// Node id for Maven coordinates: `group:name@version`, or bare
/// `group:name` when version is empty.
fn gradle_node(g: &str, a: &str, ver: &str) -> String {
    if ver.is_empty() {
        format!("{g}:{a}")
    } else {
        format!("{g}:{a}@{ver}")
    }
}

/// Read dependency triples from a component's cache dir: prefer
/// `.module` (Gradle Module Metadata, exact versions), fall back to
/// `.pom`.
fn gradle_component_deps(dir: &Path) -> Vec<(String, String, String)> {
    // files-2.1/<g>/<a>/<v>/<sha1>/<file>: one sha1 dir per artifact.
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut module_text = None;
    let mut pom_text = None;
    for e in entries.flatten() {
        let Ok(files) = fs::read_dir(e.path()) else {
            continue;
        };
        for f in files.flatten() {
            let name = f.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".module") && module_text.is_none() {
                module_text = fs::read_to_string(f.path()).ok();
            } else if name.ends_with(".pom") && pom_text.is_none() {
                pom_text = fs::read_to_string(f.path()).ok();
            }
        }
    }
    if let Some(t) = module_text {
        crate::locks::gradle_module_deps(&t)
    } else if let Some(t) = pom_text {
        crate::locks::pom_deps(&t)
    } else {
        Vec::new()
    }
}

/// BFS the Gradle module cache from locked `group:name@version`
/// coordinates, emitting `component -> component` edges from
/// `.module`/`.pom` dependency declarations. Bounded by MAX_PARSE
/// so huge caches stay fast; the visited set keeps it terminating.
fn gradle_cache_edges(seed: &BTreeSet<String>) -> EdgeList {
    const MAX_PARSE: usize = 4000;
    let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) else {
        return Vec::new();
    };
    let root = PathBuf::from(home).join(".gradle/caches/modules-2/files-2.1");
    if !root.is_dir() {
        return Vec::new();
    }

    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    // Self-loop declarations for every node we emit.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let push_node = |edges: &mut EdgeList,
                     seen: &mut BTreeSet<(String, String)>,
                     declared: &mut BTreeSet<String>,
                     src: &str,
                     dst: String| {
        if dst.is_empty() {
            return;
        }
        declared.insert(dst.clone());
        if seen.insert((src.to_string(), dst.clone())) {
            edges.push((src.to_string(), dst, None, EdgeKind::Static));
        }
    };

    // known[(g,a)] = versions seen so far, for versionless deps.
    let mut known: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut queue: Vec<(String, String, String)> = Vec::new();
    let mut visited: BTreeSet<(String, String, String)> = BTreeSet::new();
    for n in seed {
        if let Some((g, a, v)) = gradle_coord_parts(n) {
            known
                .entry((g.clone(), a.clone()))
                .or_default()
                .insert(v.clone());
            queue.push((g, a, v));
        }
    }

    let mut parsed = 0usize;
    while let Some((g, a, v)) = queue.pop() {
        if !visited.insert((g.clone(), a.clone(), v.clone())) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let src_node = gradle_node(&g, &a, &v);
        let dir = root.join(&g).join(&a).join(&v);
        let triples = gradle_component_deps(&dir);
        for (dg, da, dv) in triples {
            let dsts: Vec<String> = if !dv.is_empty() {
                let node = gradle_node(&dg, &da, &dv);
                known
                    .entry((dg.clone(), da.clone()))
                    .or_default()
                    .insert(dv.clone());
                // Enqueue so transitive deps resolve too.
                queue.push((dg.clone(), da.clone(), dv.clone()));
                vec![node]
            } else {
                // Versionless dep (pom without <version>): resolve
                // against everything seen so far.
                match known.get(&(dg.clone(), da.clone())) {
                    Some(vs) if vs.len() == 1 => {
                        let only = vs.iter().next().unwrap().clone();
                        vec![gradle_node(&dg, &da, &only)]
                    }
                    Some(vs) if !vs.is_empty() => {
                        // May-edge to bare coord + disambiguation.
                        let bare = gradle_node(&dg, &da, "");
                        for ver in vs {
                            let pin = gradle_node(&dg, &da, ver);
                            declared.insert(pin.clone());
                            if seen.insert((bare.clone(), pin.clone())) {
                                edges.push((bare.clone(), pin, None, EdgeKind::Static));
                            }
                        }
                        vec![bare]
                    }
                    _ => vec![gradle_node(&dg, &da, "")],
                }
            };
            for dst in dsts {
                push_node(&mut edges, &mut seen, &mut declared, &src_node, dst);
            }
        }
        declared.insert(src_node.clone());
    }

    // Node declarations for srcs and dsts.
    for n in declared {
        if seen.insert((n.clone(), n.clone())) {
            edges.push((n.clone(), n.clone(), None, EdgeKind::Static));
        }
    }
    edges
}
