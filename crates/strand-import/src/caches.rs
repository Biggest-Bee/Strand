//! Local package-cache probes. Several lockfile formats record
//! pins but no dependency relations (`pubspec.lock`,
//! `Package.resolved`, `mix.lock`, `Cartfile.resolved`, `go.sum`,
//! `paket.lock`, `packages.config`); the ecosystem's local cache or
//! checkout dir holds real metadata (`pubspec.yaml`, `go.mod`,
//! `.pom`, `nuspec`, `mix.exs`, `Package.swift`, `Cartfile`), so we
//! BFS those exactly like the Gradle module-cache probe. Everything
//! degrades silently when the cache is absent.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use strand_core::EdgeKind;

use crate::EdgeList;
use crate::locks::{nv, split_nv};

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

/// Default pub cache root (`PUB_CACHE` wins).
pub fn pub_cache_root() -> Option<PathBuf> {
    std::env::var_os("PUB_CACHE")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".pub-cache")))
}

/// Default Go module cache (`GOMODCACHE`, then `GOPATH/pkg/mod`,
/// then `~/go/pkg/mod`).
pub fn go_mod_cache_root() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("GOMODCACHE") {
        return Some(PathBuf::from(p));
    }
    if let Some(g) = std::env::var_os("GOPATH") {
        return Some(PathBuf::from(g).join("pkg/mod"));
    }
    home_dir().map(|h| h.join("go/pkg/mod"))
}

/// Default NuGet global packages dir (`NUGET_PACKAGES` wins).
pub fn nuget_cache_root() -> Option<PathBuf> {
    std::env::var_os("NUGET_PACKAGES")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".nuget/packages")))
}

/// Default Maven local repo (`~/.m2/repository`).
pub fn maven_repo_root() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".m2/repository"))
}

/// Split `name@version` where version starts with a digit.
fn split_name_ver(node: &str) -> Option<(String, String)> {
    let (n, v) = split_nv(node);
    if n.is_empty() || v.is_empty() {
        None
    } else {
        Some((n.to_string(), v.to_string()))
    }
}

struct Probe {
    edges: EdgeList,
    seen: BTreeSet<(String, String)>,
    declared: BTreeSet<String>,
    /// bare dep name -> locked node ids, for versionless deps.
    known: BTreeMap<String, BTreeSet<String>>,
    visited: BTreeSet<String>,
}

impl Probe {
    fn new(seed: &BTreeSet<String>, bare_of: fn(&str) -> String) -> Probe {
        let mut known: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for n in seed {
            known.entry(bare_of(n)).or_default().insert(n.clone());
        }
        Probe {
            edges: Vec::new(),
            seen: BTreeSet::new(),
            declared: seed.iter().cloned().collect(),
            known,
            visited: BTreeSet::new(),
        }
    }

    fn edge(&mut self, src: &str, dst: String) {
        if dst.is_empty() {
            return;
        }
        self.declared.insert(dst.clone());
        if self.seen.insert((src.to_string(), dst.clone())) {
            self.edges.push((src.to_string(), dst, None, EdgeKind::Static));
        }
    }

    /// Resolve a bare dep name: unique locked version pins, several
    /// versions emit a may-edge to the bare name plus
    /// disambiguation edges, none yields the bare name itself.
    fn resolve(&mut self, name: &str) -> Vec<String> {
        self.resolve_key(name, name)
    }

    /// Like [`Probe::resolve`] but the known-map lookup uses `key`
    /// (e.g. lowercased) while the bare fallback keeps `display`
    /// casing.
    fn resolve_key(&mut self, key: &str, display: &str) -> Vec<String> {
        match self.known.get(key) {
            Some(vs) if vs.len() == 1 => vec![vs.iter().next().unwrap().clone()],
            Some(vs) if !vs.is_empty() => {
                let bare = display.to_string();
                for pin in vs {
                    self.declared.insert(pin.clone());
                    if self.seen.insert((bare.clone(), pin.clone())) {
                        self.edges.push((
                            bare.clone(),
                            pin.clone(),
                            None,
                            EdgeKind::Static,
                        ));
                    }
                }
                vec![bare]
            }
            _ => vec![display.to_string()],
        }
    }

    /// Register a discovered pinned node so later versionless deps
    /// resolve to it and BFS can visit it.
    fn learn(&mut self, node: &str) {
        let (n, _) = split_nv(node);
        self.known.entry(n.to_string()).or_default().insert(node.to_string());
        self.declared.insert(node.to_string());
    }

    fn finish(mut self) -> EdgeList {
        for n in std::mem::take(&mut self.declared) {
            if self.seen.insert((n.clone(), n.clone())) {
                self.edges.push((n.clone(), n.clone(), None, EdgeKind::Static));
            }
        }
        self.edges
    }
}

// ---------- pub (Dart/Flutter) ----------

/// BFS `pubspec.lock` pins through the pub cache: each hosted
/// package's cached `pubspec.yaml` lists its real dependencies.
/// Seed nodes are `name@version`; cache dirs are
/// `hosted/pub.dev/<name>-<version>` (pub.dartlang.org fallback).
pub fn pub_cache_edges(seed: &BTreeSet<String>, cache_root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 2000;
    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_lowercase());
    let mut queue: Vec<(String, String)> = Vec::new();
    for n in seed {
        if let Some((nm, v)) = split_name_ver(n) {
            queue.push((nm, v));
        }
    }
    let mut parsed = 0usize;
    while let Some((name, ver)) = queue.pop() {
        if !probe.visited.insert(format!("{name}@{ver}")) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let src = nv(&name, &ver);
        let leaf = format!("{name}-{ver}");
        let mut text = None;
        for host in ["pub.dev", "pub.dartlang.org"] {
            let p = cache_root
                .join("hosted")
                .join(host)
                .join(&leaf)
                .join("pubspec.yaml");
            if let Ok(t) = fs::read_to_string(&p) {
                text = Some(t);
                break;
            }
        }
        let Some(text) = text else { continue };
        for dep in crate::manifests::pubspec_deps(&text) {
            // `sdk`-sourced entries (flutter, flutter_test) are not
            // pub.dev packages and have no cache dir.
            if dep == "flutter" || dep == "flutter_test" {
                continue;
            }
            for dst in probe.resolve(&dep) {
                probe.edge(&src, dst.clone());
                if let Some((dn, dv)) = split_name_ver(&dst) {
                    queue.push((dn, dv));
                }
            }
        }
    }
    probe.finish()
}

// ---------- go ----------

/// Escape a module path for the module cache: uppercase letters
/// become `!` + lowercase (golang.org/x/mod/module.EscapePath for
/// the common case).
fn go_escape(module: &str) -> String {
    // golang.org/x/mod/module.EscapePath: every uppercase letter
    // becomes `!` + lowercase (`BurntSushi` -> `!burnt!sushi`).
    let mut out = String::with_capacity(module.len());
    for c in module.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse `require` directives with versions from a cached `go.mod`:
/// single-line `require path version` and `require (`/`require [`
/// block forms. Returns `(path, version)` pairs.
fn go_mod_requires(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" || line == "]" {
                in_block = false;
                continue;
            }
            let mut it = line.split_whitespace();
            if let (Some(p), Some(v)) = (it.next(), it.next()) {
                if seen.insert((p.to_string(), v.to_string())) {
                    out.push((p.to_string(), v.to_string()));
                }
            }
            continue;
        }
        if line == "require"
            || line.starts_with("require (")
            || line.starts_with("require [")
        {
            in_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ") {
            let rest = rest.trim_start_matches(['(', '[']).trim();
            if rest.is_empty() {
                in_block = true;
                continue;
            }
            let mut it = rest.split_whitespace();
            if let (Some(p), Some(v)) = (it.next(), it.next()) {
                if seen.insert((p.to_string(), v.to_string())) {
                    out.push((p.to_string(), v.to_string()));
                }
            }
        }
    }
    out
}

/// BFS `go.sum` pins through the module cache: each cached module
/// version's `go.mod` `require`s are real edges. Seed nodes are
/// `module version` (space form).
pub fn go_cache_edges(seed: &BTreeSet<String>, mod_cache: &Path) -> EdgeList {
    const MAX_PARSE: usize = 2000;
    let bare_of = |n: &str| {
        n.rsplit_once(' ')
            .map(|(m, _)| m.to_string())
            .unwrap_or_else(|| n.to_string())
    };
    let mut probe = Probe::new(seed, bare_of);
    let mut queue: Vec<(String, String)> = Vec::new();
    for n in seed {
        if let Some((m, v)) = n.rsplit_once(' ') {
            if !m.is_empty() && !v.is_empty() {
                queue.push((m.to_string(), v.to_string()));
            }
        }
    }
    let mut parsed = 0usize;
    while let Some((module, ver)) = queue.pop() {
        let coord = format!("{module} {ver}");
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        // Module cache layout: escaped module path with `@version`
        // appended to the final element, e.g.
        // github.com/a/mod@v1.0.0/go.mod.
        let dir = mod_cache.join(format!("{}@{}", go_escape(&module), ver));
        let gomod = dir.join("go.mod");
        let Ok(text) = fs::read_to_string(&gomod) else { continue };
        for (dm, dv) in go_mod_requires(&text) {
            let dst = format!("{dm} {dv}");
            probe.edge(&coord, dst.clone());
            if !probe.visited.contains(&dst) {
                queue.push((dm, dv));
            }
        }
    }
    probe.finish()
}

// ---------- nuget ----------

/// Extract `(id, version)` dependency pairs from a `.nuspec`:
/// `<dependencies><dependency id="X" version="Y"/>` attributes.
/// Version ranges (`[1.0,)`) yield an empty version.
fn nuspec_deps(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut rest = text;
    while let Some(i) = rest.find("<dependency") {
        let after = &rest[i..];
        if after["<dependency".len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric())
        {
            rest = &rest[i + 1..];
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        let attrs = &after[..gt];
        let get = |attr: &str| -> Option<String> {
            for q in ['"', '\''] {
                let needle = format!("{attr}={q}");
                if let Some(p) = attrs.find(&needle) {
                    let val = &attrs[p + needle.len()..];
                    if let Some(e) = val.find(q) {
                        return Some(val[..e].to_string());
                    }
                }
            }
            None
        };
        if let Some(id) = get("id") {
            let mut ver = get("version").unwrap_or_default();
            // `[1.0,)`, `(,2.0]` style ranges are not pins.
            if !ver.is_empty() && !ver.chars().next().unwrap().is_ascii_digit() {
                ver.clear();
            }
            if seen.insert((id.clone(), ver.clone())) {
                out.push((id, ver));
            }
        }
        rest = &after[gt + 1..];
    }
    out
}

/// BFS NuGet `id@version` pins through the global packages cache:
/// each `<id>.<version>.nuspec` lists real dependencies.
pub fn nuget_cache_edges(seed: &BTreeSet<String>, cache_root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 2000;
    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_lowercase());
    let mut queue: Vec<(String, String)> = Vec::new();
    for n in seed {
        if let Some((id, v)) = split_name_ver(n) {
            queue.push((id, v));
        }
    }
    let mut parsed = 0usize;
    while let Some((id, ver)) = queue.pop() {
        let coord = nv(&id, &ver);
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        // ~/.nuget/packages/<id-lower>/<version>/<id>.<version>.nuspec
        let leaf = format!("{}.{}.nuspec", id.to_lowercase(), ver);
        let nuspec = cache_root
            .join(id.to_lowercase())
            .join(&ver)
            .join(&leaf);
        let Ok(text) = fs::read_to_string(&nuspec) else { continue };
        for (did, dv) in nuspec_deps(&text) {
            let dsts: Vec<String> = if !dv.is_empty() {
                let node = nv(&did, &dv);
                probe.learn(&node);
                vec![node]
            } else {
                probe.resolve_key(&did.to_lowercase(), &did)
            };
            for dst in dsts {
                probe.edge(&coord, dst.clone());
                if let Some((dn, dvv)) = split_name_ver(&dst) {
                    queue.push((dn, dvv));
                }
            }
        }
    }
    probe.finish()
}

// ---------- maven (paket.lock / jvm) ----------

/// Split `group:artifact@version` Maven-style node ids.
fn split_ga_ver(node: &str) -> Option<(String, String, String)> {
    let (ga, ver) = split_nv(node);
    if ver.is_empty() {
        return None;
    }
    let (g, a) = ga.split_once(':')?;
    if g.is_empty() || a.is_empty() {
        return None;
    }
    Some((g.to_string(), a.to_string(), ver.to_string()))
}

/// BFS `group:artifact@version` pins through `~/.m2/repository`:
/// each artifact's `.pom` lists real dependencies via
/// [`crate::locks::pom_deps`].
pub fn maven_cache_edges(seed: &BTreeSet<String>, repo: &Path) -> EdgeList {
    const MAX_PARSE: usize = 3000;
    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_lowercase());
    let mut queue: Vec<(String, String, String)> = Vec::new();
    for n in seed {
        if let Some(c) = split_ga_ver(n) {
            queue.push(c);
        }
    }
    let mut parsed = 0usize;
    while let Some((g, a, v)) = queue.pop() {
        let coord = nv(&format!("{g}:{a}"), &v);
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let pom = repo
            .join(g.replace('.', "/"))
            .join(&a)
            .join(&v)
            .join(format!("{a}-{v}.pom"));
        let Ok(text) = fs::read_to_string(&pom) else { continue };
        for (dg, da, dv) in crate::locks::pom_deps(&text) {
            let dsts: Vec<String> = if !dv.is_empty() {
                let node = nv(&format!("{dg}:{da}"), &dv);
                probe.learn(&node);
                vec![node]
            } else {
                probe.resolve(&format!("{dg}:{da}").to_lowercase())
            };
            for dst in dsts {
                probe.edge(&coord, dst.clone());
                if let Some(c) = split_ga_ver(&dst) {
                    queue.push(c);
                }
            }
        }
    }
    probe.finish()
}

// ---------- mix (Elixir) ----------

/// BFS `name@version` pins through the project's `deps/` dir: each
/// fetched dep's `mix.exs` declares its own deps. Project-local,
/// so `root` is the project root, not a home cache.
pub fn mix_deps_edges(seed: &BTreeSet<String>, root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 2000;
    let deps_dir = root.join("deps");
    if !deps_dir.is_dir() {
        return Vec::new();
    }
    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_string());
    let mut queue: Vec<(String, String)> = Vec::new();
    for n in seed {
        if let Some((nm, v)) = split_name_ver(n) {
            queue.push((nm, v));
        }
    }
    let mut parsed = 0usize;
    while let Some((name, ver)) = queue.pop() {
        let coord = nv(&name, &ver);
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        // deps/<app-name>/mix.exs - dir name is the OTP app name,
        // which matches the hex package name for hex deps.
        let mixexs = deps_dir.join(&name).join("mix.exs");
        let Ok(text) = fs::read_to_string(&mixexs) else { continue };
        for dep in crate::manifests::mix_exs_deps(&text) {
            for dst in probe.resolve(&dep) {
                probe.edge(&coord, dst.clone());
                if let Some((dn, dv)) = split_name_ver(&dst) {
                    queue.push((dn, dv));
                }
            }
        }
    }
    probe.finish()
}

// ---------- swift ----------

/// BFS `identity@version` pins through `.build/checkouts` (or
/// `SourcePackages/checkouts`): each checkout's `Package.swift`
/// declares `.package(url:)` deps whose identity is the lowercased
/// last URL path component. Checkout dirs are `<name>-<hash>`;
/// matched to pins by lowercase identity.
pub fn swift_checkout_edges(seed: &BTreeSet<String>, root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 1000;
    let checkouts = [".build/checkouts", "SourcePackages/checkouts"]
        .iter()
        .map(|p| root.join(p))
        .find(|p| p.is_dir());
    let Some(checkouts) = checkouts else {
        return Vec::new();
    };
    // identity -> Package.swift path.
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&checkouts) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let base = strip_hash_suffix(&name);
            let psw = e.path().join("Package.swift");
            if psw.is_file() {
                dirs.push((base.to_lowercase(), psw));
            }
        }
    }
    if dirs.is_empty() {
        return Vec::new();
    }

    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_lowercase());
    let mut queue: Vec<String> = Vec::new();
    for n in seed {
        if split_name_ver(n).is_some() {
            queue.push(n.clone());
        }
    }
    let mut parsed = 0usize;
    while let Some(node) = queue.pop() {
        let Some((identity, _ver)) = split_name_ver(&node) else { continue };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let Some((_, psw)) = dirs
            .iter()
            .find(|(id, _)| id == &identity.to_lowercase())
        else {
            continue;
        };
        let Ok(text) = fs::read_to_string(psw) else { continue };
        for dep in crate::manifests::package_swift_deps(&text) {
            let dep_id = dep.to_lowercase();
            for dst in probe.resolve(&dep_id) {
                probe.edge(&coord, dst.clone());
                if split_name_ver(&dst).is_some() && !probe.visited.contains(&dst) {
                    queue.push(dst);
                }
            }
        }
    }
    probe.finish()
}

// ---------- carthage ----------

/// Strip a trailing `-<hexhash>` checkout suffix (6+ hex chars).
fn strip_hash_suffix(name: &str) -> String {
    name.rsplit_once('-')
        .filter(|(_, h)| {
            h.len() >= 6 && h.chars().all(|c| c.is_ascii_hexdigit())
        })
        .map(|(b, _)| b.to_string())
        .unwrap_or_else(|| name.to_string())
}

/// BFS `org/repo@version` pins through `SourcePackages/checkouts`
/// (or `Carthage/Checkouts`): each checkout's `Cartfile` or
/// `Package.swift` declares its own deps. Checkout dirs are named
/// after the repo; matched by repo-name suffix against `org/repo`.
pub fn carthage_checkout_edges(seed: &BTreeSet<String>, root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 1000;
    let checkouts = ["SourcePackages/checkouts", "Carthage/Checkouts"]
        .iter()
        .map(|p| root.join(p))
        .find(|p| p.is_dir());
    let Some(checkouts) = checkouts else {
        return Vec::new();
    };
    let mut by_repo: BTreeMap<String, PathBuf> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir(&checkouts) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let base = strip_hash_suffix(&name);
            by_repo.entry(base.to_lowercase()).or_insert(e.path());
        }
    }
    if by_repo.is_empty() {
        return Vec::new();
    }

    // GitHub org/repo is case-insensitive; lowercase keys so
    // `Alamofire/Alamofire` and `alamofire/alamofire` unify.
    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_lowercase());
    let mut queue: Vec<String> = Vec::new();
    for n in seed {
        if split_name_ver(n).is_some() {
            queue.push(n.clone());
        }
    }
    let mut parsed = 0usize;
    while let Some(node) = queue.pop() {
        let Some((org_repo, _ver)) = split_name_ver(&node) else { continue };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let org_repo_l = org_repo.to_lowercase();
        let Some(repo) = org_repo_l.rsplit('/').next() else { continue };
        let Some(dir) = by_repo.get(&repo.to_lowercase()) else { continue };
        // Prefer Cartfile (github "org/repo" pins), fall back to
        // Package.swift (.package url deps).
        let mut deps: Vec<String> = Vec::new();
        let cartfile = dir.join("Cartfile");
        if let Ok(t) = fs::read_to_string(&cartfile) {
            deps = crate::manifests::cartfile_deps(&t);
        }
        if deps.is_empty() {
            let psw = dir.join("Package.swift");
            if let Ok(t) = fs::read_to_string(&psw) {
                deps = crate::manifests::package_swift_deps(&t)
                    .into_iter()
                    .map(|d| d.to_lowercase())
                    .collect();
            }
        }
        for dep in deps {
            let dep = dep.to_lowercase();
            let dsts: Vec<String> = if dep.contains('/') {
                probe.resolve(&dep)
            } else {
                // Bare repo name from Package.swift: match org/repo
                // pins by repo-name suffix; unique pin pins, several
                // emit all as may-edges, none yields the bare name.
                let matches: Vec<String> = probe
                    .known
                    .iter()
                    .filter(|(k, _)| k.rsplit('/').next() == Some(dep.as_str()))
                    .flat_map(|(_, vs)| vs.iter().cloned())
                    .collect();
                if matches.is_empty() {
                    vec![dep.clone()]
                } else {
                    matches
                }
            };
            for dst in dsts {
                probe.edge(&coord, dst.clone());
                if split_name_ver(&dst).is_some() && !probe.visited.contains(&dst) {
                    queue.push(dst);
                }
            }
        }
    }
    probe.finish()
}
