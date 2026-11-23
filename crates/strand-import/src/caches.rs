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

use crate::locks::{nv, split_nv};
use crate::EdgeList;

/// User home directory (`USERPROFILE`/`HOME`).
pub fn home_dir_public() -> Option<PathBuf> {
    home_dir()
}

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
    bare_of: fn(&str) -> String,
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
            bare_of,
        }
    }

    fn edge(&mut self, src: &str, dst: String) {
        if dst.is_empty() {
            return;
        }
        self.declared.insert(dst.clone());
        if self.seen.insert((src.to_string(), dst.clone())) {
            self.edges
                .push((src.to_string(), dst, None, EdgeKind::Static));
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
                        self.edges
                            .push((bare.clone(), pin.clone(), None, EdgeKind::Static));
                    }
                }
                vec![bare]
            }
            _ => vec![display.to_string()],
        }
    }

    /// Register a discovered pinned node so later versionless deps
    /// resolve to it and BFS can visit it. The known-map key uses the
    /// same normalization as the seeds (`bare_of`).
    fn learn(&mut self, node: &str) {
        let key = (self.bare_of)(node);
        self.known.entry(key).or_default().insert(node.to_string());
        self.declared.insert(node.to_string());
    }

    fn finish(mut self) -> EdgeList {
        for n in std::mem::take(&mut self.declared) {
            if self.seen.insert((n.clone(), n.clone())) {
                self.edges
                    .push((n.clone(), n.clone(), None, EdgeKind::Static));
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
        if line == "require" || line.starts_with("require (") || line.starts_with("require [") {
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
        let Ok(text) = fs::read_to_string(&gomod) else {
            continue;
        };
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
        let nuspec = cache_root.join(id.to_lowercase()).join(&ver).join(&leaf);
        let Ok(text) = fs::read_to_string(&nuspec) else {
            continue;
        };
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
        let Ok(text) = fs::read_to_string(&pom) else {
            continue;
        };
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
        let Ok(text) = fs::read_to_string(&mixexs) else {
            continue;
        };
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
        let Some((identity, _ver)) = split_name_ver(&node) else {
            continue;
        };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let Some((_, psw)) = dirs.iter().find(|(id, _)| id == &identity.to_lowercase()) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(psw) else {
            continue;
        };
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
        .filter(|(_, h)| h.len() >= 6 && h.chars().all(|c| c.is_ascii_hexdigit()))
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
        let Some((org_repo, _ver)) = split_name_ver(&node) else {
            continue;
        };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let org_repo_l = org_repo.to_lowercase();
        let Some(repo) = org_repo_l.rsplit('/').next() else {
            continue;
        };
        let Some(dir) = by_repo.get(&repo.to_lowercase()) else {
            continue;
        };
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

// ---------- stack (Haskell pkgdb) ----------

/// One installed-package `.conf` record: `(name, version)` plus its
/// `depends:` entries.
struct PkgConf {
    name: String,
    ver: String,
    deps: Vec<String>,
    path: PathBuf,
}

/// Parse a Cabal installed-package `.conf`: `name:`, `version:`,
/// `depends:` (comma-separated installed package ids).
fn parse_pkg_conf(text: &str) -> PkgConf {
    let mut name = String::new();
    let mut ver = String::new();
    let mut deps: Vec<String> = Vec::new();
    let mut in_depends = false;
    for line in text.lines() {
        // Continuation lines of `depends:` are indented and carry no
        // `field:` prefix; a new top-level `field:` ends the list.
        let is_cont = line.starts_with(' ') || line.starts_with('\t');
        let t = line.trim();
        if !is_cont {
            in_depends = false;
        }
        if in_depends && is_cont {
            deps.extend(
                t.split(',')
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty()),
            );
            continue;
        }
        if let Some(v) = t.strip_prefix("name:") {
            name = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("version:") {
            ver = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("depends:") {
            in_depends = true;
            deps.extend(
                v.split(',')
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty()),
            );
        }
    }
    PkgConf {
        name,
        ver,
        deps,
        path: PathBuf::new(),
    }
}

/// Collect `.conf` files under `dir` (non-recursive).
fn conf_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "conf") {
                out.push(p);
            }
        }
    }
}

/// Bounded walk collecting directories named `pkgdb` (Stack/Cabal
/// package databases sit at variable depths under snapshots and
/// .stack-work install trees).
fn find_pkgdbs(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 5 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        if p.file_name().is_some_and(|n| n == "pkgdb") {
            out.push(p);
            continue; // don't descend into pkgdb itself
        }
        find_pkgdbs(&p, depth + 1, out);
    }
}

/// BFS `name@version` pins through Stack/Cabal package databases:
/// snapshot pkgdbs at `~/.stack/snapshots/*/pkgdb` and project-local
/// `.stack-work/install/*/*/pkgdb` hold `.conf` files whose
/// `depends:` fields are real edges. Dep entries are installed
/// package ids `name-version` possibly with a `-unithash` suffix;
/// resolved by prefix match against the conf index.
pub fn stack_pkgdb_edges(
    seed: &BTreeSet<String>,
    stack_home: &Path,
    project_root: &Path,
) -> EdgeList {
    const MAX_PARSE: usize = 4000;
    // Candidate pkgdb dirs. Snapshot layout is
    // snapshots/<platform>/<ghc>/<hash>/pkgdb (variable depth), so
    // walk it bounded like the install tree.
    let mut pkgdbs: Vec<PathBuf> = Vec::new();
    find_pkgdbs(&stack_home.join("snapshots"), 0, &mut pkgdbs);
    find_pkgdbs(
        &stack_home.join("global-project/.stack-work/install"),
        0,
        &mut pkgdbs,
    );
    // <project>/.stack-work/install/**/pkgdb - the install tree has
    // variable depth (platform/ghc/hash), so walk it bounded.
    find_pkgdbs(&project_root.join(".stack-work/install"), 0, &mut pkgdbs);

    // Index every .conf by (name, version).
    let mut confs: Vec<PkgConf> = Vec::new();
    for dir in &pkgdbs {
        let mut files = Vec::new();
        conf_files(dir, &mut files);
        for f in files {
            if confs.len() >= MAX_PARSE {
                break;
            }
            let Ok(text) = fs::read_to_string(&f) else {
                continue;
            };
            let mut c = parse_pkg_conf(&text);
            if c.name.is_empty() {
                continue;
            }
            c.path = f;
            confs.push(c);
        }
    }
    if confs.is_empty() {
        return Vec::new();
    }
    // name-version -> conf index for dep-id resolution.
    let id_of = |c: &PkgConf| -> String {
        if c.ver.is_empty() {
            c.name.clone()
        } else {
            format!("{}-{}", c.name, c.ver)
        }
    };
    // dep entry `name-ver` or `name-ver-hash` -> matching confs.
    let resolve_dep = |entry: &str| -> Vec<String> {
        let mut hits: Vec<String> = Vec::new();
        for c in &confs {
            let id = id_of(c);
            if entry == id || entry.starts_with(&format!("{id}-")) {
                hits.push(nv(&c.name, &c.ver));
            }
        }
        hits.sort();
        hits.dedup();
        hits
    };

    let mut probe = Probe::new(seed, |n| split_nv(n).0.to_lowercase());
    let mut queue: Vec<String> = Vec::new();
    for n in seed {
        if split_name_ver(n).is_some() {
            queue.push(n.clone());
        }
    }
    let mut parsed = 0usize;
    while let Some(node) = queue.pop() {
        let Some((name, ver)) = split_name_ver(&node) else {
            continue;
        };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        // Find the conf matching this pin.
        let Some(c) = confs.iter().find(|c| c.name == name && c.ver == ver) else {
            continue;
        };
        for dep in &c.deps {
            for dst in resolve_dep(dep) {
                probe.edge(&coord, dst.clone());
                if split_name_ver(&dst).is_some() && !probe.visited.contains(&dst) {
                    queue.push(dst);
                }
            }
        }
    }
    probe.finish()
}

// ---------- erlang (_build .app files) ----------

/// Extract the `{applications, [...]}` atom list from an `.app`
/// file (Erlang term, usually one line).
fn app_applications(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(i) = text.find("{applications,") else {
        return out;
    };
    let rest = &text[i + "{applications,".len()..];
    let Some(bi) = rest.find('[') else { return out };
    let after = &rest[bi + 1..];
    let Some(ei) = after.find(']') else {
        return out;
    };
    for atom in after[..ei].split(',') {
        let a = atom.trim().trim_matches(|c| c == '\'' || c == '"').trim();
        if !a.is_empty()
            && a.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !matches!(
                a,
                "kernel" | "stdlib" | "compiler" | "syntax_tools" | "tools"
            )
        {
            out.push(a.to_string());
        }
    }
    out
}

/// BFS `name@version` pins through `_build/*/lib/<app>/ebin/*.app`:
/// each app file's `applications` list is a real dep edge. Project-
/// local; dep names resolve to lock pins by bare name.
pub fn erlang_app_edges(seed: &BTreeSet<String>, root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 2000;
    // Collect app files: _build/<profile>/lib/<app>/ebin/<app>.app
    // (also _checkouts). Non-recursive walk of _build/*/lib/*/ebin.
    let mut apps: Vec<(String, PathBuf)> = Vec::new(); // (app name, .app path)
    for profile_dir in ["_build/default/lib", "_build/test/lib", "_build/prod/lib"] {
        let lib = root.join(profile_dir);
        if let Ok(lib_entries) = fs::read_dir(&lib) {
            for app_dir in lib_entries.flatten() {
                let ebin = app_dir.path().join("ebin");
                if let Ok(files) = fs::read_dir(&ebin) {
                    for f in files.flatten() {
                        let p = f.path();
                        if p.extension().is_some_and(|x| x == "app") {
                            let name = p
                                .file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            apps.push((name, p));
                        }
                    }
                }
            }
        }
    }
    if apps.is_empty() {
        return Vec::new();
    }
    // Parse each .app once: name -> applications.
    let mut app_deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, path) in &apps {
        if app_deps.len() >= MAX_PARSE {
            break;
        }
        if let Ok(text) = fs::read_to_string(path) {
            app_deps.insert(name.clone(), app_applications(&text));
        }
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
        let Some((app, _ver)) = split_name_ver(&node) else {
            continue;
        };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let Some(deps) = app_deps.get(&app.to_lowercase()).cloned() else {
            continue;
        };
        for dep in deps {
            for dst in probe.resolve(&dep.to_lowercase()) {
                probe.edge(&coord, dst.clone());
                if split_name_ver(&dst).is_some() && !probe.visited.contains(&dst) {
                    queue.push(dst);
                }
            }
        }
    }
    probe.finish()
}

// ---------- pip site-packages (venv dist-info) ----------

/// PEP 503 normalize a distribution name.
pub(crate) fn pep503(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect()
}

/// Extract the package name from a `Requires-Dist:` value:
/// `name (>=1.0); marker`, `name>=1.0`, `name; marker`,
/// `name @ https://...` (direct ref -> None).
fn requires_dist_name(req: &str) -> Option<String> {
    let req = req.trim();
    if req.contains(" @ ") {
        return None;
    }
    let mut end = 0;
    for (i, c) in req.char_indices() {
        if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '[' | ']') {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    let name = req[..end].split('[').next().unwrap_or("").trim();
    if name.is_empty() {
        None
    } else {
        Some(pep503(name))
    }
}

/// Site-packages dirs under a project root's virtualenvs:
/// `<root>/{.venv,venv,env,.env}/lib/python*/site-packages` and the
/// Windows `<root>/<venv>/Lib/site-packages` layout.
pub(crate) fn site_packages_dirs(root: &Path) -> Vec<PathBuf> {
    let mut sp_dirs: Vec<PathBuf> = Vec::new();
    for venv in [".venv", "venv", "env", ".env"] {
        let v = root.join(venv);
        let lib = v.join("lib");
        if let Ok(py_dirs) = fs::read_dir(&lib) {
            for py in py_dirs.flatten() {
                let sp = py.path().join("site-packages");
                if sp.is_dir() {
                    sp_dirs.push(sp);
                }
            }
        }
        let win = v.join("Lib/site-packages");
        if win.is_dir() {
            sp_dirs.push(win);
        }
    }
    sp_dirs
}

/// `(group, dist node)` pairs declared by installed packages'
/// `entry_points.txt` files - the provider side of plugin groups.
/// Dist node is `pep503name@version` matching the pip lockfile
/// namespace. Bounded by MAX_PARSE dist-infos.
pub(crate) fn entry_point_providers(root: &Path) -> Vec<(String, String)> {
    const MAX_PARSE: usize = 2000;
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for dir in site_packages_dirs(root) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            if out.len() >= MAX_PARSE {
                return out;
            }
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let fname = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if !fname.ends_with(".dist-info") {
                continue;
            }
            // `name-version.dist-info` -> `pep503(name)@version`.
            let stem = &fname[..fname.len() - ".dist-info".len()];
            let Some((nm, ver)) = stem.rsplit_once('-') else {
                continue;
            };
            if ver.is_empty() || !ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let node = nv(&pep503(nm), ver);
            let ep = p.join("entry_points.txt");
            let Ok(text) = fs::read_to_string(&ep) else {
                continue;
            };
            let mut group = String::new();
            for line in text.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                if t.starts_with('[') && t.ends_with(']') {
                    group = t[1..t.len() - 1].trim().to_string();
                    continue;
                }
                if group.is_empty() {
                    continue;
                }
                // `name = module:attr` (or `module`); the target
                // module isn't resolvable offline, the provider dist
                // is what matters.
                if seen.insert((group.clone(), node.clone())) {
                    out.push((group.clone(), node.clone()));
                }
            }
        }
    }
    out
}

/// One installed dist-info record.
struct DistInfo {
    node: String,      // normname@version
    deps: Vec<String>, // normalized dep names
}

/// Parse a dist-info METADATA file.
fn parse_dist_info(text: &str) -> Option<DistInfo> {
    let mut name = String::new();
    let mut ver = String::new();
    let mut deps = Vec::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Version:") {
            ver = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Requires-Dist:") {
            if let Some(d) = requires_dist_name(v) {
                deps.push(d);
            }
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(DistInfo {
        node: nv(&pep503(&name), &ver),
        deps,
    })
}

/// BFS python `name@version` pins through venv site-packages
/// dist-info METADATA `Requires-Dist` fields. Checks `<root>/.venv`,
/// `venv`, `env`, `.env` for `lib/python*/site-packages` and
/// `Lib/site-packages` (Windows). Emits edges for every installed
/// dist (the venv graph is real metadata), bounded.
pub fn pip_site_packages_edges(seed: &BTreeSet<String>, root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 3000;
    let sp_dirs = site_packages_dirs(root);
    if sp_dirs.is_empty() {
        return Vec::new();
    }
    // Index all dist-infos: normname -> node ids.
    let mut infos: Vec<DistInfo> = Vec::new();
    let mut known: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for dir in &sp_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            if infos.len() >= MAX_PARSE {
                break;
            }
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let fname = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if !fname.ends_with(".dist-info") {
                continue;
            }
            let meta = p.join("METADATA");
            let Ok(text) = fs::read_to_string(&meta) else {
                continue;
            };
            let Some(info) = parse_dist_info(&text) else {
                continue;
            };
            known
                .entry(pep503(split_nv(&info.node).0))
                .or_default()
                .insert(info.node.clone());
            infos.push(info);
        }
    }
    if infos.is_empty() {
        return Vec::new();
    }
    // Seed pins also join the known index so versionless Requires-
    // Dist entries resolve to locked versions even when the dist
    // isn't installed locally.
    for n in seed {
        let (nm, _) = split_nv(n);
        known.entry(pep503(nm)).or_default().insert(n.clone());
    }

    let mut probe = Probe::new(seed, |n| pep503(split_nv(n).0));
    // Merge discovered dist nodes into known.
    for (k, vs) in &known {
        probe
            .known
            .entry(k.clone())
            .or_default()
            .extend(vs.iter().cloned());
    }
    let mut queue: Vec<String> = Vec::new();
    for n in seed {
        if split_name_ver(n).is_some() {
            queue.push(n.clone());
        }
    }
    // Also process every discovered dist-info node so transitive
    // Requires-Dist chains are covered even beyond the seeds.
    for info in &infos {
        if split_name_ver(&info.node).is_some() {
            queue.push(info.node.clone());
        }
    }
    let mut parsed = 0usize;
    while let Some(node) = queue.pop() {
        if !probe.visited.insert(node.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let Some(info) = infos.iter().find(|i| i.node == node) else {
            continue;
        };
        for dep in &info.deps {
            for dst in probe.resolve(dep) {
                probe.edge(&node, dst.clone());
                if split_name_ver(&dst).is_some() && !probe.visited.contains(&dst) {
                    queue.push(dst);
                }
            }
        }
    }
    probe.finish()
}

// ---------- renv (R library DESCRIPTION files) ----------

/// BFS `name@version` pins through a renv project library:
/// `renv/library/<r-ver>/<pkg>/DESCRIPTION` files carry real
/// Depends/Imports edges via [`crate::manifests::description_deps`].
/// Project-local.
pub fn renv_library_edges(seed: &BTreeSet<String>, root: &Path) -> EdgeList {
    const MAX_PARSE: usize = 2000;
    let lib = root.join("renv/library");
    if !lib.is_dir() {
        return Vec::new();
    }
    // renv/library/<R-version>/<pkg>/DESCRIPTION
    let mut descs: Vec<(String, PathBuf)> = Vec::new(); // (pkg name, path)
    if let Ok(rvers) = fs::read_dir(&lib) {
        for rv in rvers.flatten() {
            if let Ok(pkgs) = fs::read_dir(rv.path()) {
                for p in pkgs.flatten() {
                    let d = p.path().join("DESCRIPTION");
                    if d.is_file() {
                        let name = p.file_name().to_string_lossy().to_string();
                        descs.push((name, d));
                    }
                }
            }
        }
    }
    if descs.is_empty() {
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
        let Some((pkg, _ver)) = split_name_ver(&node) else {
            continue;
        };
        let coord = node.clone();
        if !probe.visited.insert(coord.clone()) {
            continue;
        }
        if parsed >= MAX_PARSE {
            break;
        }
        parsed += 1;
        let Some((_, desc)) = descs
            .iter()
            .find(|(n, _)| n.to_lowercase() == pkg.to_lowercase())
        else {
            continue;
        };
        let Ok(text) = fs::read_to_string(desc) else {
            continue;
        };
        for dep in crate::manifests::description_deps(&text) {
            for dst in probe.resolve(&dep.to_lowercase()) {
                probe.edge(&coord, dst.clone());
                if split_name_ver(&dst).is_some() && !probe.visited.contains(&dst) {
                    queue.push(dst);
                }
            }
        }
    }
    probe.finish()
}
