//! Lockfile/manifest importers: `Cargo.lock`, `package-lock.json`,
//! `poetry.lock`, `go.mod`, `pom.xml`.
//!
//! Node naming is unqualified and deterministic:
//! - npm / cargo / poetry: package name (multiple installed versions
//!   collapse to a single node, matching the cargo-metadata importer)
//! - go: module path
//! - maven: `groupId:artifactId`
//!
//! Edge direction everywhere: `A -> B` means "A depends on B".

use std::collections::{BTreeMap, BTreeSet};

use strand_core::Result;

use crate::{err, EdgeList};

// ---------- shared helpers ----------

/// Strip `//` line comments (go.mod, and harmless elsewhere).
fn strip_line_comment(line: &str) -> &str {
    line.split("//").next().unwrap_or("")
}


/// Inner content of each `"..."` string in a TOML-ish array fragment.
fn quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '"' {
            let mut tok = String::new();
            for c in it.by_ref() {
                if c == '"' {
                    break;
                }
                tok.push(c);
            }
            out.push(tok);
        }
    }
    out
}

fn push_edge(edges: &mut EdgeList, src: &str, dst: String) {
    if dst != src {
        edges.push((src.to_string(), dst, None, strand_core::EdgeKind::Static));
    }
}

/// Source node id used by flat lockfiles (no inter-package edges
/// recorded): `scan_project` rewrites it to the lockfile's rel path.
pub(crate) const FLAT_SRC: &str = "(lockfile)";

/// `name@version` node id; bare `name` when version is empty.
pub(crate) fn nv(name: &str, version: &str) -> String {
    if version.is_empty() {
        name.to_string()
    } else {
        format!("{name}@{version}")
    }
}

/// Split a `name@version` node id. The `@` must be followed by a
/// digit so scoped names (`@scope/name`) and `name@range` specs are
/// not mistaken for pinned ids.
pub(crate) fn split_nv(node: &str) -> (&str, &str) {
    if let Some(i) = node.rfind('@') {
        if i > 0 && node[i + 1..].chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return (&node[..i], &node[i + 1..]);
        }
    }
    (node, "")
}

/// Index of locked `name@version` node ids by bare name. Dep
/// references that carry no version resolve through it: a unique
/// version pins to `name@ver`; several versions emit a may-edge to
/// the bare `name` plus `name -> name@ver` disambiguation edges.
#[derive(Default)]
struct VerIndex {
    by_name: BTreeMap<String, Vec<String>>,
}

impl VerIndex {
    fn add(&mut self, node: &str) {
        let (n, _) = split_nv(node);
        let v = self.by_name.entry(n.to_string()).or_default();
        if !v.contains(&node.to_string()) {
            v.push(node.to_string());
        }
    }

    /// Node ids a bare dep `name` resolves to. `seen`/`edges`
    /// collect the `name -> name@ver` disambiguation edges emitted
    /// for multi-version names.
    fn resolve(
        &self,
        name: &str,
        edges: &mut EdgeList,
        seen: &mut BTreeSet<(String, String)>,
    ) -> Vec<String> {
        match self.by_name.get(name).map(Vec::as_slice) {
            Some([]) | None => vec![name.to_string()],
            Some([one]) => vec![one.clone()],
            Some(many) => {
                for m in many {
                    if seen.insert((name.to_string(), m.clone())) {
                        edges.push((
                            name.to_string(),
                            m.clone(),
                            None,
                            strand_core::EdgeKind::Static,
                        ));
                    }
                }
                vec![name.to_string()]
            }
        }
    }
}

// ---------- Cargo.lock ----------

/// Parse `Cargo.lock`. `[[package]]` blocks carry `name`, `version`,
/// and a possibly multi-line `dependencies = [ "dep", "dep ver
/// (src)", ... ]`. Nodes are `name@version`; dep strings that omit a
/// version resolve through the package index (unique version pins,
/// several versions get may-edges to the bare name plus
/// disambiguation edges). Every package emits a self-loop edge as a
/// node declaration (skipped as an edge by `fill_builder`).
pub fn cargo_lock(text: &str) -> Result<EdgeList> {
    struct Pkg {
        name: String,
        version: String,
        deps: Vec<String>, // raw quoted dep strings
    }
    let mut pkgs: Vec<Pkg> = Vec::new();
    let mut cur_name = String::new();
    let mut cur_ver = String::new();
    let mut cur_deps: Vec<String> = Vec::new();
    let mut dep_buf: Option<String> = None;
    let mut have_pkg = false;

    let flush = |pkgs: &mut Vec<Pkg>,
                     name: &mut String,
                     ver: &mut String,
                     deps: &mut Vec<String>,
                     have: &mut bool| {
        if *have {
            pkgs.push(Pkg {
                name: std::mem::take(name),
                version: std::mem::take(ver),
                deps: std::mem::take(deps),
            });
            *have = false;
        }
    };

    for line in text.lines() {
        let t = line.trim();
        if let Some(buf) = dep_buf.as_mut() {
            buf.push(' ');
            buf.push_str(t);
            if t.contains(']') {
                cur_deps.extend(quoted_strings(buf));
                dep_buf = None;
            }
            continue;
        }
        if t == "[[package]]" {
            flush(&mut pkgs, &mut cur_name, &mut cur_ver, &mut cur_deps, &mut have_pkg);
            continue;
        }
        if t.starts_with('[') {
            continue; // any other section header
        }
        if let Some((key, val)) = t.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            match key {
                "name" => {
                    cur_name = unquote(val);
                    have_pkg = true;
                }
                "version" => cur_ver = unquote(val),
                "dependencies" if val.starts_with('[') => {
                    if val.contains(']') {
                        cur_deps.extend(quoted_strings(val));
                    } else {
                        dep_buf = Some(val.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    flush(&mut pkgs, &mut cur_name, &mut cur_ver, &mut cur_deps, &mut have_pkg);

    let mut index = VerIndex::default();
    let nodes: Vec<String> = pkgs.iter().map(|p| nv(&p.name, &p.version)).collect();
    for n in &nodes {
        index.add(n);
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for n in &nodes {
        // Node declaration: self-loop, skipped as an edge downstream.
        if seen.insert((n.clone(), n.clone())) {
            edges.push((n.clone(), n.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    for (p, node) in pkgs.iter().zip(&nodes) {
        for d in &p.deps {
            // Dep string: `name`, `name version`, or
            // `name version (source)`. An explicit version pins the
            // node directly; otherwise resolve via the index.
            let toks: Vec<&str> = d.split_whitespace().collect();
            let Some(name) = toks.first() else { continue };
            if name.is_empty() {
                continue;
            }
            let ver = toks.get(1).copied().unwrap_or("");
            let dsts = if !ver.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                vec![nv(name, ver)]
            } else {
                index.resolve(name, &mut edges, &mut seen)
            };
            for dst in dsts {
                if seen.insert((node.clone(), dst.clone())) {
                    edges.push((node.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
    }
    Ok(edges)
}

// ---------- poetry.lock ----------

/// Parse `poetry.lock`. `[[package]]` blocks have `name`, `version`,
/// and `[package.dependencies]`/`[package.dev-dependencies]` tables
/// of `name = constraint` lines. Nodes are `name@version`; dep names
/// resolve through the package index like [`cargo_lock`]. Every
/// package emits a self-loop node declaration.
pub fn poetry_lock(text: &str) -> Result<EdgeList> {
    struct Pkg {
        name: String,
        version: String,
        deps: Vec<String>,
    }
    let mut pkgs: Vec<Pkg> = Vec::new();
    let mut name = String::new();
    let mut ver = String::new();
    let mut deps: Vec<String> = Vec::new();
    let mut have = false;
    // None = not in a dep table.
    let mut in_deps = false;
    let mut depth = 0i32; // {} [] nesting inside a dep value

    let flush = |pkgs: &mut Vec<Pkg>,
                     name: &mut String,
                     ver: &mut String,
                     deps: &mut Vec<String>,
                     have: &mut bool| {
        if *have {
            pkgs.push(Pkg {
                name: std::mem::take(name),
                version: std::mem::take(ver),
                deps: std::mem::take(deps),
            });
            *have = false;
        }
    };

    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(&mut pkgs, &mut name, &mut ver, &mut deps, &mut have);
            in_deps = false;
            depth = 0;
            continue;
        }
        if t.starts_with('[') {
            in_deps = matches!(t, "[package.dependencies]" | "[package.dev-dependencies]");
            depth = 0;
            continue;
        }
        if let Some((key, val)) = t.split_once('=') {
            let key = key.trim();
            if key == "name" && !in_deps && cur_name_empty(&name) {
                name = unquote(val.trim());
                have = true;
                continue;
            }
            if key == "version" && !in_deps && have {
                ver = unquote(val.trim());
                continue;
            }
        }
        if !in_deps {
            continue;
        }
        // In a dep table: `name = "^1.0"` or `name = {version = "..."}`
        // possibly spanning lines. A `key =` at brace depth 0 starts a
        // dep; continuation lines (depth > 0) are part of its value.
        if depth == 0 {
            if let Some((key, _)) = t.split_once('=') {
                let dep = unquote(key.trim());
                if dep != "python" {
                    deps.push(dep);
                }
            }
        }
        for c in t.chars() {
            match c {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
        depth = depth.max(0);
    }
    flush(&mut pkgs, &mut name, &mut ver, &mut deps, &mut have);

    let mut index = VerIndex::default();
    let nodes: Vec<String> = pkgs.iter().map(|p| nv(&p.name, &p.version)).collect();
    for n in &nodes {
        index.add(n);
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for n in &nodes {
        if seen.insert((n.clone(), n.clone())) {
            edges.push((n.clone(), n.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    for (p, node) in pkgs.iter().zip(&nodes) {
        for dep in &p.deps {
            for dst in index.resolve(dep, &mut edges, &mut seen) {
                if seen.insert((node.clone(), dst.clone())) {
                    edges.push((node.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
    }
    Ok(edges)
}

fn cur_name_empty(name: &str) -> bool {
    name.is_empty()
}

// ---------- go.mod ----------

/// Parse `go.mod`: `module X` plus `require` lines/blocks.
/// `replace`/`exclude`/`retract` directives are ignored.
pub fn go_mod(text: &str) -> Result<EdgeList> {
    let mut module: Option<String> = None;
    let mut reqs: BTreeSet<String> = BTreeSet::new();
    let mut in_block = false;

    for raw in text.lines() {
        let line = strip_line_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" || line == "]" {
                in_block = false;
                continue;
            }
            let mut it = line.split_whitespace();
            if let Some(path) = it.next() {
                reqs.insert(path.to_string());
            }
            continue;
        }
        // Directive names must be followed by whitespace or `(` so that
        // e.g. `modulex` isn't mistaken for `module`.
        let is_dir = |name: &str| {
            line == name
                || line.strip_prefix(name).is_some_and(|r| {
                    r.chars()
                        .next()
                        .is_some_and(|c| c.is_whitespace() || c == '(')
                })
        };
        if is_dir("module") {
            let rest = line["module".len()..].trim();
            if !rest.is_empty() && !rest.starts_with('(') {
                module = Some(rest.split_whitespace().next().unwrap().to_string());
            }
            continue;
        }
        if is_dir("require") {
            let rest = line["require".len()..].trim();
            if rest.is_empty() || rest.starts_with('(') || rest.starts_with('[') {
                in_block = true;
            } else {
                let mut it = rest.split_whitespace();
                if let Some(path) = it.next() {
                    reqs.insert(path.to_string());
                }
            }
            continue;
        }
        // go / toolchain / replace / exclude / retract: ignored.
    }

    let module = module.ok_or_else(|| err("go.mod: missing 'module' directive"))?;
    let mut edges = EdgeList::new();
    for dep in reqs {
        push_edge(&mut edges, &module, dep);
    }
    Ok(edges)
}

// ---------- pom.xml ----------

#[derive(Default, Clone)]
struct Ga {
    group: Option<String>,
    artifact: Option<String>,
}

/// Parse a Maven `pom.xml` with a minimal tag scanner (no XML dep).
/// Project node = `groupId:artifactId` (groupId falls back to the
/// parent's). Edges project -> each `<dependency>`'s `g:a`, skipping
/// `dependencyManagement` and `import`-scoped BOMs.
pub fn pom_xml(text: &str) -> Result<EdgeList> {
    // Project coordinates: first <groupId>/<artifactId> outside <parent>.
    let mut parent_ga = Ga::default();
    let mut proj_ga = Ga::default();
    // Strip parent block so its coords don't leak into project coords.
    let no_parent = strip_section(text, "parent");
    // Project coords live in the header, before any dependency/build
    // section - searching the whole doc would hit a dependency's
    // <groupId> when the project inherits its groupId from <parent>.
    let header_end = [
        "<dependencies",
        "<dependencyManagement",
        "<build",
        "<profiles",
        "<reporting",
    ]
    .iter()
    .filter_map(|m| no_parent.find(m))
    .min()
    .unwrap_or(no_parent.len());
    let header = &no_parent[..header_end];
    proj_ga.group = first_tag_text(header, "groupId");
    proj_ga.artifact = first_tag_text(header, "artifactId");
    parent_ga.group = first_tag_text(text, "groupId");
    parent_ga.artifact = first_tag_text(text, "artifactId");
    // If the only coords were inside <parent>, project inherits them.
    if proj_ga.group.is_none() && proj_ga.artifact.is_none() {
        proj_ga = parent_ga.clone();
    }
    let proj_group = proj_ga
        .group
        .clone()
        .or_else(|| parent_ga.group.clone())
        .ok_or_else(|| err("pom.xml: no groupId"))?;
    let proj_artifact = proj_ga
        .artifact
        .clone()
        .ok_or_else(|| err("pom.xml: no artifactId"))?;
    let proj_node = format!("{proj_group}:{proj_artifact}");

    let mut edges = EdgeList::new();
    // Dependencies: only inside <dependencies> that are NOT inside
    // <dependencyManagement> or <build> (plugin deps aren't project deps).
    let clean = strip_section(&strip_section(&no_parent, "dependencyManagement"), "build");
    for block in xml_blocks(&clean, "dependencies") {
        for dep in xml_blocks(&block, "dependency") {
            let g = first_tag_text(&dep, "groupId").or_else(|| Some(proj_group.clone()));
            let Some(a) = first_tag_text(&dep, "artifactId") else {
                continue;
            };
            let scope = first_tag_text(&dep, "scope").unwrap_or_default();
            if scope == "import" {
                continue; // BOM, not a real dependency
            }
            let Some(g) = g else { continue };
            push_edge(&mut edges, &proj_node, format!("{g}:{a}"));
        }
    }
    Ok(edges)
}

/// Remove every `<tag>...</tag>` section (non-greedy, one level deep is
/// enough for our use since these sections don't nest).
fn strip_section(text: &str, tag: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start..];
        if !tag_boundary(after_open, tag) {
            // False match (e.g. `<builder`): keep the prefix, rescan
            // from just past the '<'.
            out.push_str(&rest[..=start]);
            rest = &rest[start + 1..];
            continue;
        }
        out.push_str(&rest[..start]);
        // skip past this open tag
        let Some(gt) = after_open.find('>') else {
            break;
        };
        let inner_start = start + gt + 1;
        let inner = &rest[inner_start..];
        match inner.find(&close) {
            Some(end) => {
                // Drop through the close tag.
                let close_end = inner_start + end + close.len();
                rest = &rest[close_end..];
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

/// True when the char after `<tag` in `s` (which starts with `<tag`)
/// is a tag-name boundary: `>`, whitespace, `/`, or end of string.
/// Prevents `<dependency` matching `<dependencyManagement`.
fn tag_boundary(s: &str, tag: &str) -> bool {
    s[tag.len() + 1..]
        .chars()
        .next()
        .is_none_or(|c| c == '>' || c == '/' || c.is_whitespace())
}

/// Inner content of every `<tag>...</tag>` block.
fn xml_blocks(text: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start..];
        if !tag_boundary(after, tag) {
            rest = &rest[start + 1..];
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        // Self-closing or attribute check: ensure it's an open tag not </tag>
        if after[..gt].trim_end().ends_with('/') {
            rest = &after[gt + 1..];
            continue;
        }
        let inner_start = start + gt + 1;
        let inner = &rest[inner_start..];
        match inner.find(&close) {
            Some(end) => {
                out.push(inner[..end].to_string());
                rest = &inner[end + close.len()..];
            }
            None => break,
        }
    }
    out
}

/// Text content of the first `<tag>...</tag>` occurrence.
fn first_tag_text(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start..];
        if !tag_boundary(after, tag) {
            rest = &rest[start + 1..];
            continue;
        }
        let gt = after.find('>')?;
        let inner = &after[gt + 1..];
        let end = inner.find(&close)?;
        let t = inner[..end].trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
        rest = &inner[end + close.len()..];
    }
    None
}

// ---------- package-lock.json ----------

/// Parse `package-lock.json` (npm v1 tree or v2/v3 `"packages"` map).
pub fn package_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("package-lock.json: {e}")))?;
    if let Some(pkgs) = v["packages"].as_object() {
        package_lock_v2(&v, pkgs)
    } else if v["dependencies"].is_object() {
        package_lock_v1(&v)
    } else {
        Err(err(
            "package-lock.json: neither 'packages' nor 'dependencies' found",
        ))
    }
}

/// v2/v3: `""` is the root project; other keys are install paths like
/// `node_modules/a` or `node_modules/a/node_modules/b`. A package's deps
/// resolve by walking up `node_modules` ancestors (node resolution).
fn package_lock_v2(
    root: &serde_json::Value,
    pkgs: &serde_json::Map<String, serde_json::Value>,
) -> Result<EdgeList> {
    // path -> declared dep names (dependencies + optionalDependencies)
    let mut decls: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, meta) in pkgs {
        let mut ds = Vec::new();
        for key in ["dependencies", "optionalDependencies"] {
            if let Some(obj) = meta[key].as_object() {
                ds.extend(obj.keys().cloned());
            }
        }
        decls.insert(path.clone(), ds);
    }

    let root_name = root["name"].as_str().unwrap_or("(root)").to_string();

    // Multiple installed versions of one package (nested node_modules)
    // would collide under a bare name - disambiguate as `name@version`.
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for path in pkgs.keys() {
        if !path.is_empty() {
            *name_counts.entry(pkg_name_from_path(path)).or_default() += 1;
        }
    }
    let disp_name = |path: &str| -> String {
        let base = pkg_name_from_path(path);
        if name_counts.get(&base).copied().unwrap_or(0) > 1 {
            // Link entries (workspace symlinks) carry no version; follow
            // `resolved` to the real package for its version.
            let ver = pkgs[path]["version"]
                .as_str()
                .or_else(|| {
                    pkgs[path]["resolved"]
                        .as_str()
                        .and_then(|r| pkgs.get(r))
                        .and_then(|m| m["version"].as_str())
                })
                .unwrap_or(path);
            format!("{base}@{ver}")
        } else {
            base
        }
    };

    let mut edges = EdgeList::new();
    let mut seen = BTreeSet::new();

    for (path, ds) in &decls {
        if ds.is_empty() {
            continue;
        }
        let src = if path.is_empty() {
            root_name.clone()
        } else {
            disp_name(path)
        };
        for dep in ds {
            if let Some(resolved) = resolve_npm_dep(pkgs, path, dep) {
                let dst = disp_name(&resolved);
                if seen.insert((src.clone(), dst.clone())) {
                    push_edge(&mut edges, &src, dst);
                }
            }
        }
    }
    Ok(edges)
}

/// v1: nested `"dependencies"` objects; parent -> child edges. The
/// top-level deps hang off the lockfile's `name` (or `(root)`).
fn package_lock_v1(root: &serde_json::Value) -> Result<EdgeList> {
    fn walk(
        obj: &serde_json::Map<String, serde_json::Value>,
        parent: &str,
        edges: &mut EdgeList,
        seen: &mut BTreeSet<(String, String)>,
    ) {
        for (name, meta) in obj {
            if seen.insert((parent.to_string(), name.clone())) {
                push_edge(edges, parent, name.clone());
            }
            if let Some(children) = meta["dependencies"].as_object() {
                walk(children, name, edges, seen);
            }
        }
    }
    let root_name = root["name"].as_str().unwrap_or("(root)").to_string();
    let mut edges = EdgeList::new();
    let mut seen = BTreeSet::new();
    if let Some(deps) = root["dependencies"].as_object() {
        walk(deps, &root_name, &mut edges, &mut seen);
    }
    Ok(edges)
}

/// Package name from an install path: text after the last `node_modules/`.
fn pkg_name_from_path(path: &str) -> String {
    path.rsplit("node_modules/")
        .next()
        .unwrap_or(path)
        .to_string()
}

/// Node-style resolution: from package dir `path`, find `dep` by checking
/// `prefix/node_modules/dep` for `path` and each ancestor prefix.
fn resolve_npm_dep(
    pkgs: &serde_json::Map<String, serde_json::Value>,
    path: &str,
    dep: &str,
) -> Option<String> {
    let mut prefix = path.to_string();
    loop {
        let candidate = if prefix.is_empty() {
            format!("node_modules/{dep}")
        } else if prefix == "node_modules" || prefix.ends_with("/node_modules") {
            // node skips dirs named node_modules
            String::new()
        } else {
            format!("{prefix}/node_modules/{dep}")
        };
        if !candidate.is_empty() && pkgs.contains_key(&candidate) {
            return Some(candidate);
        }
        if prefix.is_empty() {
            return None;
        }
        match prefix.rfind('/') {
            Some(i) => prefix.truncate(i),
            None => prefix.clear(),
        }
    }
}

// ---------- dispatch helpers ----------

pub(crate) fn unquote(s: &str) -> String {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
        .to_string()
}

// ---------- yarn.lock (v1 + berry) ----------

/// Parse `yarn.lock`. Block keys are comma-separated `name@range`
/// specs (quoted); each block has `version "x"` and a `dependencies:`
/// subsection of `name "range"` lines. Emits inter-package edges so
/// `deps` walks the full transitive chain. Node ids are `name@version`.
pub fn yarn_lock(text: &str) -> Result<EdgeList> {
    use std::collections::HashMap;

    struct Block {
        name: String,
        version: String,
        deps: Vec<(String, String)>,
    }

    let mut blocks: Vec<Block> = Vec::new();
    // spec string ("name@range") -> block index; name -> first block.
    let mut spec_map: HashMap<String, usize> = HashMap::new();
    let mut name_map: HashMap<String, usize> = HashMap::new();

    let mut cur: Option<usize> = None;
    let mut dep_indent = 0usize;
    let mut in_deps = false;

    let split_specs = |key: &str| -> Vec<String> {
        key.split("\", \"")
            .map(|s| {
                s.trim()
                    .trim_end_matches(':')
                    .trim_matches('"')
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .collect()
    };

    for raw in text.lines() {
        if raw.starts_with('#') || raw.trim().is_empty() {
            continue;
        }
        let ind = raw.len() - raw.trim_start().len();
        let t = raw.trim();

        if ind == 0 {
            // New block: `"a@^1", "a@^2":` or `abbrev@1:`.
            in_deps = false;
            cur = None;
            for spec in split_specs(t) {
                // name@range: name ends at first '@' (second for
                // scoped `@scope/name@range`).
                let at = if spec.starts_with('@') {
                    spec[1..].find('@').map(|i| i + 1)
                } else {
                    spec.find('@')
                };
                let Some(at) = at else { continue };
                let name = spec[..at].to_string();
                if name.is_empty() {
                    continue;
                }
                let idx = blocks.len();
                blocks.push(Block {
                    name: name.clone(),
                    version: String::new(),
                    deps: Vec::new(),
                });
                spec_map.insert(spec, idx);
                name_map.entry(name).or_insert(idx);
                cur = Some(idx);
            }
            continue;
        }

        let Some(ci) = cur else { continue };
        if in_deps {
            if ind <= dep_indent {
                in_deps = false;
            } else {
                // `"name" "range"` or `name "range"`.
                let mut it = t.split_whitespace();
                let name = it.next().map(unquote);
                let range = it.next().map(unquote);
                if let (Some(n), Some(r)) = (name, range) {
                    if !n.is_empty() && !r.is_empty() {
                        blocks[ci].deps.push((n, r));
                    }
                }
                continue;
            }
        }
        if t == "dependencies:" || t == "optionalDependencies:" || t == "peerDependencies:" {
            in_deps = true;
            dep_indent = ind;
            continue;
        }
        if let Some(v) = t.strip_prefix("version ") {
            blocks[ci].version = unquote(v);
        }
    }

    if blocks.is_empty() {
        return Err(err("yarn.lock: no package blocks found"));
    }

    let node_of = |i: usize| -> String {
        let b = &blocks[i];
        if b.version.is_empty() {
            b.name.clone()
        } else {
            format!("{}@{}", b.name, b.version)
        }
    };

    let mut edges: EdgeList = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for (i, b) in blocks.iter().enumerate() {
        for (dn, dr) in &b.deps {
            let spec = format!("{dn}@{dr}");
            let di = spec_map
                .get(&spec)
                .or_else(|| name_map.get(dn))
                .copied();
            let Some(di) = di else { continue };
            if di == i {
                continue;
            }
            let e = (node_of(i), node_of(di));
            if seen.insert(e.clone()) {
                edges.push((e.0, e.1, None, strand_core::EdgeKind::Static));
            }
        }
    }
    Ok(edges)
}

// ---------- pnpm-lock.yaml ----------

/// Parse `pnpm-lock.yaml`. `importers` map project dirs to their
/// direct deps (emits `<dir>/package.json -> name@version`);
/// `snapshots` hold each package's resolved dependencies
/// (emits `name@version -> dep@version`). Peer suffixes `( ... )`
/// are stripped so dep references resolve to snapshot keys.
pub fn pnpm_lock(text: &str) -> Result<EdgeList> {
    let doc: serde_yml::Value =
        serde_yml::from_str(text).map_err(|e| err(format!("pnpm-lock.yaml: {e}")))?;

    // Normalize a pnpm version ref: strip peer-dep suffix `( ... )`.
    fn norm_ver(v: &str) -> String {
        v.split('(').next().unwrap_or(v).trim().to_string()
    }
    // `name@version` node id from a snapshot/package key or a
    // `name` + `version` pair.
    fn node_id(key: &str) -> String {
        // Keys look like `name@1.2.3` or `@scope/name@1.2.3(peers)`.
        let k = norm_ver(key);
        k
    }

    let mut edges: EdgeList = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    let mut push = |s: String, d: String| {
        if s != d && seen.insert((s.clone(), d.clone())) {
            edges.push((s, d, None, strand_core::EdgeKind::Static));
        }
    };

    // importers: dir -> dep name -> {specifier, version}
    if let Some(importers) = doc.get("importers").and_then(|v| v.as_mapping()) {
        for (dir_v, imp) in importers {
            let Some(dir) = dir_v.as_str() else { continue };
            let src = if dir == "." {
                "package.json".to_string()
            } else {
                format!("{dir}/package.json")
            };
            for section in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(deps) = imp.get(section).and_then(|v| v.as_mapping()) {
                    for (name_v, meta) in deps {
                        let Some(name) = name_v.as_str() else { continue };
                        let ver = meta
                            .get("version")
                            .and_then(|v| v.as_str())
                            .map(norm_ver);
                        if let Some(ver) = ver {
                            if !ver.is_empty() && !ver.contains("://") {
                                push(src.clone(), format!("{name}@{ver}"));
                            }
                        }
                    }
                }
            }
        }
    }

    // snapshots: `name@ver(peers)` -> { dependencies: {name: ver} }
    if let Some(snaps) = doc.get("snapshots").and_then(|v| v.as_mapping()) {
        for (key_v, snap) in snaps {
            let Some(key) = key_v.as_str() else { continue };
            let src = node_id(key);
            for section in ["dependencies", "optionalDependencies"] {
                if let Some(deps) = snap.get(section).and_then(|v| v.as_mapping()) {
                    for (name_v, ver_v) in deps {
                        let (Some(name), Some(ver)) =
                            (name_v.as_str(), ver_v.as_str())
                        else {
                            continue;
                        };
                        let ver = norm_ver(ver);
                        if ver.is_empty() || ver.contains("://") {
                            continue;
                        }
                        push(src.clone(), format!("{name}@{ver}"));
                    }
                }
            }
        }
    }
    Ok(edges)
}

// ---------- composer.lock (PHP) ----------

/// Parse `composer.lock`: `packages` + `packages-dev` arrays of
/// `{name, version, require: {dep: constraint}}`. Nodes `name@version`.
pub fn composer_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("composer.lock: {e}")))?;
    let mut pkgs = Vec::new();
    for section in ["packages", "packages-dev"] {
        if let Some(arr) = v[section].as_array() {
            for p in arr {
                let name = p["name"].as_str().unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                let ver = p["version"].as_str().unwrap_or("");
                let mut deps = Vec::new();
                if let Some(req) = p["require"].as_object() {
                    deps.extend(req.keys().cloned());
                }
                pkgs.push(PkgSpec {
                    node: nv(name, ver),
                    deps,
                });
            }
        }
    }
    Ok(indexed_edges(&pkgs))
}

// ---------- Gemfile.lock (Ruby) ----------

/// Parse `Gemfile.lock`. `GEM`/`PATH`/`GIT` sections hold `specs:`
/// entries `    name (version)` with dep lines `      dep (req)`.
/// `DEPENDENCIES` is the root list (covered by the Gemfile manifest).
/// Nodes `name@version`.
pub fn gemfile_lock(text: &str) -> Result<EdgeList> {
    let mut pkgs: Vec<PkgSpec> = Vec::new();
    let mut in_specs = false;
    let mut cur: Option<usize> = None;

    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let ind = raw.len() - raw.trim_start().len();
        let t = raw.trim();
        // Section headers are unindented uppercase words.
        if ind == 0 {
            in_specs = false;
            cur = None;
            if matches!(t, "GEM" | "PATH" | "GIT") {
                // specs: marker handled below
            } else if t == "DEPENDENCIES:" || t == "SPEC CHECKSUMS:" || t.starts_with("PODFILE") {
                // not spec sections
            }
            continue;
        }
        if !in_specs {
            if t == "specs:" {
                in_specs = true;
            }
            continue;
        }
        // Inside specs: `    name (version)` at indent 4 starts a
        // spec; `      dep (req)` at indent 6 is its dependency.
        if ind <= 4 {
            if let Some((name, ver)) = parse_paren_spec(t) {
                pkgs.push(PkgSpec {
                    node: nv(name, ver),
                    deps: Vec::new(),
                });
                cur = Some(pkgs.len() - 1);
            }
            continue;
        }
        if let (Some(ci), Some((dn, _))) = (cur, parse_paren_spec(t)) {
            pkgs[ci].deps.push(dn.to_string());
        }
    }
    if pkgs.is_empty() {
        return Err(err("Gemfile.lock: no specs found"));
    }
    Ok(indexed_edges(&pkgs))
}

/// `name (version)` -> (name, version). Version keeps platform
/// suffixes (`1.2.3-java`).
fn parse_paren_spec(t: &str) -> Option<(&str, &str)> {
    let open = t.rfind('(')?;
    let close = t.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = t[..open].trim();
    let ver = t[open + 1..close].trim();
    if name.is_empty() || ver.is_empty() || name.contains(' ') {
        return None;
    }
    Some((name, ver))
}

// ---------- packages.lock.json (NuGet) ----------

/// Parse `packages.lock.json` (NuGet PackageReference restore).
/// `dependencies` maps target framework -> package id ->
/// `{resolved, dependencies: {id: range}}`. Nodes `id@resolved`.
pub fn nuget_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("packages.lock.json: {e}")))?;
    let mut pkgs: Vec<(String, Vec<String>)> = Vec::new(); // (node, dep ids)
    let mut seen_nodes: BTreeSet<String> = BTreeSet::new();
    if let Some(targets) = v["dependencies"].as_object() {
        for (_tfm, pkgs_obj) in targets {
            let Some(pkgs_obj) = pkgs_obj.as_object() else {
                continue;
            };
            // id -> resolved version within this target.
            let mut resolved: BTreeMap<String, String> = BTreeMap::new();
            for (id, meta) in pkgs_obj {
                if let Some(r) = meta["resolved"].as_str() {
                    resolved.insert(id.clone(), r.to_string());
                }
            }
            for (id, meta) in pkgs_obj {
                let ver = meta["resolved"].as_str().unwrap_or("");
                let node = nv(id, ver);
                if !seen_nodes.insert(node.clone()) {
                    continue;
                }
                let mut deps = Vec::new();
                if let Some(d) = meta["dependencies"].as_object() {
                    for did in d.keys() {
                        // Resolve dep id to its locked version in
                        // this target; bare id when unknown.
                        let dnode = resolved
                            .get(did)
                            .map(|dv| nv(did, dv))
                            .unwrap_or_else(|| did.clone());
                        deps.push(dnode);
                    }
                }
                pkgs.push((node, deps));
            }
        }
    }
    // pkgs deps are already node ids, not bare names - build edges
    // directly with self-loop declarations.
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (n, _) in &pkgs {
        if seen.insert((n.clone(), n.clone())) {
            edges.push((n.clone(), n.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    for (node, deps) in &pkgs {
        for dst in deps {
            if seen.insert((node.clone(), dst.clone())) {
                edges.push((node.clone(), dst.clone(), None, strand_core::EdgeKind::Static));
            }
        }
    }
    Ok(edges)
}

// ---------- Package.resolved (Swift) ----------

/// Parse `Package.resolved` (SwiftPM). `pins[]` carry `identity`
/// and `state.version`/`state.revision`. The format records no
/// inter-package edges, so each pin hangs off [`FLAT_SRC`].
pub fn swift_resolved(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("Package.resolved: {e}")))?;
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if let Some(pins) = v["pins"].as_array() {
        for p in pins {
            let id = p["identity"].as_str().unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let ver = p["state"]["version"]
                .as_str()
                .or_else(|| p["state"]["revision"].as_str())
                .unwrap_or("");
            let node = nv(id, ver);
            if seen.insert(node.clone()) {
                edges.push((
                    FLAT_SRC.to_string(),
                    node,
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
        }
    }
    if edges.is_empty() {
        return Err(err("Package.resolved: no pins found"));
    }
    Ok(edges)
}

// ---------- pubspec.lock (Dart/Flutter) ----------

/// Parse `pubspec.lock`. `packages:` maps name -> `{version, ...}`.
/// The format records no inter-package edges, so each package hangs
/// off [`FLAT_SRC`].
pub fn pubspec_lock(text: &str) -> Result<EdgeList> {
    let doc: serde_yml::Value =
        serde_yml::from_str(text).map_err(|e| err(format!("pubspec.lock: {e}")))?;
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if let Some(pkgs) = doc.get("packages").and_then(|v| v.as_mapping()) {
        for (name_v, meta) in pkgs {
            let Some(name) = name_v.as_str() else { continue };
            let ver = meta.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let node = nv(name, ver);
            if seen.insert(node.clone()) {
                edges.push((
                    FLAT_SRC.to_string(),
                    node,
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
        }
    }
    if edges.is_empty() {
        return Err(err("pubspec.lock: no packages found"));
    }
    Ok(edges)
}

// ---------- go.sum ----------

/// Parse `go.sum`: `module version hash` lines (plus `/go.mod`
/// hash variants). Emits `module -> module version` edges so the
/// bare module nodes that `go.mod` requires point at their locked
/// versions.
pub fn go_sum(text: &str) -> Result<EdgeList> {
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(module), Some(ver)) = (it.next(), it.next()) else {
            continue;
        };
        if module.is_empty() {
            continue;
        }
        let ver = ver.strip_suffix("/go.mod").unwrap_or(ver);
        if ver.is_empty() {
            continue;
        }
        let dst = format!("{module} {ver}");
        if seen.insert((module.to_string(), dst.clone())) {
            edges.push((module.to_string(), dst, None, strand_core::EdgeKind::Static));
        }
    }
    if edges.is_empty() {
        return Err(err("go.sum: no module entries found"));
    }
    Ok(edges)
}

// ---------- uv.lock ----------

/// Parse `uv.lock` (uv). `[[package]]` entries carry `name`,
/// `version`, and `dependencies = [{name = "...", ...}]`. Dep
/// entries pin no version, so names resolve through the package
/// index. Nodes `name@version`.
pub fn uv_lock(text: &str) -> Result<EdgeList> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| err(format!("uv.lock: {e}")))?;
    let mut pkgs = Vec::new();
    if let Some(arr) = doc.get("package").and_then(|v| v.as_array()) {
        for p in arr {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let ver = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let mut deps = Vec::new();
            if let Some(darr) = p.get("dependencies").and_then(|v| v.as_array()) {
                for d in darr {
                    if let Some(dn) = d.get("name").and_then(|v| v.as_str()) {
                        if !dn.is_empty() {
                            deps.push(dn.to_string());
                        }
                    }
                }
            }
            pkgs.push(PkgSpec {
                node: nv(name, ver),
                deps,
            });
        }
    }
    if pkgs.is_empty() {
        return Err(err("uv.lock: no packages found"));
    }
    Ok(indexed_edges(&pkgs))
}

// ---------- bun.lock ----------

/// Parse `bun.lock` (JSONC). `workspaces` maps project dirs to
/// their declared deps (emitted as `<dir>/package.json -> dep`,
/// matching the package.json manifest nodes); `packages` maps
/// `name@version` to `[resolution, {dependencies: {...}}]`.
pub fn bun_lock(text: &str) -> Result<EdgeList> {
    let cleaned = jsonc_clean(text);
    let v: serde_json::Value =
        serde_json::from_str(&cleaned).map_err(|e| err(format!("bun.lock: {e}")))?;

    // Index of locked `name@version` package keys by bare name.
    let mut index = VerIndex::default();
    if let Some(pkgs) = v["packages"].as_object() {
        for key in pkgs.keys() {
            index.add(key);
        }
    }

    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    // Resolve a dep spec like `^1.0`, `npm:name@1.2.3`, `name@1.2.3`,
    // `workspace:*` to locked node ids.
    fn resolve_spec(
        index: &VerIndex,
        name: &str,
        spec: &str,
        edges: &mut EdgeList,
        seen: &mut BTreeSet<(String, String)>,
    ) -> Vec<String> {
        let spec = spec.strip_prefix("npm:").unwrap_or(spec);
        if let Some((n, ver)) = spec.rsplit_once('@') {
            if n == name && !ver.is_empty() && !ver.contains(':') {
                let node = nv(name, ver);
                if index.by_name.get(name).is_some_and(|v| v.contains(&node)) {
                    return vec![node];
                }
            }
        }
        index.resolve(name, edges, seen)
    }

    // workspaces: dir -> {name?, dependencies/devDependencies/...}
    if let Some(ws) = v["workspaces"].as_object() {
        for (dir, meta) in ws {
            let src = if dir.is_empty() {
                "package.json".to_string()
            } else {
                format!("{dir}/package.json")
            };
            for section in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(deps) = meta[section].as_object() {
                    for (name, spec) in deps {
                        let spec = spec.as_str().unwrap_or("");
                        if spec == "workspace:*" || spec.starts_with("link:") {
                            continue; // intra-workspace, not external
                        }
                        for dst in resolve_spec(&index, name, spec, &mut edges, &mut seen) {
                            if src != dst && seen.insert((src.clone(), dst.clone())) {
                                edges.push((
                                    src.clone(),
                                    dst,
                                    None,
                                    strand_core::EdgeKind::Static,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // packages: `name@ver` -> [resolution, meta?]
    if let Some(pkgs) = v["packages"].as_object() {
        for (key, val) in pkgs {
            let meta = if let Some(arr) = val.as_array() {
                arr.get(1).cloned().unwrap_or(serde_json::Value::Null)
            } else {
                val.clone()
            };
            for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
                if let Some(deps) = meta[section].as_object() {
                    for (name, spec) in deps {
                        let spec = spec.as_str().unwrap_or("");
                        for dst in resolve_spec(&index, name, spec, &mut edges, &mut seen) {
                            if key != &dst && seen.insert((key.clone(), dst.clone())) {
                                edges.push((
                                    key.clone(),
                                    dst,
                                    None,
                                    strand_core::EdgeKind::Static,
                                ));
                            }
                        }
                    }
                }
            }
            // Node declaration so leaf packages still appear.
            if seen.insert((key.clone(), key.clone())) {
                edges.push((
                    key.clone(),
                    key.clone(),
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
        }
    }
    if edges.is_empty() {
        return Err(err("bun.lock: no packages found"));
    }
    Ok(edges)
}

/// Strip `//` line comments and trailing commas from JSONC text
/// (bun.lock). String-aware: `//` inside quotes is preserved.
fn jsonc_clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_str = false;
    let mut esc = false;
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ',' => {
                // Drop the comma if the next non-ws char closes a
                // container (trailing comma).
                let mut lookahead = chars.clone();
                let mut next = None;
                for c in lookahead.by_ref() {
                    if !c.is_whitespace() {
                        next = Some(c);
                        break;
                    }
                }
                match next {
                    Some('}') | Some(']') => {}
                    _ => out.push(','),
                }
            }
            _ => out.push(c),
        }
    }
    out
}

// ---------- Podfile.lock (CocoaPods) ----------

/// Parse `Podfile.lock`. `PODS:` entries `  - Name (version)` may be
/// followed by deeper `    - Dep (constraint)` lines; dep names
/// without `/` (subspecs) are external pod deps. `DEPENDENCIES:` is
/// the root list (covered by the Podfile manifest). Nodes
/// `Name@version`.
pub fn podfile_lock(text: &str) -> Result<EdgeList> {
    let mut pkgs = Vec::new();
    let mut in_pods = false;
    let mut cur: Option<usize> = None;

    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let ind = raw.len() - raw.trim_start().len();
        let t = raw.trim();
        if ind == 0 {
            in_pods = t == "PODS:";
            cur = None;
            continue;
        }
        if !in_pods {
            continue;
        }
        let Some(item) = t.strip_prefix("- ") else {
            continue;
        };
        if ind <= 2 {
            // `  - Name (version)` or `  - Name (version):`
            if let Some((name, ver)) = parse_paren_spec(item.trim_end_matches(':')) {
                pkgs.push(PkgSpec {
                    node: nv(name, ver),
                    deps: Vec::new(),
                });
                cur = Some(pkgs.len() - 1);
            }
            continue;
        }
        // Deeper `- Dep (req)`: subspecs contain `/`, skip those.
        if let (Some(ci), Some((dn, _))) = (cur, parse_paren_spec(item)) {
            if !dn.contains('/') {
                pkgs[ci].deps.push(dn.to_string());
            }
        }
    }
    if pkgs.is_empty() {
        return Err(err("Podfile.lock: no pods found"));
    }
    Ok(indexed_edges(&pkgs))
}

// ---------- shared ----------

/// One locked package: `node` is its `name@version` id, `deps` are
/// bare dep names resolved through [`VerIndex`].
struct PkgSpec {
    node: String,
    deps: Vec<String>,
}

/// Build `name@version -> dep` edges for a package list whose deps
/// are bare names: self-loop node declarations plus index-resolved
/// dep edges with multi-version disambiguation.
fn indexed_edges(pkgs: &[PkgSpec]) -> EdgeList {
    let mut index = VerIndex::default();
    for p in pkgs {
        index.add(&p.node);
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for p in pkgs {
        if seen.insert((p.node.clone(), p.node.clone())) {
            edges.push((p.node.clone(), p.node.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    for p in pkgs {
        for dep in &p.deps {
            for dst in index.resolve(dep, &mut edges, &mut seen) {
                if seen.insert((p.node.clone(), dst.clone())) {
                    edges.push((p.node.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
    }
    edges
}

// ---------- stack.yaml.lock (Haskell) ----------

/// Parse `stack.yaml.lock`. `packages:` entries carry
/// `original.hackage: name` (dep name) with `completed.hackage:
/// name-version@hash`. No inter-package edges are recorded, so
/// resolved `name@version` nodes hang off [`FLAT_SRC`].
pub fn stack_lock(text: &str) -> Result<EdgeList> {
    let doc: serde_yml::Value =
        serde_yml::from_str(text).map_err(|e| err(format!("stack.yaml.lock: {e}")))?;
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if let Some(pkgs) = doc.get("packages").and_then(|v| v.as_sequence()) {
        for p in pkgs {
            // Prefer completed (resolved) hackage `name-version`;
            // fall back to the original dep name.
            let node = p
                .get("completed")
                .and_then(|c| c.get("hackage"))
                .and_then(|h| h.as_str())
                .or_else(|| {
                    p.get("original")
                        .and_then(|o| o.get("hackage"))
                        .and_then(|h| h.as_str())
                })
                .unwrap_or("");
            if node.is_empty() {
                continue;
            }
            // `name-1.2.3@sha256:...` -> `name@1.2.3`
            let node = hackage_node(node);
            if seen.insert(node.clone()) {
                edges.push((FLAT_SRC.to_string(), node, None, strand_core::EdgeKind::Static));
            }
        }
    }
    // pantry/git/archive deps in `original` without hackage.
    if let Some(pkgs) = doc.get("packages").and_then(|v| v.as_sequence()) {
        for p in pkgs {
            let orig = p.get("original");
            for key in ["pantry", "git", "archive"] {
                if let Some(v) = orig.and_then(|o| o.get(key)).and_then(|x| x.as_str()) {
                    if !v.is_empty() && seen.insert(v.to_string()) {
                        edges.push((
                            FLAT_SRC.to_string(),
                            v.to_string(),
                            None,
                            strand_core::EdgeKind::Static,
                        ));
                    }
                }
            }
        }
    }
    if edges.is_empty() {
        return Err(err("stack.yaml.lock: no packages found"));
    }
    Ok(edges)
}

/// `aeson-2.2.1.0@sha256:abc` -> `aeson@2.2.1.0`; `text-2.0.2` ->
/// `text@2.0.2`. Hackage versions start with a digit after the last
/// `-` that precedes a digit.
fn hackage_node(s: &str) -> String {
    let s = s.split('@').next().unwrap_or(s).trim();
    // Find the last '-' followed by a digit.
    let bytes = s.as_bytes();
    for i in (0..s.len()).rev() {
        if bytes[i] == b'-' && i + 1 < s.len() && bytes[i + 1].is_ascii_digit() {
            return format!("{}@{}", &s[..i], &s[i + 1..]);
        }
    }
    s.to_string()
}

// ---------- mix.lock (Elixir/Erlang terms) ----------

/// Parse `mix.lock`: `%{"name": {:hex, :name, "version", ...}}`.
/// Entries record no dep relations, so `name@version` nodes hang
/// off [`FLAT_SRC`].
pub fn mix_lock(text: &str) -> Result<EdgeList> {
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        // `"decimal": {:hex, :decimal, "2.0.0", ...}` or
        // `"phoenix": {:hex, :phoenix, "1.7.0", ...}`.
        let t = line.trim();
        let Some(q1) = t.find('"') else { continue };
        let rest = &t[q1 + 1..];
        let Some(q2) = rest.find('"') else { continue };
        let name = &rest[..q2];
        let after = &rest[q2..];
        let Some(hex_pos) = after.find(":hex") else { continue };
        // First quoted string after `:hex, :name,` is the version.
        let tail = &after[hex_pos..];
        let Some(q) = tail.find('"') else { continue };
        let inner = &tail[q + 1..];
        let Some(e) = inner.find('"') else { continue };
        let ver = &inner[..e];
        let node = nv(name, ver);
        if seen.insert(node.clone()) {
            edges.push((FLAT_SRC.to_string(), node, None, strand_core::EdgeKind::Static));
        }
    }
    if edges.is_empty() {
        return Err(err("mix.lock: no hex packages found"));
    }
    Ok(edges)
}

// ---------- Cartfile.resolved (Carthage) ----------

/// Parse `Cartfile.resolved`: `github "org/repo" "1.2.3"` lines.
/// Flat - each pinned repo hangs off [`FLAT_SRC`].
pub fn cartfile_resolved(text: &str) -> Result<EdgeList> {
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        // `github "org/repo" "version"` / `git "url" "version"` /
        // `binary "name" "version"`.
        let mut it = t.split_whitespace();
        let Some(_kind) = it.next() else { continue };
        let mut quoted = Vec::new();
        let mut rest = t;
        while let Some(q) = rest.find('"') {
            let inner = &rest[q + 1..];
            if let Some(e) = inner.find('"') {
                quoted.push(&inner[..e]);
                rest = &inner[e + 1..];
            } else {
                break;
            }
        }
        if quoted.len() >= 2 {
            let node = format!("{}@{}", quoted[0], quoted[1]);
            if seen.insert(node.clone()) {
                edges.push((FLAT_SRC.to_string(), node, None, strand_core::EdgeKind::Static));
            }
        }
    }
    if edges.is_empty() {
        return Err(err("Cartfile.resolved: no entries found"));
    }
    Ok(edges)
}

// ---------- deno.lock ----------

/// Parse `deno.lock` (JSON). `remote`/`npm`/`jsr`/`workspace`
/// sections key resolved specifiers to integrity entries; emit each
/// key as a node off [`FLAT_SRC`].
/// Normalize a deno.lock specifier to `name@version` when it is a
/// remote URL: `host/std@0.224.0/...` (deno.land), `esm.sh/pkg@1.2.3`,
/// `jsr.io/@scope/pkg/1.0.0/...` (version as its own segment).
/// Returns None for non-URL keys (npm/jsr/workspace entries are
/// already emitted verbatim).
fn deno_url_node(key: &str) -> Option<String> {
    let rest = key
        .strip_prefix("https://")
        .or_else(|| key.strip_prefix("http://"))?;
    let mut segs = rest.split('/');
    segs.next()?; // host
    let segs: Vec<&str> = segs.collect();
    // Try joining 1-2 leading segments as the package specifier:
    // `name@ver`, `@scope/name@ver`, `name/ver`, `@scope/name/ver`.
    for w in 1..=2usize.min(segs.len()) {
        let joined = segs[..w].join("/");
        if let Some((n, v)) = joined.rsplit_once('@') {
            if !n.is_empty()
                && v.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                return Some(nv(n, v));
            }
        }
        if w < segs.len()
            && segs[w].chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return Some(nv(&joined, segs[w]));
        }
    }
    None
}

/// Split a deno.lock package key `name@version` into (name, version),
/// tolerating peer suffixes (`1.2.3_peer@4.5.6` -> `1.2.3`) and
/// `npm:`/`jsr:` protocol prefixes.
fn deno_split_key(key: &str) -> (String, String) {
    let key = key
        .strip_prefix("npm:")
        .or_else(|| key.strip_prefix("jsr:"))
        .unwrap_or(key);
    // Last '@' followed by a digit starts the version (scoped names
    // keep their leading '@').
    let bytes = key.as_bytes();
    let mut cut = None;
    for (i, &c) in bytes.iter().enumerate().skip(1) {
        if c == b'@'
            && bytes
                .get(i + 1)
                .is_some_and(|d| d.is_ascii_digit())
        {
            cut = Some(i);
        }
    }
    match cut {
        Some(i) => {
            let name = &key[..i];
            let ver = key[i + 1..].split('_').next().unwrap_or("");
            (name.to_string(), ver.to_string())
        }
        None => (key.to_string(), String::new()),
    }
}

/// Parse one deno.lock `dependencies` entry: `"name"`,
/// `"name@version"`, `"@scope/name@version"`, optionally prefixed
/// `npm:`/`jsr:`. Returns (name, Option<version>).
fn deno_dep_spec(spec: &str) -> (String, Option<String>) {
    let (name, ver) = deno_split_key(spec.trim().trim_matches('"'));
    (name, if ver.is_empty() { None } else { Some(ver) })
}

/// deno.lock v5 records real edges: `npm`/`jsr` entries carry a
/// `dependencies` array of resolved specs (`"ms"`, `"@scope/p@1.2.3"`),
/// `workspace.dependencies` lists the root's specifiers (resolved
/// through `specifiers`), and `remote`/`workspace` stay flat nodes.
/// Bare dep names resolve through the lock's own `name@version`
/// index: unique version pins, several versions emit may-edges.
pub fn deno_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("deno.lock: {e}")))?;
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut nodes: BTreeSet<String> = BTreeSet::new();

    let push = |edges: &mut EdgeList,
                    seen: &mut BTreeSet<(String, String)>,
                    nodes: &mut BTreeSet<String>,
                    src: &str,
                    dst: String| {
        if !dst.is_empty() {
            nodes.insert(dst.clone());
            if seen.insert((src.to_string(), dst.clone())) {
                edges.push((
                    src.to_string(),
                    dst,
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
        }
    };

    // Index every locked `name@version` node for bare-name dep
    // resolution.
    let mut index = VerIndex::default();
    for section in ["npm", "jsr"] {
        if let Some(obj) = v[section].as_object() {
            for key in obj.keys() {
                let (n, ver) = deno_split_key(key);
                if !ver.is_empty() {
                    index.add(&nv(&n, &ver));
                }
            }
        }
    }

    // npm/jsr packages: node declarations + dependencies edges.
    for section in ["npm", "jsr"] {
        let Some(obj) = v[section].as_object() else { continue };
        for (key, meta) in obj {
            let (n, ver) = deno_split_key(key);
            let node = nv(&n, &ver);
            if node.is_empty() {
                continue;
            }
            nodes.insert(node.clone());
            // Self-loop node declaration for leaf packages.
            if seen.insert((node.clone(), node.clone())) {
                edges.push((
                    node.clone(),
                    node.clone(),
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
            if let Some(deps) = meta["dependencies"].as_array() {
                for d in deps {
                    let Some(spec) = d.as_str() else { continue };
                    let (dn, dver) = deno_dep_spec(spec);
                    let dsts = match dver {
                        Some(dv) => vec![nv(&dn, &dv)],
                        None => index.resolve(&dn, &mut edges, &mut seen),
                    };
                    for dst in dsts {
                        push(&mut edges, &mut seen, &mut nodes, &node, dst);
                    }
                }
            }
        }
    }

    // workspace.dependencies: root specifiers resolved through the
    // `specifiers` map ("npm:chalk@^5" -> "5.6.2").
    let spec_map: std::collections::BTreeMap<String, String> = v["specifiers"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, val)| (k.clone(), val.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();
    if let Some(deps) = v["workspace"]["dependencies"].as_array() {
        for d in deps {
            let Some(spec) = d.as_str() else { continue };
            // specifier -> resolved version via specifiers map.
            let resolved = spec_map.get(spec).cloned();
            // Name is everything before the last '@' (ranges like
            // ^5.6.2 follow it); protocol prefixes stripped.
            let bare = spec
                .strip_prefix("npm:")
                .or_else(|| spec.strip_prefix("jsr:"))
                .unwrap_or(spec);
            let n = match bare.rsplit_once('@') {
                Some((n, _)) if !n.is_empty() => n,
                _ => bare,
            };
            let mut ver = resolved.unwrap_or_default();
            if ver.is_empty() {
                // No specifier entry: use the spec's own version
                // part when it is an exact pin.
                if let Some((_, v)) = bare.rsplit_once('@') {
                    if v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        ver = v.to_string();
                    }
                }
            }
            // spec_map values can carry peer suffixes too.
            let ver = ver.split('_').next().unwrap_or("").to_string();
            let dst = nv(n, &ver);
            push(&mut edges, &mut seen, &mut nodes, FLAT_SRC, dst);
        }
    }

    // remote entries stay flat nodes; remote URLs also yield
    // normalized name@version nodes. workspace.members keys are
    // local paths, emitted as flat nodes too.
    for section in ["remote", "workspace"] {
        let Some(obj) = v[section].as_object() else { continue };
        let entries: Vec<&String> = if section == "workspace" {
            obj.get("members")
                .and_then(|m| m.as_object())
                .map(|m| m.keys().collect())
                .unwrap_or_default()
        } else {
            obj.keys().collect()
        };
        for key in entries {
                if nodes.insert(key.clone()) {
                    if seen.insert((FLAT_SRC.to_string(), key.clone())) {
                        edges.push((
                            FLAT_SRC.to_string(),
                            key.clone(),
                            None,
                            strand_core::EdgeKind::Static,
                        ));
                    }
                }
                if let Some(n) = deno_url_node(key) {
                    push(&mut edges, &mut seen, &mut nodes, FLAT_SRC, n);
                }
        }
    }

    if edges.is_empty() {
        return Err(err("deno.lock: no locked specifiers found"));
    }
    // Emit node declarations for every collected node that has no
    // edges yet (flat remote/workspace entries).
    for n in nodes {
        if seen.insert((n.clone(), n.clone())) {
            edges.push((n.clone(), n.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    Ok(edges)
}

// ---------- conan.lock ----------

/// Parse `conan.lock` (JSON `graph_lock`). `nodes` map id ->
/// `{ref, requires: [ids]}`; emit `ref -> ref` edges so the full
/// transitive graph resolves.
pub fn conan_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("conan.lock: {e}")))?;
    let nodes = &v["graph_lock"]["nodes"];
    let Some(nodes) = nodes.as_object() else {
        return Err(err("conan.lock: no graph_lock.nodes"));
    };
    // id -> ref
    let mut refs: BTreeMap<String, String> = BTreeMap::new();
    for (id, n) in nodes {
        if let Some(r) = n["ref"].as_str() {
            refs.insert(id.clone(), r.to_string());
        }
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (id, n) in nodes {
        let Some(src) = refs.get(id) else { continue };
        if let Some(reqs) = n["requires"].as_array() {
            for r in reqs {
                let Some(rid) = r.as_str() else { continue };
                let Some(dst) = refs.get(rid) else { continue };
                if seen.insert((src.clone(), dst.clone())) {
                    edges.push((src.clone(), dst.clone(), None, strand_core::EdgeKind::Static));
                }
            }
        }
        // Node declaration for leaf/root packages.
        if seen.insert((src.clone(), src.clone())) {
            edges.push((src.clone(), src.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    if edges.is_empty() {
        return Err(err("conan.lock: no nodes found"));
    }
    Ok(edges)
}

// ---------- gradle/verification-metadata.xml ----------

/// Parse `gradle/verification-metadata.xml`: `<component
/// group=".." name=".." version="..">` entries are the fully
/// resolved dependency set (no relations recorded). Nodes
/// `group:name@version` hang off [`FLAT_SRC`].
pub fn gradle_verification(text: &str) -> Result<EdgeList> {
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rest = text;
    while let Some(i) = rest.find("<component") {
        let after = &rest[i..];
        if after["<component".len()..]
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
        if let (Some(g), Some(n), Some(ver)) =
            (get("group"), get("name"), get("version"))
        {
            let id = format!("{g}:{n}");
            let node = nv(&id, &ver);
            if seen.insert(node.clone()) {
                edges.push((
                    FLAT_SRC.to_string(),
                    node,
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
        }
        rest = &after[gt + 1..];
    }
    if edges.is_empty() {
        return Err(err("verification-metadata.xml: no components found"));
    }
    Ok(edges)
}

// ---------- flake.lock ----------

/// Parse `flake.lock` (JSON). `nodes` keys are flake input names;
/// each node's `locked` object carries `owner`/`repo`/`rev`/`narHash`
/// or a `path`/`tarball`/`git`/`github`/`gitlab`/`sourcehut` source.
/// Emit `input -> source-ref` edges: the flake's declared inputs
/// resolved to their pinned sources.
pub fn flake_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("flake.lock: {e}")))?;
    let nodes = &v["nodes"];
    let Some(nodes) = nodes.as_object() else {
        return Err(err("flake.lock: no nodes"));
    };
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (name, node) in nodes {
        // Root node has no locked source; skip it.
        let locked = &node["locked"];
        if locked.is_null() {
            continue;
        }
        // Source ref: prefer owner/repo, else type-specific fields.
        let mut dst = String::new();
        if let (Some(o), Some(r)) = (
            locked["owner"].as_str(),
            locked["repo"].as_str(),
        ) {
            dst = format!("{o}/{r}");
        } else if let Some(t) = locked["type"].as_str() {
            dst = t.to_string();
            for k in ["owner", "repo", "rev", "ref", "path", "url"] {
                if let Some(val) = locked[k].as_str() {
                    dst = format!("{dst}:{val}");
                }
            }
        }
        if dst.is_empty() {
            dst = locked.to_string();
        }
        if seen.insert((name.clone(), dst.clone())) {
            edges.push((name.clone(), dst, None, strand_core::EdgeKind::Static));
        }
    }
    if edges.is_empty() {
        return Err(err("flake.lock: no locked inputs"));
    }
    Ok(edges)
}
  

// ---------- bun.lockb (binary, format v2) ----------

fn rd_u32(b: &[u8], p: &mut usize) -> Result<u32> {
    let s = b
        .get(*p..*p + 4)
        .ok_or_else(|| err("bun.lockb: truncated u32"))?;
    *p += 4;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], p: &mut usize) -> Result<u64> {
    let s = b
        .get(*p..*p + 8)
        .ok_or_else(|| err("bun.lockb: truncated u64"))?;
    *p += 8;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

/// Decode an 8-byte string reference: inline NUL-terminated ASCII
/// when the high bit of byte 7 is clear, otherwise (offset, len)
/// into the `string_bytes` buffer with the high bit set on len.
fn lockb_str(r: &[u8], string_bytes: &[u8]) -> Result<String> {
    if r.len() < 8 {
        return Err(err("bun.lockb: short string ref"));
    }
    if r[7] & 0x80 == 0 {
        let end = r.iter().position(|&c| c == 0).unwrap_or(r.len());
        Ok(String::from_utf8_lossy(&r[..end]).into_owned())
    } else {
        let off = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize;
        let len = (u32::from_le_bytes([r[4], r[5], r[6], r[7]]) & 0x7fff_ffff) as usize;
        let s = string_bytes
            .get(off..off.saturating_add(len))
            .ok_or_else(|| err("bun.lockb: string ref out of range"))?;
        Ok(String::from_utf8_lossy(s).into_owned())
    }
}

/// Decode a 64-byte resolution record into a version/source string.
/// npm resolutions carry major/minor/patch u32s plus pre/build
/// string refs; string kinds (folder, tarball, workspace, symlink,
/// single-file) carry one string ref; git kinds carry
/// owner/repo/commitish/resolved string refs.
fn lockb_resolution(res: &[u8], string_bytes: &[u8]) -> Result<String> {
    if res.len() < 64 {
        return Err(err("bun.lockb: short resolution"));
    }
    match res[0] {
        // npm: url string @8 (skipped), version u32s @16/20/24,
        // pad @28, pre str @32, build str @48.
        2 => {
            let u32at = |o: usize| -> Result<u32> {
                let s = res
                    .get(o..o + 4)
                    .ok_or_else(|| err("bun.lockb: short resolution"))?;
                Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            };
            let (major, minor, patch) = (u32at(16)?, u32at(20)?, u32at(24)?);
            let pre = lockb_str(&res[32..40], string_bytes)?;
            let build = lockb_str(&res[48..56], string_bytes)?;
            let mut v = format!("{major}.{minor}.{patch}");
            if !pre.is_empty() {
                v.push('-');
                v.push_str(&pre);
            }
            if !build.is_empty() {
                v.push('+');
                v.push_str(&build);
            }
            Ok(v)
        }
        // folder=4, local_tarball=8, github=16, gitlab=24, git=32,
        // symlink=64, workspace=72, remote_tarball=80,
        // single_file_module=100.
        4 | 8 | 64 | 72 | 80 | 100 => {
            let s = lockb_str(&res[8..16], string_bytes)?;
            Ok(match res[0] {
                72 => format!("workspace:{s}"),
                64 => format!("link:{s}"),
                100 => format!("module:{s}"),
                _ => s,
            })
        }
        16 | 24 | 32 => {
            let owner = lockb_str(&res[8..16], string_bytes)?;
            let repo = lockb_str(&res[16..24], string_bytes)?;
            let commitish = lockb_str(&res[24..32], string_bytes)?;
            let resolved = lockb_str(&res[32..40], string_bytes)?;
            let mut out = match res[0] {
                16 => "github:".to_string(),
                24 => "gitlab:".to_string(),
                _ => "git+".to_string(),
            };
            if !owner.is_empty() {
                out.push_str(&owner);
                out.push('/');
            }
            out.push_str(&repo);
            let sha = if !resolved.is_empty() { &resolved } else { &commitish };
            if !sha.is_empty() {
                out.push('#');
                out.push_str(sha);
            }
            Ok(out)
        }
        // root=1, uninitialized=0: no version info.
        _ => Ok(String::new()),
    }
}

/// Parse `bun.lockb` (Bun's binary lockfile, format v2). The file
/// is a columnar package table plus string table; each package's
/// dependency records resolve through a global `resolutions` u32
/// array to package indices, so real transitive edges are emitted.
/// Root (index 0) deps hang off `package.json`, matching the text
/// `bun.lock` workspace convention.
pub fn bun_lockb(bytes: &[u8]) -> Result<EdgeList> {
    const HEADER: &[u8] = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n";
    if !bytes.starts_with(HEADER) {
        return Err(err("bun.lockb: missing header magic"));
    }
    let mut pos = HEADER.len();
    let format = rd_u32(bytes, &mut pos)?;
    if format != 2 {
        return Err(err(format!(
            "bun.lockb: unsupported format version {format}"
        )));
    }
    pos += 32; // meta hash
    let _end = rd_u64(bytes, &mut pos)?;
    let list_len = rd_u64(bytes, &mut pos)? as usize;
    let align = rd_u64(bytes, &mut pos)?;
    let field_count = rd_u64(bytes, &mut pos)?;
    let begin_at = rd_u64(bytes, &mut pos)? as usize;
    let end_at = rd_u64(bytes, &mut pos)? as usize;
    if align != 8 || field_count != 8 {
        return Err(err("bun.lockb: unexpected table shape"));
    }
    if list_len == 0
        || list_len > 1_000_000
        || begin_at >= end_at
        || end_at > bytes.len()
    {
        return Err(err("bun.lockb: invalid package table range"));
    }

    // Column layout: 8 fields of fixed per-item sizes in order
    // name(8), name_hash(8), resolution(64), dependencies(8),
    // resolutions(8), meta(88), bin(20), scripts(48).
    const SIZES: [usize; 8] = [8, 8, 64, 8, 8, 88, 20, 48];
    let mut col: [usize; 8] = [0; 8];
    let mut off = begin_at;
    for (f, &sz) in SIZES.iter().enumerate() {
        col[f] = off;
        off += sz * list_len;
    }
    if off > end_at {
        return Err(err("bun.lockb: package table overlaps buffers"));
    }
    let item = |f: usize, i: usize, n: usize| -> Result<&[u8]> {
        bytes
            .get(col[f] + i * SIZES[f]..col[f] + i * SIZES[f] + n)
            .ok_or_else(|| err("bun.lockb: package table out of range"))
    };

    // Six buffers follow the table, each described by absolute
    // (start, end) u64 offsets: trees, hoisted_dependencies,
    // resolutions(u32[]), dependencies(26B records), extern_strings,
    // string_bytes.
    let mut bpos = end_at;
    let mut bufs: Vec<&[u8]> = Vec::with_capacity(6);
    for _ in 0..6 {
        let s = rd_u64(bytes, &mut bpos)? as usize;
        let e = rd_u64(bytes, &mut bpos)? as usize;
        bufs.push(
            bytes
                .get(s..e)
                .ok_or_else(|| err("bun.lockb: buffer out of range"))?,
        );
    }
    let res_buf = bufs[2];
    // bufs[3] is the dependency record table; record k's target is
    // resolutions[k], so the records themselves are not needed.
    let string_bytes = bufs[5];

    let resolutions: Vec<u32> = res_buf
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // Node id per package index.
    let mut nodes: Vec<String> = Vec::with_capacity(list_len);
    for i in 0..list_len {
        let name = lockb_str(item(0, i, 8)?, string_bytes)?;
        let ver = lockb_resolution(item(2, i, 64)?, string_bytes)?;
        nodes.push(nv(&name, &ver));
    }

    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    // Self-loop declarations so leaf packages still appear.
    for n in &nodes {
        if !n.is_empty() && seen.insert((n.clone(), n.clone())) {
            edges.push((n.clone(), n.clone(), None, strand_core::EdgeKind::Static));
        }
    }

    // Dependency records: package i's `dependencies` field is
    // (start record, count); record k resolves to package index
    // resolutions[k]. Record layout: name str(8) + name_hash(8) +
    // behavior(1) + tag(1) + literal str(8) = 26 bytes.
    for i in 0..list_len {
        if nodes[i].is_empty() {
            continue;
        }
        let src = if i == 0 {
            "package.json".to_string()
        } else {
            nodes[i].clone()
        };
        let f = item(3, i, 8)?;
        let start = u32::from_le_bytes([f[0], f[1], f[2], f[3]]) as usize;
        let count = u32::from_le_bytes([f[4], f[5], f[6], f[7]]) as usize;
        for j in 0..count {
            let k = start + j;
            let Some(&dst_idx) = resolutions.get(k) else { break };
            let dst_idx = dst_idx as usize;
            if dst_idx == 0 || dst_idx >= list_len || dst_idx == i {
                continue;
            }
            let dst = &nodes[dst_idx];
            if dst.is_empty() {
                continue;
            }
            if seen.insert((src.clone(), dst.clone())) {
                edges.push((
                    src.clone(),
                    dst.clone(),
                    None,
                    strand_core::EdgeKind::Static,
                ));
            }
        }
    }
    if edges.is_empty() {
        return Err(err("bun.lockb: no packages found"));
    }
    Ok(edges)
}

// ---------- gradle.lockfile ----------

/// Parse `gradle.lockfile`: one `group:name:version=config,...`
/// coordinate per line (the part before `=` is the coordinate).
/// Flat node list `group:name@version`, same shape as
/// verification-metadata components.
pub fn gradle_lockfile(text: &str) -> Result<EdgeList> {
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let coord = t.split('=').next().unwrap_or(t).trim();
        let parts: Vec<&str> = coord.split(':').collect();
        if parts.len() != 3 {
            continue;
        }
        let (g, a, v) = (parts[0], parts[1], parts[2]);
        if g.is_empty() || a.is_empty() || v.is_empty() {
            continue;
        }
        let node = nv(&format!("{g}:{a}"), v);
        if seen.insert(node.clone()) {
            edges.push((
                FLAT_SRC.to_string(),
                node,
                None,
                strand_core::EdgeKind::Static,
            ));
        }
    }
    if edges.is_empty() {
        return Err(err("gradle.lockfile: no coordinates"));
    }
    Ok(edges)
}

// ---------- gradle module cache (.module / .pom) ----------

/// Extract `(group, module, version)` dependency triples from a
/// Gradle Module Metadata `.module` file (JSON). Every variant's
/// `dependencies` array contributes; `version.requires` wins over
/// `prefers`, empty when neither is present.
pub fn gradle_module_deps(text: &str) -> Vec<(String, String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let Some(variants) = v["variants"].as_array() else {
        return out;
    };
    for var in variants {
        let Some(deps) = var["dependencies"].as_array() else {
            continue;
        };
        for d in deps {
            let (Some(g), Some(m)) = (
                d["group"].as_str(),
                d["module"].as_str(),
            ) else {
                continue;
            };
            let ver = d["version"]["requires"]
                .as_str()
                .or_else(|| d["version"]["prefers"].as_str())
                .unwrap_or("")
                .to_string();
            if seen.insert((g.to_string(), m.to_string(), ver.clone())) {
                out.push((g.to_string(), m.to_string(), ver));
            }
        }
    }
    out
}

/// Extract `(group, artifact, version)` dependency triples from a
/// `.pom` file: `<dependencies>` blocks minus dependencyManagement
/// and build sections; `import`-scoped BOM entries skipped.
pub fn pom_deps(text: &str) -> Vec<(String, String, String)> {
    let no_parent = strip_section(text, "parent");
    let clean = strip_section(
        &strip_section(&no_parent, "dependencyManagement"),
        "build",
    );
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    for block in xml_blocks(&clean, "dependencies") {
        for dep in xml_blocks(&block, "dependency") {
            let scope = first_tag_text(&dep, "scope").unwrap_or_default();
            if scope == "import" || scope == "test" {
                continue;
            }
            let (Some(g), Some(a)) = (
                first_tag_text(&dep, "groupId"),
                first_tag_text(&dep, "artifactId"),
            ) else {
                continue;
            };
            let v = first_tag_text(&dep, "version").unwrap_or_default();
            if seen.insert((g.clone(), a.clone(), v.clone())) {
                out.push((g, a, v));
            }
        }
    }
    out
}

// ---------- pdm.lock ----------

/// PEP 503-style name normalization for index lookups.
fn norm_dep_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect()
}

/// Extract the package name from a PEP 508-ish requirement string:
/// `name[extra] (>=1.0); marker` -> `name`. Direct references
/// (`name @ url`) return None.
fn pep508_name(req: &str) -> Option<String> {
    let req = req.split(';').next().unwrap_or(req).trim();
    // `name @ https://...` direct reference - skip.
    if let Some(at) = req.find('@') {
        let before = req[..at].trim_end();
        if before
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '[' | ']'))
            && req[at + 1..].trim_start().starts_with("http")
        {
            return None;
        }
    }
    let mut end = 0;
    for (i, c) in req.char_indices() {
        if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '[' | ']') {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    let name = req[..end]
        .split('[')
        .next()
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(norm_dep_name(name))
    }
}

/// `pdm.lock` (TOML): `[[package]]` entries with `name`, `version`,
/// and `dependencies = ["req; marker", ...]` - real edges.
pub fn pdm_lock(text: &str) -> Result<EdgeList> {
    let doc: toml::Table =
        toml::from_str(text).map_err(|e| err(format!("pdm.lock: {e}")))?;
    let mut index = VerIndex::default();
    let mut pkgs: Vec<(String, String, Vec<String>)> = Vec::new();
    if let Some(arr) = doc.get("package").and_then(|p| p.as_array()) {
        for p in arr {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let ver = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let node = nv(&norm_dep_name(name), ver);
            index.add(&node);
            let deps = p
                .get("dependencies")
                .and_then(|d| d.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            pkgs.push((node, name.to_string(), deps));
        }
    }
    if pkgs.is_empty() {
        return Err(err("pdm.lock: no packages found"));
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (node, raw_name, deps) in &pkgs {
        for d in deps {
            let Some(dep) = pep508_name(d) else { continue };
            if dep == norm_dep_name(raw_name) {
                continue; // extras self-reference
            }
            for dst in index.resolve(&dep, &mut edges, &mut seen) {
                if seen.insert((node.clone(), dst.clone())) {
                    edges.push((node.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
        if seen.insert((node.clone(), node.clone())) {
            edges.push((node.clone(), node.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    Ok(edges)
}

// ---------- conda-lock.yml ----------

/// `conda-lock.yml`: top-level `package:` sequence; each entry has
/// `name`, `version`, `manager` and a `dependencies:` map of
/// `name: constraint`. Constraint values are ranges, not pins, so
/// dep names resolve through the lock's own name index.
pub fn conda_lock(text: &str) -> Result<EdgeList> {
    let doc: serde_yml::Value =
        serde_yml::from_str(text).map_err(|e| err(format!("conda-lock.yml: {e}")))?;
    let mut index = VerIndex::default();
    let mut pkgs: Vec<(String, Vec<String>)> = Vec::new();
    let push_pkg = |index: &mut VerIndex,
                        pkgs: &mut Vec<(String, Vec<String>)>,
                        p: &serde_yml::Value| {
        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let ver = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return;
        }
        let node = nv(name, ver);
        index.add(&node);
        let deps: Vec<String> = p
            .get("dependencies")
            .map(|d| match d {
                serde_yml::Value::Mapping(m) => m
                    .keys()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect(),
                serde_yml::Value::Sequence(s) => s
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        pkgs.push((node, deps));
    };
    // `package:` may be a sequence (v1 unified) or a map keyed by
    // name (older per-platform style).
    match doc.get("package") {
        Some(serde_yml::Value::Sequence(seq)) => {
            for p in seq {
                push_pkg(&mut index, &mut pkgs, p);
            }
        }
        Some(serde_yml::Value::Mapping(map)) => {
            for (name, entries) in map {
                let Some(n) = name.as_str() else { continue };
                if n.is_empty() {
                    continue;
                }
                if let Some(seq) = entries.as_sequence() {
                    for e in seq {
                        let ver = e.get("version").and_then(|v| v.as_str()).unwrap_or("");
                        let node = nv(n, ver);
                        index.add(&node);
                        let deps: Vec<String> = e
                            .get("dependencies")
                            .map(|d| match d {
                                serde_yml::Value::Mapping(m) => m
                                    .keys()
                                    .filter_map(|k| k.as_str().map(String::from))
                                    .collect(),
                                _ => Vec::new(),
                            })
                            .unwrap_or_default();
                        pkgs.push((node, deps));
                    }
                }
            }
        }
        _ => {}
    }
    if pkgs.is_empty() {
        return Err(err("conda-lock.yml: no packages found"));
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (node, deps) in &pkgs {
        for d in deps {
            let dep = norm_dep_name(d);
            for dst in index.resolve(&dep, &mut edges, &mut seen) {
                if seen.insert((node.clone(), dst.clone())) {
                    edges.push((node.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
        if seen.insert((node.clone(), node.clone())) {
            edges.push((node.clone(), node.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    Ok(edges)
}

// ---------- Julia Manifest.toml ----------

/// `Manifest.toml` (Julia): `[deps]` is a table of `Name -> {uuid,
/// version, deps = ["DepName", ...]}`. `deps` entries are bare
/// package names resolved through the manifest's own index.
pub fn julia_manifest(text: &str) -> Result<EdgeList> {
    let doc: toml::Table =
        toml::from_str(text).map_err(|e| err(format!("Manifest.toml: {e}")))?;
    let Some(deps_tbl) = doc.get("deps").and_then(|d| d.as_table()) else {
        return Err(err("Manifest.toml: no [deps] table"));
    };
    let mut index = VerIndex::default();
    let mut pkgs: Vec<(String, Vec<String>)> = Vec::new();
    for (name, entry) in deps_tbl {
        // `[[deps.X]]` yields an array-of-tables; `[deps.X]`
        // yields a plain table. Normalize to the entry table.
        let entry_tbl = entry
            .as_table()
            .or_else(|| entry.as_array().and_then(|a| a.first()).and_then(|v| v.as_table()));
        let Some(entry_tbl) = entry_tbl else { continue };
        let ver = entry_tbl.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let node = nv(name, ver);
        index.add(&node);
        let deps: Vec<String> = entry_tbl
            .get("deps")
            .and_then(|d| d.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        pkgs.push((node, deps));
    }
    if pkgs.is_empty() {
        return Err(err("Manifest.toml: no packages found"));
    }
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (node, deps) in &pkgs {
        for d in deps {
            for dst in index.resolve(d, &mut edges, &mut seen) {
                if seen.insert((node.clone(), dst.clone())) {
                    edges.push((node.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
        if seen.insert((node.clone(), node.clone())) {
            edges.push((node.clone(), node.clone(), None, strand_core::EdgeKind::Static));
        }
    }
    Ok(edges)
}

// ---------- rebar.lock ----------

/// `rebar.lock` (Erlang/rebar3): `{"1.2.0", [{Name,{pkg,Name,Vsn},
/// Level}, ...]}.` - the modern format records pins but no dep
/// edges (the `_build` `.app` probe in caches.rs recovers them).
/// Emits `name@version` nodes; git/hg entries get `name@git:<sha>`
/// or bare `name`.
pub fn rebar_lock(text: &str) -> Result<EdgeList> {
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rest = text;
    while let Some(i) = rest.find("{pkg,") {
        let after = &rest[i + 5..];
        let Some(close) = after.find('}') else { break };
        let inner = &after[..close];
        let mut parts = inner.split(',');
        let unq = |p: &str| -> String {
            p.trim()
                .trim_start_matches("<<")
                .trim_end_matches(">>")
                .trim_matches('"')
                .to_string()
        };
        let name = parts.next().map(unq).filter(|n| !n.is_empty());
        let ver = parts.next().map(unq).filter(|v| !v.is_empty());
        if let Some(n) = name {
            let node = match ver {
                Some(v) => nv(&n, &v),
                None => n.clone(),
            };
            if seen.insert(node.clone()) {
                edges.push((FLAT_SRC.to_string(), node, None, strand_core::EdgeKind::Static));
            }
        }
        rest = &rest[i + close + 1..];
    }
    // Git/hg-sourced entries: {Name,{git,"url",{ref,"sha"}},Lvl}
    // and {Name,{git_subdir,...}} - emit name@git:<sha> nodes.
    let mut rest = text;
    while let Some(i) = rest.find("{git") {
        let before = &rest[..i];
        let name = before.rfind("<<\"").and_then(|s| {
            let inner = &before[s + 3..];
            inner.find("\">>").map(|e| inner[..e].to_string())
        });
        let after = &rest[i..];
        let sha = after.find("{ref,").and_then(|r| {
            let seg = &after[r + 5..];
            seg.find('"').and_then(|q1| {
                seg[q1 + 1..]
                    .find('"')
                    .map(|q2| seg[q1 + 1..q1 + 1 + q2].to_string())
            })
        });
        if let Some(n) = name {
            let node = match sha {
                Some(s) if !s.is_empty() => format!("{n}@git:{s}"),
                _ => n.clone(),
            };
            if seen.insert(node.clone()) {
                edges.push((FLAT_SRC.to_string(), node, None, strand_core::EdgeKind::Static));
            }
        }
        rest = &rest[i + 4..];
    }
    if edges.is_empty() {
        return Err(err("rebar.lock: no packages found"));
    }
    Ok(edges)
}

// ---------- renv.lock (R) ----------

/// `renv.lock` (JSON): `Packages` maps name -> {Version, Source}.
/// Flat inventory of pinned R packages.
pub fn renv_lock(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("renv.lock: {e}")))?;
    let mut edges: EdgeList = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if let Some(pkgs) = v.get("Packages").and_then(|p| p.as_object()) {
        for (name, meta) in pkgs {
            let ver = meta.get("Version").and_then(|x| x.as_str()).unwrap_or("");
            let node = nv(name, ver);
            if seen.insert(node.clone()) {
                edges.push((FLAT_SRC.to_string(), node, None, strand_core::EdgeKind::Static));
            }
        }
    }
    if edges.is_empty() {
        return Err(err("renv.lock: no packages found"));
    }
    Ok(edges)
}
