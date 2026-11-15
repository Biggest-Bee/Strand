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

/// Extract the first whitespace-separated token of each `"..."` string
/// in a TOML-ish array fragment like `"a", "b 1.0 (src)",`.
fn quoted_first_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '"' {
            let mut tok = String::new();
            for c in it.by_ref() {
                if c == '"' {
                    break;
                }
                tok.push(c);
            }
            if let Some(name) = tok.split_whitespace().next() {
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

fn push_edge(edges: &mut EdgeList, src: &str, dst: String) {
    if dst != src {
        edges.push((src.to_string(), dst, None));
    }
}

// ---------- Cargo.lock ----------

/// Parse `Cargo.lock`. `[[package]]` blocks carry `name = "..."` and a
/// possibly multi-line `dependencies = [ "dep", "dep ver (src)", ... ]`.
pub fn cargo_lock(text: &str) -> Result<EdgeList> {
    let mut edges = EdgeList::new();
    let mut cur: Option<String> = None;
    let mut dep_buf: Option<String> = None;

    for line in text.lines() {
        let t = line.trim();
        if let Some(buf) = dep_buf.as_mut() {
            buf.push(' ');
            buf.push_str(t);
            if t.contains(']') {
                if let Some(src) = &cur {
                    for dep in quoted_first_tokens(buf) {
                        push_edge(&mut edges, src, dep);
                    }
                }
                dep_buf = None;
            }
            continue;
        }
        if t == "[[package]]" {
            cur = None;
            continue;
        }
        if t.starts_with('[') {
            continue; // any other section header
        }
        if let Some((key, val)) = t.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            match key {
                "name" => cur = Some(unquote(val)),
                "dependencies" if val.starts_with('[') => {
                    if val.contains(']') {
                        if let Some(src) = &cur {
                            for dep in quoted_first_tokens(val) {
                                push_edge(&mut edges, src, dep);
                            }
                        }
                    } else {
                        dep_buf = Some(val.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(edges)
}

// ---------- poetry.lock ----------

/// Parse `poetry.lock`. `[[package]]` blocks have `[package.dependencies]`
/// and `[package.dev-dependencies]` tables of `name = constraint` lines.
pub fn poetry_lock(text: &str) -> Result<EdgeList> {
    let mut edges = EdgeList::new();
    let mut cur: Option<String> = None;
    // None = not in a dep table; Some(true) = deps, Some(false) = dev-deps
    // (both treated the same; the flag exists only for clarity).
    let mut in_deps = false;
    let mut depth = 0i32; // {} [] nesting inside a dep value

    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            cur = None;
            in_deps = false;
            depth = 0;
            continue;
        }
        if t.starts_with('[') {
            in_deps = matches!(
                t,
                "[package.dependencies]" | "[package.dev-dependencies]"
            );
            depth = 0;
            continue;
        }
        if let Some((key, _)) = t.split_once('=') {
            if key.trim() == "name" && cur.is_none() && !in_deps {
                // Only the package's own `name`, not table keys.
                if let Some((k, v)) = t.split_once('=') {
                    if k.trim() == "name" {
                        cur = Some(unquote(v.trim()));
                        continue;
                    }
                }
            }
        }
        if !in_deps {
            continue;
        }
        // In a dep table: `name = "^1.0"` or `name = {version = "...", ...}`
        // possibly spanning lines. A `key =` at brace depth 0 starts a
        // dep; continuation lines (depth > 0) are part of its value.
        if depth == 0 {
            if let Some((key, _)) = t.split_once('=') {
                let dep = unquote(key.trim());
                if dep != "python" {
                    if let Some(src) = &cur {
                        push_edge(&mut edges, src, dep);
                    }
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
    Ok(edges)
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
    // section — searching the whole doc would hit a dependency's
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
            let g = first_tag_text(&dep, "groupId")
                .or_else(|| Some(proj_group.clone()));
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
        let Some(gt) = after_open.find('>') else { break };
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
        Err(err("package-lock.json: neither 'packages' nor 'dependencies' found"))
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
    // would collide under a bare name — disambiguate as `name@version`.
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
