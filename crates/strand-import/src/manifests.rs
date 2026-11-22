//! Manifest dependency scanner: extracts declared dependencies from
//! project config files so the graph covers external packages, not
//! just intra-project source edges.
//!
//! Covered manifests:
//! - Python: `requirements*.txt`, `pyproject.toml` ([project] +
//!   [dependency-groups] + [tool.poetry]), `Pipfile`, `setup.cfg`,
//!   `environment.yml`/`environment.yaml` (conda)
//! - JS/TS: `package.json` (deps/dev/peer/optional)
//! - Rust: `Cargo.toml` ([dependencies], [dev-dependencies],
//!   [build-dependencies], `[target.*]` variants)
//! - PHP: `composer.json` (require/require-dev)
//! - Ruby: `Gemfile` (gem declarations)
//! - Dart/Flutter: `pubspec.yaml` (dependencies/dev_dependencies)
//! - Swift: `Package.swift` (.package(url:))
//! - .NET: `*.csproj` + `Directory.Packages.props` (PackageReference/
//!   PackageVersion)
//! - JVM: `*.gradle`/`*.gradle.kts` (quoted `group:artifact:version`)
//! - iOS: `Podfile` (pod declarations)
//! - Config: `.github/workflows/*.yml` `uses:` actions,
//!   `Dockerfile` `FROM` images
//!
//! Edges are `manifest_rel_path -> dep_name` with
//! [`strand_core::EdgeKind::Declared`] - explicitly declared by config.
//! Dep names are normalized per ecosystem (PyPI names to PEP 503,
//! npm/cargo names as written).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scan::{ScanOutput, walk_files};
use crate::EdgeList;
use strand_core::EdgeKind;

/// Scan `root` for manifest files and emit `manifest -> dep` edges.
pub fn scan_manifests(root: &Path) -> Result<ScanOutput, crate::Error> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_files(root, root, &mut |rel, abs| {
        let name = abs
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let parent = abs
            .parent()
            .map(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
            .flatten()
            .unwrap_or_default();
        let norm_rel = rel.replace('\\', "/").to_lowercase();
        let hit = matches!(
            name.as_str(),
            "pyproject.toml"
                | "pipfile"
                | "setup.cfg"
                | "package.json"
                | "cargo.toml"
                | "environment.yml"
                | "environment.yaml"
                | "composer.json"
                | "gemfile"
                | "pubspec.yaml"
                | "podfile"
                | "package.swift"
                | "dockerfile"
                | "directory.packages.props"
        ) || name.ends_with(".csproj")
            || name.ends_with(".gradle")
            || name.ends_with(".gradle.kts")
            || name.ends_with(".dockerfile")
            || (name.starts_with("requirements") && name.ends_with(".txt"))
            || (parent == "requirements" && name.ends_with(".txt"))
            || (norm_rel.starts_with(".github/workflows/") || norm_rel.contains("/.github/workflows/")
                && (name.ends_with(".yml") || name.ends_with(".yaml")));
        if hit {
            files.push((rel, abs));
        }
    });
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut edges: EdgeList = Vec::new();
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut warnings = Vec::new();

    for (rel, abs) in &files {
        let text = match fs::read_to_string(abs) {
            Ok(t) => t,
            Err(e) => {
                warnings.push(format!("{rel}: {e}"));
                continue;
            }
        };
        let name = abs
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let rel_norm = rel.replace('\\', "/").to_lowercase();
        let deps = if name == "pyproject.toml" {
            pyproject_deps(&text)
        } else if name == "pipfile" {
            pipfile_deps(&text)
        } else if name == "setup.cfg" {
            setup_cfg_deps(&text)
        } else if name == "package.json" {
            package_json_deps(&text)
        } else if name == "cargo.toml" {
            cargo_toml_deps(&text)
        } else if name == "environment.yml" || name == "environment.yaml" {
            conda_env_deps(&text)
        } else if name == "composer.json" {
            composer_deps(&text)
        } else if name == "gemfile" {
            gemfile_deps(&text)
        } else if name == "pubspec.yaml" {
            pubspec_deps(&text)
        } else if name == "podfile" {
            podfile_deps(&text)
        } else if name == "package.swift" {
            package_swift_deps(&text)
        } else if name.ends_with(".csproj") || name == "directory.packages.props" {
            nuget_manifest_deps(&text)
        } else if name.ends_with(".gradle") || name.ends_with(".gradle.kts") {
            gradle_deps(&text)
        } else if rel_norm.starts_with(".github/workflows/") || rel_norm.contains("/.github/workflows/") {
            workflow_deps(&text)
        } else if name == "dockerfile" || name.ends_with(".dockerfile") {
            dockerfile_deps(&text)
        } else {
            requirements_deps(&text, abs, root, 0)
        };
        nodes.insert(rel.clone());
        for dep in deps {
            if dep.is_empty() || dep == rel.as_str() {
                continue;
            }
            edges.push((rel.clone(), dep.clone(), None, EdgeKind::Declared));
            nodes.insert(dep);
        }
    }

    edges.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    edges.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    Ok(ScanOutput {
        edges,
        nodes: nodes.into_iter().collect(),
        warnings,
    })
}

// ---------- Python ----------

/// PEP 508 / PEP 503 name extraction: leading name token, normalized
/// to lowercase with `-_.` runs collapsed to `-`.
fn pep503_name(spec: &str) -> Option<String> {
    let s = spec.trim();
    // Blank, comment, or option lines (-r, -i, --index-url, ...) are
    // not deps. `-e` editable lines are handled by the caller.
    if s.is_empty() || s.starts_with('#') || s.starts_with('-') {
        return None;
    }
    // Strip environment marker and direct-reference URL.
    let s = s.split(';').next().unwrap_or("").trim();
    let s = s.split('@').next().unwrap_or("").trim();
    // Name ends at first version specifier, bracket, or whitespace.
    let end = s
        .find(|c: char| c == '[' || c == '<' || c == '>' || c == '=' || c == '!' || c == '~' || c == '^' || c == ' ')
        .unwrap_or(s.len());
    let name = &s[..end];
    if name.is_empty() {
        return None;
    }
    // PEP 503 normalize.
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_dash && !out.is_empty() {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `requirements*.txt`: one dep per line; `#` comments, `\` continuations,
/// `-r`/`--requirement` includes resolved relative to the file.
fn requirements_deps(text: &str, abs: &Path, root: &Path, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    if depth > 4 {
        return out;
    }
    let mut logical = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = if let Some(prev) = logical.strip_suffix('\\') {
            format!("{}{}", prev.trim_end(), line)
        } else {
            std::mem::take(&mut logical);
            line.to_string()
        };
        if line.ends_with('\\') {
            logical = line;
            continue;
        }
        let line = line.trim();
        if line.starts_with("-r") || line.starts_with("--requirement") {
            let path = line
                .split_whitespace()
                .nth(1)
                .or_else(|| line.split('=').nth(1));
            if let Some(p) = path {
                let inc = abs.parent().unwrap_or(root).join(p);
                if let Ok(t) = fs::read_to_string(&inc) {
                    out.extend(requirements_deps(&t, &inc, root, depth + 1));
                }
            }
            continue;
        }
        let editable = line == "-e"
            || line.starts_with("-e ")
            || line == "--editable"
            || line.starts_with("--editable ")
            || line.starts_with("--editable=");
        if editable {
            let rest = line
                .strip_prefix("-e")
                .or_else(|| line.strip_prefix("--editable"))
                .unwrap_or("")
                .trim()
                .trim_start_matches('=');
            // Editable: prefer #egg=fragment, else path basename.
            if let Some(egg) = rest.split("#egg=").nth(1).and_then(|e| e.split('&').next()) {
                if let Some(n) = pep503_name(egg) {
                    out.push(n);
                }
            } else {
                let p = rest.trim().trim_start_matches(['.', '/']).trim_end_matches('/');
                if let Some(n) = p.rsplit('/').next() {
                    if !n.is_empty() {
                        out.push(n.to_lowercase());
                    }
                }
            }
            continue;
        }
        if let Some(n) = pep503_name(line) {
            out.push(n);
        }
    }
    out
}

/// `pyproject.toml`: PEP 621 `[project]` deps + optional-deps +
/// `[dependency-groups]`, plus Poetry `[tool.poetry]` tables.
fn pyproject_deps(text: &str) -> Vec<String> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    let dep_list = |v: Option<&toml::Value>, out: &mut Vec<String>| {
        if let Some(arr) = v.and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if let Some(n) = pep503_name(s) {
                        out.push(n);
                    }
                }
            }
        }
    };
    let dep_table = |v: Option<&toml::Value>, out: &mut Vec<String>| {
        if let Some(tbl) = v.and_then(|v| v.as_table()) {
            for (k, _) in tbl {
                if k != "python" {
                    if let Some(n) = pep503_name(k) {
                        out.push(n);
                    }
                }
            }
        }
    };

    if let Some(project) = doc.get("project") {
        dep_list(project.get("dependencies"), &mut out);
        if let Some(opt) = project.get("optional-dependencies").and_then(|v| v.as_table()) {
            for (_, arr) in opt {
                dep_list(Some(arr), &mut out);
            }
        }
    }
    if let Some(groups) = doc.get("dependency-groups").and_then(|v| v.as_table()) {
        for (_, arr) in groups {
            dep_list(Some(arr), &mut out);
        }
    }
    if let Some(poetry) = doc.get("tool").and_then(|t| t.get("poetry")) {
        dep_table(poetry.get("dependencies"), &mut out);
        dep_table(poetry.get("dev-dependencies"), &mut out);
        if let Some(group) = poetry.get("group").and_then(|v| v.as_table()) {
            for (_, g) in group {
                dep_table(g.get("dependencies"), &mut out);
            }
        }
    }
    out
}

/// `Pipfile`: `[packages]` and `[dev-packages]` tables.
fn pipfile_deps(text: &str) -> Vec<String> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["packages", "dev-packages"] {
        if let Some(tbl) = doc.get(section).and_then(|v| v.as_table()) {
            for (k, _) in tbl {
                if let Some(n) = pep503_name(k) {
                    out.push(n);
                }
            }
        }
    }
    out
}

/// `setup.cfg` `[options] install_requires` - inline or indented
/// continuation lines, comma-separated.
fn setup_cfg_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_options = false;
    let mut collecting = false;
    let mut buf = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if collecting {
                flush_cfg_requires(&buf, &mut out);
                buf.clear();
                collecting = false;
            }
            in_options = t == "[options]";
            continue;
        }
        if !in_options {
            continue;
        }
        if collecting {
            if line.starts_with(char::is_whitespace) || t.starts_with('#') {
                if !t.starts_with('#') {
                    buf.push(' ');
                    buf.push_str(t);
                }
                continue;
            }
            flush_cfg_requires(&buf, &mut out);
            buf.clear();
            collecting = false;
        }
        if let Some((k, v)) = t.split_once('=') {
            if k.trim() == "install_requires" {
                collecting = true;
                buf.push_str(v.trim());
            }
        }
    }
    if collecting {
        flush_cfg_requires(&buf, &mut out);
    }
    out
}

fn flush_cfg_requires(buf: &str, out: &mut Vec<String>) {
    for part in buf.split(',') {
        let p = part.trim();
        if p.is_empty() || p.starts_with("file:") {
            continue;
        }
        if let Some(n) = pep503_name(p) {
            out.push(n);
        }
    }
}

/// `environment.yml`/`environment.yaml`: conda `dependencies:` list.
/// Minimal line parser - handles `- name`, `- name=ver`, `- pip:`
/// subsections, `conda-forge::name`, `git+...#egg=name`.
fn conda_env_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut dep_indent = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if !in_deps {
            if t == "dependencies:" || t.starts_with("dependencies:") {
                in_deps = true;
                dep_indent = indent;
            }
            continue;
        }
        // Section ends at a same-or-shallower indent key.
        if indent <= dep_indent && !t.starts_with('-') {
            break;
        }
        let Some(item) = t.strip_prefix("- ").or_else(|| t.strip_prefix('-')) else {
            continue;
        };
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        // `- pip:` introduces a nested pip list; its items are deeper
        // `- pkg` lines handled by the same rule. The marker itself
        // is not a dep.
        if item == "pip:" || item.starts_with("pip:") && item.len() == 4 {
            continue;
        }
        if let Some(rest) = item.strip_prefix("pip:") {
            let _ = rest;
            continue;
        }
        // git/url deps: take #egg= name when present.
        if item.contains("://") {
            if let Some(egg) = item.split("#egg=").nth(1).and_then(|e| e.split('&').next()) {
                if let Some(n) = pep503_name(egg) {
                    out.push(n);
                }
            }
            continue;
        }
        // conda-forge::name=ver -> strip channel prefix.
        let item = item.rsplit("::").next().unwrap_or(item);
        // name=ver / name>=ver / name ver
        let name_part = item
            .split(|c| c == '=' || c == '<' || c == '>' || c == ' ' || c == '!')
            .next()
            .unwrap_or("")
            .trim();
        if name_part.is_empty() {
            continue;
        }
        // Skip interpreter pin - not a package dep.
        if name_part == "python" {
            continue;
        }
        let norm = name_part
            .chars()
            .map(|c| if c == '_' { '-' } else { c })
            .collect::<String>()
            .to_lowercase();
        out.push(norm);
    }
    out
}

// ---------- JS/TS ----------

/// `package.json`: dependencies + dev/peer/optional.
fn package_json_deps(text: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = doc.get(key).and_then(|v| v.as_object()) {
            for (name, _) in obj {
                out.push(name.clone());
            }
        }
    }
    out
}

// ---------- Rust ----------

/// `Cargo.toml`: [dependencies], [dev-dependencies],
/// [build-dependencies], and `[target.<triple>.<kind>]` variants.
/// Table entries use `package = "real-name"` when renamed.
fn cargo_toml_deps(text: &str) -> Vec<String> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let dep_kinds = ["dependencies", "dev-dependencies", "build-dependencies"];
    let collect = |tbl: Option<&toml::value::Table>, out: &mut Vec<String>| {
        let Some(tbl) = tbl else { return };
        for (key, val) in tbl {
            let name = val
                .get("package")
                .and_then(|p| p.as_str())
                .unwrap_or(key);
            out.push(name.to_string());
        }
    };
    for kind in dep_kinds {
        collect(doc.get(kind).and_then(|v| v.as_table()), &mut out);
    }
    if let Some(targets) = doc.get("target").and_then(|v| v.as_table()) {
        for (_, t) in targets {
            for kind in dep_kinds {
                collect(t.get(kind).and_then(|v| v.as_table()), &mut out);
            }
        }
    }
    out
}

// ---------- PHP / Ruby / Dart / Swift / .NET / JVM / iOS / config ----------

/// `composer.json`: `require` + `require-dev` object keys
/// (`vendor/package`).
fn composer_deps(text: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in ["require", "require-dev"] {
        if let Some(obj) = doc.get(key).and_then(|v| v.as_object()) {
            for name in obj.keys() {
                if name != "php" {
                    out.push(name.clone());
                }
            }
        }
    }
    out
}

/// `Gemfile`: `gem 'name'` / `gem "name"` declarations (first quoted
/// arg; version constraints and source options ignored).
fn gemfile_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("gem") else {
            continue;
        };
        let rest = rest.trim_start();
        if !rest.starts_with(['\'', '"']) {
            continue;
        }
        let q = rest.chars().next().unwrap();
        if let Some(end) = rest[1..].find(q) {
            let name = &rest[1..1 + end];
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// `pubspec.yaml`: `dependencies` + `dev_dependencies` map keys.
fn pubspec_deps(text: &str) -> Vec<String> {
    let Ok(doc) = serde_yml::from_str::<serde_yml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["dependencies", "dev_dependencies"] {
        if let Some(tbl) = doc.get(section).and_then(|v| v.as_mapping()) {
            for (k, _) in tbl {
                if let Some(name) = k.as_str() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

/// `Podfile`: `pod 'Name'` / `pod "Name"` declarations.
fn podfile_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("pod") else {
            continue;
        };
        let rest = rest.trim_start();
        if !rest.starts_with(['\'', '"', '(']) {
            continue;
        }
        let rest = rest.trim_start_matches('(').trim_start();
        if let Some(q) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') {
            if let Some(end) = rest[1..].find(q) {
                let name = &rest[1..1 + end];
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

/// `Package.swift`: `.package(url: "https://.../Name.git", ...)` -
/// dep name is the last URL path component minus `.git`.
fn package_swift_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in text.match_indices(".package(") {
        // Scan the call's text for `url:` then a quoted string.
        let rest = &text[m.0 + ".package(".len()..];
        let end = rest.find(')').unwrap_or(rest.len().min(400));
        let call = &rest[..end];
        let Some(u) = call.find("url:") else { continue };
        let after = &call[u + 4..];
        let Some(q) = after.find(['\'', '"']) else { continue };
        let quote = after.as_bytes()[q];
        let inner = &after[q + 1..];
        let Some(close) = inner.find(quote as char) else { continue };
        let url = inner[..close].trim();
        if url.is_empty() || url.starts_with("path:") {
            continue;
        }
        let base = url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".git");
        if !base.is_empty() {
            out.push(base.to_string());
        }
    }
    out
}

/// `*.csproj` / `Directory.Packages.props`: `Include="Id"` on
/// `<PackageReference` / `<PackageVersion` tags.
fn nuget_manifest_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tag in ["PackageReference", "PackageVersion"] {
        let mut rest = text;
        let open = format!("<{tag}");
        while let Some(i) = rest.find(&open) {
            // Tag-name boundary: next char must not be alphanumeric.
            let after = &rest[i..];
            let boundary = after[open.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '-'));
            if !boundary {
                rest = &rest[i + 1..];
                continue;
            }
            let Some(gt) = after.find('>') else { break };
            let attrs = &after[..gt];
            for q in ['"', '\''] {
                let needle = format!("Include={q}");
                if let Some(p) = attrs.find(&needle) {
                    let val = &attrs[p + needle.len()..];
                    if let Some(end) = val.find(q) {
                        let id = val[..end].trim();
                        if !id.is_empty() {
                            out.push(id.to_string());
                        }
                    }
                    break;
                }
            }
            rest = &after[gt + 1..];
        }
    }
    out
}

/// `*.gradle` / `*.gradle.kts`: quoted `group:artifact:version`
/// coordinates on dependency-declaring lines.
fn gradle_deps(text: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "implementation",
        "api(",
        "api ",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testRuntimeOnly",
        "testCompileOnly",
        "kapt",
        "ksp",
        "annotationProcessor",
        "classpath",
        "detektPlugins",
        "libs.",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if !KEYWORDS.iter().any(|k| t.contains(k)) {
            continue;
        }
        // Quoted strings on the line; `g:a:v` coords -> `g:a`.
        let mut rest = t;
        while let Some(q) = rest.find(['\'', '"']) {
            let quote = rest.as_bytes()[q];
            let inner = &rest[q + 1..];
            let Some(end) = inner.find(quote as char) else { break };
            let s = inner[..end].trim();
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() >= 3
                && parts.iter().all(|p| !p.is_empty() && !p.contains(' '))
                && parts[0].chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                out.push(format!("{}:{}", parts[0], parts[1]));
            }
            rest = &inner[end + 1..];
        }
    }
    out
}

/// `.github/workflows/*.yml`: `uses: owner/repo@ref` action deps.
/// Local (`./`) and Docker (`docker://`) refs are skipped.
fn workflow_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim().trim_start_matches('-').trim_start();
        let Some(rest) = t.strip_prefix("uses:") else {
            continue;
        };
        let dep = rest.trim().trim_matches(['"', '\'']);
        if dep.is_empty() || dep.starts_with("./") || dep.starts_with("docker://") {
            continue;
        }
        out.push(dep.to_string());
    }
    out
}

/// `Dockerfile`: `FROM image[:tag][@digest]` base-image deps.
fn dockerfile_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(rest) = t.strip_prefix("FROM") else {
            continue;
        };
        // Instruction must be `FROM ` (word boundary).
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let mut it = rest.split_whitespace();
        let Some(img) = it.next() else { continue };
        if img.eq_ignore_ascii_case("scratch") {
            continue;
        }
        out.push(img.to_string());
    }
    out
}
