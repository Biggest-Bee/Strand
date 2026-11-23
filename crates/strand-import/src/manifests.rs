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
                | "deno.json"
                | "deno.jsonc"
                | "dockerfile"
                | "brewfile"
                | "docker-compose.yml"
                | "docker-compose.yaml"
                | "compose.yml"
                | "compose.yaml"
                | "packages.config"
                | "paket.dependencies"
                | "libs.versions.toml"
                | "setup.py"
                | "flake.nix"
                | "shell.nix"
                | "stack.yaml"
                | "mix.exs"
                | "cartfile"
                | "conanfile.txt"
                | "vcpkg.json"
                | "pubspec_overrides.yaml"
                | ".python-version"
                | ".nvmrc"
                | ".tool-versions"
                | "workspace"
                | "workspace.bazel"
                | "module.bazel"
                | "directory.packages.props"
        ) || name.ends_with(".csproj")
            || name.ends_with(".gradle")
            || name.ends_with(".gradle.kts")
            || name.ends_with(".dockerfile")
            || name.ends_with(".nix")
            || name.ends_with(".tf")
            || name.ends_with(".bzl")
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
        } else if name == "deno.json" || name == "deno.jsonc" {
            deno_json_deps(&text)
        } else if name == "brewfile" {
            brewfile_deps(&text)
        } else if matches!(
            name.as_str(),
            "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
        ) {
            compose_deps(&text)
        } else if name == "packages.config" {
            packages_config_deps(&text)
        } else if name == "paket.dependencies" {
            paket_deps(&text)
        } else if name == "libs.versions.toml" {
            version_catalog_deps(&text)
        } else if name == "setup.py" {
            setup_py_deps(&text)
        } else if name.ends_with(".nix") {
            nix_deps(&text)
        } else if name == "stack.yaml" {
            stack_yaml_deps(&text)
        } else if name == "mix.exs" {
            mix_exs_deps(&text)
        } else if name == "cartfile" {
            cartfile_deps(&text)
        } else if name == "conanfile.txt" {
            conanfile_deps(&text)
        } else if name == "vcpkg.json" {
            vcpkg_deps(&text)
        } else if name == "pubspec_overrides.yaml" {
            pubspec_deps(&text)
        } else if name == ".python-version" {
            runtime_pin_deps(&text, "python")
        } else if name == ".nvmrc" {
            runtime_pin_deps(&text, "node")
        } else if name == ".tool-versions" {
            tool_versions_deps(&text)
        } else if name.ends_with(".tf") {
            terraform_deps(&text)
        } else if matches!(name.as_str(), "workspace" | "workspace.bazel" | "module.bazel")
            || name.ends_with(".bzl")
        {
            bazel_deps(&text)
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
            out.push(pin_version(line, n));
        }
    }
    out
}

/// `name==1.2.3` / `name===1.2.3` pins become `name@1.2.3` node ids
/// so requirements files carry resolved versions, not just names.
/// Other specifiers (`>=`, `~=`, bare) keep the bare name.
fn pin_version(spec: &str, name: String) -> String {
    let s = spec.split(';').next().unwrap_or("").trim();
    for (i, _) in s.match_indices("==") {
        // Skip `>=`/`<=`/`!=`/`~=`: the char before `==`... actually
        // those operators are single `=`, so `==` only matches the
        // equality operator. A preceding `=` (i.e. `===`) is fine.
        let _ = i;
        let after = &s[i + 2..];
        let after = after.strip_prefix('=').unwrap_or(after);
        let ver: String = after
            .trim_start()
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ',')
            .collect();
        let ver = ver.trim().trim_end_matches(".*");
        if !ver.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return format!("{name}@{ver}");
        }
    }
    name
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

/// `setup.cfg` `[options] install_requires` plus
/// `[options.extras_require]` extra dep lists - inline or indented
/// continuation lines, comma-separated.
fn setup_cfg_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut collecting = false;
    let mut buf = String::new();
    // In extras_require every `key = csv` line's VALUE is a dep
    // list; in [options] only install_requires counts.
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if collecting {
                flush_cfg_requires(&buf, &mut out);
                buf.clear();
                collecting = false;
            }
            section = t.trim_matches(|c| c == '[' || c == ']').to_lowercase();
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
            let key = k.trim();
            // [options] install_requires and every
            // [options.extras_require] `extra = deps` line both
            // collect comma/continuation dep lists.
            if (section == "options" && key == "install_requires")
                || section == "options.extras_require"
            {
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
        // Entries are comma-separated, but continuation lines can
        // also be space-separated (`req1 req2` with no commas).
        // Split on whitespace only when there's no `;` marker -
        // markers contain spaces that would yield fake deps.
        if !p.contains(';') {
            for tok in p.split_whitespace() {
                if let Some(n) = pep503_name(tok) {
                    out.push(n);
                }
            }
        } else if let Some(n) = pep503_name(p) {
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
    // [workspace.dependencies]: inherited via `dep.workspace = true`.
    if let Some(ws) = doc
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        for (key, val) in ws {
            let name = val
                .get("package")
                .and_then(|p| p.as_str())
                .unwrap_or(key);
            out.push(name.to_string());
        }
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
pub(crate) fn pubspec_deps(text: &str) -> Vec<String> {
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
                // `pod 'Firebase/Core'` declares the Firebase pod;
                // the `/Subspec` suffix is not part of the name.
                let name = name.split('/').next().unwrap_or("");
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
pub(crate) fn package_swift_deps(text: &str) -> Vec<String> {
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

/// `deno.json`/`deno.jsonc`: `imports` map values that are remote
/// URLs or `npm:`/`jsr:` specifiers become dep nodes (local `./`
/// paths are source edges handled elsewhere, not manifest deps).
fn deno_json_deps(text: &str) -> Vec<String> {
    // deno.jsonc allows comments/trailing commas: reuse the JSONC
    // cleaner from locks.rs is private, so do a light strip here.
    let cleaned = strip_jsonc(text);
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&cleaned) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(imports) = doc.get("imports").and_then(|v| v.as_object()) {
        for (_, spec) in imports {
            let specs: Vec<&str> = match spec {
                serde_json::Value::String(s) => vec![s.as_str()],
                serde_json::Value::Object(o) => o
                    .values()
                    .filter_map(|v| v.as_str())
                    .collect(),
                _ => vec![],
            };
            for s in specs {
                if s.starts_with("npm:") || s.starts_with("jsr:") {
                    // `npm:pkg@1.2.3` / `jsr:@scope/pkg@1.2.3`
                    out.push(s.to_string());
                } else if s.starts_with("https://") || s.starts_with("http://") {
                    // Remote module URL: dep is the URL itself.
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

/// Minimal JSONC cleaner for deno.jsonc: drop `//` comments and
/// trailing commas outside strings.
fn strip_jsonc(text: &str) -> String {
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

// ---------- Brewfile / compose / legacy package formats ----------

/// `Brewfile`: `brew 'name'` / `cask "name"` declarations.
fn brewfile_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let rest = t
            .strip_prefix("brew")
            .or_else(|| t.strip_prefix("cask"));
        let Some(rest) = rest else { continue };
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

/// `docker-compose.yml`/`compose.yml`: `services:` -> `image:` refs.
fn compose_deps(text: &str) -> Vec<String> {
    let Ok(doc) = serde_yml::from_str::<serde_yml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(services) = doc.get("services").and_then(|v| v.as_mapping()) {
        for (_svc, cfg) in services {
            if let Some(img) = cfg.get("image").and_then(|v| v.as_str()) {
                let img = img.trim();
                if !img.is_empty() {
                    out.push(img.to_string());
                }
            }
        }
    }
    out
}

/// Legacy NuGet `packages.config`: `<package id="X" version="Y"/>`.
fn packages_config_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("<package") {
        let after = &rest[i..];
        // Tag boundary: `<packages` must not match.
        if after["<package".len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric())
        {
            rest = &rest[i + 1..];
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        let attrs = &after[..gt];
        let attr = |name: &str| -> Option<String> {
            for q in ['"', '\''] {
                let needle = format!("{name}={q}");
                if let Some(p) = attrs.find(&needle) {
                    let val = &attrs[p + needle.len()..];
                    if let Some(end) = val.find(q) {
                        return Some(val[..end].trim().to_string());
                    }
                }
            }
            None
        };
        if let Some(id) = attr("id") {
            if !id.is_empty() {
                // Exact pins become `id@version` nodes so they bridge
                // to packages.lock.json / the NuGet cache probe.
                match attr("version") {
                    Some(v) if v.chars().next().is_some_and(|c| c.is_ascii_digit()) => {
                        out.push(format!("{id}@{v}"));
                    }
                    _ => out.push(id),
                }
            }
        }
        rest = &after[gt + 1..];
    }
    out
}

/// `paket.dependencies`: `nuget Group:Artifact, Version` and
/// `github "org/repo"` lines.
fn paket_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some(rest) = t.strip_prefix("nuget ") {
            // `nuget Group:Artifact` or `Group % Artifact % Version`
            let coord = rest
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .replace('%', ":")
                .trim()
                .to_string();
            // `Group:Artifact:Version` -> keep group:artifact.
            let parts: Vec<&str> = coord.split(':').collect();
            if parts.len() >= 2 {
                out.push(format!("{}:{}", parts[0].trim(), parts[1].trim()));
            }
        } else if let Some(rest) = t.strip_prefix("github ") {
            let rest = rest.trim().trim_matches(['"', '\'']);
            let repo = rest.split('/').take(2).collect::<Vec<_>>().join("/");
            if repo.contains('/') {
                out.push(repo);
            }
        }
    }
    out
}

/// Gradle version catalog `gradle/libs.versions.toml`:
/// `[libraries]`/`[plugins]` entries `x = "g:a:v"` or
/// `x = { module = "g:a", ... }` -> dep `g:a`.
fn version_catalog_deps(text: &str) -> Vec<String> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["libraries", "plugins", "bundles"] {
        let Some(tbl) = doc.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        for (_alias, val) in tbl {
            match val {
                toml::Value::String(s) => {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() >= 3 {
                        out.push(format!("{}:{}", parts[0], parts[1]));
                    }
                }
                toml::Value::Table(t) => {
                    if let Some(m) = t.get("module").and_then(|v| v.as_str()) {
                        let parts: Vec<&str> = m.split(':').collect();
                        if parts.len() >= 2 {
                            out.push(format!("{}:{}", parts[0], parts[1]));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// `setup.py`: `install_requires=[...]`, `setup_requires=[...]`,
/// `tests_require=[...]` lists of quoted requirement strings.
fn setup_py_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["install_requires", "setup_requires", "tests_require"] {
        let mut rest = text;
        while let Some(i) = rest.find(key) {
            let after_key = &rest[i + key.len()..];
            // Must be `key =` or `key=`.
            let trimmed = after_key.trim_start();
            if !trimmed.starts_with('=') {
                rest = &rest[i + key.len()..];
                continue;
            }
            let after_eq = trimmed[1..].trim_start();
            let Some(open) = after_eq.find(['[', '(']) else {
                break;
            };
            let close = if after_eq.as_bytes()[open] == b'[' { ']' } else { ')' };
            let body = &after_eq[open + 1..];
            let Some(end) = body.find(close) else { break };
            let list = &body[..end];
            // Extract all quoted spans.
            let bytes = list.as_bytes();
            let mut j = 0;
            while j < bytes.len() {
                let b = bytes[j];
                if b == b'\'' || b == b'"' {
                    let q = b;
                    let mut k = j + 1;
                    let mut s = String::new();
                    while k < bytes.len() && bytes[k] != q {
                        if bytes[k] == b'\\' && k + 1 < bytes.len() {
                            k += 1;
                        }
                        s.push(bytes[k] as char);
                        k += 1;
                    }
                    if let Some(n) = pep503_name(&s) {
                        out.push(pin_version(&s, n));
                    }
                    j = k;
                }
                j += 1;
            }
            rest = &body[end + 1..];
        }
    }
    out
}

// ---------- Nix / Haskell / Elixir / Apple / Conan / vcpkg / misc ----------

/// `flake.nix`/`shell.nix`/any `.nix`: flake `inputs` url deps plus
/// `pkgs.<name>` package references (last dotted segment; common
/// non-package attrs like `pkgs.lib`/`pkgs.stdenv` excluded).
fn nix_deps(text: &str) -> Vec<String> {
    const NON_PKGS: &[&str] = &[
        "lib", "stdenv", "callPackage", "mkShell", "mkDerivation",
        "fetchurl", "fetchzip", "fetchgit", "fetchFromGitHub",
        "fetchFromGitLab", "runCommand", "writeText", "writeScript",
        "writers", "overlays", "newScope", "extend", "isLinux",
        "isDarwin", "isWindows", "pkgsStatic", "gcc", "binutils",
    ];
    let mut out = Vec::new();
    // flake inputs: `name.url = "..."` or `name = { url = "..."; }`.
    // Track `{}` depth inside the `inputs = { ... }` attrset; only
    // `url`-keyed values count (rev/ref/narHash are quoted too).
    let mut in_inputs = false;
    let mut inputs_depth = 0i32;
    for line in text.lines() {
        let t = line.trim();
        if !in_inputs && t.contains("inputs") && t.contains('=') {
            in_inputs = true;
        }
        if in_inputs {
            // `url = "..."` or `foo.url = "..."` on this line.
            let mut rest = t;
            while let Some(eq) = rest.find('=') {
                let key = rest[..eq].trim();
                let val = rest[eq + 1..].trim_start();
                let is_url_key = key == "url" || key.ends_with(".url");
                if is_url_key && (val.starts_with('"') || val.starts_with('\'')) {
                    let q = val.as_bytes()[0] as char;
                    if let Some(e) = val[1..].find(q) {
                        let u = val[1..1 + e].trim();
                        if !u.is_empty() {
                            out.push(u.to_string());
                        }
                    }
                }
                rest = &rest[eq + 1..];
            }
            inputs_depth += t.matches('{').count() as i32 - t.matches('}').count() as i32;
            if inputs_depth <= 0 {
                in_inputs = false;
                inputs_depth = 0;
            }
        }
    }
    // pkgs.<a>.<b>... -> last segment as the package name.
    let mut rest = text;
    while let Some(i) = rest.find("pkgs.") {
        let after = &rest[i + 5..];
        let ident: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect();
        rest = &rest[i + 5..];
        let segs: Vec<&str> = ident.split('.').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            continue;
        }
        if NON_PKGS.contains(&segs[0]) {
            continue;
        }
        if let Some(last) = segs.last() {
            if !last.is_empty() && last.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                out.push(last.to_string());
            }
        }
    }
    out
}

/// `stack.yaml`: `extra-deps` entries (git/pantry/url/http).
fn stack_yaml_deps(text: &str) -> Vec<String> {
    let Ok(doc) = serde_yml::from_str::<serde_yml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(deps) = doc.get("extra-deps").and_then(|v| v.as_sequence()) {
        for d in deps {
            // Entries are maps like `{git: "url"}` or scalars.
            if let Some(s) = d.as_str() {
                out.push(s.to_string());
                continue;
            }
            if let Some(m) = d.as_mapping() {
                for (_k, v) in m {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

/// `mix.exs`: inside `def deps`/`defp deps`, `{:name, "spec"}`
/// tuples. `{:ok,`/`{:error,` style tuples outside deps are
/// excluded by section tracking.
pub(crate) fn mix_exs_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut depth = 0i32;
    for line in text.lines() {
        let t = line.trim();
        if !in_deps {
            if t.starts_with("def deps") || t.starts_with("defp deps") {
                in_deps = true;
                depth = t.matches(" do").count() as i32;
                if depth == 0 {
                    depth = 1; // `def deps, do:` still opens a block
                }
            }
            continue;
        }
        // dep tuples: `{:phoenix, "~> 1.7"}` anywhere on the line
        // (they sit inside a `[ ... ]` keyword list).
        let mut rest = t;
        while let Some(i) = rest.find("{:") {
            let after = &rest[i + 2..];
            rest = after;
            let name_end = after.find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '?'));
            if let Some(e) = name_end {
                let name = &after[..e];
                if !name.is_empty()
                    && !matches!(name, "ok" | "error" | "nil" | "true" | "false")
                {
                    out.push(name.to_string());
                }
            }
        }
        // Track `end` closing the def (deps bodies are flat lists).
        depth += t.matches(" do").count() as i32;
        if t == "end" || t.starts_with("end ") || t == "end," {
            depth -= 1;
            if depth <= 0 {
                in_deps = false;
            }
        }
    }
    out
}

/// `Cartfile`: `github "org/repo"`, `git "url"`, `binary "name"`.
pub(crate) fn cartfile_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        let mut it = t.split_whitespace();
        let Some(kind) = it.next() else { continue };
        if !matches!(kind, "github" | "git" | "binary") {
            continue;
        }
        if let Some(q) = t.find('"') {
            let inner = &t[q + 1..];
            if let Some(e) = inner.find('"') {
                let dep = &inner[..e];
                if !dep.is_empty() {
                    out.push(dep.to_string());
                }
            }
        }
    }
    out
}

/// `conanfile.txt`: `[requires]` entries `pkg/version@user/channel`.
/// Emitted verbatim so they match `conan.lock` `ref` node ids.
fn conanfile_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_requires = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_requires = t == "[requires]";
            continue;
        }
        if !in_requires || t.starts_with('#') || t.is_empty() {
            continue;
        }
        // `pkg/version@user/channel` possibly with trailing comment.
        let dep = t.split_whitespace().next().unwrap_or("");
        let dep = dep.split('#').next().unwrap_or("").trim();
        // Must look like name/version.
        if dep.contains('/') && !dep.starts_with('/') {
            out.push(dep.to_string());
        }
    }
    out
}

/// `vcpkg.json`: `dependencies`/`overrides` name arrays.
fn vcpkg_deps(text: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in ["dependencies", "overrides"] {
        if let Some(arr) = doc.get(key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !s.is_empty() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

/// `.python-version`/`.nvmrc`/`.tool-versions` runtime pins ->
/// `tool@version` dep nodes.
fn runtime_pin_deps(text: &str, tool: &str) -> Vec<String> {
    let v = text.trim().split_whitespace().next().unwrap_or("");
    if v.is_empty() {
        Vec::new()
    } else {
        vec![format!("{tool}@{v}")]
    }
}

/// `.tool-versions`: `tool version` lines (asdf).
fn tool_versions_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut it = t.split_whitespace();
        if let (Some(tool), Some(ver)) = (it.next(), it.next()) {
            out.push(format!("{tool}@{ver}"));
        }
    }
    out
}

/// Terraform `.tf`: `source = "..."` values (module sources and
/// `required_providers` sources).
fn terraform_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("source") {
        let after = &rest[i + 6..];
        let trimmed = after.trim_start();
        if !trimmed.starts_with('=') {
            rest = after;
            continue;
        }
        let val = trimmed[1..].trim_start();
        if let Some(q) = val.find(['"', '\'']) {
            let quote = val.as_bytes()[q];
            let inner = &val[q + 1..];
            if let Some(e) = inner.find(quote as char) {
                let src = inner[..e].trim();
                if !src.is_empty() {
                    out.push(src.to_string());
                }
                rest = &inner[e + 1..];
                continue;
            }
        }
        rest = after;
    }
    out
}

/// Bazel `WORKSPACE`/`MODULE.bazel`/`*.bzl`: `load("@repo//...")`
/// references plus `name = "x"` inside `http_archive`/`git_repository`/
/// `bazel_dep`/`http_file` rules.
fn bazel_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // load("@repo//path") -> repo
    let mut rest = text;
    while let Some(i) = rest.find("@") {
        let after = &rest[i + 1..];
        // Skip @@canonical labels - take repo part before //.
        let repo: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
            .collect();
        rest = after;
        if repo.is_empty() || repo == "@" {
            continue;
        }
        // Only count when followed by `//` (external repo label).
        if rest.starts_with("//") || after[repo.len()..].starts_with("//") {
            out.push(repo);
        }
    }
    // name = "x" inside dep-rule calls.
    for rule in ["http_archive", "git_repository", "bazel_dep", "http_file", "archive_override"] {
        let mut rest = text;
        let pat = format!("{rule}(");
        while let Some(i) = rest.find(&pat) {
            let after = &rest[i + pat.len()..];
            let Some(end) = after.find(')') else { break };
            let body = &after[..end];
            if let Some(n) = body.find("name") {
                let nb = &body[n + 4..];
                let nb = nb.trim_start();
                if let Some(eq) = nb.strip_prefix('=') {
                    let v = eq.trim_start();
                    if let Some(q) = v.find('"') {
                        let inner = &v[q + 1..];
                        if let Some(e) = inner.find('"') {
                            let name = inner[..e].trim();
                            if !name.is_empty() {
                                out.push(name.to_string());
                            }
                        }
                    }
                }
            }
            rest = &after[end + 1..];
        }
    }
    out
}
