//! Importers that produce `(src, dst, weight)` edge lists for
//! [`strand_core::GraphBuilder`].
//!
//! Edge direction convention everywhere: `A -> B` means "A depends on B".

pub mod bundler;
pub mod caches;
pub mod cargo;
pub mod csv;
pub mod locks;
pub mod manifests;
pub mod scan;

use strand_core::{Error, Result};

/// Input formats understood by [`parse`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Generic CSV/TSV edge list: `src,dst[,weight]` per line.
    Csv,
    /// `cargo metadata --format-version 1` JSON output.
    Cargo,
    /// `Cargo.lock` (TOML).
    CargoLock,
    /// `package-lock.json` / `npm-shrinkwrap.json` (npm).
    NpmLock,
    /// `yarn.lock` (v1 and berry).
    YarnLock,
    /// `pnpm-lock.yaml`.
    PnpmLock,
    /// `poetry.lock` (TOML).
    PoetryLock,
    /// `go.mod`.
    GoMod,
    /// `go.sum`.
    GoSum,
    /// `pom.xml` (Maven).
    Pom,
    /// `composer.lock` (PHP).
    ComposerLock,
    /// `Gemfile.lock` (Ruby).
    GemfileLock,
    /// `packages.lock.json` (NuGet).
    NugetLock,
    /// `Package.resolved` (SwiftPM).
    SwiftResolved,
    /// `pubspec.lock` (Dart/Flutter).
    PubspecLock,
    /// `uv.lock` (uv).
    UvLock,
    /// `bun.lock` (Bun, JSONC).
    BunLock,
    /// `Podfile.lock` (CocoaPods).
    PodfileLock,
    /// `paket.lock` (JVM, packages.lock.json schema).
    PaketLock,
    /// `stack.yaml.lock` (Haskell).
    StackLock,
    /// `mix.lock` (Elixir).
    MixLock,
    /// `Cartfile.resolved` (Carthage).
    CartfileResolved,
    /// `deno.lock`.
    DenoLock,
    /// `conan.lock`.
    ConanLock,
    /// `gradle/verification-metadata.xml`.
    GradleVerification,
    /// `gradle.lockfile` (flat resolved coordinates).
    GradleLockfile,
    /// `flake.lock` (Nix).
    FlakeLock,
    /// `webpack --json` stats output (per-module resolved deps).
    WebpackStats,
    /// `esbuild --metafile` JSON output (per-input imports).
    EsbuildMeta,
}

/// One parsed edge: `src -> dst` ("src depends on dst"), optional
/// weight, and a provenance/confidence tag ([`strand_core::EdgeKind`];
/// parsers always emit [`strand_core::EdgeKind::Static`]).
pub type EdgeList = Vec<(String, String, Option<f32>, strand_core::EdgeKind)>;

/// Parse `text` according to `format`.
pub fn parse(text: &str, format: Format) -> Result<EdgeList> {
    match format {
        Format::Csv => csv::parse(text),
        Format::Cargo => cargo::parse(text),
        Format::CargoLock => locks::cargo_lock(text),
        Format::NpmLock => locks::package_lock(text),
        Format::YarnLock => locks::yarn_lock(text),
        Format::PnpmLock => locks::pnpm_lock(text),
        Format::PoetryLock => locks::poetry_lock(text),
        Format::GoMod => locks::go_mod(text),
        Format::GoSum => locks::go_sum(text),
        Format::Pom => locks::pom_xml(text),
        Format::ComposerLock => locks::composer_lock(text),
        Format::GemfileLock => locks::gemfile_lock(text),
        Format::NugetLock => locks::nuget_lock(text),
        Format::SwiftResolved => locks::swift_resolved(text),
        Format::PubspecLock => locks::pubspec_lock(text),
        Format::UvLock => locks::uv_lock(text),
        Format::BunLock => locks::bun_lock(text),
        Format::PodfileLock => locks::podfile_lock(text),
        Format::PaketLock => locks::nuget_lock(text),
        Format::StackLock => locks::stack_lock(text),
        Format::MixLock => locks::mix_lock(text),
        Format::CartfileResolved => locks::cartfile_resolved(text),
        Format::DenoLock => locks::deno_lock(text),
        Format::ConanLock => locks::conan_lock(text),
        Format::GradleVerification => locks::gradle_verification(text),
        Format::GradleLockfile => locks::gradle_lockfile(text),
        Format::FlakeLock => locks::flake_lock(text),
        Format::WebpackStats => bundler::webpack_stats(text),
        Format::EsbuildMeta => bundler::esbuild_meta(text),
    }
}

/// Auto-detect format from file name, then content.
pub fn detect_format(path: &std::path::Path, text: &str) -> Format {
    // Lockfile/manifest names are unambiguous.
    if let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_lowercase()) {
        match name.as_str() {
            "cargo.lock" => return Format::CargoLock,
            "package-lock.json" | "npm-shrinkwrap.json" => return Format::NpmLock,
            "yarn.lock" => return Format::YarnLock,
            "pnpm-lock.yaml" => return Format::PnpmLock,
            "poetry.lock" => return Format::PoetryLock,
            "go.mod" => return Format::GoMod,
            "go.sum" => return Format::GoSum,
            "pom.xml" => return Format::Pom,
            "composer.lock" => return Format::ComposerLock,
            "gemfile.lock" => return Format::GemfileLock,
            "packages.lock.json" => return Format::NugetLock,
            "package.resolved" => return Format::SwiftResolved,
            "pubspec.lock" => return Format::PubspecLock,
            "uv.lock" => return Format::UvLock,
            "bun.lock" => return Format::BunLock,
            "podfile.lock" => return Format::PodfileLock,
            "paket.lock" => return Format::PaketLock,
            "stack.yaml.lock" => return Format::StackLock,
            "mix.lock" => return Format::MixLock,
            "cartfile.resolved" => return Format::CartfileResolved,
            "deno.lock" => return Format::DenoLock,
            "conan.lock" => return Format::ConanLock,
            "verification-metadata.xml" => return Format::GradleVerification,
            "gradle.lockfile" => return Format::GradleLockfile,
            "flake.lock" => return Format::FlakeLock,
            _ => {}
        }
    }
    // Content sniffing for renamed files.
    let t = text.trim_start();
    // bun.lock is JSONC with lockfileVersion 1 + workspaces; check
    // before the generic npm lockfileVersion sniff.
    if t.contains("\"lockfileVersion\": 1") && t.contains("\"workspaces\"") {
        return Format::BunLock;
    }
    if t.contains("\"lockfileVersion\"") {
        return Format::NpmLock;
    }
    if t.contains("yarn lockfile") {
        return Format::YarnLock;
    }
    // pnpm yaml: `lockfileVersion: '9.0'` (unquoted key, colon form).
    if t.contains("lockfileVersion:") {
        return Format::PnpmLock;
    }
    if t.starts_with("module ") {
        return Format::GoMod;
    }
    if t.contains("<project") && t.contains("<dependencies>") {
        return Format::Pom;
    }
    if t.contains("generated by Cargo") {
        return Format::CargoLock;
    }
    if t.contains("generated by Poetry") || t.contains("[metadata]") {
        return Format::PoetryLock;
    }
    if t.contains("PODFILE CHECKSUM") {
        return Format::PodfileLock;
    }
    if t.contains("\"pins\"") && t.contains("\"identity\"") {
        return Format::SwiftResolved;
    }
    if t.contains("\"content-hash\"") && t.contains("\"packages\"") {
        return Format::ComposerLock;
    }
    if t.contains(" h1:") {
        return Format::GoSum;
    }
    if t.contains("requires-python") && t.contains("[[package]]") {
        return Format::UvLock;
    }
    if t.contains("\"graph_lock\"") {
        return Format::ConanLock;
    }
    if t.contains("\"nodes\"") && t.contains("\"locked\"") {
        return Format::FlakeLock;
    }
    if t.contains("<verification-metadata") {
        return Format::GradleVerification;
    }
    if t.contains("\"remote\"") && t.contains("\"npm\"") {
        return Format::DenoLock;
    }
    // Bundler metadata before the cargo-JSON fallback.
    if let Some(f) = bundler::sniff(text) {
        return f;
    }
    if path.extension().is_some_and(|e| e == "json") || t.starts_with('{') {
        Format::Cargo
    } else {
        Format::Csv
    }
}

/// Feed an [`EdgeList`] into a [`strand_core::GraphBuilder`].
pub fn fill_builder(edges: EdgeList, builder: &mut strand_core::GraphBuilder) -> Result<()> {
    for (src, dst, w, kind) in edges {
        if src == dst {
            // Self-loops are node declarations emitted by lockfile
            // parsers for packages with no recorded edges; register
            // the node but skip the edge so `cycles` stays meaningful.
            builder.add_node(src);
            continue;
        }
        match w {
            Some(w) => builder.add_edge_weighted_kind(src, dst, w, kind),
            None => builder.add_edge_kind(src, dst, kind),
        }
    }
    Ok(())
}

/// Convenience: parse + build in one call.
pub fn build_from_text(
    text: &str,
    format: Format,
    out: &std::path::Path,
) -> Result<strand_core::BuildStats> {
    let edges = parse(text, format)?;
    let mut b = strand_core::GraphBuilder::new();
    fill_builder(edges, &mut b)?;
    b.build(out)
}

pub(crate) fn err(msg: impl Into<String>) -> Error {
    Error::Usage(msg.into())
}
