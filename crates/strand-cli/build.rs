use std::path::PathBuf;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Extract `name=version` for every `strand-*` package in the nearest
/// Cargo.lock (workspace root when building in the repo, the packaged
/// lock inside a `.crate`) and write it to OUT_DIR so the update
/// checker knows which strand crate versions are compiled in.
fn emit_strand_versions() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../Cargo.lock"),
        manifest.join("Cargo.lock"),
    ];
    let mut out = String::new();
    if let Some(lock) = candidates.iter().find(|p| p.is_file()) {
        if let Ok(text) = std::fs::read_to_string(lock) {
            for block in text.split("[[package]]").skip(1) {
                let mut name = None;
                let mut version = None;
                for line in block.lines() {
                    let line = line.trim();
                    if name.is_none() {
                        name = line
                            .strip_prefix("name = \"")
                            .and_then(|s| s.strip_suffix('"'));
                    }
                    if version.is_none() {
                        version = line
                            .strip_prefix("version = \"")
                            .and_then(|s| s.strip_suffix('"'));
                    }
                    if name.is_some() && version.is_some() {
                        break;
                    }
                }
                if let (Some(n), Some(v)) = (name, version) {
                    if n.starts_with("strand-") {
                        out.push_str(&format!("{n}={v}\n"));
                    }
                }
            }
        }
    }
    let _ = std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("strand_versions.txt"),
        out,
    );
}

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    emit_strand_versions();
    // `git describe --tags --always --dirty` gives e.g. "v2026-11-15.4-3-gabc1234"
    // or a bare commit hash outside a tag; fall back to the commit hash.
    let describe = git(&["describe", "--tags", "--always", "--dirty"])
        .or_else(|| git(&["rev-parse", "--short", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=STRAND_GIT_DESCRIBE={describe}");
}
