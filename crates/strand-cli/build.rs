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

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    // `git describe --tags --always --dirty` gives e.g. "v2026-11-15.4-3-gabc1234"
    // or a bare commit hash outside a tag; fall back to the commit hash.
    let describe = git(&["describe", "--tags", "--always", "--dirty"])
        .or_else(|| git(&["rev-parse", "--short", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=STRAND_GIT_DESCRIBE={describe}");
}
