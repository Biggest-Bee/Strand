use std::path::PathBuf;

/// Extract `name=version` for every `strand-*` package in the nearest
/// Cargo.lock (workspace root when building in the repo, the packaged
/// lock inside a `.crate`) and write it to OUT_DIR so the update
/// checker knows which strand crate versions are compiled in.
fn main() {
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
