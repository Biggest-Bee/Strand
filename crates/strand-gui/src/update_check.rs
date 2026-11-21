//! crates.io version check on every run: all `strand-*` crates are
//! queried in parallel on a background thread (~800ms timeout each),
//! silent on any error (Strand is offline-first). Disable with
//! `STRAND_NO_UPDATE_CHECK=1`.
//!
//! "Installed" versions come from the Cargo.lock embedded at build
//! time (written to OUT_DIR by build.rs). Crates that aren't
//! dependencies - the sibling binary - fall back to FALLBACK_VERSIONS,
//! which must be bumped alongside Cargo.toml versions each release.

use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

const PKG: &str = env!("CARGO_PKG_NAME");
const CURRENT: &str = env!("CARGO_PKG_VERSION");
const TIMEOUT: Duration = Duration::from_millis(800);

const LOCK_VERSIONS: &str = include_str!(concat!(env!("OUT_DIR"), "/strand_versions.txt"));

/// Fallback for strand crates missing from the embedded Cargo.lock
/// (sibling binaries are not dependencies). Keep in sync with the
/// workspace crate versions at release time.
const FALLBACK_VERSIONS: &[(&str, &str)] = &[
    ("strand-core", "0.1.0"),
    ("strand-import", "0.4.0"),
    ("strand-store", "0.2.1"),
    ("strand-cli", "0.3.4"),
    ("strand-gui", "0.3.6"),
];

const CRATES: &[&str] = &[
    "strand-core",
    "strand-import",
    "strand-store",
    "strand-cli",
    "strand-gui",
];

/// A strand crate on crates.io that is newer than the version
/// compiled into this binary.
pub struct Update {
    pub name: String,
    pub installed: String,
    pub latest: String,
}

/// Spawn a background check. The receiver yields `Some(updates)`
/// (possibly empty is collapsed to `None`) once crates.io answers;
/// `None` on any failure or when disabled.
pub fn spawn() -> Receiver<Option<Vec<Update>>> {
    let (tx, rx) = channel();
    if std::env::var_os("STRAND_NO_UPDATE_CHECK").is_some() {
        let _ = tx.send(None);
        return rx;
    }
    std::thread::spawn(move || {
        let updates = fetch_all();
        let _ = tx.send((!updates.is_empty()).then_some(updates));
    });
    rx
}

fn fetch_all() -> Vec<Update> {
    std::thread::scope(|s| {
        let handles: Vec<_> = CRATES
            .iter()
            .map(|name| s.spawn(move || fetch_one(name)))
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok().flatten())
            .collect()
    })
}

fn fetch_one(name: &str) -> Option<Update> {
    let latest = fetch_latest(name)?;
    let installed = installed_version(name)?;
    match (parse_ver(&latest), parse_ver(&installed)) {
        (Some(a), Some(b)) if a > b => Some(Update {
            name: name.to_string(),
            installed,
            latest,
        }),
        _ => None,
    }
}

/// Version of `name` compiled into this binary: own crate version,
/// else the Cargo.lock snapshot, else the release-time fallback.
fn installed_version(name: &str) -> Option<String> {
    if name == PKG {
        return Some(CURRENT.to_string());
    }
    for line in LOCK_VERSIONS.lines() {
        if let Some(v) = line.strip_prefix(name).and_then(|s| s.strip_prefix('=')) {
            return Some(v.to_string());
        }
    }
    FALLBACK_VERSIONS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.to_string())
}

fn fetch_latest(name: &str) -> Option<String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .new_agent();
    let url = format!("https://crates.io/api/v1/crates/{name}");
    let mut resp = agent
        .get(&url)
        .header("User-Agent", concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")))
        .call()
        .ok()?;
    let body = resp.body_mut().read_to_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v.get("crate")?
        .get("newest_version")?
        .as_str()
        .map(str::to_string)
}

fn parse_ver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim_start_matches('v').split('-').next()?;
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next().unwrap_or("0").parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_and_compare() {
        assert!(parse_ver("0.2.0") > parse_ver("0.1.0"));
        assert!(parse_ver("0.10.0") > parse_ver("0.9.9"));
        assert!(parse_ver("1.0.0-rc.1") == parse_ver("1.0.0"));
        assert!(parse_ver("bogus").is_none());
    }

    #[test]
    fn installed_versions_resolve() {
        // Own crate always resolves; every fallback crate resolves too.
        assert!(installed_version(PKG).is_some());
        for (name, _) in FALLBACK_VERSIONS {
            assert!(installed_version(name).is_some(), "{name}");
        }
    }
}
