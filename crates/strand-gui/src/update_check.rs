//! crates.io version check: at most once per 24h, cached in
//! `~/.strand/update_check_<pkg>`, ~800ms timeout, silent on any
//! error (Strand is offline-first). Disable with
//! `STRAND_NO_UPDATE_CHECK=1`.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PKG: &str = env!("CARGO_PKG_NAME");
const CURRENT: &str = env!("CARGO_PKG_VERSION");
const CACHE_SECS: u64 = 24 * 3600;
const TIMEOUT: Duration = Duration::from_millis(800);

fn cache_path() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))?;
    Some(
        PathBuf::from(home)
            .join(".strand")
            .join(format!("update_check_{PKG}")),
    )
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_fresh() -> bool {
    let Some(c) = cache_path() else { return false };
    let Ok(ts) = std::fs::read_to_string(c) else { return false };
    ts.trim()
        .parse::<u64>()
        .map_or(false, |t| now_secs().saturating_sub(t) < CACHE_SECS)
}

/// Spawn a background check. The receiver yields `Some(new_version)`
/// at most once if crates.io has a newer release; `None` otherwise.
pub fn spawn() -> Receiver<Option<String>> {
    let (tx, rx) = channel();
    if std::env::var_os("STRAND_NO_UPDATE_CHECK").is_some() || cache_fresh() {
        let _ = tx.send(None);
        return rx;
    }
    let cache = cache_path();
    std::thread::spawn(move || {
        let _ = tx.send(fetch_latest());
        if let Some(c) = cache {
            if let Some(dir) = c.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(c, now_secs().to_string());
        }
    });
    rx
}

fn fetch_latest() -> Option<String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .new_agent();
    let url = format!("https://crates.io/api/v1/crates/{PKG}");
    let mut resp = agent.get(&url).call().ok()?;
    let body = resp.body_mut().read_to_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let latest = v
        .get("crate")?
        .get("newest_version")?
        .as_str()?;
    match (parse_ver(latest), parse_ver(CURRENT)) {
        (Some(a), Some(b)) if a > b => Some(latest.to_string()),
        _ => None,
    }
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
}
