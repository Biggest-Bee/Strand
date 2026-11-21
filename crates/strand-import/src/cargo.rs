//! `cargo metadata --format-version 1` JSON importer.
//!
//! Produces package dependency edges `A -> B` meaning "package A depends on
//! package B". Node names are package names; when several versions of a
//! dependency exist, the highest version is chosen (deterministic).
//! Self-edges are dropped by [`crate::fill_builder`].

use strand_core::Result;

use crate::{err, EdgeList};

pub fn parse(text: &str) -> Result<EdgeList> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("cargo metadata JSON: {e}")))?;
    let packages = v["packages"]
        .as_array()
        .ok_or_else(|| err("cargo metadata: missing 'packages' array"))?;

    // name -> sorted list of (version, ) for resolution
    let mut by_name: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for p in packages {
        let name = p["name"].as_str().unwrap_or("");
        let version = p["version"].as_str().unwrap_or("");
        if !name.is_empty() {
            by_name
                .entry(name.to_string())
                .or_default()
                .push(version.to_string());
        }
    }
    for vers in by_name.values_mut() {
        vers.sort_by(|a, b| cmp_version(b, a)); // descending
        vers.dedup();
    }

    let mut edges = Vec::new();
    for p in packages {
        let src = match p["name"].as_str() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let Some(deps) = p["dependencies"].as_array() else {
            continue;
        };
        for d in deps {
            // `name` is the package name; `rename` is the alias if renamed.
            // Try `name` first, then `rename`.
            let mut resolved = None;
            for key in ["name", "rename"] {
                if let Some(dep_name) = d[key].as_str() {
                    if let Some(vers) = by_name.get(dep_name) {
                        if !vers.is_empty() {
                            resolved = Some(dep_name.to_string());
                            break;
                        }
                    }
                }
            }
            if let Some(dst) = resolved {
                if dst != src {
                    edges.push((src.clone(), dst, None, strand_core::EdgeKind::Static));
                }
            }
        }
    }
    Ok(edges)
}

/// Compare two semver-ish version strings, highest first.
/// Falls back to lexicographic order for unparsable versions.
fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(v: &str) -> (u64, u64, u64, &str) {
        let core = v.split(['-', '+']).next().unwrap_or("");
        let mut it = core.split('.');
        let n = |s: Option<&str>| s.and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        (n(it.next()), n(it.next()), n(it.next()), core)
    }
    let (a1, a2, a3, ar) = parts(a);
    let (b1, b2, b3, br) = parts(b);
    (a1, a2, a3, ar).cmp(&(b1, b2, b3, br))
}
