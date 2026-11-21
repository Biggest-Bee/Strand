//! Generic CSV/TSV edge-list importer.
//!
//! Format: one edge per line, `src,dst[,weight]`. Delimiter is auto-detected
//! (tab if the first data line contains a tab, else comma). Blank lines and
//! lines starting with `#` are ignored. A header row whose first cell is a
//! common source-column name (`src`, `source`, `from`, `package`,
//! `name`) is skipped - deliberately not `a`, which is a plausible node
//! name and would silently drop a real `a -> b` edge. Fields may be
//! wrapped in double quotes.

use strand_core::Result;

use crate::{err, EdgeList};

const HEADER_NAMES: &[&str] = &["src", "source", "from", "package", "name"];

pub fn parse(text: &str) -> Result<EdgeList> {
    // Detect delimiter from the first data line.
    let mut delim = ',';
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.contains('\t') {
            delim = '\t';
        }
        break;
    }

    let mut edges = Vec::new();
    let mut first_data = true;
    for (lineno, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = t.split(delim).map(|f| unquote(f.trim())).collect();
        if fields.len() < 2 {
            return Err(err(format!(
                "csv line {}: expected at least 2 fields, got {}",
                lineno + 1,
                fields.len()
            )));
        }
        if first_data {
            first_data = false;
            if HEADER_NAMES.contains(&fields[0].to_ascii_lowercase().as_str()) {
                continue;
            }
        }
        let src = fields[0].to_string();
        let dst = fields[1].to_string();
        if src.is_empty() || dst.is_empty() {
            return Err(err(format!("csv line {}: empty node name", lineno + 1)));
        }
        let weight = match fields.get(2) {
            Some(w) if !w.is_empty() => Some(
                w.parse::<f32>()
                    .map_err(|_| err(format!("csv line {}: bad weight '{w}'", lineno + 1)))?,
            ),
            _ => None,
        };
        edges.push((src, dst, weight));
    }
    Ok(edges)
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}
