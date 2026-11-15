//! `strand check` — architecture rules over a graph.
//!
//! Rules live in `strand.rules` (or `--rules <path>`), one per line:
//!
//! ```text
//! # forbid <pattern> -> <pattern>
//! forbid ui/ -> db/
//! forbid *.test -> src/
//! ```
//!
//! A pattern without `*`/`?` is a substring match; otherwise it's a
//! glob where `*` matches any run of characters and `?` one character.
//! Matching is against the full node name.
//!
//! `forbid A -> B` is transitive: it flags every node matching `A` that
//! can reach (through dependency edges) a node matching `B`.

use std::collections::BTreeSet;
use std::path::Path;

use strand_core::algo::{self, Dir};
use strand_core::{Error, Graph, Result};

/// One parsed rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub forbid: String,
    pub ban: String,
}

/// Parse a rules file. Blank lines and `#` comments are ignored;
/// anything else must be `forbid <a> -> <b>`.
pub fn parse_rules(text: &str) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        // Strip comments: ` #` starts a comment (patterns can't contain #).
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once("->") else {
            return Err(Error::Usage(format!(
                "strand.rules:{}: expected `forbid <a> -> <b>`, got `{line}`",
                lineno + 1
            )));
        };
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        if !lhs.starts_with("forbid") {
            return Err(Error::Usage(format!(
                "strand.rules:{}: expected `forbid`, got `{lhs}`",
                lineno + 1
            )));
        }
        let forbid = lhs["forbid".len()..].trim().to_string();
        if forbid.is_empty() || rhs.is_empty() {
            return Err(Error::Usage(format!(
                "strand.rules:{}: empty pattern in `{line}`",
                lineno + 1
            )));
        }
        rules.push(Rule {
            forbid,
            ban: rhs.to_string(),
        });
    }
    Ok(rules)
}

/// Glob/substring matcher. No `*`/`?` => substring; else `*` = any run,
/// `?` = one char, all other chars literal.
pub fn pattern_matches(pat: &str, name: &str) -> bool {
    if !pat.contains('*') && !pat.contains('?') {
        return name.contains(pat);
    }
    glob_match(pat.as_bytes(), name.as_bytes())
}

fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    // Iterative glob with backtracking on the last '*'.
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            mark = i;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// A single violation: node `a` transitively depends on the banned set.
#[derive(Debug)]
pub struct Violation {
    pub a: u32,
    /// A concrete banned node reached, when computed (chain budget).
    pub b: Option<u32>,
    /// Shortest dependency chain a -> ... -> b, when computed.
    pub chain: Option<Vec<u32>>,
}

/// Evaluate all rules. Returns violations grouped by rule index.
/// `max_chains` bounds how many violations get a target node + chain
/// (each costs one forward BFS + one shortest-path run).
pub fn check(g: &Graph, rules: &[Rule], max_chains: usize) -> Vec<Vec<Violation>> {
    let n = g.n_nodes() as u32;
    let names: Vec<&str> = (0..n).map(|i| g.node_name(i)).collect();

    let mut out = Vec::with_capacity(rules.len());
    let mut budget = max_chains;

    for rule in rules {
        let banned: BTreeSet<u32> = (0..n)
            .filter(|&i| pattern_matches(&rule.ban, names[i as usize]))
            .collect();
        if banned.is_empty() {
            out.push(Vec::new());
            continue;
        }
        // One reverse BFS from all banned nodes: everything reaching
        // the banned set transitively depends on it.
        let seeds: Vec<u32> = banned.iter().copied().collect();
        let depths = algo::bfs(g, &seeds, Dir::In, None);
        let mut viols: Vec<Violation> = (0..n)
            .filter(|&i| {
                depths[i as usize] != algo::UNVISITED
                    && !banned.contains(&i)
                    && pattern_matches(&rule.forbid, names[i as usize])
            })
            .map(|i| Violation {
                a: i,
                b: None,
                chain: None,
            })
            .collect();
        // Resolve target + chain only while the budget lasts.
        for v in &mut viols {
            if budget == 0 {
                break;
            }
            if let Some(b) = nearest_banned(g, v.a, &banned) {
                v.chain = algo::shortest_path(g, v.a, b);
                v.b = Some(b);
                budget -= 1;
            }
        }
        out.push(viols);
    }
    out
}

/// Nearest banned node reachable from `a` (fewest hops).
fn nearest_banned(g: &Graph, a: u32, banned: &BTreeSet<u32>) -> Option<u32> {
    let depths = algo::bfs(g, &[a], Dir::Out, None);
    let mut best: Option<(u32, u32)> = None; // (depth, id)
    for &b in banned {
        let d = depths[b as usize];
        if d != algo::UNVISITED && d != 0 && best.is_none_or(|(bd, _)| d < bd) {
            best = Some((d, b));
        }
    }
    best.map(|(_, b)| b)
}

/// Load rules from `path` (or the default `strand.rules` in `dir`).
pub fn load_rules(path: Option<&Path>, dir: &Path) -> Result<Vec<Rule>> {
    let p = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dir.join("strand.rules"));
    let text = std::fs::read_to_string(&p).map_err(|e| {
        Error::Usage(format!("cannot read rules file {}: {e}", p.display()))
    })?;
    parse_rules(&text)
}
