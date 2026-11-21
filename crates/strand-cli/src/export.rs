//! Export graph subsets (impact sets, why-paths) as DOT or Mermaid
//! diagrams that can be pasted into READMEs, PRs, or docs.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use strand_core::Graph;

/// Output diagram syntax.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Diagram {
    /// Graphviz DOT (`digraph`).
    Dot,
    /// Mermaid `graph LR` flowchart.
    Mermaid,
}

/// Collect the edges of `g` whose both endpoints are in `nodes`,
/// deduplicated and capped at `max_edges`. Returns (edges, truncated).
pub fn edges_within(g: &Graph, nodes: &BTreeSet<u32>, max_edges: usize) -> (Vec<(u32, u32)>, bool) {
    let mut edges = BTreeSet::new();
    let mut truncated = false;
    'outer: for &id in nodes {
        for &dst in g.out_targets(id) {
            if nodes.contains(&dst) {
                if edges.len() >= max_edges {
                    truncated = true;
                    break 'outer;
                }
                edges.insert((id, dst));
            }
        }
    }
    (edges.into_iter().collect(), truncated)
}

/// Render `nodes` + `edges` as a diagram. Node order is by name so
/// output is deterministic. Arrow direction: dependent -> dependency.
pub fn render(
    g: &Graph,
    fmt: Diagram,
    nodes: &BTreeSet<u32>,
    edges: &[(u32, u32)],
    truncated: bool,
) -> String {
    // Deterministic id assignment sorted by node name.
    let mut sorted: Vec<u32> = nodes.iter().copied().collect();
    sorted.sort_by(|&a, &b| g.node_name(a).cmp(g.node_name(b)));
    let ids: std::collections::HashMap<u32, usize> =
        sorted.iter().enumerate().map(|(i, &id)| (id, i)).collect();

    let mut out = String::new();
    match fmt {
        Diagram::Dot => {
            out.push_str("digraph strand {\n  rankdir=LR;\n");
            for &id in &sorted {
                let _ = writeln!(
                    out,
                    "  n{} [label=\"{}\"];",
                    ids[&id],
                    dot_escape(g.node_name(id))
                );
            }
            for &(a, b) in edges {
                let _ = writeln!(out, "  n{} -> n{};", ids[&a], ids[&b]);
            }
            if truncated {
                let _ = writeln!(out, "  // truncated: edge limit reached");
            }
            out.push_str("}\n");
        }
        Diagram::Mermaid => {
            out.push_str("graph LR\n");
            for &id in &sorted {
                let _ = writeln!(
                    out,
                    "  n{}[\"{}\"]",
                    ids[&id],
                    mermaid_escape(g.node_name(id))
                );
            }
            for &(a, b) in edges {
                let _ = writeln!(out, "  n{} --> n{}", ids[&a], ids[&b]);
            }
            if truncated {
                let _ = writeln!(out, "  %% truncated: edge limit reached");
            }
        }
    }
    out
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn mermaid_escape(s: &str) -> String {
    // Mermaid quoted labels: `"` ends the label, so swap it for a quote char.
    s.replace('"', "'")
}
