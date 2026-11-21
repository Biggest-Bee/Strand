//! Build order: SCC condensation, topological (dependencies-first) order,
//! and the longest dependency chain ("critical path").

use crate::algo::scc::{condensation, strongly_connected, Condensation};
use crate::view::GraphView;

/// Result of [`analyze`].
#[derive(Debug)]
pub struct BuildOrder {
    /// SCCs in dependencies-first order (what `order` prints).
    pub sccs: Vec<Vec<u32>>,
    /// Condensation DAG; `adj[c]` are the components `c` depends on.
    pub dag: Condensation,
    /// Critical path as a flat list of node ids (dependencies first).
    pub critical_path: Vec<u32>,
    /// Number of nodes on the critical path.
    pub critical_len: usize,
}

/// Compute SCCs, their dependencies-first order, and the critical path.
///
/// Tarjan emits SCCs in reverse topological order of the condensation,
/// which - given `A -> B` = "A depends on B" - is already dependencies-first.
pub fn analyze<G: GraphView>(graph: &G) -> BuildOrder {
    let sccs = strongly_connected(graph);
    let dag = condensation(graph, &sccs);

    // dp[c] = size(c) + max dp[succ]; sccs are already in an order where
    // every successor (dependency) precedes c, so a single forward pass
    // over emission order works.
    let ncomp = sccs.len();
    let mut dp = vec![0usize; ncomp];
    let mut choice = vec![usize::MAX; ncomp];
    for c in 0..ncomp {
        let mut best = 0usize;
        let mut best_succ = usize::MAX;
        for &s in &dag.adj[c] {
            let sv = s as usize;
            debug_assert!(
                sv < c,
                "condensation successor must precede its dependent"
            );
            if dp[sv] > best {
                best = dp[sv];
                best_succ = sv;
            }
        }
        dp[c] = sccs[c].len() + best;
        choice[c] = best_succ;
    }

    // Find the component with the maximum dp.
    let mut best_c = 0usize;
    for c in 1..ncomp {
        if dp[c] > dp[best_c] {
            best_c = c;
        }
    }

    // Reconstruct the critical path: walk successors (dependencies) from
    // the topmost component down to a leaf, then emit dependencies-first.
    let mut comps = Vec::new();
    let mut c = best_c;
    loop {
        comps.push(c);
        if choice[c] == usize::MAX {
            break;
        }
        c = choice[c];
    }
    let mut path = Vec::new();
    for &cc in comps.iter().rev() {
        path.extend_from_slice(&sccs[cc]);
    }
    let critical_len = dp[best_c];

    BuildOrder {
        sccs,
        dag,
        critical_path: path,
        critical_len,
    }
}
