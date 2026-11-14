//! Graph algorithms for dependency and impact analysis.
//!
//! Edge convention throughout: `A -> B` means "A depends on B".
//! - Forward edges (`out_edges`) = dependencies of a node.
//! - Reverse edges (`in_edges`)  = dependents of a node (impact direction).
//!
//! All functions are generic over [`crate::view::GraphView`], so they run on
//! both the mmap'd [`crate::Graph`] and the read-write store's merged
//! base+delta view.

mod bfs;
mod order;
mod pagerank;
mod path;
mod scc;
mod sets;

pub use bfs::{bfs, Dir};
pub use order::{analyze, BuildOrder};
pub use pagerank::pagerank;
pub use path::{k_shortest_paths, shortest_path, shortest_path_weighted};
pub use scc::{condensation, strongly_connected, Condensation};
pub use sets::{common, reachable_set};

use crate::view::GraphView;

/// Sentinel depth value meaning "unreached".
pub const UNVISITED: u32 = u32::MAX;

/// Count nodes per BFS depth. Returns a map depth -> count, skipping
/// unreached nodes.
pub fn depth_counts(depths: &[u32]) -> std::collections::BTreeMap<u32, usize> {
    let mut m = std::collections::BTreeMap::new();
    for &d in depths {
        if d != UNVISITED {
            *m.entry(d).or_insert(0) += 1;
        }
    }
    m
}

/// Transitive impact size (number of dependents, excluding depth-0 seeds)
/// for every node, computed with a reverse BFS per node in parallel.
///
/// This is the naive O(V * (V + E)) algorithm; fine for small/medium graphs.
/// For very large graphs prefer sampling or the condensation-DAG approach.
pub fn impact_sizes<G: GraphView>(graph: &G) -> Vec<u32> {
    use rayon::prelude::*;
    let n = graph.n_nodes();
    (0..n as u32)
        .into_par_iter()
        .map_init(
            || {
                (
                    vec![0u32; n], // generation stamps
                    0u32,         // current generation
                    Vec::with_capacity(1024),
                )
            },
            |(seen, gen, queue), v| {
                *gen = gen.wrapping_add(1);
                if *gen == 0 {
                    seen.iter_mut().for_each(|x| *x = 0);
                    *gen = 1;
                }
                let g = *gen;
                seen[v as usize] = g;
                queue.clear();
                queue.push(v);
                let mut count = 0u32;
                while let Some(x) = queue.pop() {
                    graph.in_edges(x, &mut |w| {
                        let wi = w as usize;
                        if wi < n && seen[wi] != g {
                            seen[wi] = g;
                            queue.push(w);
                            count += 1;
                        }
                    });
                }
                count
            },
        )
        .collect()
}
