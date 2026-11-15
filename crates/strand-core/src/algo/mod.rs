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
pub use path::{
    k_shortest_paths, paths_within_depth, shortest_path, shortest_path_weighted,
    shortest_path_weighted_csr, PathList,
};
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

/// Transitive impact size (number of dependents, excluding the node
/// itself) for every node.
///
/// Strategy: collapse the graph to its SCC condensation DAG, then compute
/// ancestor sets with bitsets in topological order — `O(E_dag * C/64)`
/// word-ops where `C` is the component count. Nodes in the same SCC share
/// an impact set, so this is exact and much faster than per-node BFS
/// whenever large cycles exist.
///
/// The `C x C` bit matrix is processed in column blocks so memory stays
/// under [`BLOCK_MEM_BYTES`] for any `C`; when the total word-op count
/// would exceed [`MAX_BITSET_OPS`] (huge mostly-acyclic graphs where
/// `C ~= V`), it falls back to the naive per-node reverse BFS.
pub fn impact_sizes<G: GraphView>(graph: &G) -> Vec<u32> {
    let n = graph.n_nodes();
    if n == 0 {
        return Vec::new();
    }
    let sccs = scc::strongly_connected(graph);
    let nc = sccs.len();
    if nc == 0 {
        return vec![0; n];
    }

    let cond = scc::condensation(graph, &sccs);

    // Predecessors in the DAG (comps that depend on c) + Kahn topo order.
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); nc];
    let mut indeg = vec![0u32; nc];
    let mut dag_edges = 0usize;
    for (c, outs) in cond.adj.iter().enumerate() {
        for &d in outs {
            preds[d as usize].push(c as u32);
            indeg[d as usize] += 1;
            dag_edges += 1;
        }
    }
    let words = nc.div_ceil(64);
    // Total word-ops ~= dag_edges * words (each DAG edge ORs one row per
    // block pass; summed over passes this is independent of blocking).
    if dag_edges.saturating_mul(words) > MAX_BITSET_OPS {
        return impact_sizes_naive(graph);
    }

    let mut order: Vec<u32> = Vec::with_capacity(nc);
    let mut stack: Vec<u32> = (0..nc as u32).filter(|&c| indeg[c as usize] == 0).collect();
    while let Some(c) = stack.pop() {
        order.push(c);
        for &d in &cond.adj[c as usize] {
            let di = d as usize;
            indeg[di] -= 1;
            if indeg[di] == 0 {
                stack.push(d);
            }
        }
    }
    // A self-edge inside the condensation would stall Kahn's algorithm;
    // treat an incomplete order as "algorithm can't handle this graph".
    if order.len() != nc {
        return impact_sizes_naive(graph);
    }

    // reach[c] = bitset of components that can reach c (incl. c itself),
    // computed one column block at a time: bit d of reach[c] depends only
    // on bit d of its predecessors' sets, so blocks are independent.
    // `order` is dependents-first, so a predecessor's row is final before
    // any of its successors read it.
    let block_words = ((BLOCK_MEM_BYTES / (nc.max(1) * 8)).max(1)).min(words);
    let mut comp_impact = vec![0u32; nc];
    let sizes: Vec<u64> = cond.members.iter().map(|m| m.len() as u64).collect();

    let mut w0 = 0usize;
    while w0 < words {
        let bw = block_words.min(words - w0);
        // Flat nc*bw row-major bit matrix for this block.
        let mut reach = vec![0u64; nc * bw];
        // Self bits that fall inside this block's column range.
        for c in 0..nc {
            let word = c / 64;
            if word >= w0 && word < w0 + bw {
                reach[c * bw + (word - w0)] = 1u64 << (c % 64);
            }
        }
        for &c in &order {
            let ci = c as usize;
            for &p in &preds[ci] {
                let pi = p as usize;
                for j in 0..bw {
                    let v = reach[pi * bw + j];
                    reach[ci * bw + j] |= v;
                }
            }
        }
        // Accumulate member counts for every set bit in this block.
        for c in 0..nc {
            let mut s = comp_impact[c] as u64;
            for j in 0..bw {
                let mut b = reach[c * bw + j];
                while b != 0 {
                    let d = (w0 + j) * 64 + b.trailing_zeros() as usize;
                    if d < nc {
                        s += sizes[d];
                    }
                    b &= b - 1;
                }
            }
            comp_impact[c] = s.min(u32::MAX as u64) as u32;
        }
        w0 += bw;
    }

    // Impact size of a component = sum of member counts over its ancestor
    // set; per-node value subtracts the node itself.
    (0..n as u32)
        .map(|v| {
            comp_impact[cond.comp[v as usize] as usize].saturating_sub(1)
        })
        .collect()
}

/// Memory budget for the reachability bit matrix (~256MB).
const BLOCK_MEM_BYTES: usize = 256 * 1024 * 1024;
/// Word-op ceiling for the bitset algorithm (~4G u64 ops, a few seconds);
/// beyond it the per-node BFS fallback is used instead.
const MAX_BITSET_OPS: usize = 4_000_000_000;

/// Naive O(V * (V + E)) impact sizes: one stamped reverse BFS per node,
/// parallelized with rayon. Used when the condensation has too many
/// components for the bitset approach.
fn impact_sizes_naive<G: GraphView>(graph: &G) -> Vec<u32> {
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
