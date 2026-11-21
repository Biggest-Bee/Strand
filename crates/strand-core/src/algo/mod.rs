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
    shortest_path_weighted_csr, shortest_path_weighted_csr_min, PathList,
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
/// ancestor sets with bitsets in topological order - `O(E_dag * C/64)`
/// word-ops where `C` is the component count. Nodes in the same SCC share
/// an impact set, so this is exact and much faster than per-node BFS
/// whenever large cycles exist.
///
/// The `C x C` bit matrix is processed in column blocks so memory stays
/// under [`BLOCK_MEM_BYTES`] for any `C`; when the total word-op count
/// would exceed [`MAX_BITSET_OPS`] (huge mostly-acyclic graphs where
/// `C ~= V`), it falls back to the naive per-node reverse BFS.
pub fn impact_sizes<G: GraphView>(graph: &G) -> Vec<u32> {
    match impact_sizes_inner(graph) {
        Ok(v) => v,
        Err(()) => impact_sizes_naive(graph),
    }
}

/// Which computation produced [`impact_sizes_auto`] results.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImpactMethod {
    /// Exact SCC-condensation bitsets.
    Exact,
    /// Deterministic landmark-sampling estimate (see
    /// [`impact_sizes_approx`]). Values are approximate.
    Approx,
}

/// Impact sizes for ranking: exact bitsets when affordable, otherwise a
/// deterministic landmark-sampling approximation. Returns the per-node
/// estimates (exact counts as `f64`) plus the method used.
pub fn impact_sizes_auto<G: GraphView>(graph: &G) -> (Vec<f64>, ImpactMethod) {
    let (v, m, _) = impact_sizes_auto_with(graph, None);
    (v, m)
}

/// [`impact_sizes_auto`] with an explicit landmark count for the
/// approximate path (`None` = [`default_approx_samples`]). Also returns
/// the number of landmarks used (0 when exact).
pub fn impact_sizes_auto_with<G: GraphView>(
    graph: &G,
    samples: Option<usize>,
) -> (Vec<f64>, ImpactMethod, usize) {
    match impact_sizes_inner(graph) {
        Ok(v) => (
            v.into_iter().map(|x| x as f64).collect(),
            ImpactMethod::Exact,
            0,
        ),
        Err(()) => {
            let k = samples.unwrap_or_else(|| default_approx_samples(graph));
            let (v, used) = impact_sizes_approx_detail(graph, k);
            (v, ImpactMethod::Approx, used)
        }
    }
}

/// Exact impact count of a single node: number of distinct dependents
/// (reverse-reachable nodes) excluding the node itself. One BFS - cheap
/// enough to rerank a few hundred top candidates on huge graphs.
pub fn impact_size_exact<G: GraphView>(graph: &G, node: u32) -> u32 {
    let depths = bfs(graph, &[node], Dir::In, None);
    depths.iter().filter(|&&d| d != UNVISITED).count() as u32 - 1
}

/// Replace the highest-scoring entries of `scores` with exact impact
/// counts (parallel BFS per candidate). At least `m` candidates are
/// reranked; ties at the boundary score are *all* included (up to
/// `cap`) so saturated estimates can't leak approximate values into
/// printed output. Ties break by lower node id, keeping the selection
/// deterministic. `cap` bounds total candidates - pass a value scaled
/// to the edge budget on huge graphs. Returns the reranked node ids
/// (sorted); `scores` outside that set keeps its estimates.
pub fn rerank_impact_exact<G: GraphView>(
    graph: &G,
    scores: &mut [f64],
    m: usize,
    cap: usize,
) -> Vec<u32> {
    use rayon::prelude::*;
    let n = scores.len();
    if n == 0 || m == 0 || cap == 0 {
        return Vec::new();
    }
    let want = m.min(n).min(cap);
    let mut idx: Vec<u32> = (0..n as u32).collect();
    // Partial sort: only the top `want` need ordering - O(n) instead of
    // O(n log n) on 10M-node graphs. total_cmp is a total order (NaN-safe).
    let cmp = |&a: &u32, &b: &u32| {
        scores[b as usize]
            .total_cmp(&scores[a as usize])
            .then(a.cmp(&b))
    };
    idx.select_nth_unstable_by(want - 1, &cmp);
    // Extend past `want` with every node tied at the boundary score
    // (deterministic by id), capped at `cap` total.
    let boundary = scores[idx[want - 1] as usize];
    let mut sel: Vec<u32> = idx[..want].to_vec();
    if want < cap {
        let mut ties: Vec<u32> = idx[want..]
            .iter()
            .copied()
            .filter(|&i| scores[i as usize] == boundary)
            .collect();
        ties.sort_unstable();
        for t in ties {
            if sel.len() >= cap {
                break;
            }
            sel.push(t);
        }
    }
    sel.sort_by(|a, b| cmp(a, b));
    let exact: Vec<f64> = sel
        .par_iter()
        .map(|&i| impact_size_exact(graph, i) as f64)
        .collect();
    for (k, &i) in sel.iter().enumerate() {
        scores[i as usize] = exact[k];
    }
    sel.sort_unstable();
    sel
}

/// Force the landmark-sampling path regardless of graph size (for
/// benchmarking/validation on graphs where the exact path is cheap).
/// Returns estimates plus the landmark count used.
pub fn impact_sizes_force_approx<G: GraphView>(
    graph: &G,
    samples: Option<usize>,
) -> (Vec<f64>, usize) {
    let k = samples.unwrap_or_else(|| default_approx_samples(graph));
    impact_sizes_approx_detail(graph, k)
}

/// Landmark count for [`impact_sizes_auto`]: ~2G edge visits total,
/// clamped to [16, 512].
fn default_approx_samples<G: GraphView>(graph: &G) -> usize {
    let e = graph.n_edges().max(1) as u64;
    ((2_000_000_000u64 / e) as usize).clamp(16, 512)
}

/// Approximate transitive impact sizes via landmark sampling.
///
/// Samples `samples` "dependent" nodes uniformly at random (deterministic
/// xxh64-threshold selection, no RNG state), computes each one's
/// dependency closure with a forward BFS, and counts how many sampled
/// dependents reach every node. `estimate(X) ≈ n/k × count(X)` is an
/// unbiased estimator of the true impact size. Error is *not* uniform:
/// nodes reached by many landmarks (high-impact nodes - the ones that
/// matter for ranking) have small relative error, while low-impact
/// nodes are noisy and often estimate as 0. Near-ties, especially in
/// the middle of the ranking, can be misordered - use
/// [`rerank_impact_exact`] for the printed top rows. Self-hits from
/// landmark nodes are subtracted so estimates exclude the node itself
/// like the exact path.
///
/// Cost: `O(samples × (V + E))` edge visits, parallelized with rayon;
/// memory is one bitset + queue per worker plus a shared counter array.
pub fn impact_sizes_approx<G: GraphView>(graph: &G, samples: usize) -> Vec<f64> {
    impact_sizes_approx_detail(graph, samples).0
}

/// [`impact_sizes_approx`] plus the number of landmarks actually used
/// (may differ from `samples` when the hash threshold selects a
/// different count, or the strided fallback kicks in).
pub fn impact_sizes_approx_detail<G: GraphView>(graph: &G, samples: usize) -> (Vec<f64>, usize) {
    let n = graph.n_nodes();
    if n == 0 || samples == 0 {
        return (vec![0.0; n], 0);
    }
    // Cap landmarks: samples >= n would make every node a landmark -
    // that's n full BFS passes (exact-cost) under an "approx" label.
    let samples = samples.min(n).min(1024);

    // Deterministic landmark set: ids whose xxh64 hash falls below the
    // samples/n quantile of hash space. Hash of the id (not the name)
    // keeps selection independent of lexicographic node order.
    // threshold ≈ samples * 2^64 / n, computed in u128.
    let t128 = (samples as u128) << 64;
    let threshold = t128 / n as u128;
    let is_landmark = |id: u32| -> bool {
        let h = xxhash_rust::xxh64::xxh64(&id.to_le_bytes(), 0) as u128;
        h < threshold
    };
    let landmarks: Vec<u32> = (0..n as u32).filter(|&i| is_landmark(i)).collect();
    if landmarks.is_empty() {
        // Pathological threshold miss: fall back to a strided sample.
        let step = (n / samples.min(n)).max(1);
        let ids: Vec<u32> = (0..n as u32).step_by(step).collect();
        let k = ids.len();
        let set: std::collections::BTreeSet<u32> = ids.iter().copied().collect();
        return (impact_sizes_sampled(graph, &ids, &set), k);
    }
    let k = landmarks.len();
    let self_set: std::collections::BTreeSet<u32> = landmarks.iter().copied().collect();
    (impact_sizes_sampled(graph, &landmarks, &self_set), k)
}

/// Shared worker for [`impact_sizes_approx`]: forward-BFS the
/// dependency closure of each id in `landmarks`, count reachability per
/// node, scale by `n / landmarks.len()`. `self_ids` marks which nodes
/// are landmarks themselves (their trivial self-hit is subtracted,
/// matching the exact path's exclusion of the node itself).
fn impact_sizes_sampled<G: GraphView>(
    graph: &G,
    landmarks: &[u32],
    self_ids: &std::collections::BTreeSet<u32>,
) -> Vec<f64> {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    let n = graph.n_nodes();
    let k = landmarks.len().max(1);
    let counters: Vec<AtomicU32> = (0..n).map(|_| AtomicU32::new(0)).collect();

    landmarks.par_iter().for_each_init(
        || (vec![0u64; n.div_ceil(64)], Vec::with_capacity(1024)),
        |(bits, queue), &y| {
            bits.fill(0);
            queue.clear();
            let yi = y as usize;
            bits[yi / 64] |= 1u64 << (yi % 64);
            queue.push(y);
            while let Some(x) = queue.pop() {
                graph.out_edges(x, &mut |w| {
                    let i = w as usize;
                    if i >= n {
                        return; // malformed edge target: skip, don't panic
                    }
                    let word = &mut bits[i / 64];
                    let bit = 1u64 << (i % 64);
                    if *word & bit == 0 {
                        *word |= bit;
                        queue.push(w);
                    }
                });
            }
            for (wi, &word) in bits.iter().enumerate() {
                let mut b = word;
                while b != 0 {
                    let id = wi * 64 + b.trailing_zeros() as usize;
                    if id < n {
                        counters[id].fetch_add(1, Ordering::Relaxed);
                    }
                    b &= b - 1;
                }
            }
        },
    );

    let scale = n as f64 / k as f64;
    // An estimate can't exceed n-1 (a node affects at most every other
    // node); clamp sampling overshoot.
    let cap = (n as f64 - 1.0).max(0.0);
    (0..n as u32)
        .map(|i| {
            let c = counters[i as usize].load(Ordering::Relaxed) as u64;
            (c.saturating_sub(self_ids.contains(&i) as u64) as f64 * scale).min(cap)
        })
        .collect()
}

/// Inner computation: `Ok` = exact bitset result, `Err(())` = graph too
/// large for the bitset budget (caller decides fallback strategy).
fn impact_sizes_inner<G: GraphView>(graph: &G) -> std::result::Result<Vec<u32>, ()> {
    let n = graph.n_nodes();
    if n == 0 {
        return Ok(Vec::new());
    }
    let sccs = scc::strongly_connected(graph);
    let nc = sccs.len();
    if nc == 0 {
        return Ok(vec![0; n]);
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
        return Err(());
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
        return Err(());
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
    Ok((0..n as u32)
        .map(|v| comp_impact[cond.comp[v as usize] as usize].saturating_sub(1))
        .collect())
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
                    0u32,          // current generation
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
