//! PageRank by power iteration, parallelized with rayon.
//!
//! `reverse = false`: PageRank on the dependency graph itself - rank flows
//! from a node to the things it depends on, so heavily-depended-upon
//! libraries accumulate rank. This is the "risk" ranking used by
//! `strand top --by pagerank`.
//!
//! `reverse = true`: PageRank on the reversed graph - rank flows from a
//! dependency toward its dependents (useful for "influence" queries).

use rayon::prelude::*;

use crate::view::GraphView;

const DAMPING: f64 = 0.85;
const TELEPORT: f64 = 1.0 - DAMPING;

/// Power-iteration PageRank. Returns one score per node id.
///
/// Gathers contributions in parallel each iteration; converges when the
/// L1 change drops below `tol` or `max_iter` is reached.
pub fn pagerank<G: GraphView>(graph: &G, reverse: bool, tol: f64, max_iter: usize) -> Vec<f64> {
    let n = graph.n_nodes();
    if n == 0 {
        return Vec::new();
    }
    let nf = n as f64;

    // Degree used for normalization, per direction.
    // Fwd mode: out_deg(u) = #dependencies. Rev mode: "out degree" in the
    // reversed graph = #dependents = in_degree(u).
    let degree = |u: u32| -> usize {
        if reverse {
            graph.in_degree(u)
        } else {
            graph.out_degree(u)
        }
    };
    let is_dangling = |u: u32| degree(u) == 0;

    let mut rank = vec![1.0 / nf; n];
    let mut next = vec![0.0f64; n];

    for _ in 0..max_iter {
        // Dangling mass (nodes with out-degree 0 in the ranked graph).
        let dangling: f64 = (0..n as u32)
            .into_par_iter()
            .filter(|&u| is_dangling(u))
            .map(|u| rank[u as usize])
            .sum();
        let dangling_share = DAMPING * dangling / nf;

        next.par_iter_mut().enumerate().for_each(|(v, slot)| {
            // Sum contributions from neighbors that point at v.
            // Fwd mode:  v's dependents u (in_edges) each give r[u]/outdeg(u).
            // Rev mode:  v's dependencies u (out_edges) each give r[u]/indeg(u).
            let mut sum = 0.0;
            let mut gather = |u: u32| {
                let d = degree(u);
                if d > 0 {
                    sum += rank[u as usize] / d as f64;
                }
            };
            if reverse {
                graph.out_edges(v as u32, &mut gather);
            } else {
                graph.in_edges(v as u32, &mut gather);
            }
            *slot = TELEPORT / nf + dangling_share + DAMPING * sum;
        });

        let diff: f64 = rank
            .par_iter()
            .zip(next.par_iter())
            .map(|(a, b)| (a - b).abs())
            .sum();
        std::mem::swap(&mut rank, &mut next);
        if diff < tol {
            break;
        }
    }
    rank
}
