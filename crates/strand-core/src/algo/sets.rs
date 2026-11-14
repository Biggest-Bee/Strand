//! Set operations over reachable sets: shared dependencies and shared
//! impact.

use std::collections::BTreeSet;

use crate::algo::{bfs, Dir, UNVISITED};
use crate::view::GraphView;

/// Set of node ids reachable from `start` following `dir` (including `start`).
pub fn reachable_set<G: GraphView>(graph: &G, start: u32, dir: Dir) -> BTreeSet<u32> {
    let depths = bfs(graph, &[start], dir, None);
    depths
        .iter()
        .enumerate()
        .filter(|(_, &d)| d != UNVISITED)
        .map(|(i, _)| i as u32)
        .collect()
}

/// Intersection of the reachable sets of `a` and `b`.
///
/// `dir = Out` gives shared (transitive) dependencies; `dir = In` gives the
/// shared impact set (everything affected by both).
pub fn common<G: GraphView>(graph: &G, a: u32, b: u32, dir: Dir) -> Vec<u32> {
    let sa = reachable_set(graph, a, dir);
    let sb = reachable_set(graph, b, dir);
    sa.intersection(&sb).copied().collect()
}
