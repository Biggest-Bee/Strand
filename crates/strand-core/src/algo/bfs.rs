//! Breadth-first search, forward and reverse, single- or multi-source,
//! optionally depth-limited.

use std::collections::VecDeque;

use crate::algo::UNVISITED;
use crate::view::GraphView;

/// Which direction to traverse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    /// Follow `out_edges`: dependencies of a node.
    Out,
    /// Follow `in_edges`: dependents of a node (impact direction).
    In,
}

/// Multi-source BFS. Returns the depth of every reached node
/// (`UNVISITED` = unreached). Seeds have depth 0.
///
/// `max_depth = Some(d)` limits the search to nodes at depth <= d.
pub fn bfs<G: GraphView>(graph: &G, starts: &[u32], dir: Dir, max_depth: Option<u32>) -> Vec<u32> {
    let n = graph.n_nodes();
    let mut depth = vec![UNVISITED; n];
    let mut queue: VecDeque<u32> = VecDeque::new();
    for &s in starts {
        let si = s as usize;
        if si < n && depth[si] == UNVISITED {
            depth[si] = 0;
            queue.push_back(s);
        }
    }
    while let Some(v) = queue.pop_front() {
        let d = depth[v as usize];
        if max_depth.is_some_and(|m| d >= m) {
            continue;
        }
        let mut visit = |w: u32| {
            let wi = w as usize;
            if wi < n && depth[wi] == UNVISITED {
                depth[wi] = d + 1;
                queue.push_back(w);
            }
        };
        match dir {
            Dir::Out => graph.out_edges(v, &mut visit),
            Dir::In => graph.in_edges(v, &mut visit),
        }
    }
    depth
}
