//! Shortest-path queries: unweighted BFS with path reconstruction, k
//! shortest-path enumeration, and weighted Dijkstra.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::algo::{bfs, Dir, UNVISITED};
use crate::view::GraphView;

/// Result of a bounded path enumeration.
#[derive(Clone, Debug)]
pub struct PathList {
    /// The enumerated paths, in deterministic discovery order.
    pub paths: Vec<Vec<u32>>,
    /// True when enumeration stopped before exhausting the search space
    /// (hit `k`/`limit` or the internal step budget) — more paths may
    /// exist that were not returned.
    pub truncated: bool,
}

/// One shortest dependency chain `from -> ... -> to` (forward edges).
/// Returns `None` if `to` is not reachable from `from`.
pub fn shortest_path<G: GraphView>(graph: &G, from: u32, to: u32) -> Option<Vec<u32>> {
    let n = graph.n_nodes();
    if from as usize >= n || to as usize >= n {
        return None;
    }
    if from == to {
        return Some(vec![from]);
    }
    let mut parent = vec![UNVISITED; n];
    let mut queue = std::collections::VecDeque::new();
    parent[from as usize] = from;
    queue.push_back(from);
    while let Some(v) = queue.pop_front() {
        let mut found = false;
        graph.out_edges(v, &mut |w| {
            let wi = w as usize;
            if wi < n && parent[wi] == UNVISITED {
                parent[wi] = v;
                if w == to {
                    found = true;
                } else {
                    queue.push_back(w);
                }
            }
        });
        if found {
            // Reconstruct.
            let mut path = vec![to];
            let mut cur = to;
            while cur != from {
                cur = parent[cur as usize];
                path.push(cur);
            }
            path.reverse();
            return Some(path);
        }
    }
    None
}

/// Up to `k` distinct shortest dependency chains from `from` to `to`.
///
/// Computes BFS distances from both ends, keeps only nodes lying on some
/// shortest path (`d_from[v] + d_to[v] == D`), then enumerates simple paths
/// through that subgraph with an iterative DFS. Deterministic: neighbors are
/// visited in the order the view yields them. Bounded by `k` results and an
/// internal step budget so adversarial graphs cannot hang the caller.
pub fn k_shortest_paths<G: GraphView>(graph: &G, from: u32, to: u32, k: usize) -> PathList {
    if k == 0 {
        return PathList {
            paths: Vec::new(),
            truncated: false,
        };
    }
    if from == to {
        // The only simple chain is the trivial one — enumeration is exact.
        return PathList {
            paths: vec![vec![from]],
            truncated: false,
        };
    }
    if from as usize >= graph.n_nodes() || to as usize >= graph.n_nodes() {
        return PathList {
            paths: Vec::new(),
            truncated: false,
        };
    }
    let d_from = bfs(graph, &[from], Dir::Out, None);
    if d_from[to as usize] == UNVISITED {
        return PathList {
            paths: Vec::new(),
            truncated: false,
        };
    }
    let d_to = bfs(graph, &[to], Dir::In, None);
    let total = d_from[to as usize];

    let n = graph.n_nodes();
    let mut allowed = vec![false; n];
    for v in 0..n as u32 {
        let a = d_from[v as usize];
        let b = d_to[v as usize];
        if a != UNVISITED && b != UNVISITED && a + b == total {
            allowed[v as usize] = true;
        }
    }
    allowed[from as usize] = true;
    allowed[to as usize] = true;

    // Collect allowed out-neighbors per node lazily.
    let neighbors_of = |v: u32| -> Vec<u32> {
        let mut out = Vec::new();
        graph.out_edges(v, &mut |w| {
            if (w as usize) < n && allowed[w as usize] {
                out.push(w);
            }
        });
        out
    };

    // Iterative DFS over the allowed subgraph.
    let mut paths: Vec<Vec<u32>> = Vec::new();
    let mut path: Vec<u32> = vec![from];
    let mut on_path = vec![false; n];
    on_path[from as usize] = true;
    // (node, neighbors, next neighbor index to try)
    let mut stack: Vec<(u32, Vec<u32>, usize)> = vec![(from, neighbors_of(from), 0)];
    let mut steps = 0usize;
    let step_budget = 4_000_000usize;

    while let Some(top) = stack.last_mut() {
        if paths.len() >= k || steps > step_budget {
            break;
        }
        let (_v, nbrs, pi) = (top.0, &top.1, top.2);
        if pi >= nbrs.len() {
            let (v, _, _) = stack.pop().unwrap();
            on_path[v as usize] = false;
            path.pop();
            continue;
        }
        let w = nbrs[pi];
        top.2 += 1;
        steps += 1;
        let wi = w as usize;
        if wi >= n || on_path[wi] {
            continue;
        }
        if w == to {
            let mut p = path.clone();
            p.push(to);
            paths.push(p);
            continue;
        }
        on_path[wi] = true;
        path.push(w);
        let nb = neighbors_of(w);
        stack.push((w, nb, 0));
    }
    PathList {
        truncated: !stack.is_empty(),
        paths,
    }
}

/// Up to `limit` distinct *simple* dependency chains from `from` to `to`
/// whose hop count is at most `max_depth`.
///
/// Unlike [`k_shortest_paths`] this is not restricted to shortest chains —
/// it enumerates every simple path within the depth bound via iterative
/// DFS. Deterministic: neighbors are visited in view order. Bounded by
/// `limit` results and an internal step budget so dense graphs cannot
/// hang the caller; when the budget trips, results are a deterministic
/// prefix of the full enumeration.
pub fn paths_within_depth<G: GraphView>(
    graph: &G,
    from: u32,
    to: u32,
    max_depth: u32,
    limit: usize,
) -> PathList {
    if limit == 0 {
        return PathList {
            paths: Vec::new(),
            truncated: false,
        };
    }
    if from == to {
        return PathList {
            paths: vec![vec![from]],
            truncated: false,
        };
    }
    if from as usize >= graph.n_nodes() || to as usize >= graph.n_nodes() {
        return PathList {
            paths: Vec::new(),
            truncated: false,
        };
    }
    let n = graph.n_nodes();
    // dist[v] = hops from v to `to` (reverse BFS). Any partial path that
    // can't reach `to` within the remaining depth budget is pruned, which
    // keeps the step budget from being wasted on dead ends.
    let dist = bfs(graph, &[to], Dir::In, None);
    if dist[from as usize] == UNVISITED || dist[from as usize] > max_depth {
        return PathList {
            paths: Vec::new(),
            truncated: false,
        };
    }
    let neighbors_of = |v: u32| -> Vec<u32> {
        let mut out = Vec::new();
        graph.out_edges(v, &mut |w| {
            if (w as usize) < n {
                out.push(w);
            }
        });
        out
    };
    // Precompute each node's allowed out-neighbors once: neighbors that
    // can still reach `to` within the depth bound from *some* position —
    // the tight per-position check happens during DFS.
    let mut paths: Vec<Vec<u32>> = Vec::new();
    let mut path: Vec<u32> = vec![from];
    let mut on_path = vec![false; n];
    on_path[from as usize] = true;
    // (node, neighbors, next neighbor index, node depth in `path`)
    let mut stack: Vec<(u32, Vec<u32>, usize, u32)> =
        vec![(from, neighbors_of(from), 0, 0)];
    let mut steps = 0usize;
    let step_budget = 4_000_000usize;

    while let Some(top) = stack.last_mut() {
        if paths.len() >= limit || steps > step_budget {
            break;
        }
        let depth = top.3;
        if top.2 >= top.1.len() {
            let (v, _, _, _) = stack.pop().unwrap();
            on_path[v as usize] = false;
            path.pop();
            continue;
        }
        let w = top.1[top.2];
        top.2 += 1;
        steps += 1;
        let wi = w as usize;
        if wi >= n || on_path[wi] {
            continue;
        }
        if w == to {
            if depth + 1 <= max_depth {
                let mut p = path.clone();
                p.push(to);
                paths.push(p);
            }
            continue;
        }
        // Prune: w must reach `to` within the hops left after taking w.
        let dw = dist[wi];
        if dw == UNVISITED || depth + 1 + dw > max_depth {
            continue;
        }
        on_path[wi] = true;
        path.push(w);
        let nb = neighbors_of(w);
        stack.push((w, nb, 0, depth + 1));
    }
    PathList {
        truncated: !stack.is_empty(),
        paths,
    }
}

/// Weighted shortest path (Dijkstra) over forward edges.
/// `weight_of(from, to)` supplies the edge weight; return `None` for "no
/// edge". Returns node ids plus total cost.
pub fn shortest_path_weighted<G, F>(
    graph: &G,
    from: u32,
    to: u32,
    weight_of: F,
) -> Option<(Vec<u32>, f64)>
where
    G: GraphView,
    F: Fn(u32, u32) -> Option<f64>,
{
    let n = graph.n_nodes();
    if from as usize >= n || to as usize >= n {
        return None;
    }
    let mut dist = vec![f64::INFINITY; n];
    let mut parent = vec![UNVISITED; n];
    let mut heap = BinaryHeap::new();
    dist[from as usize] = 0.0;
    heap.push(State {
        cost: 0.0,
        node: from,
    });
    while let Some(State { cost, node }) = heap.pop() {
        if cost > dist[node as usize] {
            continue;
        }
        if node == to {
            break;
        }
        graph.out_edges(node, &mut |w| {
            let wi = w as usize;
            if wi >= n {
                return;
            }
            let Some(weight) = weight_of(node, w) else {
                return;
            };
            if weight < 0.0 {
                return; // Dijkstra requires non-negative weights
            }
            let nd = cost + weight;
            if nd < dist[wi] {
                dist[wi] = nd;
                parent[wi] = node;
                heap.push(State { cost: nd, node: w });
            }
        });
    }
    if !dist[to as usize].is_finite() {
        return None;
    }
    let mut path = vec![to];
    let mut cur = to;
    while cur != from {
        cur = parent[cur as usize];
        path.push(cur);
    }
    path.reverse();
    Some((path, dist[to as usize]))
}

/// Weighted shortest path (Dijkstra) specialized for [`crate::Graph`]:
/// zips `out_targets` with `out_weights` directly — O(E log V), no
/// per-edge weight lookups. Returns `None` if `to` is unreachable.
/// Unweighted graphs are treated as all-ones weights.
pub fn shortest_path_weighted_csr(
    graph: &crate::Graph,
    from: u32,
    to: u32,
) -> Option<(Vec<u32>, f64)> {
    if from == to {
        return Some((vec![from], 0.0));
    }
    let n = graph.n_nodes() as usize;
    if from as usize >= n || to as usize >= n {
        return None;
    }
    let mut dist = vec![f64::INFINITY; n];
    let mut parent = vec![UNVISITED; n];
    let mut heap = BinaryHeap::new();
    dist[from as usize] = 0.0;
    heap.push(State {
        cost: 0.0,
        node: from,
    });
    while let Some(State { cost, node }) = heap.pop() {
        if cost > dist[node as usize] {
            continue;
        }
        if node == to {
            break;
        }
        let targets = graph.out_targets(node);
        let weights = graph.out_weights(node);
        for (i, &w) in targets.iter().enumerate() {
            let wi = w as usize;
            if wi >= n {
                continue;
            }
            let weight = weights.map(|ws| ws[i] as f64).unwrap_or(1.0);
            if weight < 0.0 {
                continue;
            }
            let nd = cost + weight;
            if nd < dist[wi] {
                dist[wi] = nd;
                parent[wi] = node;
                heap.push(State { cost: nd, node: w });
            }
        }
    }
    if !dist[to as usize].is_finite() {
        return None;
    }
    let mut path = vec![to];
    let mut cur = to;
    while cur != from {
        cur = parent[cur as usize];
        path.push(cur);
    }
    path.reverse();
    Some((path, dist[to as usize]))
}

#[derive(Clone, Copy)]
struct State {
    cost: f64,
    node: u32,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.node == other.node
    }
}
impl Eq for State {}
impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for State {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap by cost, then node id for determinism.
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.node.cmp(&self.node))
    }
}
