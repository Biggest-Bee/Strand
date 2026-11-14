//! Strongly connected components via **iterative** Tarjan (no recursion, so
//! deep graphs cannot overflow the stack), plus condensation into a DAG.

use std::collections::BTreeSet;

use crate::view::GraphView;

/// Tarjan's SCC algorithm, iterative.
///
/// Returns components in reverse topological order of the condensation:
/// if component C has an edge to component D, D is emitted before C.
/// Since `A -> B` means "A depends on B", emission order is therefore
/// *dependencies-first* — exactly build order.
pub fn strongly_connected<G: GraphView>(graph: &G) -> Vec<Vec<u32>> {
    let n = graph.n_nodes();
    let mut index = vec![u32::MAX; n]; // discovery index
    let mut low = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut next_index = 0u32;
    let mut sccs: Vec<Vec<u32>> = Vec::new();

    let out_neighbors = |v: u32| -> Vec<u32> {
        let mut out = Vec::new();
        graph.out_edges(v, &mut |w| {
            if (w as usize) < n {
                out.push(w);
            }
        });
        out
    };

    // Explicit DFS stack: (node, neighbors, next neighbor position).
    let mut call: Vec<(u32, Vec<u32>, usize)> = Vec::new();

    for s in 0..n as u32 {
        if index[s as usize] != u32::MAX {
            continue;
        }
        index[s as usize] = next_index;
        low[s as usize] = next_index;
        next_index += 1;
        stack.push(s);
        on_stack[s as usize] = true;
        call.push((s, out_neighbors(s), 0));

        while let Some(top) = call.last_mut() {
            let (v, nbrs, pi) = (top.0, &top.1, top.2);
            if pi < nbrs.len() {
                let w = nbrs[pi];
                top.2 += 1;
                let wi = w as usize;
                if wi >= n {
                    continue;
                }
                if index[wi] == u32::MAX {
                    index[wi] = next_index;
                    low[wi] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[wi] = true;
                    let nb = out_neighbors(w);
                    call.push((w, nb, 0));
                } else if on_stack[wi] {
                    let iw = index[wi];
                    if iw < low[v as usize] {
                        low[v as usize] = iw;
                    }
                }
            } else {
                // Finished v: propagate lowlink to parent, maybe emit SCC.
                let v = top.0;
                call.pop();
                if low[v as usize] == index[v as usize] {
                    let mut comp = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack[w as usize] = false;
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    comp.sort_unstable();
                    sccs.push(comp);
                }
                if let Some(&(p, _, _)) = call.last() {
                    let lv = low[v as usize];
                    if lv < low[p as usize] {
                        low[p as usize] = lv;
                    }
                }
            }
        }
    }
    sccs
}

/// The condensation DAG of an SCC decomposition.
#[derive(Debug)]
pub struct Condensation {
    /// component id per node
    pub comp: Vec<u32>,
    /// members of each component (sorted node ids)
    pub members: Vec<Vec<u32>>,
    /// `adj[c]` = sorted, deduplicated component ids that `c` depends on
    /// (i.e. original edges c -> d, c != d).
    pub adj: Vec<Vec<u32>>,
}

/// Build the condensation DAG from an SCC list (as returned by
/// [`strongly_connected`]). Component ids follow the SCC list order.
pub fn condensation<G: GraphView>(graph: &G, sccs: &[Vec<u32>]) -> Condensation {
    let n = graph.n_nodes();
    let mut comp = vec![u32::MAX; n];
    for (cid, members) in sccs.iter().enumerate() {
        for &v in members {
            comp[v as usize] = cid as u32;
        }
    }
    let mut sets: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); sccs.len()];
    for v in 0..n as u32 {
        let cv = comp[v as usize];
        graph.out_edges(v, &mut |w| {
            if (w as usize) < n {
                let cw = comp[w as usize];
                if cw != cv && cw != u32::MAX {
                    sets[cv as usize].insert(cw);
                }
            }
        });
    }
    Condensation {
        comp,
        members: sccs.to_vec(),
        adj: sets.into_iter().map(|s| s.into_iter().collect()).collect(),
    }
}
