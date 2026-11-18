//! Read view: the merged graph of immutable base CSR + in-memory delta.
//! Implements [`strand_core::view::GraphView`] so every Phase-1 algorithm
//! runs on it unchanged.

use std::collections::BTreeSet;
use std::collections::btree_map::Iter as BTreeIter;
use std::iter::Peekable;

use strand_core::graph::Graph;
use strand_core::view::GraphView;

use crate::delta::{Delta, EdgeOp};

/// A consistent point-in-time view of the store.
///
/// Cheap to create (two `Arc` clones); all data is borrowed, nothing is
/// copied. When the delta is empty, neighbor iteration degenerates to the
/// pure base CSR slices.
pub struct View<'a> {
    pub(crate) base: Option<&'a Graph>,
    pub(crate) base_n: u64,
    pub(crate) delta: &'a Delta,
    pub(crate) n_nodes: usize,
    /// Precomputed `delta.is_noop()` — checked on every neighbor call.
    pub(crate) noop: bool,
    /// Precomputed `delta.removed.is_empty()`.
    pub(crate) no_removed: bool,
}

impl<'a> View<'a> {
    /// Build a view, precomputing the delta flags used by the hot paths.
    pub(crate) fn new(
        base: Option<&'a Graph>,
        base_n: u64,
        delta: &'a Delta,
        n_nodes: usize,
    ) -> Self {
        View {
            base,
            base_n,
            delta,
            n_nodes,
            noop: delta.is_noop(),
            no_removed: delta.removed.is_empty(),
        }
    }
}

/// Merge state for one node's adjacency: sorted base slice + sorted delta
/// op-map + removed-node set. Yields surviving `(neighbor, weight)` pairs.
struct Merger<'a, 'b> {
    base: &'a [u32],
    base_w: Option<&'a [f32]>,
    delta: Option<Peekable<BTreeIter<'b, u32, EdgeOp>>>,
    removed: &'a BTreeSet<u32>,
    bi: usize,
}

impl<'a, 'b> Merger<'a, 'b> {
    /// Next surviving edge as `(target, weight)`, or `None` when exhausted.
    /// Deleted (`Del`) and removed-node edges are skipped internally.
    fn next_edge(&mut self) -> Option<(u32, f32)> {
        // Fast path: no pending delta ops -> drain the sorted base slice
        // directly (this is every node untouched by the delta).
        let delta_pending = self
            .delta
            .as_mut()
            .map_or(false, |it| it.peek().is_some());
        if !delta_pending {
            while self.bi < self.base.len() {
                let t = self.base[self.bi];
                self.bi += 1;
                if !self.removed.contains(&t) {
                    let w = self.base_w.map(|ws| ws[self.bi - 1]).unwrap_or(1.0);
                    return Some((t, w));
                }
            }
            return None;
        }
        loop {
            let bv = self.base.get(self.bi).copied();
            let dv = self
                .delta
                .as_mut()
                .and_then(|it| it.peek().map(|e| *e.0));
            let take_base = match (bv, dv) {
                (Some(_), Some(_)) => bv <= dv,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return None,
            };
            if take_base {
                let t = bv.unwrap();
                self.bi += 1;
                if dv == Some(t) {
                    // Delta overrides the base edge entirely.
                    let (_, op) = self.delta.as_mut().unwrap().next().unwrap();
                    match *op {
                        EdgeOp::Set(w) => {
                            if !self.removed.contains(&t) {
                                return Some((t, w));
                            }
                        }
                        EdgeOp::Del => {}
                    }
                } else if !self.removed.contains(&t) {
                    let w = self.base_w.map(|ws| ws[self.bi - 1]).unwrap_or(1.0);
                    return Some((t, w));
                }
            } else {
                let d = dv.unwrap();
                let (_, op) = self.delta.as_mut().unwrap().next().unwrap();
                if let EdgeOp::Set(w) = *op {
                    if !self.removed.contains(&d) {
                        return Some((d, w));
                    }
                }
            }
        }
    }
}

impl<'a> View<'a> {
    /// Node id for `name`, or `None`. Delta-added names shadow base names:
    /// a name re-added after removal resolves to its newest incarnation.
    /// Tombstoned (removed) nodes never resolve.
    pub fn node_id(&self, name: &str) -> Option<u32> {
        if let Some(id) = self.delta.added_id(name) {
            return (!self.delta.removed.contains(&id)).then_some(id);
        }
        self.base
            .and_then(|b| b.node_id(name))
            .filter(|id| !self.delta.removed.contains(id))
    }

    /// Node name as `&str` (avoids the `String` alloc of the trait method).
    pub fn node_name_ref(&self, id: u32) -> Option<&'a str> {
        if id < self.base_n as u32 {
            return self.base.map(|b| b.node_name(id));
        }
        self.delta.added_name(self.base_n, id)
    }

    /// Build the merger for one direction of `id`.
    fn merger(&self, id: u32, out_dir: bool) -> Option<Merger<'a, 'a>> {
        if id as usize >= self.n_nodes || self.delta.removed.contains(&id) {
            return None;
        }
        let is_base_node = (id as u64) < self.base_n;
        let (base, base_w, dmap) = match (self.base, out_dir) {
            (Some(b), true) if is_base_node => (
                b.out_targets(id),
                if b.has_weights() { b.out_weights(id) } else { None },
                self.delta.out.get(&id),
            ),
            (Some(b), false) if is_base_node => (
                b.in_targets(id),
                if b.has_weights() { b.in_weights(id) } else { None },
                self.delta.inn.get(&id),
            ),
            _ => (&[][..], None, if out_dir { self.delta.out.get(&id) } else { self.delta.inn.get(&id) }),
        };
        Some(Merger {
            base,
            base_w,
            delta: dmap.map(|m| m.iter().peekable()),
            removed: &self.delta.removed,
            bi: 0,
        })
    }

    /// All out-edges of `id` as `(neighbor, weight)` pairs. Used by compaction.
    pub(crate) fn merged_out(&self, id: u32) -> Vec<(u32, f32)> {
        let mut out = Vec::new();
        if let Some(mut m) = self.merger(id, true) {
            while let Some(e) = m.next_edge() {
                out.push(e);
            }
        }
        out
    }
}

impl<'a> GraphView for View<'a> {
    fn n_nodes(&self) -> usize {
        self.n_nodes
    }

    fn out_edges(&self, id: u32, f: &mut dyn FnMut(u32)) {
        if self.noop {
            // Fast path: pure base CSR, no merge work at all.
            if let Some(b) = self.base {
                if (id as u64) < self.base_n {
                    for &t in b.out_targets(id) {
                        f(t);
                    }
                }
            }
            return;
        }
        // Per-node fast path: delta has no ops for this node and nothing
        // was removed, so its adjacency is exactly the base slice.
        if self.no_removed
            && !self.delta.out.contains_key(&id)
            && (id as u64) < self.base_n
        {
            if let Some(b) = self.base {
                for &t in b.out_targets(id) {
                    f(t);
                }
            }
            return;
        }
        if let Some(mut m) = self.merger(id, true) {
            while let Some((t, _)) = m.next_edge() {
                f(t);
            }
        }
    }

    fn in_edges(&self, id: u32, f: &mut dyn FnMut(u32)) {
        if self.noop {
            if let Some(b) = self.base {
                if (id as u64) < self.base_n {
                    for &t in b.in_targets(id) {
                        f(t);
                    }
                }
            }
            return;
        }
        if self.no_removed
            && !self.delta.inn.contains_key(&id)
            && (id as u64) < self.base_n
        {
            if let Some(b) = self.base {
                for &t in b.in_targets(id) {
                    f(t);
                }
            }
            return;
        }
        if let Some(mut m) = self.merger(id, false) {
            while let Some((t, _)) = m.next_edge() {
                f(t);
            }
        }
    }

    fn node_name(&self, id: u32) -> String {
        self.node_name_ref(id)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("#{id}"))
    }
}
