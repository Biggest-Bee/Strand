//! [`GraphView`]: the minimal topology interface every algorithm runs on.
//!
//! Implemented by [`crate::Graph`] (zero-copy mmap CSR) and by the
//! read-write store's merged base+delta view (`strand-store`), so all
//! Phase-1 analyses work unchanged on either.
//!
//! Edge convention: `u -> v` means "u depends on v".
//! - `out_edges(u)` = dependencies of `u`
//! - `in_edges(u)`  = dependents of `u` (impact direction)

/// Topology access used by all algorithms. Implementations must guarantee
/// neighbor ids are `< n_nodes()` and must be `Send + Sync` (algorithms
/// parallelize with rayon).
pub trait GraphView: Send + Sync {
    /// Number of nodes (dense ids `0..n_nodes`).
    fn n_nodes(&self) -> usize;

    /// Number of edges (default: sums out-degrees, O(E)).
    fn n_edges(&self) -> usize {
        (0..self.n_nodes() as u32).map(|i| self.out_degree(i)).sum()
    }

    /// Call `f` on each dependency of `id` (forward neighbors).
    fn out_edges(&self, id: u32, f: &mut dyn FnMut(u32));

    /// Call `f` on each dependent of `id` (reverse neighbors).
    fn in_edges(&self, id: u32, f: &mut dyn FnMut(u32));

    /// Display name of `id`. Only used by CLI/reporting code, never by the
    /// algorithms themselves.
    fn node_name(&self, id: u32) -> String;

    /// Number of dependencies of `id` (default: counts via `out_edges`).
    fn out_degree(&self, id: u32) -> usize {
        let mut n = 0usize;
        self.out_edges(id, &mut |_| n += 1);
        n
    }

    /// Number of dependents of `id` (default: counts via `in_edges`).
    fn in_degree(&self, id: u32) -> usize {
        let mut n = 0usize;
        self.in_edges(id, &mut |_| n += 1);
        n
    }

    /// Edge-kind tags parallel to `out_edges` iteration order, if the
    /// backing store records them. `None` = all edges are `Static`.
    fn out_kinds(&self, _id: u32) -> Option<&[u8]> {
        None
    }

    /// Edge-kind tags parallel to `in_edges` iteration order.
    fn in_kinds(&self, _id: u32) -> Option<&[u8]> {
        None
    }
}

impl GraphView for crate::Graph {
    #[inline]
    fn n_nodes(&self) -> usize {
        self.n_nodes() as usize
    }

    #[inline]
    fn n_edges(&self) -> usize {
        self.n_edges() as usize
    }

    #[inline]
    fn out_edges(&self, id: u32, f: &mut dyn FnMut(u32)) {
        for &w in self.out_targets(id) {
            f(w);
        }
    }

    #[inline]
    fn in_edges(&self, id: u32, f: &mut dyn FnMut(u32)) {
        for &w in self.in_targets(id) {
            f(w);
        }
    }

    #[inline]
    fn node_name(&self, id: u32) -> String {
        crate::Graph::node_name(self, id).to_string()
    }

    #[inline]
    fn out_degree(&self, id: u32) -> usize {
        crate::Graph::out_targets(self, id).len()
    }

    #[inline]
    fn in_degree(&self, id: u32) -> usize {
        crate::Graph::in_targets(self, id).len()
    }

    #[inline]
    fn out_kinds(&self, id: u32) -> Option<&[u8]> {
        crate::Graph::out_kinds(self, id)
    }

    #[inline]
    fn in_kinds(&self, id: u32) -> Option<&[u8]> {
        crate::Graph::in_kinds(self, id)
    }
}

/// A [`GraphView`] that hides edges below a confidence threshold.
/// Wrap any view; edges whose kind tag is `< min` are skipped during
/// traversal. Views without kind data pass everything through
/// (unknown provenance is treated as fully trusted).
pub struct ConfidenceView<'a, T: GraphView + ?Sized> {
    pub inner: &'a T,
    /// Minimum [`crate::EdgeKind::confidence`] to traverse.
    pub min: u8,
}

impl<'a, T: GraphView + ?Sized> ConfidenceView<'a, T> {
    pub fn new(inner: &'a T, min: u8) -> Self {
        ConfidenceView { inner, min }
    }
}

impl<T: GraphView + ?Sized> GraphView for ConfidenceView<'_, T> {
    #[inline]
    fn n_nodes(&self) -> usize {
        self.inner.n_nodes()
    }

    #[inline]
    fn n_edges(&self) -> usize {
        self.inner.n_edges()
    }

    fn out_edges(&self, id: u32, f: &mut dyn FnMut(u32)) {
        let kinds = self.inner.out_kinds(id);
        let mut i = 0usize;
        self.inner.out_edges(id, &mut |w| {
            let tag = kinds.and_then(|ks| ks.get(i).copied()).unwrap_or(4);
            if crate::EdgeKind::from_tag(tag).confidence() >= self.min {
                f(w);
            }
            i += 1;
        });
    }

    fn in_edges(&self, id: u32, f: &mut dyn FnMut(u32)) {
        let kinds = self.inner.in_kinds(id);
        let mut i = 0usize;
        self.inner.in_edges(id, &mut |w| {
            let tag = kinds.and_then(|ks| ks.get(i).copied()).unwrap_or(4);
            if crate::EdgeKind::from_tag(tag).confidence() >= self.min {
                f(w);
            }
            i += 1;
        });
    }

    #[inline]
    fn node_name(&self, id: u32) -> String {
        self.inner.node_name(id)
    }

    // Kind slices stay aligned with the *unfiltered* inner adjacency;
    // exposing them here would mis-pair kinds with the filtered edge
    // stream, so report "no kind data" instead.
    #[inline]
    fn out_kinds(&self, _id: u32) -> Option<&[u8]> {
        None
    }

    #[inline]
    fn in_kinds(&self, _id: u32) -> Option<&[u8]> {
        None
    }
}
