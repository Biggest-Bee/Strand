//! In-memory delta layer: recent writes applied on top of the immutable
//! base CSR. Held behind `Arc` so readers keep a consistent point-in-time
//! view while the writer commits new deltas.

use std::collections::{BTreeMap, BTreeSet};

/// Per-edge operation in the delta.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EdgeOp {
    /// Edge present with this weight (1.0 for unweighted adds).
    Set(f32),
    /// Tombstone: edge removed relative to the base.
    Del,
}

/// The delta: a small write-optimized layer of edge/node changes.
///
/// Invariant: `added_names[i]` is the name of node id `base_n + i`, and
/// `added_ids` is its inverse map.
#[derive(Clone, Default)]
pub struct Delta {
    /// node -> (neighbor -> op) for outgoing (dependency) edges.
    /// `BTreeMap` keeps lookups cheap on small deltas and iteration
    /// deterministic (compaction order stability).
    pub out: BTreeMap<u32, BTreeMap<u32, EdgeOp>>,
    /// node -> (neighbor -> op) for incoming (dependent) edges
    pub inn: BTreeMap<u32, BTreeMap<u32, EdgeOp>>,
    /// names of delta-added nodes, indexed by `id - base_n`
    pub added_names: Vec<String>,
    /// name -> id for delta-added nodes
    pub added_ids: BTreeMap<String, u32>,
    /// node ids removed by `RemoveNode`
    pub removed: BTreeSet<u32>,
    /// whether any weighted edge was added (drives compaction format)
    pub weighted: bool,
    /// cumulative ops applied since the delta was last reset (by
    /// compaction or store open). Drives auto-compaction.
    pub op_count: usize,
}

impl Delta {
    /// True when the delta contributes nothing - readers can then take the
    /// pure-CSR fast path.
    pub fn is_noop(&self) -> bool {
        self.out.is_empty()
            && self.inn.is_empty()
            && self.added_names.is_empty()
            && self.removed.is_empty()
    }

    /// Node id for a delta-added name, if present.
    pub fn added_id(&self, name: &str) -> Option<u32> {
        self.added_ids.get(name).copied()
    }

    /// Name of a delta-added node id (`id - base_n` indexes `added_names`).
    pub fn added_name(&self, base_n: u64, id: u32) -> Option<&str> {
        if id < base_n as u32 {
            return None;
        }
        self.added_names
            .get(id as usize - base_n as usize)
            .map(|s| s.as_str())
    }
}
