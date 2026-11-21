//! Strand core: a memory-mapped CSR graph engine plus dependency/impact
//! analysis algorithms.
//!
//! File format version 1 is documented in `docs/FORMAT.md`.

pub mod algo;
pub mod builder;
pub mod format;
pub mod graph;
mod mmap;
pub mod view;

pub use builder::{BuildStats, Edge, GraphBuilder, MergeOp};
pub use graph::Graph;

/// Provenance/confidence of a single edge, ordered by trust:
/// `Heuristic` < `Traced` < `Declared` < `Resolved` < `Static`.
///
/// `--min-confidence`-style filters keep edges with
/// [`EdgeKind::confidence`] >= the threshold. Files written before
/// edge kinds existed report every edge as [`EdgeKind::Static`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(u8)]
pub enum EdgeKind {
    /// Inferred, not observed (e.g. a parent module guessed from
    /// directory layout). Lowest trust.
    Heuristic = 0,
    /// Observed at runtime (`strand trace`) - real, but only covers
    /// the paths the command exercised.
    Traced = 1,
    /// Explicitly declared by config or comment: `# strand:
    /// depends-on`, entry-point targets, `pytest_plugins`,
    /// `INSTALLED_APPS`, `conftest.py` wiring.
    Declared = 2,
    /// Deterministically resolved from literals: const-propagated
    /// `import_module`, glob expansions, `entry_points(group=)`
    /// consumer links.
    Resolved = 3,
    /// Directly parsed syntax: `import`, `use`, `mod`, literal
    /// `require`/`import()`. Highest trust; the default.
    #[default]
    Static = 4,
}

impl EdgeKind {
    /// Numeric confidence for threshold comparisons (0..=4).
    #[inline]
    pub fn confidence(self) -> u8 {
        self as u8
    }

    /// Decode an on-disk kind tag; unknown tags read as `Static`
    /// (forward-compatible: newer kinds never lower trust silently
    /// below what an old reader assumes... they do, but `Static` is
    /// the least surprising fallback for filtering).
    #[inline]
    pub fn from_tag(tag: u8) -> EdgeKind {
        match tag {
            0 => EdgeKind::Heuristic,
            1 => EdgeKind::Traced,
            2 => EdgeKind::Declared,
            3 => EdgeKind::Resolved,
            _ => EdgeKind::Static,
        }
    }

    #[inline]
    pub fn as_tag(self) -> u8 {
        self as u8
    }
}

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by strand-core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The file is not a valid strand graph (bad magic, version,
    /// checksum, bounds, or inconsistent section layout).
    #[error("invalid strand file: {0}")]
    Invalid(String),

    /// Generic usage/input error (CLI args, parse failures, rule
    /// violations) - not a corrupt graph file.
    #[error("{0}")]
    Usage(String),

    /// A node name was not present in the graph.
    #[error("node not found: {0}")]
    NodeNotFound(String),
}
