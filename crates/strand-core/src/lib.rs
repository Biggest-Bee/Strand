//! Strand core: a memory-mapped CSR graph engine plus dependency/impact
//! analysis algorithms.
//!
//! File format version 1 is documented in `docs/FORMAT.md`.

pub mod algo;
pub mod builder;
pub mod format;
pub mod graph;
pub mod view;
mod mmap;

pub use builder::{BuildStats, Edge, GraphBuilder, MergeOp};
pub use graph::Graph;

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
    /// violations) — not a corrupt graph file.
    #[error("{0}")]
    Usage(String),

    /// A node name was not present in the graph.
    #[error("node not found: {0}")]
    NodeNotFound(String),
}
