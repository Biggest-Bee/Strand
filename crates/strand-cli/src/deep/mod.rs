//! Interprocedural analysis engine (vendored from the strand-deep
//! research binary): Python call graph, dynamic-import resolution,
//! and the taint/null/leak summary solver.

pub mod callgraph;
pub mod facts;
pub mod ipa;
pub mod models;
pub mod solver;
