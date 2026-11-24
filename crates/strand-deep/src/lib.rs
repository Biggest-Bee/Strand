//! Interprocedural analysis engine (vendored from the strand-deep
//! research binary): Python call graph, dynamic-import resolution,
//! and the taint/null/leak summary solver.

pub mod analyze;
pub mod callgraph;
pub mod facts;
pub mod facts_js;
pub mod facts_go;
pub mod facts_rs;
pub mod go_deep;
pub mod ipa;
pub mod js_ipa;
pub mod models;
pub mod rust_deep;
pub mod solver;
pub mod solver_go;
pub mod solver_js;
pub mod solver_rs;
