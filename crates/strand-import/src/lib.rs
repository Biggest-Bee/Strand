//! Importers that produce `(src, dst, weight)` edge lists for
//! [`strand_core::GraphBuilder`].
//!
//! Edge direction convention everywhere: `A -> B` means "A depends on B".

pub mod cargo;
pub mod csv;

use strand_core::{Error, Result};

/// Input formats understood by [`parse`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Generic CSV/TSV edge list: `src,dst[,weight]` per line.
    Csv,
    /// `cargo metadata --format-version 1` JSON output.
    Cargo,
}

/// One parsed edge: `src -> dst` ("src depends on dst"), optional weight.
pub type EdgeList = Vec<(String, String, Option<f32>)>;

/// Parse `text` according to `format`.
pub fn parse(text: &str, format: Format) -> Result<EdgeList> {
    match format {
        Format::Csv => csv::parse(text),
        Format::Cargo => cargo::parse(text),
    }
}

/// Auto-detect format from file content/extension.
///
/// `.json` extension or leading `{` => cargo metadata; otherwise CSV.
pub fn detect_format(path: &std::path::Path, text: &str) -> Format {
    if path.extension().is_some_and(|e| e == "json")
        || text.trim_start().starts_with('{')
    {
        Format::Cargo
    } else {
        Format::Csv
    }
}

/// Feed an [`EdgeList`] into a [`strand_core::GraphBuilder`].
pub fn fill_builder(
    edges: EdgeList,
    builder: &mut strand_core::GraphBuilder,
) -> Result<()> {
    for (src, dst, w) in edges {
        if src == dst {
            // Self-loops carry no dependency information; skip them so
            // `cycles` output stays meaningful (cargo dev-deps self-loop
            // on almost every package).
            continue;
        }
        match w {
            Some(w) => builder.add_edge_weighted(src, dst, w),
            None => builder.add_edge(src, dst),
        }
    }
    Ok(())
}

/// Convenience: parse + build in one call.
pub fn build_from_text(
    text: &str,
    format: Format,
    out: &std::path::Path,
) -> Result<strand_core::BuildStats> {
    let edges = parse(text, format)?;
    let mut b = strand_core::GraphBuilder::new();
    fill_builder(edges, &mut b)?;
    b.build(out)
}

pub(crate) fn err(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}
