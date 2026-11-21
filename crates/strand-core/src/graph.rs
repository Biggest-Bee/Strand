//! Read-only, zero-copy view of a `.strand` file.
//!
//! [`Graph::open`] validates the header, section layout, xxh64 checksum,
//! monotonicity of the CSR offset arrays, target bounds, and name-blob UTF-8
//! before any slice is trusted. All typed access is done through `bytemuck`
//! casts of already bounds-checked byte ranges; the only `unsafe` in the
//! crate is the mmap itself (see `crate::mmap`).

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;
use rayon::prelude::*;
use xxhash_rust::xxh64::xxh64;

use crate::format::{self, Header, N_SECTIONS};
use crate::{Error, Result};

/// Parsed `node_meta` kind table (only present when the builder wrote kinds).
#[derive(Debug)]
pub struct NodeKinds {
    /// kind index per node id (`u32::MAX` = untyped)
    pub ids: Vec<u32>,
    /// interned kind names, indexed by `ids`
    pub names: Vec<String>,
}

/// An open `.strand` graph.
pub struct Graph {
    mmap: Mmap,
    header: Header,
    /// Absolute `(offset, len)` byte range of each section.
    ranges: [(usize, usize); N_SECTIONS],
    kinds: Option<NodeKinds>,
    /// Absolute mmap offsets of the edge-kind tables inside
    /// `node_meta`: `(fwd_off, rev_off)`, each `n_edges` bytes long.
    /// `None` for files written before edge kinds existed.
    edge_kinds: Option<(usize, usize)>,
}

impl Graph {
    /// Open and fully validate a `.strand` file.
    pub fn open(path: impl AsRef<Path>) -> Result<Graph> {
        let file = File::open(path)?;
        let mmap = crate::mmap::map_readonly(&file)?;
        if mmap.len() < format::HEADER_LEN {
            return Err(Error::Invalid(format!(
                "file too small: {} bytes",
                mmap.len()
            )));
        }
        let header = format::decode_header(&mmap[..format::HEADER_LEN])?;

        // Locate the name-offsets section first (its position depends only on
        // n_nodes/n_edges/weights), read the name-blob length, then compute
        // the full layout.
        let lay0 = format::layout(&header, 0, 0);
        check_range(&mmap, lay0[format::sec::NAME_OFFSETS], "name_offsets")?;
        let name_offsets_len = lay0[format::sec::NAME_OFFSETS].1;
        let last_off_pos = lay0[format::sec::NAME_OFFSETS].0 + name_offsets_len - 8;
        let name_bytes_len = read_u64(&mmap, last_off_pos as usize)?;

        // node_meta is the last section; its length is whatever remains.
        let lay1 = format::layout(&header, name_bytes_len, 0);
        let meta_off = lay1[format::sec::NODE_META].0;
        if meta_off > mmap.len() as u64 {
            return Err(Error::Invalid("section offsets exceed file length".into()));
        }
        let meta_len = mmap.len() as u64 - meta_off;

        let lay = format::layout(&header, name_bytes_len, meta_len);
        // Every computed section must lie inside the file.
        for (i, &(off, len)) in lay.iter().enumerate() {
            let end = off
                .checked_add(len)
                .ok_or_else(|| Error::Invalid(format!("section {i} offset overflow")))?;
            if end > mmap.len() as u64 {
                return Err(Error::Invalid(format!(
                    "section {i} [{off}, {end}) exceeds file length {}",
                    mmap.len()
                )));
            }
        }
        // The stored section table must match the deterministic layout.
        for (i, &(off, _)) in lay.iter().enumerate() {
            if header.section_offsets[i] != off {
                return Err(Error::Invalid(format!(
                    "section {i} offset mismatch: stored {}, computed {off}",
                    header.section_offsets[i]
                )));
            }
        }

        // Checksum over everything after the header.
        let actual = xxh64(&mmap[format::HEADER_LEN..], 0);
        if actual != header.checksum {
            return Err(Error::Invalid(format!(
                "checksum mismatch: stored {:016x}, computed {:016x}",
                header.checksum, actual
            )));
        }

        let mut g = Graph {
            mmap,
            header,
            ranges: [(0, 0); N_SECTIONS],
            kinds: None,
            edge_kinds: None,
        };
        for (i, &(off, len)) in lay.iter().enumerate() {
            g.ranges[i] = (off as usize, len as usize);
        }
        g.validate_offsets()?;
        g.validate_names()?;
        let (kinds, edge_kinds) = g.parse_meta()?;
        g.kinds = kinds;
        g.edge_kinds = edge_kinds;
        Ok(g)
    }

    fn validate_offsets(&self) -> Result<()> {
        let n_edges = self.header.n_edges;
        for &sec in &[
            format::sec::FWD_OFFSETS,
            format::sec::REV_OFFSETS,
            format::sec::NAME_OFFSETS,
        ] {
            let offs = self.u64s(sec)?;
            if offs.is_empty() {
                return Err(Error::Invalid("empty offsets section".into()));
            }
            // Monotonic non-decreasing.
            if offs.windows(2).any(|w| w[0] > w[1]) {
                return Err(Error::Invalid("offsets not monotonic".into()));
            }
        }
        let fwd = self.u64s(format::sec::FWD_OFFSETS)?;
        let rev = self.u64s(format::sec::REV_OFFSETS)?;
        if *fwd.last().unwrap() != n_edges {
            return Err(Error::Invalid("fwd_offsets last != n_edges".into()));
        }
        if *rev.last().unwrap() != n_edges {
            return Err(Error::Invalid("rev_offsets last != n_edges".into()));
        }

        // Every target/source id must be a valid node id. Parallel scan.
        let n_nodes = self.header.n_nodes;
        for sec in [format::sec::FWD_TARGETS, format::sec::REV_SOURCES] {
            let targets = self.u32s(sec)?;
            let ok = targets
                .par_chunks(1 << 20)
                .all(|chunk| chunk.iter().all(|&t| (t as u64) < n_nodes));
            if !ok {
                return Err(Error::Invalid(format!(
                    "section {sec} contains out-of-range node id"
                )));
            }
        }
        Ok(())
    }

    fn validate_names(&self) -> Result<()> {
        let name_bytes = self.bytes(format::sec::NAME_BYTES);
        std::str::from_utf8(name_bytes)
            .map_err(|e| Error::Invalid(format!("name_bytes not utf-8: {e}")))?;
        let name_offsets = self.u64s(format::sec::NAME_OFFSETS)?;
        let nb_len = name_bytes.len() as u64;
        if *name_offsets.last().unwrap() != nb_len {
            return Err(Error::Invalid("name_offsets last != name_bytes len".into()));
        }
        // name_index entries must be valid node ids.
        let name_index = self.u32s(format::sec::NAME_INDEX)?;
        let n_nodes = self.header.n_nodes;
        if name_index.iter().any(|&i| i as u64 >= n_nodes) {
            return Err(Error::Invalid("name_index out of range".into()));
        }
        Ok(())
    }

    /// Parse the optional `node_meta` section into an owned kind table
    /// plus the edge-kind table offsets. Layout: `[u64 payload_len]
    /// [payload]` where payload is `u32 nkinds`, `nkinds` x (`u32 len`
    /// + utf8 name), `n_nodes` x `u32 kind_id`, then optionally
    /// `2 * n_edges` bytes of edge-kind tags (fwd CSR order, then rev
    /// CSR order). Files without edge kinds simply end after the ids.
    fn parse_meta(&self) -> Result<(Option<NodeKinds>, Option<(usize, usize)>)> {
        let (off, len) = self.ranges[format::sec::NODE_META];
        if len < 8 {
            return Ok((None, None));
        }
        let payload_len = read_u64(&self.mmap, off)? as usize;
        if payload_len + 8 > len {
            return Ok((None, None)); // trailing padding only
        }
        if payload_len == 0 {
            return Ok((None, None));
        }
        let p = &self.mmap[off + 8..off + 8 + payload_len];
        let mut cur = 0usize;
        let take = |cur: &mut usize, n: usize| -> Result<&[u8]> {
            if *cur + n > p.len() {
                return Err(Error::Invalid("node_meta truncated".into()));
            }
            let s = &p[*cur..*cur + n];
            *cur += n;
            Ok(s)
        };
        let nkinds = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
        // Each kind entry needs at least a u32 length prefix.
        if nkinds > p.len() / 4 {
            return Err(Error::Invalid("node_meta kind count unreasonable".into()));
        }
        let mut names = Vec::with_capacity(nkinds);
        for _ in 0..nkinds {
            let klen = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
            let bytes = take(&mut cur, klen)?;
            names.push(
                std::str::from_utf8(bytes)
                    .map_err(|e| Error::Invalid(format!("node_meta kind not utf-8: {e}")))?
                    .to_string(),
            );
        }
        let n_nodes = self.header.n_nodes as usize;
        let mut ids = Vec::with_capacity(n_nodes);
        for _ in 0..n_nodes {
            let v = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap());
            if v != u32::MAX && v as usize >= names.len() {
                return Err(Error::Invalid("node_meta kind id out of range".into()));
            }
            ids.push(v);
        }
        let kinds = Some(NodeKinds { ids, names });

        // Optional edge-kind tail: exactly 2 * n_edges bytes.
        let remaining = p.len() - cur;
        let n_edges = self.header.n_edges as usize;
        let edge_kinds = if remaining == 0 {
            None
        } else if remaining == 2 * n_edges {
            let base = off + 8 + cur;
            Some((base, base + n_edges))
        } else {
            return Err(Error::Invalid(format!(
                "node_meta edge-kind tail is {remaining} bytes, expected {}",
                2 * n_edges
            )));
        };
        Ok((kinds, edge_kinds))
    }

    // ---- typed section access (bounds already validated at open) ----

    fn bytes(&self, sec: usize) -> &[u8] {
        let (o, l) = self.ranges[sec];
        &self.mmap[o..o + l]
    }

    fn u64s(&self, sec: usize) -> Result<&[u64]> {
        bytemuck::try_cast_slice(self.bytes(sec))
            .map_err(|e| Error::Invalid(format!("section {sec} cast failed: {e}")))
    }

    fn u32s(&self, sec: usize) -> Result<&[u32]> {
        bytemuck::try_cast_slice(self.bytes(sec))
            .map_err(|e| Error::Invalid(format!("section {sec} cast failed: {e}")))
    }

    fn f32s(&self, sec: usize) -> Result<&[f32]> {
        bytemuck::try_cast_slice(self.bytes(sec))
            .map_err(|e| Error::Invalid(format!("section {sec} cast failed: {e}")))
    }

    // ---- public API ----

    #[inline]
    pub fn n_nodes(&self) -> u64 {
        self.header.n_nodes
    }

    #[inline]
    pub fn n_edges(&self) -> u64 {
        self.header.n_edges
    }

    #[inline]
    pub fn has_weights(&self) -> bool {
        self.header.has_weights()
    }

    /// Look up a node id by name (binary search over the sorted name blob).
    pub fn node_id(&self, name: &str) -> Option<u32> {
        let n = self.header.n_nodes;
        let (mut lo, mut hi) = (0u64, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.node_name(mid as u32).as_bytes().cmp(name.as_bytes()) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid as u32),
            }
        }
        None
    }

    /// Node name for `id`. Panics only if `id >= n_nodes` (programmer error;
    /// ids obtained from this graph are always valid).
    pub fn node_name(&self, id: u32) -> &str {
        let offs = self
            .u64s(format::sec::NAME_OFFSETS)
            .expect("validated at open");
        let nb = self.bytes(format::sec::NAME_BYTES);
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        // UTF-8 was validated at open.
        std::str::from_utf8(&nb[s..e]).expect("name blob validated at open")
    }

    /// Kind tag of a node, if the builder wrote `node_meta`.
    pub fn node_kind(&self, id: u32) -> Option<&str> {
        let k = self.kinds.as_ref()?;
        let idx = *k.ids.get(id as usize)?;
        if idx == u32::MAX {
            return None;
        }
        k.names.get(idx as usize).map(|s| s.as_str())
    }

    /// Dependencies of `id`: targets of forward edges (`id -> dep`).
    #[inline]
    pub fn out_targets(&self, id: u32) -> &[u32] {
        let offs = self
            .u64s(format::sec::FWD_OFFSETS)
            .expect("validated at open");
        let t = self
            .u32s(format::sec::FWD_TARGETS)
            .expect("validated at open");
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        &t[s..e]
    }

    /// Weights parallel to [`Graph::out_targets`], if the file has weights.
    #[inline]
    pub fn out_weights(&self, id: u32) -> Option<&[f32]> {
        if !self.has_weights() {
            return None;
        }
        let offs = self
            .u64s(format::sec::FWD_OFFSETS)
            .expect("validated at open");
        let w = self
            .f32s(format::sec::FWD_WEIGHTS)
            .expect("validated at open");
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        Some(&w[s..e])
    }

    /// Dependents of `id`: sources of reverse edges (`dep -> id`).
    /// These are the nodes that break if `id` changes.
    #[inline]
    pub fn in_targets(&self, id: u32) -> &[u32] {
        let offs = self
            .u64s(format::sec::REV_OFFSETS)
            .expect("validated at open");
        let t = self
            .u32s(format::sec::REV_SOURCES)
            .expect("validated at open");
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        &t[s..e]
    }

    /// Kind tags parallel to [`Graph::out_targets`], if the file
    /// carries edge kinds. `None` means "all edges are `Static`"
    /// (pre-kind files).
    #[inline]
    pub fn out_kinds(&self, id: u32) -> Option<&[u8]> {
        let (foff, _) = self.edge_kinds?;
        let offs = self
            .u64s(format::sec::FWD_OFFSETS)
            .expect("validated at open");
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        Some(&self.mmap[foff + s..foff + e])
    }

    /// Kind tags parallel to [`Graph::in_targets`].
    #[inline]
    pub fn in_kinds(&self, id: u32) -> Option<&[u8]> {
        let (_, roff) = self.edge_kinds?;
        let offs = self
            .u64s(format::sec::REV_OFFSETS)
            .expect("validated at open");
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        Some(&self.mmap[roff + s..roff + e])
    }

    /// Weights parallel to [`Graph::in_targets`], if the file has weights.
    #[inline]
    pub fn in_weights(&self, id: u32) -> Option<&[f32]> {
        if !self.has_weights() {
            return None;
        }
        let offs = self
            .u64s(format::sec::REV_OFFSETS)
            .expect("validated at open");
        let w = self
            .f32s(format::sec::REV_WEIGHTS)
            .expect("validated at open");
        let s = offs[id as usize] as usize;
        let e = offs[id as usize + 1] as usize;
        Some(&w[s..e])
    }

    /// Number of dependencies of `id`.
    #[inline]
    pub fn out_degree(&self, id: u32) -> usize {
        self.out_targets(id).len()
    }

    /// Number of direct dependents of `id`.
    #[inline]
    pub fn in_degree(&self, id: u32) -> usize {
        self.in_targets(id).len()
    }
}

fn check_range(mmap: &Mmap, (off, len): (u64, u64), what: &str) -> Result<()> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| Error::Invalid(format!("{what} offset overflow")))?;
    if end > mmap.len() as u64 {
        return Err(Error::Invalid(format!(
            "{what} [{off},{end}) exceeds file length {}",
            mmap.len()
        )));
    }
    Ok(())
}

fn read_u64(mmap: &Mmap, pos: usize) -> Result<u64> {
    if pos + 8 > mmap.len() {
        return Err(Error::Invalid("u64 read out of bounds".into()));
    }
    Ok(u64::from_le_bytes(mmap[pos..pos + 8].try_into().unwrap()))
}
