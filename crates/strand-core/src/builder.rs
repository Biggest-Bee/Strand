//! Graph builder: turns `(name, name[, weight])` edge lists into the
//! immutable CSR file format.
//!
//! Node ids are dense `u32`s assigned by sorting node names lexicographically,
//! which keeps builds deterministic: the same input always produces a
//! byte-identical file.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use xxhash_rust::xxh64::xxh64;

use crate::format::{self, Header, N_SECTIONS};
use crate::{EdgeKind, Error, Result};

/// How duplicate `(src, dst)` edges are merged.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MergeOp {
    /// Weights of duplicates are summed.
    #[default]
    Sum,
    /// The maximum weight wins.
    Max,
}

/// One input edge. `weight` is only meaningful when the builder is in
/// weighted mode (see [`GraphBuilder::add_edge_weighted`]).
#[derive(Clone, Debug)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub weight: f32,
    /// Provenance/confidence tag (see [`EdgeKind`]).
    pub kind: EdgeKind,
}

/// Statistics returned by [`GraphBuilder::build`].
#[derive(Clone, Debug)]
pub struct BuildStats {
    pub n_nodes: u64,
    pub n_edges: u64,
    pub bytes: u64,
    pub path: std::path::PathBuf,
}

/// Accumulates edges and writes a `.strand` file.
pub struct GraphBuilder {
    edges: Vec<Edge>,
    merge: MergeOp,
    /// node name -> kind string (written to `node_meta` when non-empty)
    kinds: BTreeMap<String, String>,
    /// isolated nodes to preserve (no edges)
    extra_nodes: BTreeSet<String>,
    /// Interned node names for the id-based edge API. Each name is
    /// stored once; `idx_edges` reference these by index, so building
    /// large graphs from ids avoids a `String` per edge endpoint.
    arena: Vec<String>,
    arena_ids: HashMap<String, u32>,
    idx_edges: Vec<(u32, u32, f32, EdgeKind)>,
    weighted: bool,
    /// True once any edge carries a non-`Static` kind - gates writing
    /// the edge-kind tables into `node_meta`.
    has_edge_kinds: bool,
    /// Scan warnings persisted into `node_meta` trailing bytes so
    /// readers (CLI, GUI) can surface "edges may be incomplete" notes
    /// without re-running the scan.
    warnings: Vec<String>,
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphBuilder {
    pub fn new() -> Self {
        GraphBuilder {
            edges: Vec::new(),
            merge: MergeOp::default(),
            kinds: BTreeMap::new(),
            extra_nodes: BTreeSet::new(),
            arena: Vec::new(),
            arena_ids: HashMap::new(),
            idx_edges: Vec::new(),
            weighted: false,
            has_edge_kinds: false,
            warnings: Vec::new(),
        }
    }

    /// Add an unweighted edge `src -> dst` (meaning "src depends on dst").
    pub fn add_edge(&mut self, src: impl Into<String>, dst: impl Into<String>) {
        self.edges.push(Edge {
            src: src.into(),
            dst: dst.into(),
            weight: 1.0,
            kind: EdgeKind::Static,
        });
    }

    /// [`add_edge`](Self::add_edge) with an explicit provenance tag.
    pub fn add_edge_kind(
        &mut self,
        src: impl Into<String>,
        dst: impl Into<String>,
        kind: EdgeKind,
    ) {
        if kind != EdgeKind::Static {
            self.has_edge_kinds = true;
        }
        self.edges.push(Edge {
            src: src.into(),
            dst: dst.into(),
            weight: 1.0,
            kind,
        });
    }

    /// Add a weighted edge `src -> dst`. Using this at least once switches the
    /// file into weighted mode; unweighted edges then default to weight 1.0.
    pub fn add_edge_weighted(
        &mut self,
        src: impl Into<String>,
        dst: impl Into<String>,
        weight: f32,
    ) {
        self.weighted = true;
        self.edges.push(Edge {
            src: src.into(),
            dst: dst.into(),
            weight,
            kind: EdgeKind::Static,
        });
    }

    /// Weighted + kinded variant of [`add_edge_kind`](Self::add_edge_kind).
    pub fn add_edge_weighted_kind(
        &mut self,
        src: impl Into<String>,
        dst: impl Into<String>,
        weight: f32,
        kind: EdgeKind,
    ) {
        self.weighted = true;
        if kind != EdgeKind::Static {
            self.has_edge_kinds = true;
        }
        self.edges.push(Edge {
            src: src.into(),
            dst: dst.into(),
            weight,
            kind,
        });
    }

    /// Set the duplicate-edge merge policy (default: [`MergeOp::Sum`]).
    pub fn set_merge(&mut self, op: MergeOp) {
        self.merge = op;
    }

    /// Register an isolated node (no edges) so it survives in the file.
    /// Nodes that appear in edges are included automatically.
    pub fn add_node(&mut self, name: impl Into<String>) {
        self.extra_nodes.insert(name.into());
    }

    /// Intern a node name and return its stable index for
    /// [`add_edge_idx`](Self::add_edge_idx). Each distinct name is stored
    /// once; interned names are always preserved as nodes (like
    /// [`add_node`](Self::add_node)).
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(&i) = self.arena_ids.get(name) {
            return i;
        }
        let i = self.arena.len() as u32;
        self.arena.push(name.to_string());
        self.arena_ids.insert(name.to_string(), i);
        i
    }

    /// Add an edge between two previously [`intern`](Self::intern)ed
    /// indices - no per-edge `String` allocation.
    pub fn add_edge_idx(&mut self, src: u32, dst: u32) {
        self.idx_edges.push((src, dst, 1.0, EdgeKind::Static));
    }

    /// [`add_edge_idx`](Self::add_edge_idx) with an explicit kind.
    pub fn add_edge_idx_kind(&mut self, src: u32, dst: u32, kind: EdgeKind) {
        if kind != EdgeKind::Static {
            self.has_edge_kinds = true;
        }
        self.idx_edges.push((src, dst, 1.0, kind));
    }

    /// Weighted variant of [`add_edge_idx`](Self::add_edge_idx).
    pub fn add_edge_idx_weighted(&mut self, src: u32, dst: u32, weight: f32) {
        self.weighted = true;
        self.idx_edges.push((src, dst, weight, EdgeKind::Static));
    }

    /// Weighted + kinded variant of [`add_edge_idx`](Self::add_edge_idx).
    pub fn add_edge_idx_weighted_kind(&mut self, src: u32, dst: u32, weight: f32, kind: EdgeKind) {
        self.weighted = true;
        if kind != EdgeKind::Static {
            self.has_edge_kinds = true;
        }
        self.idx_edges.push((src, dst, weight, kind));
    }

    /// Assign a "kind" tag to a node (e.g. `"crate"`, `"service"`). Written
    /// into the optional `node_meta` section.
    pub fn set_kind(&mut self, node: impl Into<String>, kind: impl Into<String>) {
        self.kinds.insert(node.into(), kind.into());
    }

    /// Persist a scan warning (e.g. "3 dynamic import site(s) - edges
    /// may be incomplete") into the file. Stored as trailing bytes of
    /// the `node_meta` section; readers that predate this feature
    /// ignore them.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    pub fn len(&self) -> usize {
        self.edges.len() + self.idx_edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty() && self.idx_edges.is_empty()
    }

    /// Encode the graph into an in-memory `.strand` file image.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // 1. Collect node names, sorted lexicographically -> dense ids.
        let mut name_set: BTreeSet<&str> = BTreeSet::new();
        for e in &self.edges {
            name_set.insert(e.src.as_str());
            name_set.insert(e.dst.as_str());
        }
        for k in self.kinds.keys() {
            name_set.insert(k.as_str());
        }
        for n in &self.extra_nodes {
            name_set.insert(n.as_str());
        }
        for n in &self.arena {
            name_set.insert(n.as_str());
        }
        let names: Vec<&str> = name_set.into_iter().collect();
        let n_nodes = names.len() as u64;
        let name_to_id: BTreeMap<&str, u32> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (*n, i as u32))
            .collect();

        // 2. Resolve edges to id pairs and sort/dedupe. Kinds merge by
        //    max confidence: the strongest claim about an edge wins.
        let mut resolved: Vec<(u32, u32, f32, EdgeKind)> =
            Vec::with_capacity(self.edges.len() + self.idx_edges.len());
        for e in &self.edges {
            resolved.push((
                name_to_id[e.src.as_str()],
                name_to_id[e.dst.as_str()],
                e.weight,
                e.kind,
            ));
        }
        for &(s, d, w, k) in &self.idx_edges {
            resolved.push((
                name_to_id[self.arena[s as usize].as_str()],
                name_to_id[self.arena[d as usize].as_str()],
                w,
                k,
            ));
        }
        resolved.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        let mut deduped: Vec<(u32, u32, f32, EdgeKind)> = Vec::with_capacity(resolved.len());
        for (s, d, w, k) in resolved {
            if let Some(last) = deduped.last_mut() {
                if last.0 == s && last.1 == d {
                    last.2 = match self.merge {
                        MergeOp::Sum => last.2 + w,
                        MergeOp::Max => last.2.max(w),
                    };
                    last.3 = last.3.max(k);
                    continue;
                }
            }
            deduped.push((s, d, w, k));
        }
        let n_edges = deduped.len() as u64;

        // 3. Forward CSR: edges of node i are targets[fwd_offsets[i]..fwd_offsets[i+1]].
        let (fwd_offsets, fwd_targets, fwd_weights, fwd_kinds) =
            build_csr(n_nodes as usize, &deduped);

        // 4. Reverse CSR over the same edges.
        let rev_edges: Vec<(u32, u32, f32, EdgeKind)> =
            deduped.iter().map(|&(s, d, w, k)| (d, s, w, k)).collect();
        let (rev_offsets, rev_sources, rev_weights, rev_kinds) =
            build_csr(n_nodes as usize, &rev_edges);

        // 5. Name blob + offsets. Ids are already name-sorted, so
        //    `name_index` is the identity permutation.
        let mut name_bytes = Vec::new();
        let mut name_offsets: Vec<u64> = Vec::with_capacity(names.len() + 1);
        name_offsets.push(0);
        for n in &names {
            name_bytes.extend_from_slice(n.as_bytes());
            name_offsets.push(name_bytes.len() as u64);
        }
        let name_index: Vec<u32> = (0..names.len() as u32).collect();

        // 6. Optional node_meta: kind tags + edge-kind tables + warnings.
        let mut meta_content =
            self.encode_meta(n_nodes as usize, &name_to_id, &fwd_kinds, &rev_kinds)?;
        if !self.warnings.is_empty() {
            // Trailing blob inside the section, after the length-prefixed
            // payload: [u64 text_len][utf8 warnings joined by '\n'].
            // Old readers slice exactly payload_len and never see this.
            //
            // encode_meta's empty-payload sentinel is payload_len=8
            // (it only works while the section is exactly 8 bytes).
            // With warnings appended the section is longer, so rewrite
            // it as a real payload_len=0 or readers would parse the
            // warnings blob as kind data.
            if meta_content.len() == 8 && meta_content == 8u64.to_le_bytes() {
                meta_content = 0u64.to_le_bytes().to_vec();
            }
            let text = self
                .warnings
                .iter()
                .map(|w| w.replace('\n', " "))
                .collect::<Vec<_>>()
                .join("\n");
            meta_content.extend_from_slice(&(text.len() as u64).to_le_bytes());
            meta_content.extend_from_slice(text.as_bytes());
        }

        // 7. Lay out sections and assemble the body (everything after the
        //    128-byte header), padding each section to 8 bytes.
        let flags = if self.weighted {
            format::FLAG_HAS_WEIGHTS
        } else {
            0
        };
        let header = Header {
            flags,
            n_nodes,
            n_edges,
            section_offsets: [0; N_SECTIONS],
            checksum: 0,
        };
        let lay = format::layout(&header, name_bytes.len() as u64, meta_content.len() as u64);

        let mut body: Vec<u8> = Vec::new();
        let section_bytes: [&[u8]; N_SECTIONS] = [
            cast_u64(&fwd_offsets),
            cast_u32(&fwd_targets),
            if self.weighted {
                cast_f32(&fwd_weights)
            } else {
                &[]
            },
            cast_u64(&rev_offsets),
            cast_u32(&rev_sources),
            if self.weighted {
                cast_f32(&rev_weights)
            } else {
                &[]
            },
            cast_u64(&name_offsets),
            &name_bytes,
            cast_u32(&name_index),
            &meta_content,
        ];

        for i in 0..N_SECTIONS {
            let (off, _len) = lay[i];
            let want = (off - format::HEADER_LEN as u64) as usize;
            if body.len() < want {
                body.resize(want, 0);
            }
            debug_assert_eq!(body.len(), want);
            body.extend_from_slice(section_bytes[i]);
        }

        // 8. Checksum covers everything after the header.
        let checksum = xxh64(&body, 0);
        let mut header = header;
        header.checksum = checksum;
        for (i, (off, _)) in lay.iter().enumerate() {
            header.section_offsets[i] = *off;
        }

        let mut file = Vec::with_capacity(format::HEADER_LEN + body.len());
        file.extend_from_slice(&format::encode_header(&header));
        file.extend_from_slice(&body);
        Ok(file)
    }

    /// Encode and atomically write the graph to `path`.
    ///
    /// Writes to a sibling temp file, fsyncs, then renames into place so a
    /// crash never leaves a half-written graph at `path`.
    pub fn build(&self, path: &Path) -> Result<BuildStats> {
        let bytes = self.encode()?;
        let bytes_len = bytes.len() as u64;

        let tmp = tmp_path(path);
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Error::Io(e)
        })?;

        let (n_nodes, n_edges) = {
            let h = format::decode_header(&bytes[..format::HEADER_LEN])?;
            (h.n_nodes, h.n_edges)
        };
        Ok(BuildStats {
            n_nodes,
            n_edges,
            bytes: bytes_len,
            path: path.to_path_buf(),
        })
    }

    /// Build the `node_meta` section content.
    ///
    /// Layout: `[u64 payload_len][payload]` where payload is
    /// `u32 nkinds`, then `nkinds` x (`u32 len` + utf8 kind name), then
    /// `n_nodes` x `u32 kind_index` (`u32::MAX` = no kind). When any
    /// edge carries a non-`Static` kind, two trailing `u8` tables of
    /// `n_edges` entries each follow - forward-CSR order then
    /// reverse-CSR order. Readers that predate edge kinds stop after
    /// the node ids and ignore the tail. Scan warnings are appended
    /// by the caller *after* this prefix+payload, outside `payload_len`.
    fn encode_meta(
        &self,
        n_nodes: usize,
        name_to_id: &BTreeMap<&str, u32>,
        fwd_kinds: &[u8],
        rev_kinds: &[u8],
    ) -> Result<Vec<u8>> {
        let write_edge_kinds =
            self.has_edge_kinds || fwd_kinds.iter().any(|&k| k != EdgeKind::Static.as_tag());
        if self.kinds.is_empty() && !write_edge_kinds {
            return Ok(8u64.to_le_bytes().to_vec()); // payload_len = 0
        }

        // Intern distinct kind strings.
        let mut kind_ids: BTreeMap<&str, u32> = BTreeMap::new();
        let mut kind_names: Vec<&str> = Vec::new();
        for k in self.kinds.values() {
            if !kind_ids.contains_key(k.as_str()) {
                kind_ids.insert(k.as_str(), kind_names.len() as u32);
                kind_names.push(k.as_str());
            }
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&(kind_names.len() as u32).to_le_bytes());
        for k in &kind_names {
            payload.extend_from_slice(&(k.len() as u32).to_le_bytes());
            payload.extend_from_slice(k.as_bytes());
        }
        // Per-node kind ids, in node-id order.
        // name_to_id maps name->id; kinds maps name->kind. Build id->kind.
        let mut id_to_kind: Vec<Option<&str>> = vec![None; n_nodes];
        for (name, kind) in &self.kinds {
            let id = name_to_id[name.as_str()] as usize;
            id_to_kind[id] = Some(kind.as_str());
        }
        for slot in &id_to_kind {
            let idx = match slot {
                Some(k) => kind_ids.get(*k).copied().unwrap_or(u32::MAX),
                None => u32::MAX,
            };
            payload.extend_from_slice(&idx.to_le_bytes());
        }
        if write_edge_kinds {
            payload.extend_from_slice(fwd_kinds);
            payload.extend_from_slice(rev_kinds);
        }

        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }
}

/// Build a CSR (offsets, targets, weights, kinds) from edges already
/// sorted by `(src, dst)`. Targets end up sorted ascending within each
/// row; `kinds` is parallel to `targets`.
fn build_csr(
    n_nodes: usize,
    edges: &[(u32, u32, f32, EdgeKind)],
) -> (Vec<u64>, Vec<u32>, Vec<f32>, Vec<u8>) {
    let mut offsets = vec![0u64; n_nodes + 1];
    for &(s, _, _, _) in edges {
        offsets[s as usize + 1] += 1;
    }
    for i in 0..n_nodes {
        offsets[i + 1] += offsets[i];
    }
    let m = edges.len();
    let mut targets = vec![0u32; m];
    let mut weights = vec![0f32; m];
    let mut kinds = vec![0u8; m];
    let mut cursor = offsets[..n_nodes].to_vec();
    for &(s, d, w, k) in edges {
        let p = cursor[s as usize] as usize;
        targets[p] = d;
        weights[p] = w;
        kinds[p] = k.as_tag();
        cursor[s as usize] += 1;
    }
    (offsets, targets, weights, kinds)
}

fn cast_u64(v: &[u64]) -> &[u8] {
    bytemuck::cast_slice(v)
}
fn cast_u32(v: &[u32]) -> &[u8] {
    bytemuck::cast_slice(v)
}
fn cast_f32(v: &[f32]) -> &[u8] {
    bytemuck::cast_slice(v)
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    std::path::PathBuf::from(s)
}
