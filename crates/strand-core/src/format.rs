//! Binary file format v1: constants, header coding, and section layout.
//!
//! See `docs/FORMAT.md` for the full specification. All integers are
//! little-endian, all sections are 8-byte aligned, and the file is
//! immutable once written.

use crate::{Error, Result};

/// File magic: `b"STRAND\0\1"`.
pub const MAGIC: [u8; 8] = *b"STRAND\x00\x01";

/// Format version. Readers reject anything else.
pub const VERSION: u32 = 1;

/// `flags` bit 0: the file carries f32 edge-weight sections.
pub const FLAG_HAS_WEIGHTS: u32 = 0x1;

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 128;

/// Number of sections in the section table.
pub const N_SECTIONS: usize = 10;

/// Section indices, in on-disk order.
pub mod sec {
    pub const FWD_OFFSETS: usize = 0;
    pub const FWD_TARGETS: usize = 1;
    pub const FWD_WEIGHTS: usize = 2;
    pub const REV_OFFSETS: usize = 3;
    pub const REV_SOURCES: usize = 4;
    pub const REV_WEIGHTS: usize = 5;
    pub const NAME_OFFSETS: usize = 6;
    pub const NAME_BYTES: usize = 7;
    pub const NAME_INDEX: usize = 8;
    pub const NODE_META: usize = 9;
}

/// Decoded 128-byte header.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub flags: u32,
    pub n_nodes: u64,
    pub n_edges: u64,
    /// Absolute byte offset of each section (lengths are derived).
    pub section_offsets: [u64; N_SECTIONS],
    /// xxh64 of every byte after the header.
    pub checksum: u64,
}

impl Header {
    #[inline]
    pub fn has_weights(self) -> bool {
        self.flags & FLAG_HAS_WEIGHTS != 0
    }
}

/// Serialize a header into its fixed 128-byte representation.
pub fn encode_header(h: &Header) -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[0..8].copy_from_slice(&MAGIC);
    b[8..12].copy_from_slice(&VERSION.to_le_bytes());
    b[12..16].copy_from_slice(&h.flags.to_le_bytes());
    b[16..24].copy_from_slice(&h.n_nodes.to_le_bytes());
    b[24..32].copy_from_slice(&h.n_edges.to_le_bytes());
    for (i, off) in h.section_offsets.iter().enumerate() {
        let p = 32 + i * 8;
        b[p..p + 8].copy_from_slice(&off.to_le_bytes());
    }
    b[112..120].copy_from_slice(&h.checksum.to_le_bytes());
    // 120..128 stays zeroed (reserved).
    b
}

/// Parse and validate the fixed fields of a header.
///
/// `buf` must be at least [`HEADER_LEN`] bytes.
pub fn decode_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < HEADER_LEN {
        return Err(Error::Invalid(format!(
            "file too small for header: {} bytes",
            buf.len()
        )));
    }
    if buf[0..8] != MAGIC {
        return Err(Error::Invalid("bad magic".into()));
    }
    let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(Error::Invalid(format!("unsupported version {version}")));
    }
    let flags = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let n_nodes = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let n_edges = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let mut section_offsets = [0u64; N_SECTIONS];
    for (i, slot) in section_offsets.iter_mut().enumerate() {
        let p = 32 + i * 8;
        *slot = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
    }
    let checksum = u64::from_le_bytes(buf[112..120].try_into().unwrap());
    if buf[120..128].iter().any(|&b| b != 0) {
        return Err(Error::Invalid("reserved header bytes non-zero".into()));
    }
    Ok(Header {
        flags,
        n_nodes,
        n_edges,
        section_offsets,
        checksum,
    })
}

/// Round `n` up to a multiple of 8.
#[inline]
pub fn align8(n: u64) -> u64 {
    (n + 7) & !7
}

/// Byte length of section `idx`, given the header and the two variable-length
/// inputs (`name_bytes` blob length and `node_meta` section length).
fn section_len(idx: usize, h: &Header, name_bytes_len: u64, node_meta_len: u64) -> u64 {
    let nn = h.n_nodes;
    let ne = h.n_edges;
    match idx {
        sec::FWD_OFFSETS | sec::REV_OFFSETS | sec::NAME_OFFSETS => (nn + 1) * 8,
        sec::FWD_TARGETS | sec::REV_SOURCES => ne * 4,
        sec::FWD_WEIGHTS | sec::REV_WEIGHTS => {
            if h.has_weights() {
                ne * 4
            } else {
                0
            }
        }
        sec::NAME_BYTES => name_bytes_len,
        sec::NAME_INDEX => nn * 4,
        sec::NODE_META => node_meta_len,
        _ => unreachable!("section index out of range"),
    }
}

/// Compute the `(offset, len)` of every section.
///
/// `name_bytes_len` is the length of the name blob; `node_meta_len` is the
/// length of the node-meta section *including* its internal length prefix.
/// Offsets are absolute file offsets and every section starts 8-byte aligned.
pub fn layout(
    h: &Header,
    name_bytes_len: u64,
    node_meta_len: u64,
) -> [(u64, u64); N_SECTIONS] {
    let mut out = [(0u64, 0u64); N_SECTIONS];
    let mut pos = HEADER_LEN as u64;
    for (i, slot) in out.iter_mut().enumerate() {
        pos = align8(pos);
        let len = section_len(i, h, name_bytes_len, node_meta_len);
        *slot = (pos, len);
        pos += len;
    }
    out
}
