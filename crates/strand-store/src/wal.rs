//! Write-ahead log: append-only record stream.
//!
//! Record framing: `[len u32][crc u32][payload]` where `len` is the payload
//! length and `crc` is `xxh32(payload)`. A commit is a *single* record whose
//! payload holds all of the transaction's ops, so a commit is atomic: either
//! the whole record is durable or none of it is.
//!
//! Replay reads records until EOF or the first bad checksum/length — a torn
//! tail write (crash mid-append) simply truncates the log there.

use std::io::{Read, Write};

use xxhash_rust::xxh32::xxh32;

use strand_core::{Error, Result};

/// One committed operation, name-based (resolved to ids at apply time).
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    /// `src -> dst` unweighted ("src depends on dst").
    AddEdge { src: String, dst: String },
    /// `src -> dst` with weight.
    AddEdgeW { src: String, dst: String, weight: f32 },
    RemoveEdge { src: String, dst: String },
    AddNode { name: String },
    RemoveNode { name: String },
}

const TAG_ADD_EDGE: u8 = 1;
const TAG_REMOVE_EDGE: u8 = 2;
const TAG_ADD_NODE: u8 = 3;
const TAG_REMOVE_NODE: u8 = 4;
const TAG_ADD_EDGE_W: u8 = 5;

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn get_str<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a str> {
    if *pos + 4 > buf.len() {
        return Err(Error::Invalid("wal: truncated string".into()));
    }
    let len = u32::from_le_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > buf.len() {
        return Err(Error::Invalid("wal: string overruns payload".into()));
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + len])
        .map_err(|_| Error::Invalid("wal: name not utf-8".into()))?;
    *pos += len;
    Ok(s)
}

fn encode_op(buf: &mut Vec<u8>, op: &Op) {
    match op {
        Op::AddEdge { src, dst } => {
            buf.push(TAG_ADD_EDGE);
            put_str(buf, src);
            put_str(buf, dst);
        }
        Op::AddEdgeW { src, dst, weight } => {
            buf.push(TAG_ADD_EDGE_W);
            put_str(buf, src);
            put_str(buf, dst);
            buf.extend_from_slice(&weight.to_le_bytes());
        }
        Op::RemoveEdge { src, dst } => {
            buf.push(TAG_REMOVE_EDGE);
            put_str(buf, src);
            put_str(buf, dst);
        }
        Op::AddNode { name } => {
            buf.push(TAG_ADD_NODE);
            put_str(buf, name);
        }
        Op::RemoveNode { name } => {
            buf.push(TAG_REMOVE_NODE);
            put_str(buf, name);
        }
    }
}

fn decode_op(buf: &[u8], pos: &mut usize) -> Result<Op> {
    if *pos >= buf.len() {
        return Err(Error::Invalid("wal: missing op tag".into()));
    }
    let tag = buf[*pos];
    *pos += 1;
    match tag {
        TAG_ADD_EDGE => Ok(Op::AddEdge {
            src: get_str(buf, pos)?.to_string(),
            dst: get_str(buf, pos)?.to_string(),
        }),
        TAG_ADD_EDGE_W => {
            let src = get_str(buf, pos)?.to_string();
            let dst = get_str(buf, pos)?.to_string();
            if *pos + 4 > buf.len() {
                return Err(Error::Invalid("wal: truncated weight".into()));
            }
            let weight = f32::from_le_bytes(buf[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            Ok(Op::AddEdgeW { src, dst, weight })
        }
        TAG_REMOVE_EDGE => Ok(Op::RemoveEdge {
            src: get_str(buf, pos)?.to_string(),
            dst: get_str(buf, pos)?.to_string(),
        }),
        TAG_ADD_NODE => Ok(Op::AddNode {
            name: get_str(buf, pos)?.to_string(),
        }),
        TAG_REMOVE_NODE => Ok(Op::RemoveNode {
            name: get_str(buf, pos)?.to_string(),
        }),
        other => Err(Error::Invalid(format!("wal: unknown op tag {other}"))),
    }
}

/// Encode a whole transaction (list of ops) as one record payload.
pub fn encode_tx(ops: &[Op]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(ops.len() as u32).to_le_bytes());
    for op in ops {
        encode_op(&mut buf, op);
    }
    buf
}

/// Decode a transaction payload back into ops.
pub fn decode_tx(payload: &[u8]) -> Result<Vec<Op>> {
    if payload.len() < 4 {
        return Err(Error::Invalid("wal: short payload".into()));
    }
    let n = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let mut pos = 4usize;
    let mut ops = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        ops.push(decode_op(payload, &mut pos)?);
    }
    Ok(ops)
}

/// Append one framed record to `w`. Does not fsync — caller decides.
pub fn append_record(w: &mut impl Write, payload: &[u8]) -> Result<()> {
    let crc = xxh32(payload, 0);
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(&crc.to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
}

/// Replay a WAL file: yields each successfully decoded transaction.
///
/// Stops silently at the first record with a bad length or checksum (torn
/// tail). Returns `(txs, trailing_bytes_ignored)`.
pub fn replay(mut r: impl Read) -> Result<Vec<Vec<Op>>> {
    let mut txs = Vec::new();
    let mut hdr = [0u8; 8];
    loop {
        match r.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Io(e)),
        }
        let len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        // Sanity: a record can't be longer than the file could plausibly be.
        if len > 1 << 30 {
            break; // torn/garbage header
        }
        let mut payload = vec![0u8; len];
        match r.read_exact(&mut payload) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Io(e)),
        }
        if xxh32(&payload, 0) != crc {
            break; // torn/corrupt record: stop here
        }
        match decode_tx(&payload) {
            Ok(ops) => txs.push(ops),
            Err(_) => break, // undecodable record: treat as torn tail
        }
    }
    Ok(txs)
}

