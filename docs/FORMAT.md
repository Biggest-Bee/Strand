# Strand file format v1

This document specifies the `.strand` binary format exactly. It is the
normative reference for `strand-core::format` - keep them in sync.

## Big picture

- All integers are **little-endian**.
- All sections are **8-byte aligned** (zero padding between sections).
- The file is **immutable** once written. Writers always produce a new file
  and rename it into place, so readers can safely memory-map it.
- Node ids are dense `u32`s assigned by sorting node names lexicographically.
  This makes builds deterministic: identical input ⇒ byte-identical file.
- Edge direction: `A -> B` means **"A depends on B"**. Forward CSR arrays
  answer "what does X depend on?"; reverse CSR arrays answer "what depends
  on X?" (the impact direction).

## Header (fixed 128 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | `b"STRAND\x00\x01"` |
| 8 | 4 | version | `u32`, currently `1` |
| 12 | 4 | flags | bit 0 = has edge weights |
| 16 | 8 | n_nodes | `u64` |
| 24 | 8 | n_edges | `u64` (after dedup/merge) |
| 32 | 80 | section_offsets | `[u64; 10]`, absolute byte offset of each section |
| 112 | 8 | checksum | `u64`, xxh64 (seed 0) of **all bytes after the header** |
| 120 | 8 | reserved | must be zero |

Section lengths are **not** stored; they are derived from `n_nodes`,
`n_edges`, `flags`, and the name blob (see below). The stored offsets must
equal the deterministic layout computed from those fields - readers verify
this.

## Sections

Section indices (on-disk order):

| # | Name | Element | Length |
|---|---|---|---|
| 0 | `fwd_offsets` | `u64` | `(n_nodes + 1) * 8` |
| 1 | `fwd_targets` | `u32` | `n_edges * 4` |
| 2 | `fwd_weights` | `f32` | `n_edges * 4` (only if flag bit 0) |
| 3 | `rev_offsets` | `u64` | `(n_nodes + 1) * 8` |
| 4 | `rev_sources` | `u32` | `n_edges * 4` |
| 5 | `rev_weights` | `f32` | `n_edges * 4` (only if flag bit 0) |
| 6 | `name_offsets` | `u64` | `(n_nodes + 1) * 8` |
| 7 | `name_bytes` | `u8` | `name_offsets[n_nodes]` (UTF-8 blob) |
| 8 | `name_index` | `u32` | `n_nodes * 4` |
| 9 | `node_meta` | `u8` | remainder of file |

### CSR layout

For node `i`, its forward edges are
`fwd_targets[fwd_offsets[i]..fwd_offsets[i+1]]`, sorted ascending by target
id. `fwd_weights` (when present) is parallel to `fwd_targets`.

The reverse CSR is the same structure over reversed edges: for every
`u -> v`, the reverse graph stores `v -> u`. Thus
`rev_sources[rev_offsets[i]..rev_offsets[i+1]]` lists the **dependents** of
`i`, sorted ascending.

Both offsets arrays are monotonic non-decreasing and end at `n_edges`.

### Names

`name_bytes` is the concatenation of all node names in id order (which is
lexicographic order). `name_offsets[i]..name_offsets[i+1]` is the byte
range of node `i`'s name. `name_index` lists node ids sorted by name - with
this format it is the identity permutation `[0, 1, ..., n-1]`, written
anyway for format stability.

### node_meta

Optional opaque metadata. Content:

```
u64 payload_len          // length of the payload that follows (0 = absent)
payload:
  u32 nkinds
  nkinds x { u32 len, utf8 kind name }     // interned kind strings
  n_nodes x u32 kind_index                 // u32::MAX = untyped
  [n_edges x u8 fwd kind tags]             // only when any edge is non-Static
  [n_edges x u8 rev kind tags]             // parallel to the CSR orders
```

When the builder assigns no node kinds AND every edge is `Static`, the
section is just the 8-byte zero length prefix. When any edge carries a
non-`Static` [`EdgeKind`](../crates/strand-core/src/lib.rs), the two
trailing `u8` tables appear after the node kind ids - forward-CSR order
then reverse-CSR order, one tag per edge, parallel to the target/source
slices. Edge-kind tags are the `EdgeKind` confidence values
(`Heuristic`=0 < `Traced`=1 < `Declared`=2 < `Resolved`=3 <
`Static`=4). Readers that predate edge kinds stop after the node ids
and treat every edge as `Static`; writers omit the tables entirely for
all-`Static` graphs, so files stay byte-identical to the old format.

## Validation (reader contract)

`Graph::open` must reject, with an error (never a crash or panic):

- file shorter than 128 bytes, bad magic, version != 1, non-zero reserved
- section offsets that don't match the deterministic layout, or that
  exceed the file length
- xxh64 checksum mismatch over bytes `[128..]`
- non-monotonic CSR/name offset arrays, or last offset != expected count
- any `fwd_targets`/`rev_sources` id >= n_nodes
- `name_bytes` not valid UTF-8, `name_index` entries out of range
- truncated `node_meta`

## Writing

`GraphBuilder::encode` produces the full file image in memory;
`GraphBuilder::build` writes it to `<path>.tmp`, fsyncs, then renames to
`<path>` - an atomic publish.

---

# Store directory format (`.strandb/`)

`strand-store` persists a read-write graph as a **directory** containing an
immutable base (the `.strand` format above), an append-only WAL for recent
commits, and a tiny manifest that binds them together. All integers are
little-endian.

## Layout

```
my.strandb/
  lock                // fd-lock file; exclusive lock = writer, shared = readers
  manifest.json       // current epoch -> base + wal (written via tmp+rename)
  base-<epoch>.strand // immutable CSR base (format above)
  wal-<epoch>.log     // append-only write-ahead log for that epoch
```

`manifest.json` is JSON:

```json
{ "version": 1, "epoch": 3, "base": "base-3.strand", "wal": "wal-3.log" }
```

`base` is `null` for a store that has never been compacted. `epoch`
increments on every compaction; stale `base-*`/`wal-*` files from older
epochs are garbage-collected lazily (a file may survive if a live snapshot
still has it memory-mapped).

## WAL record framing

The WAL is a sequence of records:

```
[u32 payload_len][u32 crc][payload bytes]
```

- `crc` = `xxh32(payload, seed 0)`.
- One record = **one committed transaction** (atomic commit unit).
- Replay reads records until EOF or the first bad length/checksum/undecodable
  payload, and stops there - this absorbs torn tail writes from crashes.
- A commit is durable once the record is appended and `sync_all()`'d
  (configurable via `Options::fsync_on_commit`).

## WAL payload (transaction)

```
[u32 n_ops]
n_ops x op:
  u8 tag
  fields (all strings are [u32 len][utf8 bytes])
```

| tag | op | fields |
|---|---|---|
| 1 | `AddEdge` | src, dst |
| 2 | `RemoveEdge` | src, dst |
| 3 | `AddNode` | name |
| 4 | `RemoveNode` | name |
| 5 | `AddEdgeW` | src, dst, `f32` weight |

Ops are name-based; ids are resolved against base+delta at apply time, so
the WAL survives compaction (old epochs' WALs are discarded, not replayed).

## Node identity across remove/re-add

`RemoveNode` tombstones a node *id* permanently. Re-adding the same name
later creates a **new** node id (a new "generation"); edges incident to the
old id never resurrect. Readers resolve a name to its newest live id.
