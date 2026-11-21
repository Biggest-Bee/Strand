//! Big-graph benchmark: generate a 10M-node / 50M-edge `.strand` file
//! directly in the documented format (streaming, ~400MB RAM), then time
//! open / BFS / SCC / PageRank.
//!
//! Run: `cargo run --release -p strand-core --example bigbench [--dir DIR] [--skip-gen]`

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;

use strand_core::algo::{self, Dir};
use strand_core::format::{self, Header, N_SECTIONS};
use strand_core::Graph;

const N: u64 = 10_000_000; // nodes
const PER_NODE: u64 = 5; // edges per node -> 50M edges
const E: u64 = N * PER_NODE;
const NAME_LEN: u64 = 11; // "n" + 10 digits

#[inline]
fn target(i: u64, k: u64) -> u64 {
    // 5 distinct targets per node (13k mod N distinct for k < 5).
    (i * 7 + k * 13 + 3) % N
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let dir = arg("--dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("testdata"));
    let skip_gen = args.iter().any(|a| a == "--skip-gen");
    let path = dir.join("big.strand");

    if !skip_gen {
        gen(&path);
    }

    // ---- benchmark ----
    let t = Instant::now();
    let g = Graph::open(&path).unwrap();
    let open_t = t.elapsed();
    println!(
        "open: {:?} ({} nodes, {} edges)",
        open_t,
        g.n_nodes(),
        g.n_edges()
    );

    let t = Instant::now();
    let d = algo::bfs(&g, &[0], Dir::Out, None);
    let reached = d.iter().filter(|&&x| x != algo::UNVISITED).count();
    println!("bfs from node 0: {:?} ({reached} reached)", t.elapsed());

    let t = Instant::now();
    let sccs = algo::strongly_connected(&g);
    let cyclic = sccs.iter().filter(|c| c.len() > 1).count();
    println!(
        "scc: {:?} ({} components, {cyclic} cyclic)",
        t.elapsed(),
        sccs.len()
    );

    let t = Instant::now();
    let pr = algo::pagerank(&g, false, 1e-8, 100);
    let top = pr.iter().cloned().fold(0.0f64, f64::max);
    println!("pagerank: {:?} (max score {top:.3e})", t.elapsed());

    // Forced-iteration cost (tol=0 never early-breaks).
    let t = Instant::now();
    let _ = algo::pagerank(&g, false, 0.0, 3);
    println!("pagerank 3 forced iters: {:?}", t.elapsed());

    let meta = std::fs::metadata(&path).unwrap();
    println!("file size: {:.1} MB", meta.len() as f64 / 1e6);
}

/// Streams the graph body to `path` in the exact format `Graph::open`
/// expects, hashing as it goes, then seek-writes the real header.
fn gen(path: &std::path::Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let tmp = path.with_extension("strand.tmp");
    let t0 = Instant::now();

    // Pass 1: in-degree counts (u32; max possible 50M < u32::MAX).
    let mut in_deg = vec![0u32; N as usize];
    for i in 0..N {
        for k in 0..PER_NODE {
            in_deg[target(i, k) as usize] += 1;
        }
    }
    println!("pass1 in-degrees: {:?}", t0.elapsed());

    // rev_offsets (u64, written to disk) + cursor (u32; offsets <= 50M fit).
    let mut rev_offsets = vec![0u64; (N + 1) as usize];
    for i in 0..N as usize {
        rev_offsets[i + 1] = rev_offsets[i] + in_deg[i] as u64;
    }
    let mut cursor: Vec<u32> = rev_offsets[..N as usize]
        .iter()
        .map(|&x| x as u32)
        .collect();
    drop(in_deg);

    // rev_sources scatter buffer (200MB).
    let mut rev_sources = vec![0u32; E as usize];

    // Layout (header checksum/offsets filled in later).
    let header = Header {
        flags: 0,
        n_nodes: N,
        n_edges: E,
        section_offsets: [0; N_SECTIONS],
        checksum: 0,
    };
    let lay = format::layout(&header, N * NAME_LEN, 8);

    let file = File::create(&tmp).unwrap();
    let mut w = BufWriter::with_capacity(1 << 22, file);
    w.write_all(&[0u8; format::HEADER_LEN]).unwrap(); // header placeholder

    let mut hasher = xxhash_rust::xxh64::Xxh64::new(0);
    let mut pos = format::HEADER_LEN as u64;

    macro_rules! pad_to {
        ($off:expr) => {{
            let want = $off;
            let zeros = [0u8; 1 << 16];
            while pos < want {
                let n = ((want - pos) as usize).min(zeros.len());
                w.write_all(&zeros[..n]).unwrap();
                hasher.update(&zeros[..n]);
                pos += n as u64;
            }
        }};
    }
    macro_rules! emit {
        ($bytes:expr) => {{
            let b: &[u8] = $bytes;
            w.write_all(b).unwrap();
            hasher.update(b);
            pos += b.len() as u64;
        }};
    }

    // ---- sec::FWD_OFFSETS: node i has PER_NODE edges -> offset i*PER_NODE.
    pad_to!(lay[format::sec::FWD_OFFSETS].0);
    {
        let mut buf = Vec::with_capacity(1 << 16);
        for i in 0..=N {
            buf.extend_from_slice(&(i * PER_NODE).to_le_bytes());
            if buf.len() + 8 > (1 << 16) {
                emit!(buf.as_slice());
                buf.clear();
            }
        }
        if !buf.is_empty() {
            emit!(buf.as_slice());
        }
    }
    println!("fwd_offsets: {:?}", t0.elapsed());

    // ---- sec::FWD_TARGETS: 5 sorted targets per node.
    pad_to!(lay[format::sec::FWD_TARGETS].0);
    {
        let mut buf = Vec::with_capacity(1 << 16);
        let mut tg = [0u64; PER_NODE as usize];
        for i in 0..N {
            for k in 0..PER_NODE {
                tg[k as usize] = target(i, k);
            }
            tg.sort_unstable();
            for &t in &tg {
                buf.extend_from_slice(&(t as u32).to_le_bytes());
                if buf.len() + 4 > (1 << 16) {
                    emit!(buf.as_slice());
                    buf.clear();
                }
            }
        }
        if !buf.is_empty() {
            emit!(buf.as_slice());
        }
    }
    println!("fwd_targets: {:?}", t0.elapsed());

    // ---- sec::REV_OFFSETS.
    pad_to!(lay[format::sec::REV_OFFSETS].0);
    emit!(bytemuck::cast_slice(&rev_offsets));
    println!("rev_offsets: {:?}", t0.elapsed());

    // ---- sec::REV_SOURCES: scatter i into each target's slot.
    pad_to!(lay[format::sec::REV_SOURCES].0);
    {
        let mut tg = [0u64; PER_NODE as usize];
        for i in 0..N {
            for k in 0..PER_NODE {
                tg[k as usize] = target(i, k);
            }
            for &t in &tg {
                let c = &mut cursor[t as usize];
                rev_sources[*c as usize] = i as u32;
                *c += 1;
            }
        }
        emit!(bytemuck::cast_slice(&rev_sources));
    }
    drop(rev_sources);
    drop(cursor);
    println!("rev_sources: {:?}", t0.elapsed());

    // ---- sec::NAME_OFFSETS: all names are NAME_LEN bytes -> offset i*NAME_LEN.
    pad_to!(lay[format::sec::NAME_OFFSETS].0);
    {
        let mut buf = Vec::with_capacity(1 << 16);
        for i in 0..=N {
            buf.extend_from_slice(&(i * NAME_LEN).to_le_bytes());
            if buf.len() + 8 > (1 << 16) {
                emit!(buf.as_slice());
                buf.clear();
            }
        }
        if !buf.is_empty() {
            emit!(buf.as_slice());
        }
    }

    // ---- sec::NAME_BYTES: "n%010d" per node.
    pad_to!(lay[format::sec::NAME_BYTES].0);
    {
        let mut buf = Vec::with_capacity(1 << 16);
        let mut tmp = [0u8; 16];
        for i in 0..N {
            let name = format!("n{i:010}");
            tmp[..name.len()].copy_from_slice(name.as_bytes());
            buf.extend_from_slice(&tmp[..name.len()]);
            if buf.len() + 16 > (1 << 16) {
                emit!(buf.as_slice());
                buf.clear();
            }
        }
        if !buf.is_empty() {
            emit!(buf.as_slice());
        }
    }
    println!("names: {:?}", t0.elapsed());

    // ---- sec::NAME_INDEX: identity permutation.
    pad_to!(lay[format::sec::NAME_INDEX].0);
    {
        let mut buf = Vec::with_capacity(1 << 16);
        for i in 0..N {
            buf.extend_from_slice(&(i as u32).to_le_bytes());
            if buf.len() + 4 > (1 << 16) {
                emit!(buf.as_slice());
                buf.clear();
            }
        }
        if !buf.is_empty() {
            emit!(buf.as_slice());
        }
    }

    // ---- sec::NODE_META: u64 payload_len = 0 (no kinds).
    pad_to!(lay[format::sec::NODE_META].0);
    let meta_empty = 0u64.to_le_bytes();
    emit!(meta_empty.as_slice());

    // pos must now equal the end of the last section.
    let (_last_off, last_len) = lay[format::sec::NODE_META];
    assert_eq!(pos, _last_off + last_len);

    w.flush().unwrap();
    drop(w);
    println!("body written: {:?}", t0.elapsed());

    // Seek back and write the real header.
    let mut header = header;
    header.checksum = hasher.digest();
    for (i, (off, _)) in lay.iter().enumerate() {
        header.section_offsets[i] = *off;
    }
    let mut f = File::options().write(true).open(&tmp).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(&format::encode_header(&header)).unwrap();
    f.sync_all().unwrap();
    drop(f);

    std::fs::rename(&tmp, path).unwrap();
    println!("gen done: {:?} -> {}", t0.elapsed(), path.display());
}
