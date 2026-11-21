//! Compaction memory probe.
//!
//! Mode 1 (synthetic): `compact_mem [edges] [nodes]` - builds a fresh
//! store, commits `edges` ops in one tx, compacts.
//!
//! Mode 2 (existing store): `compact_mem --store DIR [ops]` - opens a
//! store directory (manifest.json + base-N.strand + wal-N.log),
//! commits `ops` small edits (default 1000), then compacts. This is
//! the large-base/small-delta case.
//!
//! Run under a memory monitor to compare peak RSS across revisions.

use strand_store::{Options, Store};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(pos) = args.iter().position(|a| a == "--store") {
        let dir = std::path::PathBuf::from(args.get(pos + 1).expect("--store DIR"));
        let ops: usize = args
            .iter()
            .filter(|a| a.chars().all(|c| c.is_ascii_digit()))
            .filter_map(|s| s.parse().ok())
            .next()
            .unwrap_or(1000);
        probe_existing(&dir, ops);
        return;
    }

    let edges: usize = args
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000);
    let nodes: usize = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    synthetic(edges, nodes);
}

fn open_opts(dir: &std::path::Path) -> Store {
    Store::open_with_options(
        dir,
        Options {
            compact_threshold_ops: 0, // keep the delta until manual compact
            ..Default::default()
        },
    )
    .unwrap()
}

fn synthetic(edges: usize, nodes: usize) {
    let dir = tempfile::tempdir().unwrap();
    let store = open_opts(dir.path());

    eprintln!("committing {edges} edge ops over {nodes} nodes...");
    {
        let mut tx = store.begin_write().unwrap();
        for i in 0..edges {
            let a = format!("n{}", (i * 7 + 3) % nodes);
            let b = format!("n{}", (i * 13 + 5) % nodes);
            tx.add_edge(&a, &b).unwrap();
        }
        tx.commit().unwrap();
    }
    eprintln!("delta ops: {}, compacting...", store.delta_op_count());
    let t = std::time::Instant::now();
    store.compact().unwrap();
    eprintln!("compact done in {:?}", t.elapsed());
}

fn probe_existing(dir: &std::path::Path, ops: usize) {
    let store = open_opts(dir);
    eprintln!("opened store, applying {ops} small edits...");
    {
        let mut tx = store.begin_write().unwrap();
        for i in 0..ops {
            let a = format!("n{:010}", i % 1_000_000);
            let b = format!("n{:010}", (i * 37 + 11) % 1_000_000);
            tx.add_edge(&a, &b).unwrap();
        }
        tx.commit().unwrap();
    }
    eprintln!("delta ops: {}, compacting...", store.delta_op_count());
    let t = std::time::Instant::now();
    store.compact().unwrap();
    eprintln!("compact done in {:?}", t.elapsed());
}
