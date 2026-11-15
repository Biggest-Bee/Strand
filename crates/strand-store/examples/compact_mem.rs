//! Compaction memory probe: build a store, commit a large delta in one
//! transaction, then compact. Run under a memory monitor to compare
//! peak RSS before/after builder changes.
//!
//! Usage: cargo run -p strand-store --release --example compact_mem [edges] [nodes]

use strand_store::{Options, Store};

fn main() {
    let edges: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000);
    let nodes: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_with_options(
        dir.path(),
        Options {
            compact_threshold_ops: 0, // keep the whole delta until manual compact
            ..Default::default()
        },
    )
    .unwrap();

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
