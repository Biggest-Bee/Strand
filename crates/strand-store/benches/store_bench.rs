//! Benchmark: merged store view vs pure CSR `Graph`, same graph, same BFS.
//!
//! Setup builds a store, commits edges, compacts (so the delta is empty and
//! the base is a real `.strand` file), then times `strand_core::algo::bfs`
//! over (a) the `Graph` directly and (b) a store `Snapshot`'s merged `View`.
//! With an empty delta the view takes the pure-CSR fast path, so the delta
//! column shows the snapshot/merge overhead floor. A second bench adds a
//! small delta on top to measure merge cost.

use criterion::{criterion_group, criterion_main, Criterion};
use strand_core::algo::{self, Dir};
use strand_store::Store;

const N: usize = 20_000;
const E: usize = 100_000;

fn build_store(dir: &std::path::Path) -> Store {
    let store = Store::open(dir).unwrap();
    // Deterministic-ish graph: node i depends on (i*7+3) % N, plus a spread.
    let mut tx = store.begin_write().unwrap();
    for i in 0..E {
        let a = format!("n{}", (i * 7 + 3) % N);
        let b = format!("n{}", (i * 13 + 5) % N);
        tx.add_edge(&a, &b).unwrap();
    }
    tx.commit().unwrap();
    store.compact().unwrap();
    store
}

fn bench_bfs(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let store = build_store(dir.path());

    // Pure CSR reference: open the compacted base file directly.
    let base_file = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|n| n.starts_with("base-"))
        .unwrap();
    let graph = strand_core::Graph::open(dir.path().join(base_file)).unwrap();
    let start = graph.node_id("n0").unwrap();

    c.bench_function("bfs/pure-csr-graph", |b| {
        b.iter(|| algo::bfs(&graph, &[start], Dir::Out, None))
    });

    let snap = store.begin_read().unwrap();
    let view = snap.view();
    let vstart = view.node_id("n0").unwrap();

    c.bench_function("bfs/store-view-empty-delta", |b| {
        b.iter(|| {
            let v = snap.view();
            algo::bfs(&v, &[vstart], Dir::Out, None)
        })
    });

    // Small delta on top: 200 extra edges -> merge path exercised.
    {
        let mut tx = store.begin_write().unwrap();
        for i in 0..200 {
            tx.add_edge(&format!("d{i}"), &format!("n{}", i % N))
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let snap2 = store.begin_read().unwrap();
    let v2start = snap2.view().node_id("n0").unwrap();
    c.bench_function("bfs/store-view-small-delta", |b| {
        b.iter(|| {
            let v = snap2.view();
            algo::bfs(&v, &[v2start], Dir::Out, None)
        })
    });
}

criterion_group!(benches, bench_bfs);
criterion_main!(benches);
