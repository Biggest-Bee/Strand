//! Benchmarks: build + open a synthetic graph, then BFS / SCC / PageRank,
//! plus a petgraph comparison on the same edge list.
//!
//! Size is controlled by env vars `STRAND_BENCH_NODES` and
//! `STRAND_BENCH_EDGES` (defaults: 200k nodes, 1M edges — large enough to be
//! meaningful, small enough to run in CI).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use petgraph::visit::EdgeRef;
use strand_core::algo::{self, Dir};
use strand_core::GraphBuilder;

fn gen_edges(n_nodes: usize, n_edges: usize) -> Vec<(u32, u32)> {
    let mut x = 0x9E3779B97F4A7C15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut edges = Vec::with_capacity(n_edges);
    for _ in 0..n_edges {
        let s = (next() % n_nodes as u64) as u32;
        let d = (next() % n_nodes as u64) as u32;
        if s != d {
            edges.push((s, d));
        }
    }
    edges
}

fn build_graph(_n_nodes: usize, edges: &[(u32, u32)]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.strand");
    let mut b = GraphBuilder::new();
    for &(s, d) in edges {
        b.add_edge(format!("n{s}"), format!("n{d}"));
    }
    b.build(&path).unwrap();
    (dir, path)
}

fn bench_graph(c: &mut Criterion) {
    let n_nodes: usize = std::env::var("STRAND_BENCH_NODES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let n_edges: usize = std::env::var("STRAND_BENCH_EDGES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);

    let edges = gen_edges(n_nodes, n_edges);
    let (_dir, path) = build_graph(n_nodes, &edges);

    c.bench_function("strand/open", |b| {
        b.iter(|| strand_core::Graph::open(black_box(&path)).unwrap())
    });

    let g = strand_core::Graph::open(&path).unwrap();
    let start = g.node_id("n0").unwrap();

    c.bench_function("strand/bfs_impact", |b| {
        b.iter(|| algo::bfs(black_box(&g), &[start], Dir::In, None))
    });

    c.bench_function("strand/scc", |b| {
        b.iter(|| algo::strongly_connected(black_box(&g)))
    });

    c.bench_function("strand/pagerank", |b| {
        b.iter(|| algo::pagerank(black_box(&g), false, 1e-8, 100))
    });

    // ---- petgraph comparison on identical edges ----
    c.bench_function("petgraph/build_bfs", |b| {
        b.iter(|| {
            let mut pg = petgraph::Graph::<(), ()>::new();
            let mut map = vec![petgraph::graph::NodeIndex::end(); n_nodes];
            for i in 0..n_nodes {
                map[i] = pg.add_node(());
            }
            for &(s, d) in &edges {
                pg.add_edge(map[s as usize], map[d as usize], ());
            }
            // BFS from node 0 over the reversed graph ("who depends on me")
            // approximated by BFS on the transpose built on the fly:
            // petgraph has no CSR transpose, so we BFS over all edges is
            // too slow — instead time just the construction + one BFS.
            let mut visited = vec![false; n_nodes];
            let mut q = std::collections::VecDeque::new();
            visited[0] = true;
            q.push_back(map[0]);
            while let Some(v) = q.pop_front() {
                for e in pg.edges_directed(v, petgraph::Direction::Outgoing) {
                    let w = e.target();
                    if !visited[w.index()] {
                        visited[w.index()] = true;
                        q.push_back(w);
                    }
                }
            }
            black_box(pg.edge_count())
        })
    });
}

criterion_group!(benches, bench_graph);
criterion_main!(benches);
