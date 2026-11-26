//! Round-trip, determinism, weights, kinds, and corruption tests.

use std::path::Path;

use strand_core::view::{ConfidenceView, GraphView};
use strand_core::{EdgeKind, Graph, GraphBuilder, MergeOp};

fn build(edges: &[(&str, &str)], dir: &tempfile::TempDir) -> std::path::PathBuf {
    let mut b = GraphBuilder::new();
    for &(s, d) in edges {
        b.add_edge(s, d);
    }
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    p
}

#[test]
fn roundtrip_neighbors() {
    let dir = tempfile::tempdir().unwrap();
    // a->b, a->c, b->d   (a depends on b,c; b depends on d)
    let p = build(&[("a", "b"), ("a", "c"), ("b", "d")], &dir);
    let g = Graph::open(&p).unwrap();

    assert_eq!(g.n_nodes(), 4);
    assert_eq!(g.n_edges(), 3);
    assert!(!g.has_weights());

    let a = g.node_id("a").unwrap();
    let b = g.node_id("b").unwrap();
    let c = g.node_id("c").unwrap();
    let d = g.node_id("d").unwrap();

    // ids assigned by sorted names: a=0,b=1,c=2,d=3
    assert_eq!((a, b, c, d), (0, 1, 2, 3));

    // out = dependencies
    assert_eq!(g.out_targets(a), &[b, c]);
    assert_eq!(g.out_targets(b), &[d]);
    assert!(g.out_targets(c).is_empty());
    assert!(g.out_targets(d).is_empty());

    // in = dependents
    assert_eq!(g.in_targets(b), &[a]);
    assert_eq!(g.in_targets(d), &[b]);
    assert!(g.in_targets(a).is_empty());

    assert_eq!(g.node_name(a), "a");
    assert_eq!(g.out_degree(a), 2);
    assert_eq!(g.in_degree(b), 1);
}

#[test]
fn determinism_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let edges = [
        ("z", "y"),
        ("y", "x"),
        ("x", "w"),
        ("a", "b"),
        ("b", "c"),
        ("a", "c"),
    ];
    let p1 = dir.path().join("g1.strand");
    let p2 = dir.path().join("g2.strand");
    let mut b1 = GraphBuilder::new();
    for &(s, d) in &edges {
        b1.add_edge(s, d);
    }
    b1.build(&p1).unwrap();
    let mut b2 = GraphBuilder::new();
    for &(s, d) in edges.iter().rev() {
        b2.add_edge(s, d);
    }
    b2.build(&p2).unwrap();
    assert_eq!(
        std::fs::read(&p1).unwrap(),
        std::fs::read(&p2).unwrap(),
        "same graph built from different input order must be byte-identical"
    );
}

#[test]
fn duplicate_edges_merge() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge_weighted("a", "b", 1.0);
    b.add_edge_weighted("a", "b", 2.0);
    b.add_edge_weighted("a", "b", 3.0);
    let p = dir.path().join("w.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert!(g.has_weights());
    assert_eq!(g.n_edges(), 1);
    let a = g.node_id("a").unwrap();
    let b = g.node_id("b").unwrap();
    assert_eq!(g.out_targets(a), &[b]);
    assert_eq!(g.out_weights(a), Some(&[6.0f32][..]));
    assert_eq!(g.in_weights(b), Some(&[6.0f32][..]));

    // Max merge.
    let mut b = GraphBuilder::new();
    b.set_merge(MergeOp::Max);
    b.add_edge_weighted("a", "b", 1.0);
    b.add_edge_weighted("a", "b", 5.0);
    b.add_edge_weighted("a", "b", 3.0);
    let p2 = dir.path().join("w2.strand");
    b.build(&p2).unwrap();
    let g2 = Graph::open(&p2).unwrap();
    assert_eq!(
        g2.out_weights(g2.node_id("a").unwrap()),
        Some(&[5.0f32][..])
    );
}

#[test]
fn node_kinds_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge("app", "lib");
    b.set_kind("app", "service");
    b.set_kind("lib", "crate");
    let p = dir.path().join("k.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert_eq!(g.node_kind(g.node_id("app").unwrap()), Some("service"));
    assert_eq!(g.node_kind(g.node_id("lib").unwrap()), Some("crate"));
}

#[test]
fn edge_kinds_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge_kind("a", "b", EdgeKind::Static);
    b.add_edge_kind("a", "c", EdgeKind::Heuristic);
    b.add_edge_kind("b", "c", EdgeKind::Traced);
    b.add_edge_kind("b", "d", EdgeKind::Declared);
    let p = dir.path().join("ek.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();

    let a = g.node_id("a").unwrap();
    let b = g.node_id("b").unwrap();
    let c = g.node_id("c").unwrap();
    let _d = g.node_id("d").unwrap();

    // Targets are id-sorted: a's out = [b(1), c(2)].
    let ka = g.out_kinds(a).unwrap();
    assert_eq!(
        ka,
        &[EdgeKind::Static.as_tag(), EdgeKind::Heuristic.as_tag()]
    );
    let kb = g.out_kinds(b).unwrap();
    assert_eq!(
        kb,
        &[EdgeKind::Traced.as_tag(), EdgeKind::Declared.as_tag()]
    );

    // Reverse kinds parallel in_targets.
    let kc = g.in_kinds(c).unwrap();
    assert_eq!(kc.len(), 2);
    assert!(kc.contains(&EdgeKind::Heuristic.as_tag()));
    assert!(kc.contains(&EdgeKind::Traced.as_tag()));

    // Kind slices parallel the target slices.
    assert_eq!(g.out_targets(a).len(), ka.len());
    assert_eq!(g.out_targets(b).len(), kb.len());
}

#[test]
fn edge_kind_dedup_keeps_max_confidence() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    // Same edge declared twice with different kinds: highest wins.
    b.add_edge_kind("a", "b", EdgeKind::Heuristic);
    b.add_edge_kind("a", "b", EdgeKind::Static);
    let p = dir.path().join("dk.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    let a = g.node_id("a").unwrap();
    assert_eq!(g.n_edges(), 1);
    assert_eq!(g.out_kinds(a).unwrap(), &[EdgeKind::Static.as_tag()]);
}

#[test]
fn all_static_edges_write_no_kind_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let p = build(&[("a", "b"), ("b", "c")], &dir);
    let g = Graph::open(&p).unwrap();
    let a = g.node_id("a").unwrap();
    // Pre-kind files (and all-Static builds) expose no kind table;
    // readers treat every edge as Static.
    assert!(g.out_kinds(a).is_none());
}

#[test]
fn confidence_view_filters_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    // a -> b (Static), b -> c (Heuristic), a -> c (Static direct).
    b.add_edge_kind("a", "b", EdgeKind::Static);
    b.add_edge_kind("b", "c", EdgeKind::Heuristic);
    b.add_edge_kind("a", "c", EdgeKind::Static);
    let p = dir.path().join("cv.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();

    let a = g.node_id("a").unwrap();
    let c = g.node_id("c").unwrap();

    // Unfiltered: c reachable from a in 1 hop (direct edge).
    let all = ConfidenceView::new(&g, 0);
    let mut reached = Vec::new();
    all.out_edges(a, &mut |t| reached.push(t));
    assert_eq!(reached.len(), 2);

    // min=Declared: b->c is Heuristic (0 < 2) so it's cut; a->b and
    // a->c remain. c still reachable via a->c.
    let v = ConfidenceView::new(&g, EdgeKind::Declared.confidence());
    let depths = strand_core::algo::bfs(&v, &[a], strand_core::algo::Dir::Out, None);
    assert_ne!(depths[c as usize], strand_core::algo::UNVISITED);

    // min=Static: only Static edges - a->c survives, a->b is Static
    // too, but b->c cut. From a: {b, c} still (a->c direct).
    // Check the b->c hop is gone: from b alone, c unreachable.
    let b = g.node_id("b").unwrap();
    let v2 = ConfidenceView::new(&g, EdgeKind::Static.confidence());
    let depths2 = strand_core::algo::bfs(&v2, &[b], strand_core::algo::Dir::Out, None);
    assert_eq!(depths2[c as usize], strand_core::algo::UNVISITED);
}

#[test]
fn weighted_path_respects_min_confidence() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    // a->b (w1, Static), b->c (w1, Heuristic), a->c (w5, Static).
    // Unfiltered cheapest a->c is via b (cost 2); filtered it's direct (5).
    b.add_edge_weighted_kind("a", "b", 1.0, EdgeKind::Static);
    b.add_edge_weighted_kind("b", "c", 1.0, EdgeKind::Heuristic);
    b.add_edge_weighted_kind("a", "c", 5.0, EdgeKind::Static);
    let p = dir.path().join("wp.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    let (a, c) = (g.node_id("a").unwrap(), g.node_id("c").unwrap());

    let (path, cost) = strand_core::algo::shortest_path_weighted_csr(&g, a, c).unwrap();
    assert_eq!(path.len(), 3);
    assert_eq!(cost, 2.0);

    let (path, cost) = strand_core::algo::shortest_path_weighted_csr_min(
        &g,
        a,
        c,
        EdgeKind::Declared.confidence(),
    )
    .unwrap();
    assert_eq!(path, vec![a, c]);
    assert_eq!(cost, 5.0);
}

#[test]
fn isolated_nodes_via_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge("a", "b");
    b.set_kind("lonely", "crate");
    let p = dir.path().join("i.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert_eq!(g.n_nodes(), 3);
    let l = g.node_id("lonely").unwrap();
    assert!(g.out_targets(l).is_empty());
    assert!(g.in_targets(l).is_empty());
}

#[test]
fn empty_graph() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.set_kind("solo", "crate");
    let p = dir.path().join("e.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert_eq!(g.n_nodes(), 1);
    assert_eq!(g.n_edges(), 0);
    assert!(g.node_id("solo").is_some());
    assert!(g.node_id("nope").is_none());
}

#[test]
fn corrupt_files_error_not_crash() {
    let dir = tempfile::tempdir().unwrap();
    let p = build(&[("a", "b"), ("b", "c"), ("a", "c")], &dir);
    let bytes = std::fs::read(&p).unwrap();

    // Truncations at many lengths must all produce Err (or at worst a clean
    // open of a shorter valid file - but truncation always breaks checksum
    // or length checks, so all must Err).
    for len in [
        0usize,
        10,
        64,
        127,
        128,
        200,
        bytes.len() / 2,
        bytes.len() - 1,
    ] {
        let tmp = dir.path().join(format!("t{len}.strand"));
        std::fs::write(&tmp, &bytes[..len]).unwrap();
        assert!(Graph::open(&tmp).is_err(), "truncated to {len} opened");
    }

    // Single-byte flips at assorted offsets must be caught (checksum).
    for pos in [0usize, 8, 16, 40, 120, 128, 200, bytes.len() - 1] {
        let mut b = bytes.clone();
        b[pos] ^= 0xFF;
        let tmp = dir.path().join(format!("f{pos}.strand"));
        std::fs::write(&tmp, &b).unwrap();
        assert!(Graph::open(&tmp).is_err(), "flip at {pos} opened");
    }

    // Garbage file.
    let tmp = dir.path().join("garbage.strand");
    std::fs::write(&tmp, b"not a strand file at all..............").unwrap();
    assert!(Graph::open(&tmp).is_err());
}

#[test]
fn open_nonexistent_errors() {
    assert!(Graph::open(Path::new("does/not/exist.strand")).is_err());
}

#[test]
fn large_name_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    // 10k chain: n0 -> n1 -> ... -> n9999 ensures binary search correctness.
    for i in 0..9999 {
        b.add_edge(format!("n{i:05}"), format!("n{:05}", i + 1));
    }
    let p = dir.path().join("big.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    for i in [0usize, 1, 5000, 9998, 9999] {
        let name = format!("n{i:05}");
        assert_eq!(g.node_id(&name), Some(i as u32));
        assert_eq!(g.node_name(i as u32), name);
    }
    assert!(g.node_id("n10000").is_none());
    assert!(g.node_id("N0001").is_none()); // case-sensitive
}

#[test]
fn builder_from_btreemap_sorted_names() {
    // Names sort lexicographically, not by insertion order.
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge("zebra", "apple");
    b.add_edge("apple", "mango");
    let p = dir.path().join("s.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert_eq!(g.node_id("apple"), Some(0));
    assert_eq!(g.node_id("mango"), Some(1));
    assert_eq!(g.node_id("zebra"), Some(2));
    // zebra depends on apple; apple depends on mango
    let z = g.node_id("zebra").unwrap();
    let ap = g.node_id("apple").unwrap();
    let m = g.node_id("mango").unwrap();
    assert_eq!(g.out_targets(z), &[ap]);
    assert_eq!(g.out_targets(ap), &[m]);
    assert_eq!(g.in_targets(m), &[ap]);
}

#[test]
fn warnings_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge("a", "b");
    b.add_warning("src/x.py: 2 dynamic import site(s) - edges may be incomplete");
    b.add_warning("lockfile drift check truncated at 10 of 42 pins");
    let p = dir.path().join("w.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert_eq!(
        g.warnings(),
        &[
            "src/x.py: 2 dynamic import site(s) - edges may be incomplete".to_string(),
            "lockfile drift check truncated at 10 of 42 pins".to_string(),
        ]
    );
}

#[test]
fn warnings_empty_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let p = build(&[("a", "b")], &dir);
    let g = Graph::open(&p).unwrap();
    assert!(g.warnings().is_empty());
}

#[test]
fn warnings_with_node_kinds() {
    // Warnings must coexist with the node_meta kind tables.
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge("a", "b");
    b.set_kind("a", "crate");
    b.add_warning("dep: possible drift");
    let p = dir.path().join("wk.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    assert_eq!(g.node_kind(g.node_id("a").unwrap()), Some("crate"));
    assert_eq!(g.warnings(), &["dep: possible drift".to_string()]);
}
