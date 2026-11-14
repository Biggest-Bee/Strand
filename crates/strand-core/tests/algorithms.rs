//! Hand-checked unit tests for every algorithm.

use strand_core::algo::{self, Dir};
use strand_core::{Graph, GraphBuilder};

/// diamond:  app->liba, app->libb, liba->core, libb->core, core->util, tool->liba
fn diamond() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    for (s, d) in [
        ("app", "liba"),
        ("app", "libb"),
        ("liba", "core"),
        ("libb", "core"),
        ("core", "util"),
        ("tool", "liba"),
    ] {
        b.add_edge(s, d);
    }
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    (dir, p)
}

#[test]
fn bfs_depths() {
    let (_d, p) = diamond();
    let g = Graph::open(&p).unwrap();
    let app = g.node_id("app").unwrap();
    let depths = algo::bfs(&g, &[app], Dir::Out, None);
    let depth_of = |n: &str| depths[g.node_id(n).unwrap() as usize];
    assert_eq!(depth_of("app"), 0);
    assert_eq!(depth_of("liba"), 1);
    assert_eq!(depth_of("libb"), 1);
    assert_eq!(depth_of("core"), 2);
    assert_eq!(depth_of("util"), 3);
    assert_eq!(depth_of("tool"), algo::UNVISITED); // tool doesn't depend on app-chain

    // depth limit
    let d2 = algo::bfs(&g, &[app], Dir::Out, Some(1));
    assert_eq!(d2[g.node_id("core").unwrap() as usize], algo::UNVISITED);
    assert_eq!(d2[g.node_id("liba").unwrap() as usize], 1);

    // impact direction: core's dependents
    let core = g.node_id("core").unwrap();
    let imp = algo::bfs(&g, &[core], Dir::In, None);
    let idepth = |n: &str| imp[g.node_id(n).unwrap() as usize];
    assert_eq!(idepth("core"), 0);
    assert_eq!(idepth("liba"), 1);
    assert_eq!(idepth("libb"), 1);
    assert_eq!(idepth("app"), 2);
    assert_eq!(idepth("tool"), 2);
    assert_eq!(idepth("util"), algo::UNVISITED);
}

#[test]
fn shortest_path() {
    let (_d, p) = diamond();
    let g = Graph::open(&p).unwrap();
    let path = algo::shortest_path(
        &g,
        g.node_id("app").unwrap(),
        g.node_id("util").unwrap(),
    )
    .unwrap();
    let names: Vec<&str> = path.iter().map(|&i| g.node_name(i)).collect();
    // app->liba->core->util or app->libb->core->util (both length 3)
    assert_eq!(names.len(), 4);
    assert_eq!(names[0], "app");
    assert_eq!(names[3], "util");
    assert!(names[1] == "liba" || names[1] == "libb");
    assert_eq!(names[2], "core");

    // unreachable
    assert!(algo::shortest_path(
        &g,
        g.node_id("util").unwrap(),
        g.node_id("app").unwrap()
    )
    .is_none());
}

#[test]
fn k_shortest_paths_counts() {
    let (_d, p) = diamond();
    let g = Graph::open(&p).unwrap();
    let paths = algo::k_shortest_paths(
        &g,
        g.node_id("app").unwrap(),
        g.node_id("util").unwrap(),
        10,
    );
    // Exactly two shortest chains: via liba and via libb.
    assert_eq!(paths.len(), 2);
    for p in &paths {
        assert_eq!(p.len(), 4);
    }

    // k=1 gives one path
    assert_eq!(
        algo::k_shortest_paths(&g, g.node_id("app").unwrap(), g.node_id("util").unwrap(), 1)
            .len(),
        1
    );
}

#[test]
fn scc_and_cycles() {
    // a->b->c->a cycle, c->d, d->e, e->d second cycle, f isolated dep
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    for (s, d) in [
        ("a", "b"), ("b", "c"), ("c", "a"), ("c", "d"), ("d", "e"), ("e", "d"), ("f", "a"),
    ] {
        b.add_edge(s, d);
    }
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();

    let sccs = algo::strongly_connected(&g);
    let sizes: Vec<usize> = sccs.iter().map(|c| c.len()).collect();
    // Two 3-cycles? a,b,c is one SCC of 3; d,e is SCC of 2; f singleton.
    assert!(sizes.contains(&3), "sizes: {sizes:?}");
    assert!(sizes.contains(&2), "sizes: {sizes:?}");
    assert!(sizes.contains(&1), "sizes: {sizes:?}");

    // order: dependencies first — f depends on a-cycle; d/e cycle: d->e,e->d
    // and c->d. Emission order must place {d,e} before {a,b,c} before f? f->a
    // means f depends on a,b,c cycle. c->d means abc depends on de.
    // deps-first: de, abc, f? but f->a edge: f depends on abc → abc before f.
    // and abc depends on de → de before abc.
    let names: Vec<Vec<String>> = sccs
        .iter()
        .map(|c| c.iter().map(|&i| g.node_name(i).to_string()).collect())
        .collect();
    let pos = |member: &str| {
        names
            .iter()
            .position(|c| c.iter().any(|m| m == member))
            .unwrap()
    };
    assert!(pos("d") < pos("a"), "de should come before abc: {names:?}");
    assert!(pos("a") < pos("f"), "abc should come before f: {names:?}");
}

#[test]
fn self_loop_is_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge("a", "a"); // self-loop (importer skips these, builder keeps)
    b.add_edge("a", "b");
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    let sccs = algo::strongly_connected(&g);
    // a's SCC contains self-loop; detect via out_targets contains self.
    let a = g.node_id("a").unwrap();
    assert!(g.out_targets(a).contains(&a));
    assert_eq!(sccs.len(), 2);
}

#[test]
fn critical_path() {
    // chain: top->mid->bot->leaf  plus shortcut top->leaf
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    for (s, d) in [("top", "mid"), ("mid", "bot"), ("bot", "leaf"), ("top", "leaf")] {
        b.add_edge(s, d);
    }
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    let bo = algo::analyze(&g);
    // Longest chain has 4 nodes.
    assert_eq!(bo.critical_len, 4);
    let names: Vec<&str> = bo.critical_path.iter().map(|&i| g.node_name(i)).collect();
    assert_eq!(names, vec!["leaf", "bot", "mid", "top"]); // deps first
}

#[test]
fn pagerank_orders_reasonably() {
    // hub depended on by many should outrank leaves in reverse mode.
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    for i in 0..50 {
        b.add_edge(format!("app{i}"), "hub");
        b.add_edge(format!("app{i}"), "leafdep");
    }
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    // Risk ranking = PageRank on the dependency graph (rank flows
    // dependent -> dependency): the hub should dominate.
    let pr = algo::pagerank(&g, false, 1e-9, 200);
    let hub = g.node_id("hub").unwrap() as usize;
    let leafdep = g.node_id("leafdep").unwrap() as usize;
    let app0 = g.node_id("app0").unwrap() as usize;
    assert!(pr[hub] > pr[app0], "hub should outrank a leaf app");
    // hub and leafdep have equal in-degree; similar scores expected.
    assert!((pr[hub] - pr[leafdep]).abs() < 1e-6);
}

#[test]
fn impact_sizes_match_bfs() {
    let (_d, p) = diamond();
    let g = Graph::open(&p).unwrap();
    let sizes = algo::impact_sizes(&g);
    let core = g.node_id("core").unwrap() as usize;
    let util = g.node_id("util").unwrap() as usize;
    let app = g.node_id("app").unwrap() as usize;
    assert_eq!(sizes[core], 4); // liba,libb,app,tool
    assert_eq!(sizes[util], 5); // core,liba,libb,app,tool
    assert_eq!(sizes[app], 0);
    assert_eq!(sizes[util], sizes.len() as u32 - 1);
    let _ = app;
}

#[test]
fn common_sets() {
    let (_d, p) = diamond();
    let g = Graph::open(&p).unwrap();
    let app = g.node_id("app").unwrap();
    let tool = g.node_id("tool").unwrap();
    // shared dependencies of app and tool: liba, core, util
    let common = algo::common(&g, app, tool, Dir::Out);
    let names: Vec<&str> = common.iter().map(|&i| g.node_name(i)).collect();
    assert!(names.contains(&"liba"));
    assert!(names.contains(&"core"));
    assert!(names.contains(&"util"));
    assert!(!names.contains(&"libb"));
    assert!(!names.contains(&"app"));
    assert!(!names.contains(&"tool"));
}

#[test]
fn weighted_dijkstra() {
    // a->b (10), a->c (1), c->b (1): shortest a->b is via c cost 2.
    let dir = tempfile::tempdir().unwrap();
    let mut b = GraphBuilder::new();
    b.add_edge_weighted("a", "b", 10.0);
    b.add_edge_weighted("a", "c", 1.0);
    b.add_edge_weighted("c", "b", 1.0);
    let p = dir.path().join("g.strand");
    b.build(&p).unwrap();
    let g = Graph::open(&p).unwrap();
    // weight lookup: out_targets/out_weights parallel arrays
    let w = |u: u32, v: u32| -> Option<f64> {
        let ts = g.out_targets(u);
        let ws = g.out_weights(u)?;
        ts.iter()
            .position(|&t| t == v)
            .map(|i| ws[i] as f64)
    };
    let (path, cost) = algo::shortest_path_weighted(
        &g,
        g.node_id("a").unwrap(),
        g.node_id("b").unwrap(),
        w,
    )
    .unwrap();
    assert_eq!(cost, 2.0);
    let names: Vec<&str> = path.iter().map(|&i| g.node_name(i)).collect();
    assert_eq!(names, vec!["a", "c", "b"]);
}
