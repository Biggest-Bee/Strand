//! Property tests: build -> read -> compare against a simple in-memory
//! reference graph, plus brute-force checks for `impact` and `why`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use proptest::prelude::*;
use strand_core::algo::{self, Dir};
use strand_core::{Graph, GraphBuilder};

/// Simple reference: name -> set of dependency names.
#[derive(Default)]
struct Ref {
    adj: HashMap<String, BTreeSet<String>>,
}

impl Ref {
    fn add(&mut self, s: &str, d: &str) {
        self.adj.entry(s.to_string()).or_default().insert(d.to_string());
        self.adj.entry(d.to_string()).or_default();
    }
    fn deps_of(&self, n: &str) -> &BTreeSet<String> {
        self.adj.get(n).unwrap()
    }
    /// Reverse adjacency: dependents.
    fn dependents_of(&self, n: &str) -> BTreeSet<String> {
        self.adj
            .iter()
            .filter(|(_, deps)| deps.contains(n))
            .map(|(k, _)| k.clone())
            .collect()
    }
    /// Transitive deps via plain DFS (independent of strand's BFS).
    fn reachable(&self, start: &str, dir_out: bool) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut q = VecDeque::from([start.to_string()]);
        while let Some(n) = q.pop_front() {
            if !seen.insert(n.clone()) {
                continue;
            }
            let next: Vec<String> = if dir_out {
                self.deps_of(&n).iter().cloned().collect()
            } else {
                self.adj
                    .iter()
                    .filter(|(_, deps)| deps.contains(&n))
                    .map(|(k, _)| k.clone())
                    .collect()
            };
            for m in next {
                q.push_back(m);
            }
        }
        seen
    }
}

fn arb_graph() -> impl Strategy<Value = (Vec<(String, String)>, Vec<String>)> {
    // Small name pool keeps collisions interesting.
    let name = prop_oneof![
        Just("a".to_string()),
        Just("b".to_string()),
        Just("c".to_string()),
        Just("d".to_string()),
        Just("e".to_string()),
        Just("f".to_string()),
        "n[0-9]{1,2}".prop_map(|s| s),
    ];
    (
        prop::collection::vec((name.clone(), name.clone()), 0..30),
        prop::collection::vec(name, 1..8),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn build_read_matches_reference((edges, _names) in arb_graph()) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.strand");

        let mut b = GraphBuilder::new();
        let mut refg = Ref::default();
        for (s, d) in &edges {
            if s != d {
                b.add_edge(s.clone(), d.clone());
                refg.add(s, d);
            }
        }
        b.build(&path).unwrap();
        let g = Graph::open(&path).unwrap();

        // Node set matches.
        let gnames: HashSet<String> = (0..g.n_nodes() as u32)
            .map(|i| g.node_name(i).to_string())
            .collect();
        let rnames: HashSet<String> = refg.adj.keys().cloned().collect();
        prop_assert_eq!(&gnames, &rnames);

        // Adjacency matches exactly, both directions.
        for name in &rnames {
            let id = g.node_id(name).unwrap();
            let got_out: BTreeSet<String> = g
                .out_targets(id)
                .iter()
                .map(|&t| g.node_name(t).to_string())
                .collect();
            prop_assert_eq!(&got_out, refg.deps_of(name));

            let got_in: BTreeSet<String> = g
                .in_targets(id)
                .iter()
                .map(|&t| g.node_name(t).to_string())
                .collect();
            prop_assert_eq!(&got_in, &refg.dependents_of(name));
        }

        // deps/impact reachability matches DFS reference.
        for name in &rnames {
            let id = g.node_id(name).unwrap();
            let d_out = algo::bfs(&g, &[id], Dir::Out, None);
            let got: HashSet<String> = d_out
                .iter()
                .enumerate()
                .filter(|&(_, &d)| d != algo::UNVISITED)
                .map(|(i, _)| g.node_name(i as u32).to_string())
                .collect();
            prop_assert_eq!(&got, &refg.reachable(name, true));

            let d_in = algo::bfs(&g, &[id], Dir::In, None);
            let goti: HashSet<String> = d_in
                .iter()
                .enumerate()
                .filter(|&(_, &d)| d != algo::UNVISITED)
                .map(|(i, _)| g.node_name(i as u32).to_string())
                .collect();
            prop_assert_eq!(&goti, &refg.reachable(name, false));
        }
    }

    #[test]
    fn why_path_valid_and_shortest((edges, _) in arb_graph()) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.strand");
        let mut b = GraphBuilder::new();
        let mut refg = Ref::default();
        for (s, d) in &edges {
            if s != d {
                b.add_edge(s.clone(), d.clone());
                refg.add(s, d);
            }
        }
        b.build(&path).unwrap();
        let g = Graph::open(&path).unwrap();

        for (s, d) in &edges {
            if s == d || !refg.adj.contains_key(s) || !refg.adj.contains_key(d) {
                continue;
            }
            let sid = g.node_id(s).unwrap();
            let did = g.node_id(d).unwrap();
            match algo::shortest_path(&g, sid, did) {
                Some(p) => {
                    // Path is a valid chain of dependencies.
                    for w in p.windows(2) {
                        prop_assert!(
                            g.out_targets(w[0]).contains(&w[1]),
                            "bad hop {} -> {}", g.node_name(w[0]), g.node_name(w[1])
                        );
                    }
                    prop_assert_eq!(*p.first().unwrap(), sid);
                    prop_assert_eq!(*p.last().unwrap(), did);
                    // Length equals BFS distance.
                    let depths = algo::bfs(&g, &[sid], Dir::Out, None);
                    prop_assert_eq!(depths[did as usize], (p.len() - 1) as u32);
                }
                None => {
                    // Reference must agree it's unreachable.
                    let reach = refg.reachable(s, true);
                    prop_assert!(!reach.contains(d));
                }
            }
        }
    }
}
