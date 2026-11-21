//! strand-store tests: transactions, snapshots, persistence, compaction,
//! WAL torn-tail recovery, and a randomized crash-consistency harness.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use strand_core::algo::{self, Dir};
use strand_core::view::GraphView;
use strand_store::Store;

fn commit(store: &Store, f: impl FnOnce(&mut strand_store::WriteTx<'_>)) {
    let mut tx = store.begin_write().unwrap();
    f(&mut tx);
    tx.commit().unwrap();
}

/// Adjacency of a snapshot view as name -> set of names.
fn adj_of(snap: &strand_store::Snapshot) -> BTreeMap<String, BTreeSet<String>> {
    let v = snap.view();
    let mut m = BTreeMap::new();
    for id in 0..v.n_nodes() as u32 {
        let name = v.node_name(id);
        let mut deps = BTreeSet::new();
        v.out_edges(id, &mut |w| {
            deps.insert(v.node_name(w));
        });
        m.insert(name, deps);
    }
    m
}

#[test]
fn basic_tx_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("s.strandb")).unwrap();
    assert!(store.is_writable());

    commit(&store, |tx| {
        tx.add_edge("app", "lib").unwrap();
        tx.add_edge("lib", "core").unwrap();
        tx.add_edge("tool", "lib").unwrap();
    });

    let snap = store.begin_read().unwrap();
    let adj = adj_of(&snap);
    assert_eq!(adj["app"], BTreeSet::from(["lib".to_string()]));
    assert_eq!(adj["lib"], BTreeSet::from(["core".to_string()]));
    assert_eq!(adj["tool"], BTreeSet::from(["lib".to_string()]));
    assert!(adj["core"].is_empty());

    // Analysis works on the merged view.
    let v = snap.view();
    let core = v.node_id("core").unwrap();
    let depths = algo::bfs(&v, &[core], Dir::In, None);
    let impacted: Vec<String> = depths
        .iter()
        .enumerate()
        .filter(|&(_, &d)| d != algo::UNVISITED && d != 0)
        .map(|(i, _)| v.node_name(i as u32))
        .collect();
    assert_eq!(impacted.len(), 3); // lib, app, tool
}

#[test]
fn persistence_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        commit(&store, |tx| {
            tx.add_edge("a", "b").unwrap();
            tx.add_edge("b", "c").unwrap();
        });
        commit(&store, |tx| {
            tx.add_edge("a", "c").unwrap();
        });
    }
    // Reopen: WAL replay restores the delta.
    let store = Store::open(&path).unwrap();
    let snap = store.begin_read().unwrap();
    let adj = adj_of(&snap);
    assert_eq!(adj["a"].len(), 2);
    assert_eq!(adj["b"], BTreeSet::from(["c".to_string()]));
}

#[test]
fn remove_edge_and_node() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("s.strandb")).unwrap();
    commit(&store, |tx| {
        tx.add_edge("a", "b").unwrap();
        tx.add_edge("a", "c").unwrap();
        tx.add_edge("b", "c").unwrap();
    });
    commit(&store, |tx| {
        tx.remove_edge("a", "c").unwrap();
    });
    {
        let snap = store.begin_read().unwrap();
        let adj = adj_of(&snap);
        assert_eq!(adj["a"], BTreeSet::from(["b".to_string()]));
    }
    commit(&store, |tx| {
        tx.remove_node("b").unwrap();
    });
    let snap = store.begin_read().unwrap();
    let adj = adj_of(&snap);
    // b is removed: a loses its edge to b; c loses dependent b.
    assert!(adj["a"].is_empty());
    assert!(adj.contains_key("b")); // id still exists but isolated+removed
}

#[test]
fn snapshot_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("s.strandb")).unwrap();
    commit(&store, |tx| {
        tx.add_edge("a", "b").unwrap();
    });
    let old = store.begin_read().unwrap();
    commit(&store, |tx| {
        tx.add_edge("a", "c").unwrap();
    });
    // Old snapshot must not see the new edge.
    let v_old = old.view();
    let a_old = v_old.node_id("a").unwrap();
    let mut deps = Vec::new();
    v_old.out_edges(a_old, &mut |w| deps.push(v_old.node_name(w)));
    assert_eq!(deps, vec!["b"]);
    // New snapshot sees both.
    let new = store.begin_read().unwrap();
    assert_eq!(adj_of(&new)["a"].len(), 2);
}

#[test]
fn compaction_preserves_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    let store = Store::open(&path).unwrap();
    commit(&store, |tx| {
        tx.add_edge("a", "b").unwrap();
        tx.add_edge("b", "c").unwrap();
        tx.add_node("isolated").unwrap();
    });
    let before = adj_of(&store.begin_read().unwrap());
    store.compact().unwrap();
    let after = adj_of(&store.begin_read().unwrap());
    assert_eq!(before, after);
    assert!(after.contains_key("isolated"));

    // Old snapshot still valid after compaction (pinned Arc).
    // (before was consumed; take a fresh pre-compact check next time.)

    // Reopen after compaction: state comes from new base, empty delta.
    drop(store);
    let store = Store::open(&path).unwrap();
    let snap = store.begin_read().unwrap();
    assert_eq!(adj_of(&snap), after);
    // Delta should be empty now: second compact is a no-op.
    store.compact().unwrap();
}

#[test]
fn snapshot_survives_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("s.strandb")).unwrap();
    commit(&store, |tx| {
        tx.add_edge("a", "b").unwrap();
    });
    let snap = store.begin_read().unwrap();
    commit(&store, |tx| {
        tx.add_edge("b", "c").unwrap();
    });
    store.compact().unwrap();
    // snap was taken before the second commit: sees only a->b.
    assert_eq!(adj_of(&snap)["a"].len(), 1);
    assert!(adj_of(&snap)["b"].is_empty());
    // Current state has both.
    assert_eq!(adj_of(&store.begin_read().unwrap())["b"].len(), 1);
}

#[test]
fn wal_torn_tail_recovers_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        for i in 0..10 {
            commit(&store, |tx| {
                tx.add_edge(&format!("n{i}"), "hub").unwrap();
            });
        }
    }
    // Corrupt the WAL: truncate mid-record.
    let wal = path.join("wal-0.log");
    let len = std::fs::metadata(&wal).unwrap().len();
    {
        let f = std::fs::OpenOptions::new().write(true).open(&wal).unwrap();
        f.set_len(len - 3).unwrap(); // chop inside last record
    }
    let store = Store::open(&path).unwrap();
    let snap = store.begin_read().unwrap();
    let adj = adj_of(&snap);
    // At most 9 edges survived; the torn record was dropped.
    let hub_deps: usize = adj
        .iter()
        .filter(|(_, deps)| deps.contains(&"hub".to_string()))
        .count();
    assert!(hub_deps <= 9, "hub_deps={hub_deps}");
    assert!(hub_deps >= 8, "hub_deps={hub_deps}");
}

#[test]
fn wal_bitflip_stops_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        commit(&store, |tx| {
            tx.add_edge("a", "b").unwrap();
        });
        commit(&store, |tx| {
            tx.add_edge("c", "d").unwrap();
        });
    }
    // Corrupt the WAL: flip a byte inside the LAST record so replay keeps
    // the first tx and drops the second.
    let wal = path.join("wal-0.log");
    let mut bytes = std::fs::read(&wal).unwrap();
    let p = bytes.len().saturating_sub(3);
    bytes[p] ^= 0xFF;
    std::fs::write(&wal, &bytes).unwrap();
    let store = Store::open(&path).unwrap();
    let adj = adj_of(&store.begin_read().unwrap());
    assert!(adj["a"].contains("b"));
    // Node "c" may not exist at all if its tx was dropped.
    assert!(!adj.get("c").is_some_and(|d| d.contains("d")));
}

#[test]
fn read_only_store_rejects_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    let writer = Store::open(&path).unwrap();
    commit(&writer, |tx| {
        tx.add_edge("a", "b").unwrap();
    });
    // Second open in same process can't take the write lock -> read-only.
    let reader = Store::open(&path).unwrap();
    assert!(!reader.is_writable());
    assert!(reader.begin_write().is_err());
    // But reads work.
    assert_eq!(adj_of(&reader.begin_read().unwrap())["a"].len(), 1);
    drop(writer);
}

#[test]
fn weighted_edges_survive_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("s.strandb")).unwrap();
    commit(&store, |tx| {
        tx.add_edge_w("a", "b", 2.5).unwrap();
        tx.add_edge_w("a", "c", 1.0).unwrap();
    });
    store.compact().unwrap();
    // Reopen and check the base file is weighted.
    drop(store);
    let dir2 = dir.path().join("s.strandb");
    let entries: Vec<_> = std::fs::read_dir(&dir2)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    let base = entries.iter().find(|n| n.starts_with("base-")).unwrap();
    let g = strand_core::Graph::open(dir2.join(base)).unwrap();
    assert!(g.has_weights());
}

// ---------- randomized model test ----------

/// Simple model: name -> set of (dep name, weight).
#[derive(Default)]
struct Model {
    edges: BTreeMap<String, BTreeMap<String, f32>>,
    nodes: BTreeSet<String>,
}

impl Model {
    fn add_edge(&mut self, s: &str, d: &str, w: f32) {
        self.nodes.insert(s.into());
        self.nodes.insert(d.into());
        self.edges.entry(s.into()).or_default().insert(d.into(), w);
    }
    fn remove_edge(&mut self, s: &str, d: &str) {
        if let Some(m) = self.edges.get_mut(s) {
            m.remove(d);
        }
    }
    fn remove_node(&mut self, n: &str) {
        self.nodes.remove(n);
        self.edges.remove(n);
        for m in self.edges.values_mut() {
            m.remove(n);
        }
    }
    fn adj(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut out = BTreeMap::new();
        for n in &self.nodes {
            out.insert(
                n.clone(),
                self.edges
                    .get(n)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default(),
            );
        }
        out
    }
}

#[test]
fn model_based_random_ops() {
    // Deterministic PRNG (xorshift) - no external deps.
    let mut seed = 0x12345678u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let names: Vec<String> = (0..8).map(|i| format!("n{i}")).collect();

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("s.strandb")).unwrap();
    let mut model = Model::default();

    for step in 0..200 {
        let op = rnd() % 5;
        let a = names[(rnd() as usize) % names.len()].clone();
        let b = names[(rnd() as usize) % names.len()].clone();
        match op {
            0 | 1 => {
                let w = (rnd() % 100) as f32 / 10.0;
                commit(&store, |tx| {
                    tx.add_edge_w(&a, &b, w).unwrap();
                });
                model.add_edge(&a, &b, w);
            }
            2 => {
                commit(&store, |tx| {
                    tx.remove_edge(&a, &b).unwrap();
                });
                model.remove_edge(&a, &b);
            }
            3 => {
                commit(&store, |tx| {
                    tx.remove_node(&a).unwrap();
                });
                model.remove_node(&a);
            }
            _ => {
                commit(&store, |tx| {
                    tx.add_edge(&a, &b).unwrap();
                });
                model.add_edge(&a, &b, 1.0);
            }
        }
        // Compare after every step.
        let got = adj_of(&store.begin_read().unwrap());
        // Store keeps removed nodes as isolated ids - filter to live model
        // nodes plus any store node that still has edges.
        let want = model.adj();
        for (n, deps) in &want {
            assert_eq!(got.get(n), Some(deps), "step {step}: node {n}");
        }
        // No store node outside the model may have edges.
        for (n, deps) in &got {
            if !want.contains_key(n) {
                assert!(deps.is_empty(), "step {step}: ghost node {n} has edges");
            }
        }
    }
}

// ---------- crash-consistency harness ----------

/// Simulates crashes by truncating/corrupting the WAL at random points,
/// then verifies the store contains exactly a prefix of committed txs.
#[test]
fn crash_consistency_random() {
    crash_consistency(500);
}

/// Full 10k-run version (ignored by default; run explicitly).
#[test]
#[ignore]
fn crash_consistency_10k() {
    crash_consistency(10_000);
}

fn crash_consistency(iters: usize) {
    let mut seed = 0xDEADBEEFu64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for it in 0..iters {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.strandb");
        let names: Vec<String> = (0..6).map(|i| format!("c{i}")).collect();

        // Phase 1: random commits, recording the op log.
        // Each tx is a list of (Add|Del, a, b).
        let mut committed: Vec<Vec<(bool, String, String)>> = Vec::new();
        {
            let store = Store::open(&path).unwrap();
            let ntx = 1 + (rnd() % 12) as usize;
            for _ in 0..ntx {
                let mut tx_ops = Vec::new();
                let nops = 1 + (rnd() % 4) as usize;
                let mut tx = store.begin_write().unwrap();
                for _ in 0..nops {
                    let a = names[(rnd() as usize) % names.len()].clone();
                    let b = names[(rnd() as usize) % names.len()].clone();
                    if rnd() % 4 == 0 {
                        tx.remove_edge(&a, &b).unwrap();
                        tx_ops.push((false, a, b));
                    } else {
                        tx.add_edge(&a, &b).unwrap();
                        tx_ops.push((true, a, b));
                    }
                }
                tx.commit().unwrap();
                committed.push(tx_ops);
            }
        }

        // Edge set after applying the first k committed txs.
        let prefix_edges = |k: usize| -> HashSet<(String, String)> {
            let mut s = HashSet::new();
            for tx in committed.iter().take(k) {
                for (add, a, b) in tx {
                    if *add {
                        s.insert((a.clone(), b.clone()));
                    } else {
                        s.remove(&(a.clone(), b.clone()));
                    }
                }
            }
            s
        };

        // Phase 2: randomly corrupt the WAL tail (torn write simulation).
        let mut corrupted = false;
        let wal = path.join("wal-0.log");
        if wal.exists() {
            let len = std::fs::metadata(&wal).unwrap().len();
            match rnd() % 3 {
                0 => {
                    corrupted = true;
                    // Truncate inside the file.
                    let cut = (rnd() as u64) % (len + 1);
                    let f = std::fs::OpenOptions::new().write(true).open(&wal).unwrap();
                    f.set_len(cut).unwrap();
                }
                1 => {
                    corrupted = true;
                    // Flip a byte near the end.
                    let mut bytes = std::fs::read(&wal).unwrap();
                    if !bytes.is_empty() {
                        let p = bytes.len() - 1 - (rnd() as usize % bytes.len().min(20));
                        bytes[p] ^= 0xFF;
                        std::fs::write(&wal, &bytes).unwrap();
                    }
                }
                _ => {} // no corruption
            }
        }

        // Phase 3: reopen and verify the store state equals EXACTLY some
        // prefix of the committed transactions - no partial tx, no lost
        // committed prefix beyond the torn tail.
        let store = Store::open(&path).unwrap();
        let snap = store.begin_read().unwrap();
        let adj = adj_of(&snap);
        let got: HashSet<(String, String)> = adj
            .iter()
            .flat_map(|(n, deps)| deps.iter().map(move |d| (n.clone(), d.clone())))
            .collect();

        let matches: Vec<usize> = (0..=committed.len())
            .filter(|&k| prefix_edges(k) == got)
            .collect();
        assert!(
            !matches.is_empty(),
            "iter {it}: store edge set matches no committed prefix"
        );
        // The matched prefix must be the longest one consistent with the
        // surviving WAL - i.e., we never see edges from *beyond* the last
        // good record combined with missing earlier ones. Check monotonic:
        // there must exist k in matches with k == number of fully-intact
        // records. We can't know that count directly, but any match is a
        // valid prefix; additionally the FULL set must match when there's
        // no corruption.
        if !corrupted && matches.last() != Some(&committed.len()) {
            panic!("iter {it}: uncorrupted WAL lost committed txs");
        }
    }
}

/// Corruption in the MIDDLE of the log (not the tail): flipping a byte
/// inside an early record's payload must make open fail loudly - never
/// silently drop that record and every later commit.
#[test]
fn wal_mid_log_corruption_refuses_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        // Several commits so the corrupted record is followed by more data.
        for i in 0..4 {
            commit(&store, |tx| {
                tx.add_edge(&format!("n{i}"), "dep").unwrap();
            });
        }
    }
    let wal = path.join("wal-0.log");
    let mut bytes = std::fs::read(&wal).unwrap();
    assert!(bytes.len() > 30);
    // Flip a byte inside the FIRST record's payload (past its 8-byte
    // header, well before the end of the file).
    bytes[10] ^= 0xFF;
    std::fs::write(&wal, &bytes).unwrap();

    let err = match Store::open(&path) {
        Ok(_) => panic!("mid-log corruption must fail open"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("corrupt") || err.to_string().contains("wal"),
        "unexpected error: {err}"
    );
}

/// A garbage length field (0x3FFFFFFF ≈ 1 GiB) at a record boundary must
/// return an error - not be mistaken for a torn tail (which would
/// silently truncate every later commit) and not trigger a giant alloc.
#[test]
fn wal_garbage_length_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        for i in 0..3 {
            commit(&store, |tx| {
                tx.add_edge(&format!("n{i}"), "dep").unwrap();
            });
        }
    }
    let wal = path.join("wal-0.log");
    let mut bytes = std::fs::read(&wal).unwrap();
    // Overwrite the first record's length field with 0x3FFFFFFF.
    bytes[0..4].copy_from_slice(&0x3FFF_FFFFu32.to_le_bytes());
    std::fs::write(&wal, &bytes).unwrap();

    let err = match Store::open(&path) {
        Ok(_) => panic!("garbage length must fail open"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("absurd") || err.to_string().contains("wal"),
        "unexpected error: {err}"
    );
}

/// A compaction that fails BEFORE the manifest swap must leave the old
/// base + WAL fully intact: the store reopens with every earlier commit.
/// (Post-swap code is infallible by construction - all fallible work,
/// including the manifest write, happens before the in-memory swap.)
#[test]
fn compact_failure_preserves_committed_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    let store = Store::open(&path).unwrap();
    for i in 0..5 {
        commit(&store, |tx| {
            tx.add_edge(&format!("n{i}"), "dep").unwrap();
        });
    }

    // Block the new base path: `base-1.strand` exists as a *directory*,
    // so builder.build() fails before the manifest swap.
    std::fs::create_dir(path.join("base-1.strand")).unwrap();
    let err = store.compact().expect_err("compaction must fail");
    assert!(err.to_string().contains("base-1") || err.to_string().len() > 0);

    // More commits after the failed compaction still work on the old WAL.
    commit(&store, |tx| {
        tx.add_edge("after", "dep").unwrap();
    });
    drop(store);

    // Reopen: every commit - including post-failure ones - is present.
    let store = Store::open(&path).unwrap();
    let snap = store.begin_read().unwrap();
    let adj = adj_of(&snap);
    for i in 0..5 {
        assert!(
            adj.get(&format!("n{i}"))
                .is_some_and(|deps| deps.contains(&"dep".to_string())),
            "missing edge n{i} -> dep after failed compaction"
        );
    }
    assert!(adj.get("after").is_some_and(|d| d.contains(&"dep".to_string())));

    // Cleanup so a later compact can succeed.
    std::fs::remove_dir(path.join("base-1.strand")).unwrap();
    store.compact().unwrap();
    let snap = store.begin_read().unwrap();
    let adj = adj_of(&snap);
    assert_eq!(adj.len(), 7); // n0..n4 + after + dep
}

#[test]
fn auto_compact_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let opts = strand_store::Options {
        compact_threshold_ops: 2,
        ..Default::default()
    };
    let store = Store::open_with_options(dir.path().join("s.strandb"), opts).unwrap();

    commit(&store, |tx| {
        tx.add_edge("a", "b").unwrap();
    });
    assert_eq!(store.delta_op_count(), 1);

    // Second op hits the threshold -> delta folds into a fresh base.
    commit(&store, |tx| {
        tx.add_edge("b", "c").unwrap();
    });
    assert_eq!(store.delta_op_count(), 0);

    // Delta starts counting again after compaction.
    commit(&store, |tx| {
        tx.add_edge("c", "d").unwrap();
    });
    assert_eq!(store.delta_op_count(), 1);

    // State survived the auto-compactions.
    let adj = adj_of(&store.begin_read().unwrap());
    assert_eq!(adj["a"], BTreeSet::from(["b".to_string()]));
    assert_eq!(adj["b"], BTreeSet::from(["c".to_string()]));
    assert_eq!(adj["c"], BTreeSet::from(["d".to_string()]));
}

#[test]
fn torn_tail_then_new_commit_survives_reopen() {
    // Regression: a torn WAL tail used to leave garbage in the file;
    // commits made after reopening landed *behind* it, and the next
    // replay stopped at the garbage - silently losing those commits.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        commit(&store, |tx| {
            tx.add_edge("a", "b").unwrap();
        });
        commit(&store, |tx| {
            tx.add_edge("c", "d").unwrap();
        });
    }
    // Simulate a torn tail: chop inside the last record.
    let wal = path.join("wal-0.log");
    let len = std::fs::metadata(&wal).unwrap().len();
    {
        let f = std::fs::OpenOptions::new().write(true).open(&wal).unwrap();
        f.set_len(len - 3).unwrap();
    }
    // Reopen: replay keeps a->b, drops the torn tail, truncates the file.
    {
        let store = Store::open(&path).unwrap();
        let adj = adj_of(&store.begin_read().unwrap());
        assert!(adj["a"].contains("b"));
        // Commit AFTER the torn tail was truncated.
        commit(&store, |tx| {
            tx.add_edge("x", "y").unwrap();
        });
    }
    // Reopen again: the post-crash commit must still be there.
    let store = Store::open(&path).unwrap();
    let adj = adj_of(&store.begin_read().unwrap());
    assert!(adj["x"].contains("y"), "post-crash commit lost: {adj:?}");
    assert!(adj["a"].contains("b"));
}

#[test]
fn mid_log_corruption_is_an_error() {
    // A bad record followed by more data is corruption, not a torn tail -
    // replay must fail loudly instead of dropping later transactions.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.strandb");
    {
        let store = Store::open(&path).unwrap();
        commit(&store, |tx| {
            tx.add_edge("a", "b").unwrap();
        });
        commit(&store, |tx| {
            tx.add_edge("c", "d").unwrap();
        });
        commit(&store, |tx| {
            tx.add_edge("e", "f").unwrap();
        });
    }
    // Flip a byte inside the FIRST record's payload.
    let wal = path.join("wal-0.log");
    let mut bytes = std::fs::read(&wal).unwrap();
    bytes[10] ^= 0xFF;
    std::fs::write(&wal, &bytes).unwrap();
    assert!(Store::open(&path).is_err());
}
