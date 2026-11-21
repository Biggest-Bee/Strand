//! `strand-store`: an embeddable read-write graph store ("SQLite for
//! graphs").
//!
//! Architecture (LSM-style, base + delta):
//!
//! - **Base**: immutable memory-mapped CSR files (`base-N.strand`), the same
//!   format `strand-core` reads.
//! - **Delta**: recent writes held in memory behind an `Arc`, persisted
//!   through an append-only **write-ahead log** (`wal-N.log`).
//! - **Reads** see the merged view via [`View`], which implements
//!   [`strand_core::view::GraphView`] - every Phase-1 analysis algorithm
//!   runs on a snapshot unchanged. With an empty delta, iteration is the
//!   pure base CSR fast path.
//! - **Compaction** periodically folds base+delta into a new base file and
//!   atomically swaps a tiny manifest; old bases are reclaimed lazily.
//!
//! Concurrency: many readers + one writer per store directory. The writer
//! holds an exclusive `fd-lock` file lock for its lifetime; readers take no
//! lock at all (they only read the manifest/WAL briefly at open, and pinned
//! `Arc`s thereafter), so readers never block the writer and compaction
//! never invalidates live snapshots.
//!
//! Durability: each commit is a single WAL record `[len][crc][payload]`,
//! fsynced before `commit()` returns (configurable). Replay stops at the
//! first bad checksum, which handles torn tail writes.
//!
//! # Example
//!
//! ```
//! use strand_core::view::GraphView;
//! use strand_store::Store;
//!
//! let dir = std::env::temp_dir().join(format!("strand-demo-{}", std::process::id()));
//! let db = Store::open(&dir).unwrap();
//!
//! {
//!     let mut tx = db.begin_write().unwrap();
//!     tx.add_edge("app", "lib").unwrap();
//!     tx.add_edge("lib", "core").unwrap();
//!     tx.commit().unwrap();
//! }
//!
//! // Readers see a consistent snapshot; analysis runs on the merged view.
//! let snap = db.begin_read().unwrap();
//! let view = snap.view();
//! assert_eq!(view.n_nodes(), 3);
//!
//! // Fold the delta into a fresh immutable base.
//! db.compact().unwrap();
//!
//! let _ = std::fs::remove_dir_all(&dir);
//! ```

mod delta;
mod view;
mod wal;

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use strand_core::Graph;
use strand_core::view::GraphView;

pub use delta::{Delta, EdgeOp};
pub use view::View;
pub use wal::Op;

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by strand-store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid store: {0}")]
    Invalid(String),
    #[error("store is read-only (another writer holds the lock)")]
    ReadOnly,
    #[error("graph error: {0}")]
    Graph(#[from] strand_core::Error),
    #[error("poisoned internal lock")]
    Poisoned,
}

/// Tunables.
#[derive(Clone, Debug)]
pub struct Options {
    /// fsync the WAL on every commit (default: true).
    pub fsync_on_commit: bool,
    /// Auto-compact once the delta's applied-op count reaches this floor
    /// AND exceeds ~10% of the base edge count (default: 1_000_000;
    /// 0 disables). Compaction is best-effort: a failure never fails the
    /// commit that triggered it, and is retried on later commits.
    pub compact_threshold_ops: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            fsync_on_commit: true,
            compact_threshold_ops: 1_000_000,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Manifest {
    version: u32,
    epoch: u64,
    base: Option<String>,
    wal: String,
}

struct State {
    base: Option<Arc<Graph>>,
    delta: Arc<Delta>,
    /// n_nodes of the base (0 when no base)
    base_n: u64,
    /// compaction epoch
    epoch: u64,
    /// commit sequence number (for snapshot ordering info)
    seq: u64,
}

/// An open store directory (`x.strandb/`).
pub struct Store {
    dir: PathBuf,
    writable: bool,
    fsync: bool,
    compact_threshold: usize,
    state: Mutex<State>,
    write_mutex: Mutex<()>,
    wal_file: Mutex<Option<File>>,
    // Keep the fd-lock guard alive for the store's lifetime. Leaked so the
    // guard can be 'static; one leak per open store, freed at process exit.
    _write_guard: Option<fd_lock::RwLockWriteGuard<'static, File>>,
}

impl Store {
    /// Open (creating if needed) a store at `dir` with default options.
    pub fn open(dir: impl AsRef<Path>) -> Result<Store> {
        Self::open_with_options(dir, Options::default())
    }

    /// Open with explicit options.
    pub fn open_with_options(dir: impl AsRef<Path>, opts: Options) -> Result<Store> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        // File lock: try exclusive write first; fall back to read-only.
        let lock_path = dir.join("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;
        let rw: &'static mut fd_lock::RwLock<File> =
            Box::leak(Box::new(fd_lock::RwLock::new(lock_file)));
        let (writable, write_guard) = match rw.try_write() {
            Ok(g) => (true, Some(g)),
            Err(_) => (false, None),
        };

        // Read manifest.
        let mpath = dir.join("manifest.json");
        let (mut state, wal_name) = if mpath.exists() {
            let text = fs::read_to_string(&mpath)?;
            let m: Manifest = serde_json::from_str(&text)
                .map_err(|e| Error::Invalid(format!("manifest.json: {e}")))?;
            if m.version != 1 {
                return Err(Error::Invalid(format!(
                    "unsupported manifest version {}",
                    m.version
                )));
            }
            let base = match &m.base {
                Some(f) => Some(Arc::new(Graph::open(dir.join(f))?)),
                None => None,
            };
            let base_n = base.as_ref().map(|g| g.n_nodes()).unwrap_or(0);
            (
                State {
                    base,
                    delta: Arc::new(Delta::default()),
                    base_n,
                    epoch: m.epoch,
                    seq: 0,
                },
                m.wal,
            )
        } else {
            // Fresh store.
            (
                State {
                    base: None,
                    delta: Arc::new(Delta::default()),
                    base_n: 0,
                    epoch: 0,
                    seq: 0,
                },
                format!("wal-0.log"),
            )
        };

        // Replay WAL into delta.
        let wal_path = dir.join(&wal_name);
        if wal_path.exists() {
            let f = File::open(&wal_path)?;
            let (txs, valid_len) = wal::replay(&f)?;
            let actual_len = f.metadata()?.len();
            for ops in txs {
                let d = Arc::make_mut(&mut state.delta);
                apply_ops_inner(&state.base, state.base_n, &ops, d)?;
                state.seq += 1;
            }
            // Truncate a torn/corrupt tail so later commits don't get
            // stranded behind garbage that replay would stop at.
            if writable && valid_len < actual_len {
                drop(f);
                let wf = OpenOptions::new().write(true).open(&wal_path)?;
                wf.set_len(valid_len)?;
                wf.sync_all()?;
            }
        }

        // Ensure the current WAL file exists for writers; fresh stores get
        // a manifest + empty wal immediately.
        let mut wal_file = None;
        if writable {
            if !wal_path.exists() {
                File::create(&wal_path)?;
            }
            wal_file = Some(
                OpenOptions::new()
                    .append(true)
                    .open(&wal_path)?,
            );
            if !mpath.exists() {
                write_manifest(&dir, &Manifest {
                    version: 1,
                    epoch: state.epoch,
                    base: state
                        .base
                        .as_ref()
                        .map(|_| format!("base-{}.strand", state.epoch)),
                    wal: wal_name.clone(),
                })?;
            }
        }

        let store = Store {
            dir,
            writable,
            fsync: opts.fsync_on_commit,
            compact_threshold: opts.compact_threshold_ops,
            state: Mutex::new(state),
            write_mutex: Mutex::new(()),
            wal_file: Mutex::new(wal_file),
            _write_guard: write_guard,
        };
        // Only the lock-holding writer garbage-collects: a read-only opener
        // could otherwise delete a live writer's in-flight .tmp files.
        if writable {
            store.gc_stale_files()?;
        }
        Ok(store)
    }

    /// Whether this handle may write.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Ops applied to the live delta since it was last reset. Useful for
    /// sizing the delta before compaction.
    pub fn delta_op_count(&self) -> usize {
        self.state
            .lock()
            .map(|st| st.delta.op_count)
            .unwrap_or(0)
    }

    /// Begin a write transaction. Only one may be open at a time; it holds
    /// the write mutex until commit/rollback, which also blocks compaction.
    pub fn begin_write(&self) -> Result<WriteTx<'_>> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let guard = self
            .write_mutex
            .lock()
            .map_err(|_| Error::Poisoned)?;
        Ok(WriteTx {
            store: self,
            ops: Vec::new(),
            _guard: guard,
        })
    }

    /// Begin a read snapshot: a consistent point-in-time view.
    pub fn begin_read(&self) -> Result<Snapshot> {
        let st = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(Snapshot {
            base: st.base.clone(),
            delta: st.delta.clone(),
            base_n: st.base_n,
            seq: st.seq,
            epoch: st.epoch,
        })
    }

    /// Fold base+delta into a new immutable base and atomically swap.
    /// Blocked while a write transaction is open.
    pub fn compact(&self) -> Result<()> {
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let _guard = self.write_mutex.lock().map_err(|_| Error::Poisoned)?;

        // Pin a consistent state.
        let (base, delta, base_n, epoch) = {
            let st = self.state.lock().map_err(|_| Error::Poisoned)?;
            (st.base.clone(), st.delta.clone(), st.base_n, st.epoch)
        };
        if delta.is_noop() {
            return Ok(()); // nothing to compact
        }

        let n_nodes = base_n as usize + delta.added_names.len();
        let view = View::new(base.as_deref(), base_n, delta.as_ref(), n_nodes);

        // Collect merged edges. Every live node is interned once so
        // isolated nodes survive compaction; edges reference interned
        // ids, avoiding a `String` alloc per edge endpoint.
        let weighted =
            base.as_ref().map(|b| b.has_weights()).unwrap_or(false) || delta.weighted;
        let mut builder = strand_core::GraphBuilder::new();
        let mut idx_of = vec![u32::MAX; n_nodes];
        for id in 0..n_nodes as u32 {
            if delta.removed.contains(&id) {
                continue;
            }
            idx_of[id as usize] = builder.intern(&view.node_name(id));
        }
        for id in 0..n_nodes as u32 {
            let ai = idx_of[id as usize];
            if ai == u32::MAX {
                continue;
            }
            if weighted {
                for (t, w) in view.merged_out(id) {
                    let ti = idx_of.get(t as usize).copied().unwrap_or(u32::MAX);
                    if ti != u32::MAX {
                        builder.add_edge_idx_weighted(ai, ti, w);
                    }
                }
            } else {
                view.out_edges(id, &mut |t| {
                    let ti = idx_of.get(t as usize).copied().unwrap_or(u32::MAX);
                    if ti != u32::MAX {
                        builder.add_edge_idx(ai, ti);
                    }
                });
            }
        }

        let new_epoch = epoch + 1;
        let base_name = format!("base-{new_epoch}.strand");
        let wal_name = format!("wal-{new_epoch}.log");
        let base_path = self.dir.join(&base_name);
        let wal_path = self.dir.join(&wal_name);
        builder.build(&base_path)?;

        // Do ALL fallible work before the manifest swap: create+validate
        // the new WAL handle and open the new base. After the swap only
        // infallible in-memory updates remain - a failure here used to
        // leave the store appending to a WAL the manifest no longer
        // referenced (and gc would delete).
        let new_wal_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)?;
        new_wal_file.sync_all()?;
        let new_base = Arc::new(Graph::open(&base_path)?);
        let new_base_n = new_base.n_nodes();

        // The only remaining fallible ops are the mutex locks - take them
        // before the swap too.
        let mut st = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut wf = self.wal_file.lock().map_err(|_| Error::Poisoned)?;

        // Atomic manifest swap.
        write_manifest(
            &self.dir,
            &Manifest {
                version: 1,
                epoch: new_epoch,
                base: Some(base_name),
                wal: wal_name,
            },
        )?;

        st.base = Some(new_base);
        st.delta = Arc::new(Delta::default());
        st.base_n = new_base_n;
        st.epoch = new_epoch;
        *wf = Some(new_wal_file);
        drop(wf);
        drop(st);

        // Best-effort: a GC failure must not report compaction as failed.
        let _ = self.gc_stale_files();
        Ok(())
    }

    /// Remove orphaned `base-*.strand` / `wal-*.log` files from older epochs.
    /// Best-effort: files still memory-mapped by live readers may resist
    /// deletion (Windows); they are retried on the next open/compact.
    fn gc_stale_files(&self) -> Result<()> {
        let keep: HashMap<String, ()> = {
            let st = self.state.lock().map_err(|_| Error::Poisoned)?;
            let mut k = HashMap::new();
            if let Some(b) = &st.base {
                // Recover base filename from epoch: base-{epoch}.strand
                k.insert(format!("base-{}.strand", st.epoch), ());
                let _ = b;
            }
            k.insert(format!("wal-{}.log", st.epoch), ());
            k
        };
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let is_base = name.starts_with("base-") && name.ends_with(".strand");
            let is_wal = name.starts_with("wal-") && name.ends_with(".log");
            // Orphaned tmp files are always safe to drop: writers only
            // publish via rename, so a leftover .tmp is an unfinished write.
            let is_tmp = name.ends_with(".tmp");
            if is_tmp || ((is_base || is_wal) && !keep.contains_key(&name)) {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(())
    }
}

/// A consistent point-in-time read snapshot.
pub struct Snapshot {
    base: Option<Arc<Graph>>,
    delta: Arc<Delta>,
    base_n: u64,
    seq: u64,
    epoch: u64,
}

impl Snapshot {
    /// The merged view - pass `&view` to any `strand_core::algo` function.
    pub fn view(&self) -> View<'_> {
        View::new(
            self.base.as_deref(),
            self.base_n,
            self.delta.as_ref(),
            self.base_n as usize + self.delta.added_names.len(),
        )
    }

    /// Commit sequence number this snapshot reflects.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Compaction epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Node id for `name` in this snapshot.
    pub fn node_id(&self, name: &str) -> Option<u32> {
        self.view().node_id(name)
    }

    /// Node count.
    pub fn n_nodes(&self) -> usize {
        self.base_n as usize + self.delta.added_names.len()
    }
}

/// A write transaction. Holds the store's write mutex until commit or drop,
/// so compaction cannot interleave and name->id resolution stays stable.
pub struct WriteTx<'a> {
    store: &'a Store,
    ops: Vec<Op>,
    _guard: MutexGuard<'a, ()>,
}

impl<'a> WriteTx<'a> {
    /// Add edge `src -> dst` ("src depends on dst"). Nodes are created if
    /// they don't exist.
    pub fn add_edge(&mut self, src: &str, dst: &str) -> Result<()> {
        self.ops.push(Op::AddEdge {
            src: src.to_string(),
            dst: dst.to_string(),
        });
        Ok(())
    }

    /// Add weighted edge `src -> dst`.
    pub fn add_edge_w(&mut self, src: &str, dst: &str, weight: f32) -> Result<()> {
        self.ops.push(Op::AddEdgeW {
            src: src.to_string(),
            dst: dst.to_string(),
            weight,
        });
        Ok(())
    }

    /// Remove edge `src -> dst` if present.
    pub fn remove_edge(&mut self, src: &str, dst: &str) -> Result<()> {
        self.ops.push(Op::RemoveEdge {
            src: src.to_string(),
            dst: dst.to_string(),
        });
        Ok(())
    }

    /// Ensure `name` exists as a node (possibly isolated).
    pub fn add_node(&mut self, name: &str) -> Result<()> {
        self.ops.push(Op::AddNode {
            name: name.to_string(),
        });
        Ok(())
    }

    /// Remove a node and all its incident edges.
    pub fn remove_node(&mut self, name: &str) -> Result<()> {
        self.ops.push(Op::RemoveNode {
            name: name.to_string(),
        });
        Ok(())
    }

    /// Number of ops staged.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Commit: append the WAL record, fsync (if configured), apply to the
    /// in-memory delta, bump the sequence. Durable once this returns.
    pub fn commit(self) -> Result<()> {
        if self.ops.is_empty() {
            return Ok(());
        }
        let payload = wal::encode_tx(&self.ops);

        // 1. WAL append + fsync -> durable.
        {
            let mut wf = self.store.wal_file.lock().map_err(|_| Error::Poisoned)?;
            let f = wf.as_mut().ok_or(Error::ReadOnly)?;
            let pre_len = f.metadata()?.len();
            if let Err(e) = wal::append_record(f, &payload)
                .and_then(|_| f.flush().map_err(strand_core::Error::Io))
            {
                // Roll back a torn record so the next replay doesn't stop
                // at garbage and strand later commits.
                let _ = f.set_len(pre_len);
                return Err(e.into());
            }
            if self.store.fsync {
                f.sync_all()?;
            }
        }

        // 2. Apply to in-memory delta. `Arc::make_mut` copies only when a
        //    live snapshot pins the old delta - steady-state commits on an
        //    unread store mutate in place instead of cloning the delta.
        let (delta_ops, base_edges) = {
            let mut st = self.store.state.lock().map_err(|_| Error::Poisoned)?;
            let base = st.base.clone();
            let base_n = st.base_n;
            let delta = Arc::make_mut(&mut st.delta);
            apply_ops_inner(&base, base_n, &self.ops, delta)?;
            let n = delta.op_count;
            let be = base.as_ref().map(|b| b.n_edges()).unwrap_or(0);
            st.seq += 1;
            (n, be)
        };

        // 3. Auto-compaction: release the write guard first (compact()
        //    takes write_mutex itself), then fold the delta into a fresh
        //    base. Threshold is the larger of the configured op count and
        //    10% of base edges, so the delta stays proportional to the
        //    graph it sits on. Best-effort - the commit above is already
        //    durable, so a compaction failure must not fail it (it will
        //    be retried on the next commit).
        let WriteTx {
            store,
            _guard,
            ops: _,
        } = self;
        drop(_guard);
        if store.compact_threshold > 0 {
            // Delta ops vs base edges: compact once the delta is both
            // over the configured floor and over ~10% of the base.
            let eff = store
                .compact_threshold
                .max((base_edges / 10).min(usize::MAX as u64) as usize);
            if delta_ops >= eff {
                if let Err(e) = store.compact() {
                    eprintln!("strand-store: auto-compaction failed: {e}");
                }
            }
        }
        Ok(())
    }
}

// ---- internals ----

fn write_manifest(dir: &Path, m: &Manifest) -> Result<()> {
    let tmp = dir.join("manifest.json.tmp");
    let text = serde_json::to_string_pretty(m)
        .map_err(|e| Error::Invalid(format!("manifest serialize: {e}")))?;
    {
        let mut f = File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join("manifest.json"))?;
    // Best-effort directory fsync so the rename itself is durable.
    // (File::open on a directory only works on Unix.)
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Resolve a name to its *current* node id. Delta-added names shadow base
/// names (a name re-added after `remove_node` gets a fresh delta id, so the
/// newest incarnation always wins).
fn resolve(base: &Option<Arc<Graph>>, delta: &Delta, name: &str) -> Option<u32> {
    if let Some(&id) = delta.added_ids.get(name) {
        return Some(id);
    }
    base.as_ref().and_then(|b| b.node_id(name))
}

/// Apply ops to `delta` in place. `base`/`base_n` describe the immutable
/// base the delta sits on.
fn apply_ops_inner(
    base: &Option<Arc<Graph>>,
    base_n: u64,
    ops: &[Op],
    delta: &mut Delta,
) -> Result<()> {
    for op in ops {
        delta.op_count += 1;
        match op {
            Op::AddEdge { src, dst } => {
                let s = get_or_create(base, delta, base_n, src);
                let d = get_or_create(base, delta, base_n, dst);
                delta.out.entry(s).or_default().insert(d, EdgeOp::Set(1.0));
                delta.inn.entry(d).or_default().insert(s, EdgeOp::Set(1.0));
            }
            Op::AddEdgeW { src, dst, weight } => {
                let s = get_or_create(base, delta, base_n, src);
                let d = get_or_create(base, delta, base_n, dst);
                delta.weighted = true;
                delta.out.entry(s).or_default().insert(d, EdgeOp::Set(*weight));
                delta.inn.entry(d).or_default().insert(s, EdgeOp::Set(*weight));
            }
            Op::RemoveEdge { src, dst } => {
                let s = resolve(base, delta, src);
                let d = resolve(base, delta, dst);
                if let (Some(s), Some(d)) = (s, d) {
                    delta.out.entry(s).or_default().insert(d, EdgeOp::Del);
                    delta.inn.entry(d).or_default().insert(s, EdgeOp::Del);
                }
            }
            Op::AddNode { name } => {
                get_or_create(base, delta, base_n, name);
            }
            Op::RemoveNode { name } => {
                if let Some(id) = resolve(base, delta, name) {
                    delta.removed.insert(id);
                }
            }
        }
    }
    Ok(())
}

fn get_or_create(
    base: &Option<Arc<Graph>>,
    delta: &mut Delta,
    base_n: u64,
    name: &str,
) -> u32 {
    // A removed id is dead forever: re-adding the name creates a new
    // generation with a fresh delta id. Old incident edges stay hidden
    // because they point at the tombstoned id.
    if let Some(id) = resolve(base, delta, name) {
        if !delta.removed.contains(&id) {
            return id;
        }
    }
    let id = base_n as u32 + delta.added_names.len() as u32;
    delta.added_names.push(name.to_string());
    delta.added_ids.insert(name.to_string(), id);
    id
}
