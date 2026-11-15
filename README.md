# Strand

[![CI](https://github.com/Biggest-Bee/Strand/actions/workflows/ci.yml/badge.svg)](https://github.com/Biggest-Bee/Strand/actions/workflows/ci.yml)

![Strand desktop app showing dependency analysis results](docs/screenshot.png)

A Rust **dependency and impact analysis tool** built on a fast,
memory-mapped **CSR (compressed sparse row) graph engine**.

Strand answers the question *"what breaks if I change X?"* in a second or
two, even on graphs with tens of millions of edges, with no server and
no query language:

```console
$ strand build deps.csv -o deps.strand
$ strand impact deps.strand serde_json
impact of [serde_json]: 20 affected (6 direct, 14 transitive)
$ strand why deps.strand my-app serde_json
my-app -> serde -> serde_json
```

## Why Strand

Existing tools are either in-memory libraries (petgraph, igraph, NetworkX)
or server databases (Neo4j). Strand's niche:

1. **Fast-open, zero-copy, single-file graphs.** A `.strand` file is a
   memory-mapped CSR with forward *and* reverse adjacency. Opening is a
   header parse + validation; traversals read straight from the mapping.
2. **Dependency/impact analysis as a first-class feature**: blast radius,
   why-paths, cycle detection, risk ranking, build order — all deterministic
   and scriptable (`--json` everywhere).
3. **Embeddable**: `Graph::open("x.strand")` from Rust, no server.

**`strand-store`** is an embeddable read-write graph store —
"SQLite for graphs" — with transactions, snapshots, a write-ahead log,
crash-safe compaction, and the same analysis algorithms running on the
merged view.

## Repository layout

```
crates/
  strand-core/      file format, mmap reader, builder, algorithms
  strand-import/    importers (cargo metadata JSON, CSV/TSV edge lists)
  strand-cli/       the `strand` binary
  strand-store/     embeddable read-write store (base + WAL delta)
  strand-app/       desktop GUI (eframe/egui) for browsing + analysis
docs/
  FORMAT.md         binary format spec (normative, .strand + .strandb)
testdata/           sample graphs used by tests and docs
```

Tests live in each crate's `tests/` directory (see [Testing](#testing)).

## Quick start

```console
cargo install --path crates/strand-cli   # or: cargo build --release
# (once published to crates.io: `cargo install strand`)

# Prebuilt binaries for Windows/Linux/macOS are on the
# [Releases](https://github.com/Biggest-Bee/Strand/releases) page.
# They are unsigned: Windows SmartScreen and macOS Gatekeeper will
# warn on first run — that's expected for unsigned binaries.

# From an edge list (src,dst[,weight]; "src depends on dst"):
strand build deps.csv -o deps.strand

# Multiple inputs merge into one graph (names must match across files):
strand build frontend.csv backend.csv meta.json -o all.strand

# From cargo metadata:
cargo metadata --format-version 1 > meta.json
strand build meta.json -o deps.strand

# Or straight from lockfiles/manifests (auto-detected by filename):
strand build Cargo.lock -o deps.strand      # Rust
strand build package-lock.json -o deps.strand  # npm
strand build poetry.lock -o deps.strand    # Python/poetry
strand build go.mod -o deps.strand         # Go
strand build pom.xml -o deps.strand        # Maven
# (--format cargo-lock|npm-lock|poetry-lock|go-mod|pom overrides)

# Scan a project folder and build a source-level dependency graph
# (skips target/, .git/, node_modules/):
strand scan ./my-project -o deps.strand

# Rust (mod/use/#[path]/include!/...crate paths), Python (import/from,
# relative imports), JS/TS (import/export-from/require, index resolution).
# --lang rust|python|js restricts to one language; default scans all.
strand scan ./my-project --lang python -o pydeps.strand

# Analyze:
strand info deps.strand
strand deps deps.strand my-crate --depth 3
strand impact deps.strand serde --by-depth
strand why deps.strand my-app serde_json
strand cycles deps.strand
strand top deps.strand --by impact -n 20
# huge DAGs: landmark-sampling estimate, top rows reranked exactly;
# tune with --samples N, force sampling with --approx (benchmarking),
# force exact (slow!) with --exact
strand order deps.strand --critical-path
strand roots deps.strand
strand leaves deps.strand
strand common deps.strand deps a b

# Impact of everything changed vs a git ref (CI use):
# maps `git diff --name-only <ref>` paths onto graph nodes — exact path
# for file-level scan graphs, directory/package segment for cargo graphs.
strand impact deps.strand --git-diff origin/main --max-impact 25
# exits non-zero when the blast radius exceeds --max-impact

# Export diagrams for docs/PRs (Graphviz DOT or Mermaid):
strand export deps.strand --format mermaid --impact serde_json --depth 2
strand export deps.strand --format dot --why my-app serde_json

# Enforce architecture rules (exit 1 on violations, CI-friendly):
# strand.rules:
#   forbid ui/ -> db/        # substring match on node names
#   forbid *.test -> src/    # * and ? globs also work
strand check deps.strand            # reads ./strand.rules
strand check deps.strand --rules ci.rules --json
```

Every command accepts `--json` for CI use.

## The store (`strand-store`)

For graphs that change, `strand-store` keeps the immutable `.strand` base
and layers a small write-optimized delta on top:

```rust
use strand_store::Store;

let db = Store::open("graph.strandb")?;

// One writer at a time (enforced by an fd-lock file); readers are unblocked.
{
    let mut tx = db.begin_write()?;
    tx.add_edge("app", "lib")?;
    tx.remove_edge("app", "old-lib")?;
    tx.commit()?;              // WAL append + fsync -> durable
}

// Any number of consistent point-in-time snapshots; compaction never
// invalidates them (they pin their own Arc'd base+delta).
let snap = db.begin_read()?;
let view = snap.view();                  // implements strand_core::view::GraphView
let depths = strand_core::algo::bfs(&view, &[core_id], Dir::In, None);

db.compact()?;   // fold delta into a fresh base-<epoch>.strand, atomic manifest swap

// Or let it manage itself: commits auto-compact once the delta passes
// Options::compact_threshold_ops (default 1M ops; best-effort).
//
// Heads-up on delta RAM: each applied op costs ~100+ bytes in the
// in-memory delta maps, so 1M ops ≈ ~120MB. The effective threshold is
// max(compact_threshold_ops, base_edges/10) — on a 50M-edge base the
// delta can reach ~5M ops (~580MB) before auto-compaction kicks in.
// Lower compact_threshold_ops if that spike matters.
```

- **Durability**: each commit is one WAL record `[len][crc][ops]`, fsynced
  before `commit()` returns. On open, replay stops at the first bad
  checksum — torn tail writes lose at most the uncommitted tail.
- **Reads**: with an empty delta, neighbor iteration *is* the pure CSR fast
  path; with a small delta, untouched nodes still take it (per-node merge
  only where the delta has ops).
- **Compaction**: rebuilds a new immutable base, fsyncs, atomically swaps
  `manifest.json`, reclaims old epoch files lazily. Live snapshots keep
  their pinned `Arc`s, so readers are never blocked.
- **Node removal**: `remove_node` tombstones the id; re-adding the name
  creates a fresh id, so stale incident edges never resurrect.

Store layout and the WAL/op encoding are specified in
[`docs/FORMAT.md`](docs/FORMAT.md#store-directory-format-strandb).

## Desktop app (`strand-app`)

A native window (eframe/egui, no webview) for people who'd rather click
than type:

```console
cargo run -p strand-app        # or: cargo build --release -p strand-app
```

- **Open .strand…** loads an immutable graph; **Open store…** loads a
  `.strandb` directory (read-write if the lock is free, read-only
  otherwise — analyses work identically on the merged view).
- Pick nodes A and B — the boxes autocomplete as you type (up to 8
  case-insensitive substring matches; the index is skipped on graphs over
  200k nodes) — then run **Deps**, **Impact**, **Why A->B**,
  **Cycles**, **Build order**, **Roots**, **Leaves**, **Top** (in-degree /
  impact / pagerank), and **Common deps/impact** — all with an optional
  depth limit.
- Report rows that name a single node are clickable: clicking one selects
  it as node A, so you can walk the graph (e.g. click an impacted
  dependent, then re-run Impact).
- The canvas draws the graph (ring layout by BFS depth after an
  impact/deps run, golden-angle scatter otherwise), highlighting the
  affected set. It handles up to 100k nodes / 300k edges: past 8k nodes
  it switches to cheap square markers, and past 150k edges it only draws
  edges touching the highlighted set.
- With a writable store open, the **Edit store** panel commits real
  transactions: **Add/Remove edge A->B** and **Add/Remove node A** (names
  come from the A/B boxes; edges auto-create missing nodes). Edits are
  WAL-durable immediately and show up in subsequent analyses.

`.strand` files stay strictly read-only; store edits go through
`strand-store` transactions (fsync'd WAL + atomic delta apply).

## File format

See [`docs/FORMAT.md`](docs/FORMAT.md). Highlights:

- 128-byte header + 10 sections, all 8-byte aligned, little-endian.
- Forward and reverse CSR adjacency, sorted targets, optional f32 weights.
- xxh64 checksum over all post-header bytes; readers validate magic,
  version, layout, monotonic offsets, target bounds, and UTF-8 names before
  trusting any slice. Corrupt/truncated files produce clean errors.
- Node ids are dense `u32`s assigned by lexicographic name order, so builds
  are **byte-for-byte deterministic**.

## Benchmarks

Criterion, synthetic graph (i5-1335U, 12 threads, 8GB RAM, release build):

| Operation | 200k nodes / ~1M edges |
|---|---|
| `strand/open` (mmap + full validation + checksum) | ~21 ms |
| reverse BFS (`impact`) | ~35 ms |
| Tarjan SCC (iterative) | ~94 ms |
| PageRank (100 iters, rayon) | ~151 ms |
| petgraph: build `Graph` + one BFS, same edges | ~123 ms |

Store read path (`strand-store`, 20k nodes / 100k edges, reverse BFS over
the merged view vs the same BFS on the bare `Graph`):

| View | time |
|---|---|
| pure CSR `Graph` | ~7 µs |
| store snapshot, empty delta | ~8–11 µs |
| store snapshot, 200-edge delta | ~9–23 µs |

Timings are microseconds on a small graph and fluctuate run-to-run; the
structural point is that the empty-delta path is within ~10–20% of pure CSR
and the merge cost is proportional to delta-touched nodes, not graph size.
Reproduce: `cargo bench -p strand-store`.

Notes:

- `open` validates *everything* (layout, monotonic offsets, target bounds,
  UTF-8 names, xxh64 checksum over the whole file), so its cost scales with
  file size. Measured on a 790MB / 50M-edge file (below): ~0.5s warm,
  ~1.8s cold.
  The mapping itself is zero-copy — traversals touch only the pages they
  need.
- petgraph has no on-disk CSR format; the comparison above is in-memory
  construction + BFS, not open+query. Strand's advantage is that the "open"
  cost is paid once and queries then run directly on the mapped file with
  no per-query deserialization.
- `impact_sizes` (used by `top --by impact`) collapses the graph to its
  SCC condensation DAG and computes ancestor sets with bitsets —
  `O(E·C/64)` word-ops, memory-blocked to ~256MB. On graphs whose
  component count makes that too expensive it falls back to a
  per-node reverse BFS (fine for small/medium graphs; see Limitations).

Reproduce: `cargo bench` (env `STRAND_BENCH_NODES`, `STRAND_BENCH_EDGES`).

### Large graph (10M nodes / 50M edges)

`cargo run --release -p strand-core --example bigbench` streams a
10,000,000-node / 50,000,000-edge graph (790MB `.strand` file) directly in
the file format, then times the real open + analyses. Measured on an
i5-1335U (12 threads, 8GB RAM); page cache warm unless noted:

| Operation | time |
|---|---|
| file generation (streaming writer) | ~3.7 s |
| `Graph::open` (mmap + validation + xxh64 over 790MB) | ~0.5 s warm / ~1.8 s cold |
| forward BFS visiting all 10M nodes / 50M edges | ~1.3 s |
| Tarjan SCC (iterative) | ~9 s |
| PageRank (~0.12 s/iter, rayon) | ~0.25 s — converged in ~2 iters |
| `top --by impact` (SCC condensation + bitsets) | ~17 s total incl. open+SCC |

Caveat: the synthetic graph is near-regular (every node has exactly 5
out-edges), so PageRank converges unusually fast. Real dependency graphs
are skewed with a few hub nodes; expect more iterations there. BFS and SCC
times are edge-count bound and should transfer to skewed graphs.

### Real-world graph (npm lockfiles)

Merged the committed `package-lock.json` files from three public repos —
[axios](https://github.com/axios/axios), [lodash](https://github.com/lodash/lodash),
[microsoft/TypeScript](https://github.com/microsoft/TypeScript) — into one
graph (1,778 nodes / 3,790 edges / 105KB):

```console
strand build axios-lock.json lodash-lock.json ts-lock.json -o web.strand
strand top web.strand --by impact -n 5
```

```
top 5 by Impact:
      209.0000  safe-buffer
      208.0000  isarray
      198.0000  yallist
      194.0000  inherits
      188.0000  pseudomap
```

`top --by impact` completes in ~0.13s and correctly surfaces the classic
npm hub packages. `impact semver` reports 182 affected packages — the
kind of blast-radius answer `--git-diff` + `--max-impact` is built for.

## Testing

`cargo test` runs ~74 tests across the workspace:

- **core algorithms** (`strand-core/tests/algorithms.rs`): BFS/depths,
  shortest & k-shortest paths, non-shortest `paths_within_depth`,
  Tarjan SCC + self-loops, critical path, weighted Dijkstra,
  PageRank sanity, common sets.
- **impact ranking verified against brute force**:
  `impact_sizes_match_bfs` and `impact_sizes_match_bfs_on_cycles` check
  every node's count against a naive per-node reverse BFS, acyclic and
  cyclic; `impact_sizes_blocked_bitsets` exercises the multi-block
  (50k-component chain) path;
  `impact_sizes_approx_tracks_exact` checks the landmark-sampling
  estimate is deterministic and tracks exact counts on a test graph;
  `impact_approx_tracks_exact_on_random_dag` compares sampled vs exact
  on a 2k-node random DAG (top-20 overlap, Spearman rank correlation,
  and exact reranking of top candidates).
- **proptest** (`proptests.rs`): random graphs built, re-opened, and
  compared against an independent in-memory reference.
- **roundtrip/corruption/determinism** (`roundtrip.rs`): byte-identical
  output regardless of input order, duplicate-edge merging, node kinds,
  truncations and bit flips produce clean errors (never panics).
- **scanner** (`strand-import/tests/scan.rs`): Rust `mod`/`use`/
  `#[path]`/`include!`, Python and JS/TS imports, `tsconfig`/`jsconfig`
  `paths` aliases + `baseUrl` + `extends` inheritance, JSONC comments/
  trailing commas, per-package configs in monorepos, `package.json`
  `"imports"` (`#alias`), dedup,
  string-literal masking, char literals vs lifetimes, raw strings,
  non-ASCII, plus a dogfood test that scans Strand's own repo.
- **store** (`strand-store/tests/store.rs`): transactions, persistence,
  snapshots, compaction (incl. weighted edges), read-only rejection,
  WAL torn-tail/bit-flip recovery, a model-based randomized op test, and
  a crash-consistency harness that corrupts the WAL at random points and
  verifies the store always equals exactly some prefix of committed
  transactions (500 cases in CI, 10,000 via
  `cargo test -p strand-store -- --ignored`), plus the auto-compaction
  threshold.
- **CLI end-to-end** (`strand-cli/tests/cli.rs`): build (single and
  multi-input), info/deps/impact/why/cycles/top/order/roots/leaves/
  common/scan/export/check, `--git-diff` seed resolution, `--max-impact`
  gating, impact-count consistency, and missing-node errors via
  `CARGO_BIN_EXE_strand`.
- **rule engine unit tests** (`strand-cli/src/check.rs`): rules-file
  parsing, comment/blank handling, malformed-rule rejection, substring
  vs glob pattern semantics (`*`/`?`).
- **lockfile importers** (`strand-import/tests/locks.rs`): all five
  formats incl. npm nested `node_modules` resolution, poetry
  dev-dependencies, go.mod directive boundaries, pom parent inheritance,
  and format auto-detection.

Tests live next to the code: `crates/strand-core/tests/` (algorithms,
proptest, roundtrip/corruption/determinism), `crates/strand-cli/`
(`tests/cli.rs` end-to-end plus `src/check.rs` unit tests),
`crates/strand-import/tests/` (`scan.rs`, `locks.rs`), and
`crates/strand-store/tests/store.rs`.

```console
cargo test
```

## Limitations (honest list)

- No query language — Rust API + CLI + desktop GUI.
- The GUI canvas caps at 100k nodes / 300k edges with level-of-detail
  rendering; beyond that use the CLI. Store edits are limited to
  node/edge add/remove — no batch import or schema changes from the GUI.
- `top --by impact` uses SCC condensation + bitset ancestor sets
  (`O(E·C/64)` word-ops, processed in ~256MB column blocks) when the op
  count fits the budget. On huge mostly-acyclic graphs (`C` ≈ V) it
  switches to a deterministic landmark-sampling estimate
  (`impact_sizes_approx`, ~2G edge visits). The estimate is unbiased
  but *not* uniform-accuracy: high-impact nodes (the top of the
  ranking) are accurate, low-impact nodes are noisy and often estimate
  as 0 — fine for ranking, near-ties can misorder. The CLI reranks the
  top candidates with exact per-node BFS (boundary ties included,
  budget-capped), prints the landmark count, marks approximate rows
  with `~`, and reports per-node `exact` flags in `--json`.
  `--samples N` overrides the landmark count; `--approx` forces
  sampling even when exact is affordable (benchmarking/validation);
  `--exact` forces the exact algorithm even over budget (per-node BFS
  fallback — can be very slow on huge DAGs). Estimates are clamped to
  `n-1`. `impact_sizes()` itself still falls back to
  per-node BFS for small graphs that exceed the bitset budget.
- `why --all-paths` enumerates alternative *shortest* chains (cap via
  `--limit`), or every simple chain up to `--max-depth N` hops. Both are
  step-budgeted and report truncation, so dense graphs can't hang.
- Weighted edges: `why --weighted` runs Dijkstra over edge weights
  (unweighted graphs count every edge as 1.0). The store preserves
  weights through compaction.
- The store is single-writer per directory (one process holds the write
  lock); scale-out means one store per shard — e.g. one `.strandb` per
  top-level subtree or per service, queried independently. Cross-shard
  queries are not supported yet.
- Store delta is in-memory, but commits auto-compact once it passes
  `Options::compact_threshold_ops` (default 1M ops, 0 disables) — the
  delta can still spike RAM between compactions, and readers pin their
  snapshot's delta until they drop it.
- Crash safety covers WAL commits and manifest swaps; orphaned
  `*.tmp` files from interrupted writes are garbage-collected on open
  (writers only publish via rename).
- mmap assumes files aren't truncated while open (inherent SIGBUS risk);
  the write path always writes-then-renames.
- `strand scan` is a pattern-matching scanner, not a real parser: it
  handles `mod`/`use`/`#[path]`/`include!` (Rust), `import`/`from`
  incl. relative imports (Python), and `import`/`export-from`/`require`
  (JS/TS), including `tsconfig`/`jsconfig` `paths` aliases and
  `baseUrl` (JSONC-tolerant, `extends` chains followed, nearest config
  per file for monorepos) and `package.json` `"imports"` (`#alias`).
  It misses
  macro-generated modules (a real parser can't see
  them either without expanding macros — `cargo expand` output is a
  workaround for inspection, not for scanning), `include_str!` payloads,
  and dynamic language tricks. Nodes are file
  paths, so it answers "what breaks if I change `src/foo.rs`?" —
  package-level questions still want `cargo metadata` input.

## License

[Apache-2.0](LICENSE) — permissive, patent-granting, and it explicitly
allows creating content about the software (reviews, videos, tutorials)
without permission.
