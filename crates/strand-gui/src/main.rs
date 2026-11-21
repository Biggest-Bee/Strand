//! `strand-gui`: desktop GUI for Strand dependency/impact analysis.
//!
//! Opens an immutable `.strand` graph or a read-write `.strandb` store and
//! runs the `strand-core` analyses on a merged read view. Read-only: store
//! writes stay in the library/CLI domain for now.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;

mod update_check;

use eframe::egui;
use strand_core::algo::{self, Dir};
use strand_core::view::GraphView;
use strand_store::Store;

enum Backend {
    /// Immutable mmap'd `.strand` file.
    File(std::sync::Arc<strand_core::Graph>),
    /// Read-write store directory (`.strandb`).
    Store(Store),
}

/// Store edit operations exposed in the GUI.
#[derive(Clone, Copy)]
enum StoreOp {
    AddEdge,
    RemoveEdge,
    AddNode,
    RemoveNode,
}

/// Assign through a pointer so `unused_assignments` can't prove the store
/// dead - callers may legitimately overwrite `status` right after.
fn set_status(status: &mut String, msg: String) {
    *status = msg;
}

/// Run `$body` with `v: &impl GraphView` bound to the concrete backend view.
/// For stores this pins a fresh read snapshot for the duration of the call.
macro_rules! with_view {
    ($app:expr, |$v:ident| $body:expr) => {
        match &$app.backend {
            Some(Backend::File(g)) => {
                let $v = g.as_ref();
                $body
            }
            Some(Backend::Store(s)) => match s.begin_read() {
                Ok(snap) => {
                    let $v = &snap.view();
                    $body
                }
                Err(e) => {
                    set_status(&mut $app.status, format!("read snapshot failed: {e}"));
                    Default::default()
                }
            },
            None => {
                set_status(&mut $app.status, "no graph open".to_string());
                Default::default()
            }
        }
    };
}

/// Owned, `Send`able view handle for worker-thread analyses.
/// File graphs are shared via `Arc`; store reads pin a `Snapshot`.
enum JobView {
    File(std::sync::Arc<strand_core::Graph>),
    Store(strand_store::Snapshot),
}

/// Run `$body` with `$v` bound to the concrete view inside a `JobView`.
/// The body must compile for both `&Graph` and `&View` - it does,
/// because every algo/view call is generic over `GraphView`.
macro_rules! job_view {
    ($jv:expr, |$v:ident| $body:expr) => {
        match $jv {
            JobView::File(g) => {
                let $v = g.as_ref();
                $body
            }
            JobView::Store(s) => {
                let view = s.view();
                let $v = &view;
                $body
            }
        }
    };
}

/// Everything a worker-thread analysis returns for the UI to apply.
struct AnalysisResult {
    title: String,
    lines: Vec<ReportRow>,
    /// `Some` = replace ring-layout depths; `None` = leave untouched.
    depths: Option<Vec<u32>>,
    /// `Some` = replace the highlight set; `None` = leave untouched.
    highlight: Option<BTreeSet<u32>>,
    status: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TopMetric {
    InDegree,
    Impact,
    PageRank,
}

struct StrandApp {
    backend: Option<Backend>,
    source_label: String,
    status: String,

    // Node selection (names resolved to ids at query time).
    node_a: String,
    node_b: String,
    sel_a: Option<u32>,
    sel_b: Option<u32>,
    depth_limit: String,
    /// Filter text for the "Browse nodes" picker.
    node_filter: String,
    top_metric: TopMetric,
    top_n: String,

    // Last analysis output.
    report_title: String,
    report_lines: Vec<ReportRow>,
    /// Substring filter applied to the report list.
    report_filter: String,

    /// All node names, sorted - powers the A/B autocomplete.
    names: Vec<String>,

    // Graph canvas state.
    viz_nodes: usize,
    viz_edges: usize,
    /// node id -> (x, y) in canvas coordinates, rebuilt on demand.
    pos: Vec<(f32, f32)>,
    /// (src, dst) id pairs for drawing (capped).
    edge_ids: Vec<(u32, u32)>,
    /// Edges incident to sel_a/sel_b that fell outside the sampled edge
    /// set - (selected node, neighbor) pairs, always drawn tier-2.
    sel_nbr_edges: Vec<(u32, u32)>,
    /// Neighbors with no canvas position: (neighbor id, anchor sel id).
    sel_nbr_extra: Vec<(u32, u32)>,
    /// Per-edge draw tier (0 cold / 1 highlight / 2 selection), computed
    /// at rebuild so painting does not rescan the highlight set per frame.
    edge_tiers: Vec<u8>,
    /// Whether tier-1 edges are under the draw cap (precomputed).
    tier1_draw: bool,
    /// Hover tooltip cache: (node id, pre-rendered text).
    hover_tip: Option<(u32, String)>,
    /// ids highlighted by the last deps/impact run.
    highlight: BTreeSet<u32>,
    /// BFS depth per node for ring layout (UNVISITED = outer scatter).
    depths: Vec<u32>,
    viz_dirty: bool,
    canvas_size: egui::Vec2,
    /// View transform: world->screen is `rect.min + pan + world * zoom`.
    zoom: f32,
    pan: egui::Vec2,
    /// Force-directed layout for the focused neighborhood.
    organic: bool,
    /// Latest layout worker result channel (generation-tagged).
    layout_rx: Option<Receiver<(u64, Vec<(f32, f32)>)>>,
    /// Node ids matching `layout_rx` result order.
    layout_ids: Vec<u32>,
    /// Per-node (super-node idx, x-offset, y-offset) when SCCs were
    /// collapsed for the layout; empty = coords align 1:1 with ids.
    layout_map: Vec<(u32, f32, f32)>,
    layout_gen: u64,

    /// First-run tutorial: `Some(i)` shows card `i`; `None` = closed/done.
    tutorial_idx: Option<usize>,
    /// Reference window opened by the "Instructions" button.
    show_instructions: bool,
    /// crates.io update check (background; resolves once).
    update_rx: Option<Receiver<Option<Vec<update_check::Update>>>>,
    /// Newer-version notice text, once known.
    update_note: Option<String>,
    /// When to re-run the update check (every 10 minutes).
    update_next_check: std::time::Instant,
    /// In-flight worker analysis; latest request wins.
    analysis_rx: Option<Receiver<AnalysisResult>>,
    /// In-flight focus-layout BFS (depths only, no report).
    depths_rx: Option<Receiver<Vec<u32>>>,
    /// Cancellation flag for the running force-layout thread.
    layout_flag: Arc<AtomicBool>,
    /// In-flight full-name collection for autocomplete/browse.
    names_rx: Option<Receiver<Vec<String>>>,
}

const MAX_VIZ_NODES: usize = 100_000;
const MAX_VIZ_EDGES: usize = 300_000;
/// Below this many nodes we draw circles; above it we batch nodes into a
/// single triangle mesh (level-of-detail).
const NODE_CIRCLE_MAX: usize = 8_000;
/// Above this many edges we only draw edges touching the highlight set.
const EDGE_DRAW_MAX: usize = 150_000;
const MAX_REPORT_LINES: usize = 20_000;
/// Neighborhood size cap for the force-directed layout (O(n²) per iter).
const MAX_LAYOUT_NODES: usize = 1_500;
/// BFS hops included in the layout neighborhood.
const LAYOUT_DEPTH: u32 = 3;
/// Fruchterman-Reingold iterations (deterministic, single-threaded).
const LAYOUT_ITERS: usize = 100;
/// Max real edges pulled in per selected node (in+out combined).
/// Max real edges pulled in per selected node per direction (in+out).
const MAX_SEL_NEIGHBORS: usize = 64;

/// One line in the report panel; `node` makes the row clickable (sets A).
struct ReportRow {
    text: String,
    node: Option<(u32, String)>,
}

fn row(text: impl Into<String>) -> ReportRow {
    ReportRow {
        text: text.into(),
        node: None,
    }
}

/// Fruchterman-Reingold layout, deterministic (no RNG, single-threaded).
/// `start`/`edges` use local indices; returns unit-ish coords centered ~0.
fn force_layout(
    start: &[(f32, f32)],
    edges: &[(u32, u32)],
    cancel: &AtomicBool,
) -> Vec<(f32, f32)> {
    let n = start.len();
    if n == 0 {
        return Vec::new();
    }
    // Normalize start positions into a centered unit box.
    let (mut minx, mut miny, mut maxx, mut maxy) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
    for &(x, y) in start {
        minx = minx.min(x);
        miny = miny.min(y);
        maxx = maxx.max(x);
        maxy = maxy.max(y);
    }
    let cx = (minx + maxx) / 2.0;
    let cy = (miny + maxy) / 2.0;
    let span = (maxx - minx).max(maxy - miny).max(1e-3);
    let mut pos: Vec<(f32, f32)> = start
        .iter()
        .enumerate()
        .map(|(i, &(x, y))| {
            // Tiny deterministic jitter: coincident start points would
            // otherwise never separate (repulsion is zero at d=0).
            let h = (i as u32).wrapping_mul(0x9E37_79B9);
            let j = ((h % 1024) as f32 / 1024.0 - 0.5) * 1e-4;
            ((x - cx) / span + j, (y - cy) / span - j)
        })
        .collect();

    let k = (1.0f32 / n as f32).sqrt() * 0.75;
    let k2 = k * k;
    let mut temp = 0.08f32;
    let mut disp = vec![(0.0f32, 0.0f32); n];
    for _ in 0..LAYOUT_ITERS {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        for d in disp.iter_mut() {
            *d = (0.0, 0.0);
        }
        // Repulsion between all pairs.
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = pos[i].0 - pos[j].0;
                let dy = pos[i].1 - pos[j].1;
                let d = (dx * dx + dy * dy + 1e-6).sqrt();
                // Standard FR: force magnitude k^2/d along unit direction.
                let mag = k2 / d;
                let ux = dx / d;
                let uy = dy / d;
                disp[i].0 += ux * mag;
                disp[i].1 += uy * mag;
                disp[j].0 -= ux * mag;
                disp[j].1 -= uy * mag;
            }
        }
        // Attraction along edges.
        for &(a, b) in edges {
            let (a, b) = (a as usize, b as usize);
            let dx = pos[b].0 - pos[a].0;
            let dy = pos[b].1 - pos[a].1;
            let d = (dx * dx + dy * dy + 1e-6).sqrt();
            let mag = d * d / k;
            let ux = dx / d;
            let uy = dy / d;
            disp[a].0 += ux * mag;
            disp[a].1 += uy * mag;
            disp[b].0 -= ux * mag;
            disp[b].1 -= uy * mag;
        }
        // Apply displacements capped by temperature, then cool.
        // Early-stop once the largest move is negligible.
        let mut max_step = 0.0f32;
        for i in 0..n {
            let (dx, dy) = disp[i];
            let len = (dx * dx + dy * dy).sqrt();
            if len > 1e-9 {
                let step = len.min(temp);
                max_step = max_step.max(step);
                let s = step / len;
                pos[i].0 += dx * s;
                pos[i].1 += dy * s;
            }
        }
        temp *= 0.97;
        if max_step < 0.0005 {
            break;
        }
    }
    pos
}

/// Nearest node id within 10px of screen point `pt`.
fn nearest_node(
    pos: &[(f32, f32)],
    pan: egui::Vec2,
    zoom: f32,
    origin: egui::Pos2,
    pt: egui::Pos2,
) -> Option<u32> {
    let mut best: Option<(u32, f32)> = None;
    for (i, &p) in pos.iter().enumerate() {
        let sp = origin + pan + egui::vec2(p.0 * zoom, p.1 * zoom);
        let d = sp.distance(pt);
        if d <= 10.0 && best.map_or(true, |(_, bd)| d < bd) {
            best = Some((i as u32, d));
        }
    }
    best.map(|(id, _)| id)
}

/// First-run tutorial cards: (title, body).
const TUTORIAL: &[(&str, &str)] = &[
    (
        "Welcome to Strand",
        "Strand draws dependency graphs and answers \"what breaks if this\n\
         changes?\" questions. This card tour takes 30 seconds.\n\n\
         You'll need a .strand file - build one with the `strand` CLI,\n\
         or open a .strandb store for read-write editing.",
    ),
    (
        "Open a graph",
        "Click \"Open .strand...\" (top-left) to load an immutable graph,\n\
         or \"Open store...\" to open a writable .strandb directory.\n\
         The status bar shows the file name and node/edge counts,\n\
         plus a warning if the file exceeds the canvas caps.",
    ),
    (
        "Pick nodes A and B",
        "Three ways: type a name in the A/B boxes (they autocomplete),\n\
         click a dot on the canvas (click = A, shift+click = B),\n\
         or browse every name under \"Browse nodes\".\n\n\
         Hover any dot to see its name and dependency counts.",
    ),
    (
        "Run an analysis",
        "Left panel, \"Analyze\" section: Deps of A/B (what it needs),\n\
         Impact of A/B (what breaks if it changes), Why A->B\n\
         or B->A (a path between two nodes), swap A/B, Cycles,
\n         Build order, Roots, Leaves,\n\
         Top, and Common deps/impact. \"max depth\" limits hops.\n\n\
         Results appear in the bottom panel - type in its filter\n\
         box to search thousands of rows.",
    ),
    (
        "Read the canvas",
        "After an analysis the graph re-lays out: rings show hop\n\
         distance from your node, orange = affected. Edges touching\n\
         A/B draw bright yellow on top; everything else stays dim.\n\n\
         Scroll to zoom (up to 200x), drag to pan, double-click to\n\
         reset. \"Clear highlight\" wipes selections and colors.\n\n\
         The \"organic layout\" checkbox runs a force-directed\n\
         layout on the neighborhood - uncheck for pure rings.",
    ),
    (
        "You're ready",
        "Click a row in the report to re-select that node and keep\n\
         exploring. Stuck? The \"Instructions\" button (top bar)\n\
         opens a full reference of every button.\n\n\
         This tour only shows once - enjoy Strand!",
    ),
];

/// Reference text for the Instructions window.
const INSTRUCTIONS: &str = "\
STRAND - button reference
==========================

TOP BAR
  Open .strand...   Load an immutable .strand graph file.
  Open store...     Open a .strandb store directory (read-write if
                    the lock is free, read-only otherwise).
  Close             Unload the current graph and reset the canvas.
  Instructions      This window.

NODES (left panel)
  A / B boxes       Type a node name; suggestions appear below -
                    click one to select it. The \"select\" button
                    resolves the typed name.
  Browse nodes      Lists every node name (filterable). Click = pick
                    as A, shift+click = pick as B.
  max depth         Optional hop limit for Deps/Impact/Why/Common.
                    Blank = unlimited.

ANALYZE
  Deps of A / B     Everything the node depends on (outgoing edges),
                    with hop distance.
  Impact of A / B   Everything affected if the node changes
                    (reverse reach).
  Why A->B / B->A   A shortest path between the two nodes.
  swap A/B          Exchange the A and B selections.
  Cycles            Circular dependency chains (needs both A and B
                    unset, or scoped - see report).
  Build order       Topological order of the graph.
  Roots             Nodes nothing depends on.
  Leaves            Nodes that depend on nothing.
  Top               Ranked nodes: in-degree, impact, or pagerank.
                    \"n\" sets how many rows.
  Common deps/impact A,B   Nodes both A and B reach (deps) or that
                    reach both (impact).

GRAPH
  Rebuild view      Force the canvas to re-layout.
  Clear highlight   Reset selections, rings, and layout - back to
                    the plain scatter view.
  organic layout    Force-directed layout of the selected
                    neighborhood (deterministic; runs on a worker).

CANVAS
  Click             Select node A.
  Shift+click       Select node B.
  Scroll / pinch    Zoom toward the cursor (up to 200x).
  Drag              Pan.
  Double-click      Reset zoom and pan.
  Hover             Node name + dep/dependent counts.

REPORT (bottom panel)
  filter            Substring search across all result rows.
  Click a row       Re-selects that node as A.
  Right-click a row Re-selects that node as B.

EDIT STORE (only when a writable store is open)
  Add/Remove edge A->B, Add/Remove node A   Real store edits, durable
                    immediately via the WAL.
  Compact           Merge the WAL into a fresh base generation.

TIPS
  Very large graphs (>100k nodes / >300k edges) show a partial canvas
  sample with a warning - analyses always cover the whole graph.
  On huge result sets the middle edge tier is skipped so the canvas
  stays readable; the report still lists everything.
";

/// Path of the first-run marker file (`~/.strand/tutorial_seen`).
fn tutorial_flag() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join(".strand").join("tutorial_seen"))
}

fn tutorial_seen() -> bool {
    tutorial_flag().map_or(false, |p| p.exists())
}

fn mark_tutorial_seen() {
    if let Some(p) = tutorial_flag() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, b"");
    }
}

fn row_node(text: impl Into<String>, id: u32, name: String) -> ReportRow {
    ReportRow {
        text: text.into(),
        node: Some((id, name)),
    }
}

/// Uniform node count: `Graph::n_nodes` (inherent) returns `u64` while the
/// trait returns `usize`, so always go through the trait.
fn nn<G: GraphView + ?Sized>(g: &G) -> usize {
    g.n_nodes()
}

/// Uniform edge count (same u64/usize split as `nn`).
fn ne<G: GraphView + ?Sized>(g: &G) -> usize {
    g.n_edges()
}

/// Uniform node name (trait method returns `String` on both backends).
fn nm<G: GraphView + ?Sized>(g: &G, id: u32) -> String {
    g.node_name(id)
}

impl StrandApp {
    fn new() -> Self {
        StrandApp {
            backend: None,
            source_label: "no graph open - File -> Open...".to_string(),
            status: String::new(),
            node_a: String::new(),
            node_b: String::new(),
            sel_a: None,
            sel_b: None,
            depth_limit: String::new(),
            node_filter: String::new(),
            top_metric: TopMetric::InDegree,
            top_n: "20".to_string(),
            report_title: String::new(),
            report_lines: Vec::new(),
            report_filter: String::new(),
            names: Vec::new(),
            viz_nodes: 0,
            viz_edges: 0,
            pos: Vec::new(),
            edge_ids: Vec::new(),
            sel_nbr_edges: Vec::new(),
            sel_nbr_extra: Vec::new(),
            edge_tiers: Vec::new(),
            tier1_draw: true,
            hover_tip: None,
            highlight: BTreeSet::new(),
            depths: Vec::new(),
            viz_dirty: true,
            canvas_size: egui::Vec2::ZERO,
            zoom: 1.0,
            pan: egui::Vec2::ZERO,
            organic: true,
            layout_rx: None,
            layout_ids: Vec::new(),
            layout_map: Vec::new(),
            layout_gen: 0,
            tutorial_idx: if tutorial_seen() { None } else { Some(0) },
            show_instructions: false,
            update_rx: Some(update_check::spawn()),
            update_note: None,
            update_next_check: std::time::Instant::now() + std::time::Duration::from_secs(600),
            analysis_rx: None,
            depths_rx: None,
            names_rx: None,
            layout_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    fn open_strand(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Strand graph", &["strand"])
            .pick_file()
        else {
            return;
        };
        match strand_core::Graph::open(&path) {
            Ok(g) => {
                self.source_label = format!(
                    "{} ({} nodes, {} edges)",
                    path.display(),
                    g.n_nodes(),
                    g.n_edges()
                );
                self.backend = Some(Backend::File(std::sync::Arc::new(g)));
                self.reset_query_state();
                self.collect_names();
                let w = self.cap_warning();
                self.status = w.unwrap_or_else(|| "opened".to_string());
            }
            Err(e) => self.status = format!("open failed: {e}"),
        }
    }

    fn open_store(&mut self) {
        let Some(dir) = rfd::FileDialog::new()
            .set_title("Open Strand store directory")
            .pick_folder()
        else {
            return;
        };
        // Auto-compaction is disabled for GUI-opened stores: it runs
        // synchronously inside commit() on the UI thread and would freeze
        // the window on large deltas. Use the "Compact" button instead.
        let opts = strand_store::Options {
            compact_threshold_ops: 0,
            ..Default::default()
        };
        match Store::open_with_options(&dir, opts) {
            Ok(s) => {
                let writable = s.is_writable();
                self.source_label = format!(
                    "{} (store, {})",
                    dir.display(),
                    if writable { "read-write" } else { "read-only" }
                );
                self.backend = Some(Backend::Store(s));
                self.reset_query_state();
                self.collect_names();
                let w = self.cap_warning();
                self.status = w.unwrap_or_else(|| "opened".to_string());
            }
            Err(e) => self.status = format!("open failed: {e}"),
        }
    }

    /// Unload the current graph/store and return to the empty state.
    fn close_graph(&mut self) {
        self.backend = None;
        self.source_label = "no graph open - File -> Open...".to_string();
        self.status = "closed".to_string();
        self.reset_query_state();
        self.pos.clear();
        self.edge_ids.clear();
        self.viz_nodes = 0;
        self.viz_edges = 0;
        self.zoom = 1.0;
        self.pan = egui::Vec2::ZERO;
    }

    fn reset_query_state(&mut self) {
        self.node_a.clear();
        self.node_b.clear();
        self.sel_a = None;
        self.sel_b = None;
        self.report_lines.clear();
        self.report_title.clear();
        self.report_filter.clear();
        self.names.clear();
        self.highlight.clear();
        self.depths.clear();
        self.viz_dirty = true;
    }

    /// Warn when the graph exceeds canvas caps - the view is then only a
    /// sample (queries still cover the full graph).
    fn cap_warning(&mut self) -> Option<String> {
        with_view!(self, |v| {
            let n = nn(v);
            let e = ne(v);
            if n > MAX_VIZ_NODES || e > MAX_VIZ_EDGES {
                Some(format!(
                    "warning: {n} nodes / {e} edges exceeds canvas caps \
                     ({MAX_VIZ_NODES} nodes / {MAX_VIZ_EDGES} edges) - \
                     canvas shows a partial sample; analyses cover everything"
                ))
            } else {
                None
            }
        })
    }

    /// Snapshot every node name (sorted, deduped) for autocomplete. Skipped
    /// on very large graphs where the index would cost too much memory.
    /// Snapshot every node name (sorted, deduped) for autocomplete.
    /// Runs on a worker thread - on big graphs this is a full scan.
    /// Skipped entirely over 200k nodes (autocomplete falls back off).
    fn collect_names(&mut self) {
        let Some(jv) = self.job_view() else { return };
        let (tx, rx) = channel();
        self.names_rx = Some(rx);
        std::thread::spawn(move || {
            let names = job_view!(&jv, |v| {
                let n = nn(v);
                let mut set = BTreeSet::new();
                if n <= 200_000 {
                    for id in 0..n as u32 {
                        set.insert(nm(v, id));
                    }
                }
                set.into_iter().collect::<Vec<String>>()
            });
            let _ = tx.send(names);
        });
    }

    /// Up to 8 names containing `q` (case-insensitive), for autocomplete.
    fn suggestions(&self, q: &str) -> Vec<String> {
        if q.is_empty() || self.names.is_empty() {
            return Vec::new();
        }
        let ql = q.to_lowercase();
        self.names
            .iter()
            .filter(|n| n.to_lowercase().contains(&ql))
            .take(8)
            .cloned()
            .collect()
    }

    /// Render suggestion buttons under an A/B box; returns the picked name.
    fn suggestion_row(&mut self, ui: &mut egui::Ui, which: usize) -> Option<String> {
        let q = if which == 0 {
            self.node_a.trim().to_string()
        } else {
            self.node_b.trim().to_string()
        };
        if q.is_empty() {
            return None;
        }
        // Hide suggestions once the typed text is already an exact name.
        if self.names.iter().any(|n| n.eq_ignore_ascii_case(&q)) {
            return None;
        }
        let sugg = self.suggestions(&q);
        if sugg.is_empty() {
            return None;
        }
        let mut picked = None;
        ui.horizontal_wrapped(|ui| {
            for m in sugg {
                if ui.small_button(&m).clicked() {
                    picked = Some(m);
                }
            }
        });
        picked
    }

    fn resolve(&mut self, which: usize) {
        let name = if which == 0 {
            self.node_a.clone()
        } else {
            self.node_b.clone()
        };
        if name.trim().is_empty() {
            return;
        }
        let id = with_view!(self, |v| v.node_id(name.trim()));
        match id {
            Some(id) => {
                if which == 0 {
                    self.sel_a = Some(id);
                    self.focus_a();
                } else {
                    self.sel_b = Some(id);
                }
                self.status = format!("'{name}' -> node {id}");
                self.viz_dirty = true;
            }
            None => self.status = format!("no node named '{name}'"),
        }
    }

    fn depth_arg(&self) -> Option<u32> {
        self.depth_limit.trim().parse::<u32>().ok()
    }

    /// Owned view handle for a worker thread: `Arc` clone for files,
    /// a pinned read `Snapshot` for stores.
    fn job_view(&self) -> Option<JobView> {
        match &self.backend {
            Some(Backend::File(g)) => Some(JobView::File(g.clone())),
            Some(Backend::Store(s)) => s.begin_read().ok().map(JobView::Store),
            None => None,
        }
    }

    /// Run an analysis on a worker thread so the UI never blocks.
    /// Latest request wins: starting a new job drops the old receiver,
    /// so a stale result can't overwrite fresher state.
    fn spawn_analysis(
        &mut self,
        status: &str,
        job: impl FnOnce(&JobView) -> AnalysisResult + Send + 'static,
    ) {
        let Some(jv) = self.job_view() else {
            self.status = "no graph open".to_string();
            return;
        };
        let (tx, rx) = channel();
        self.analysis_rx = Some(rx);
        self.status = status.to_string();
        std::thread::spawn(move || {
            let res = job(&jv);
            let _ = tx.send(res);
        });
    }

    /// Poll worker channels once per frame: apply finished analyses,
    /// focus depths, and the name index.
    fn poll_workers(&mut self) {
        if let Some(rx) = &self.analysis_rx {
            match rx.try_recv() {
                Ok(res) => {
                    self.set_report(res.title, res.lines);
                    if let Some(d) = res.depths {
                        self.depths = d;
                    }
                    if let Some(h) = res.highlight {
                        self.highlight = h;
                    }
                    self.status = res.status;
                    self.viz_dirty = true;
                    self.analysis_rx = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.analysis_rx = None,
            }
        }
        if let Some(rx) = &self.depths_rx {
            match rx.try_recv() {
                Ok(d) => {
                    self.depths = d;
                    self.viz_dirty = true;
                    self.depths_rx = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.depths_rx = None,
            }
        }
        if let Some(rx) = &self.names_rx {
            match rx.try_recv() {
                Ok(names) => {
                    self.names = names;
                    self.names_rx = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.names_rx = None,
            }
        }
    }

    fn set_report(&mut self, title: String, lines: Vec<ReportRow>) {
        let mut lines = lines;
        if lines.len() > MAX_REPORT_LINES {
            lines.truncate(MAX_REPORT_LINES);
            lines.push(row(format!("... truncated at {MAX_REPORT_LINES} lines")));
        }
        self.report_title = title;
        self.report_lines = lines;
        self.report_filter.clear();
    }

    // ---- analyses ----

    fn run_deps(&mut self) {
        self.bfs_report(0, Dir::Out);
    }

    fn run_deps_b(&mut self) {
        self.bfs_report(1, Dir::Out);
    }

    fn run_impact(&mut self) {
        self.bfs_report(0, Dir::In);
    }

    fn run_impact_b(&mut self) {
        self.bfs_report(1, Dir::In);
    }

    /// Shared body for Deps/Impact on either selection slot.
    /// `which`: 0 = A, 1 = B. `dir`: Out = dependencies, In = impact.
    fn bfs_report(&mut self, which: usize, dir: Dir) {
        let seed = if which == 0 { self.sel_a } else { self.sel_b };
        let Some(a) = seed else {
            self.status = format!("select node {} first", if which == 0 { "A" } else { "B" });
            return;
        };
        let depth = self.depth_arg();
        self.spawn_analysis("analyzing…", move |jv| {
            job_view!(jv, |v| {
                let d = algo::bfs(v, &[a], dir, depth);
                let mut out = Vec::new();
                let mut by_depth: BTreeMap<u32, Vec<(u32, String)>> = BTreeMap::new();
                let mut affected = BTreeSet::new();
                for (id, &dep) in d.iter().enumerate() {
                    if dep != algo::UNVISITED && dep > 0 {
                        affected.insert(id as u32);
                        by_depth
                            .entry(dep)
                            .or_default()
                            .push((id as u32, nm(v, id as u32)));
                    }
                }
                for (dep, items) in by_depth {
                    for (id, name) in items {
                        out.push(row_node(format!("{dep}\t{name}"), id, name));
                    }
                }
                let title = match dir {
                    Dir::Out => format!("dependencies of node {a}"),
                    Dir::In => format!("impact of node {a} (who depends on it)"),
                };
                AnalysisResult {
                    status: title.clone(),
                    title,
                    lines: out,
                    depths: Some(d),
                    highlight: Some(affected),
                }
            })
        });
    }

    /// Re-layout around the selected node: BFS a few hops in both
    /// directions so its neighborhood clusters into view. Runs on a
    /// worker thread (depths only - does not touch the report).
    fn focus_a(&mut self) {
        let Some(a) = self.sel_a else { return };
        let Some(jv) = self.job_view() else { return };
        let (tx, rx) = channel();
        self.depths_rx = Some(rx);
        std::thread::spawn(move || {
            let depths = job_view!(&jv, |v| {
                let out = algo::bfs(v, &[a], Dir::Out, Some(3));
                let inn = algo::bfs(v, &[a], Dir::In, Some(3));
                out.iter()
                    .zip(inn.iter())
                    .map(|(&x, &y)| match (x, y) {
                        (algo::UNVISITED, d) | (d, algo::UNVISITED) => d,
                        (x, y) => x.min(y),
                    })
                    .collect::<Vec<u32>>()
            });
            let _ = tx.send(depths);
        });
    }

    fn run_why(&mut self) {
        let (Some(a), Some(b)) = (self.sel_a, self.sel_b) else {
            self.status = "select nodes A and B first".into();
            return;
        };
        self.spawn_analysis("finding path…", move |jv| {
            job_view!(jv, |v| {
                let title = format!("shortest dependency path {a} -> {b}");
                let lines = match algo::shortest_path(v, a, b) {
                    Some(path) => {
                        let names: Vec<String> = path.iter().map(|&id| nm(v, id)).collect();
                        vec![row(names.join(" -> "))]
                    }
                    None => vec![row("no path")],
                };
                AnalysisResult {
                    status: title.clone(),
                    title,
                    lines,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    /// Same as run_why but B -> A.
    fn run_why_rev(&mut self) {
        let (Some(a), Some(b)) = (self.sel_a, self.sel_b) else {
            self.status = "select nodes A and B first".into();
            return;
        };
        self.spawn_analysis("finding path…", move |jv| {
            job_view!(jv, |v| {
                let title = format!("shortest dependency path {b} -> {a}");
                let lines = match algo::shortest_path(v, b, a) {
                    Some(path) => {
                        let names: Vec<String> = path.iter().map(|&id| nm(v, id)).collect();
                        vec![row(names.join(" -> "))]
                    }
                    None => vec![row("no path")],
                };
                AnalysisResult {
                    status: title.clone(),
                    title,
                    lines,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    /// Swap the A and B selections (ids and name boxes).
    fn swap_ab(&mut self) {
        std::mem::swap(&mut self.sel_a, &mut self.sel_b);
        std::mem::swap(&mut self.node_a, &mut self.node_b);
        self.viz_dirty = true;
    }

    fn run_cycles(&mut self) {
        self.spawn_analysis("finding cycles…", move |jv| {
            job_view!(jv, |v| {
                let lines = {
                    let sccs = algo::strongly_connected(v);
                    let cycles: Vec<&Vec<u32>> = sccs.iter().filter(|c| c.len() > 1).collect();
                    if cycles.is_empty() {
                        vec![row("no cycles")]
                    } else {
                        let mut out = Vec::new();
                        for c in cycles.iter().take(500) {
                            let names: Vec<String> =
                                c.iter().take(20).map(|&id| nm(v, id)).collect();
                            let suffix = if c.len() > 20 {
                                format!(", ... +{} more", c.len() - 20)
                            } else {
                                String::new()
                            };
                            out.push(row(format!(
                                "cycle ({}): {}{}",
                                c.len(),
                                names.join(", "),
                                suffix
                            )));
                        }
                        if cycles.len() > 500 {
                            out.push(row(format!("... {} more cycles", cycles.len() - 500)));
                        }
                        out
                    }
                };
                AnalysisResult {
                    status: "cycles".into(),
                    title: "cycles (SCCs with >1 node)".into(),
                    lines,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    fn run_top(&mut self) {
        let n: usize = self.top_n.trim().parse().unwrap_or(20);
        let metric = self.top_metric;
        self.spawn_analysis("ranking…", move |jv| {
            job_view!(jv, |v| {
                let nv = nn(v);
                let mut scored: Vec<(f64, u32)> = match metric {
                    TopMetric::InDegree => (0..nv as u32)
                        .map(|id| (v.in_degree(id) as f64, id))
                        .collect(),
                    TopMetric::PageRank => {
                        let pr = algo::pagerank(v, false, 1e-9, 100);
                        pr.into_iter()
                            .enumerate()
                            .map(|(i, s)| (s, i as u32))
                            .collect()
                    }
                    TopMetric::Impact => {
                        let imp = algo::impact_sizes(v);
                        imp.into_iter()
                            .enumerate()
                            .map(|(i, s)| (s as f64, i as u32))
                            .collect()
                    }
                };
                scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                let lines: Vec<ReportRow> = scored
                    .iter()
                    .take(n)
                    .map(|&(s, id)| {
                        let name = nm(v, id);
                        row_node(format!("{s:>10.4}\t{name}"), id, name)
                    })
                    .collect();
                let label = match metric {
                    TopMetric::InDegree => "in-degree",
                    TopMetric::Impact => "impact size",
                    TopMetric::PageRank => "pagerank",
                };
                let title = format!("top {n} by {label}");
                AnalysisResult {
                    status: title.clone(),
                    title,
                    lines,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    fn run_order(&mut self) {
        self.spawn_analysis("building order…", move |jv| {
            job_view!(jv, |v| {
                let bo = algo::analyze(v);
                let mut out = vec![row(format!(
                    "{} SCCs, critical path length {}",
                    bo.sccs.len(),
                    bo.critical_len
                ))];
                out.push(row(""));
                for (i, comp) in bo.sccs.iter().enumerate() {
                    if comp.len() == 1 {
                        let name = nm(v, comp[0]);
                        out.push(row_node(format!("{}. {name}", i + 1), comp[0], name));
                    } else {
                        let names: Vec<String> =
                            comp.iter().take(20).map(|&id| nm(v, id)).collect();
                        let suffix = if comp.len() > 20 {
                            format!(", ... +{} more", comp.len() - 20)
                        } else {
                            String::new()
                        };
                        out.push(row(format!(
                            "{}. {{{}{}}}",
                            i + 1,
                            names.join(", "),
                            suffix
                        )));
                    }
                    if out.len() > MAX_REPORT_LINES {
                        out.push(row("... truncated"));
                        break;
                    }
                }
                AnalysisResult {
                    status: "build order".into(),
                    title: "build order (dependencies first)".into(),
                    lines: out,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    fn run_roots(&mut self) {
        self.spawn_analysis("finding roots…", move |jv| {
            job_view!(jv, |v| {
                let mut out = Vec::new();
                let mut total = 0usize;
                for id in 0..nn(v) as u32 {
                    if v.in_degree(id) == 0 {
                        total += 1;
                        if out.len() < MAX_REPORT_LINES {
                            let name = nm(v, id);
                            out.push(row_node(name.clone(), id, name));
                        }
                    }
                }
                if total > out.len() {
                    out.push(row(format!("... {} more", total - out.len())));
                }
                AnalysisResult {
                    status: "roots".into(),
                    title: "roots (nothing depends on them)".into(),
                    lines: out,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    fn run_leaves(&mut self) {
        self.spawn_analysis("finding leaves…", move |jv| {
            job_view!(jv, |v| {
                let mut out = Vec::new();
                let mut total = 0usize;
                for id in 0..nn(v) as u32 {
                    if v.out_degree(id) == 0 {
                        total += 1;
                        if out.len() < MAX_REPORT_LINES {
                            let name = nm(v, id);
                            out.push(row_node(name.clone(), id, name));
                        }
                    }
                }
                if total > out.len() {
                    out.push(row(format!("... {} more", total - out.len())));
                }
                AnalysisResult {
                    status: "leaves".into(),
                    title: "leaves (depend on nothing)".into(),
                    lines: out,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    fn run_common(&mut self) {
        let (Some(a), Some(b)) = (self.sel_a, self.sel_b) else {
            self.status = "select nodes A and B first".into();
            return;
        };
        self.spawn_analysis("comparing…", move |jv| {
            job_view!(jv, |v| {
                let mut out = Vec::new();
                for (dir, label) in [
                    (Dir::Out, "common dependencies"),
                    (Dir::In, "common impact"),
                ] {
                    let names: Vec<(u32, String)> = algo::common(v, a, b, dir)
                        .iter()
                        .map(|&id| (id, nm(v, id)))
                        .collect();
                    out.push(row(format!("== {label} ({}) ==", names.len())));
                    for (i, (id, name)) in names.iter().enumerate() {
                        if i >= MAX_REPORT_LINES {
                            out.push(row(format!("... {} more", names.len() - i)));
                            break;
                        }
                        out.push(row_node(name.clone(), *id, name.clone()));
                    }
                    out.push(row(""));
                }
                let title = format!("common sets of {a} and {b}");
                AnalysisResult {
                    status: title.clone(),
                    title,
                    lines: out,
                    depths: None,
                    highlight: None,
                }
            })
        });
    }

    // ---- graph canvas ----

    /// Apply a store edit as a committed transaction, then refresh names
    /// and the visualization. No-op unless a writable store is open.
    fn store_edit(&mut self, op: StoreOp) {
        let a = self.node_a.trim().to_string();
        let b = self.node_b.trim().to_string();
        let res = match &self.backend {
            Some(Backend::Store(s)) => s.begin_write().and_then(|mut tx| {
                let r = match op {
                    StoreOp::AddEdge => tx.add_edge(&a, &b),
                    StoreOp::RemoveEdge => tx.remove_edge(&a, &b),
                    StoreOp::AddNode => tx.add_node(&a),
                    StoreOp::RemoveNode => tx.remove_node(&a),
                };
                r.and_then(|_| tx.commit())
            }),
            _ => return,
        };
        match res {
            Ok(()) => {
                self.status = "edit committed".into();
                self.collect_names();
                self.viz_dirty = true;
            }
            Err(e) => self.status = format!("edit failed: {e}"),
        }
    }

    /// Fold the delta into a fresh base. Runs on the UI thread - fine for
    /// typical deltas; very large ones will pause the window briefly.
    fn store_compact(&mut self) {
        // Compaction renumbers node ids - capture selection names first.
        let name_a = self.sel_a.map(|id| with_view!(self, |v| nm(v, id)));
        let name_b = self.sel_b.map(|id| with_view!(self, |v| nm(v, id)));
        let res = match &self.backend {
            Some(Backend::Store(s)) => s.compact(),
            _ => return,
        };
        match res {
            Ok(()) => {
                self.status = "compacted".into();
                self.sel_a = None;
                self.sel_b = None;
                self.highlight.clear();
                self.depths.clear();
                self.cancel_layout();
                if let Some(name) = name_a {
                    self.node_a = name.clone();
                    self.sel_a = with_view!(self, |v| v.node_id(&name));
                }
                if let Some(name) = name_b {
                    self.node_b = name.clone();
                    self.sel_b = with_view!(self, |v| v.node_id(&name));
                }
                self.collect_names();
                self.viz_dirty = true;
            }
            Err(e) => self.status = format!("compact failed: {e}"),
        }
    }

    fn rebuild_viz(&mut self) {
        self.viz_dirty = false;
        self.pos.clear();
        self.edge_ids.clear();
        self.sel_nbr_edges.clear();
        self.sel_nbr_extra.clear();
        with_view!(self, |v| {
            let n = nn(v);
            self.viz_nodes = n;
            self.viz_edges = 0usize;
            let cap_n = n.min(MAX_VIZ_NODES);
            self.pos = vec![(0.0, 0.0); cap_n];
            self.edge_ids = Vec::with_capacity(MAX_VIZ_EDGES.min(1 << 16));
            'nodes: for id in 0..cap_n as u32 {
                if self.edge_ids.len() >= MAX_VIZ_EDGES {
                    break 'nodes;
                }
                v.out_edges(id, &mut |t| {
                    if self.edge_ids.len() < MAX_VIZ_EDGES && (t as usize) < cap_n {
                        self.edge_ids.push((id, t));
                    }
                });
            }
            self.viz_edges = self.edge_ids.len();

            // Always pull in edges incident to the A/B selection - the
            // sampled edge set can miss them entirely on big graphs.
            // Each direction gets its own budget so a hub's out-edges
            // can't starve its dependents (the impact direction).
            for &s in [self.sel_a, self.sel_b].iter().flatten() {
                if s as usize >= cap_n {
                    continue;
                }
                let mut seen = HashSet::new();
                let push = |t: u32,
                            edges: &mut Vec<(u32, u32)>,
                            extra: &mut Vec<(u32, u32)>,
                            seen: &mut HashSet<u32>| {
                    if seen.insert(t) {
                        edges.push((s, t));
                        if t as usize >= cap_n {
                            extra.push((t, s));
                        }
                    }
                };
                let mut out_n = 0usize;
                v.out_edges(s, &mut |t| {
                    if out_n < MAX_SEL_NEIGHBORS {
                        out_n += 1;
                        push(
                            t,
                            &mut self.sel_nbr_edges,
                            &mut self.sel_nbr_extra,
                            &mut seen,
                        );
                    }
                });
                let mut in_n = 0usize;
                v.in_edges(s, &mut |t| {
                    if in_n < MAX_SEL_NEIGHBORS {
                        in_n += 1;
                        push(
                            t,
                            &mut self.sel_nbr_edges,
                            &mut self.sel_nbr_extra,
                            &mut seen,
                        );
                    }
                });
            }
        });

        // Edge tiers depend only on sel/highlight, which always dirty the
        // viz - compute once here instead of per frame.
        self.edge_tiers = self
            .edge_ids
            .iter()
            .map(|&(s, t)| {
                if Some(s) == self.sel_a
                    || Some(s) == self.sel_b
                    || Some(t) == self.sel_a
                    || Some(t) == self.sel_b
                {
                    2
                } else if self.highlight.contains(&s) || self.highlight.contains(&t) {
                    1
                } else {
                    0
                }
            })
            .collect();
        self.tier1_draw = self.edge_tiers.iter().filter(|&&t| t == 1).count() <= 20_000;

        // Layout: ring by BFS depth when we have one, else a circle.
        let w = self.canvas_size.x.max(400.0);
        let h = self.canvas_size.y.max(300.0);
        let cx = w / 2.0;
        let cy = h / 2.0;
        let cap = self.pos.len();
        if !self.depths.is_empty() && self.depths.len() >= cap {
            // Group node ids by depth.
            let mut rings: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
            for id in 0..cap as u32 {
                let d = self.depths.get(id as usize).copied().unwrap_or(u32::MAX);
                rings.entry(d).or_default().push(id);
            }
            let max_d = rings
                .keys()
                .copied()
                .filter(|&d| d != u32::MAX)
                .max()
                .unwrap_or(0);
            let ring_step = (w.min(h) / 2.0 / (max_d.max(1) as f32 + 2.0)).max(24.0);
            for (d, members) in rings {
                let r = if d == u32::MAX {
                    // Unreached: outer scatter ring.
                    w.min(h) / 2.0 - 10.0
                } else {
                    (d as f32 + 1.0) * ring_step
                };
                for (i, &id) in members.iter().enumerate() {
                    // Golden-angle spiral keeps rings readable.
                    let ang = i as f32 * 2.399_963 + d as f32;
                    self.pos[id as usize] = (cx + r * ang.cos(), cy + r * ang.sin());
                }
            }
        } else {
            let capf = cap.max(1) as f32;
            let radius = w.min(h) / 2.0 - 20.0;
            for i in 0..cap {
                let ang = i as f32 * 2.399_963;
                let r = radius * ((i * 37 % cap.max(1)) as f32 / capf).sqrt();
                self.pos[i] = (cx + r * ang.cos(), cy + r * ang.sin());
            }
        }
        self.maybe_start_layout();
    }

    /// Kick off a force-directed layout for the focused neighborhood
    /// (nodes within LAYOUT_DEPTH hops of the last analysis/selection),
    /// capped at MAX_LAYOUT_NODES. Runs on a worker thread; results are
    /// generation-tagged so stale layouts are dropped.
    /// Invalidate any in-flight layout so a stale worker result can't
    /// overwrite fresh positions.
    fn cancel_layout(&mut self) {
        self.layout_flag.store(true, Ordering::Relaxed);
        self.layout_gen += 1;
        self.layout_rx = None;
        self.layout_ids.clear();
        self.layout_map.clear();
    }

    fn maybe_start_layout(&mut self) {
        if !self.organic || self.depths.is_empty() {
            self.cancel_layout();
            return;
        }
        // Candidates: drawn nodes within the hop limit, nearest first.
        let mut cand: Vec<(u32, u32)> = Vec::new(); // (depth, id)
        for id in 0..self.pos.len().min(self.depths.len()) as u32 {
            let d = self.depths[id as usize];
            if d != algo::UNVISITED && d <= LAYOUT_DEPTH {
                cand.push((d, id));
            }
        }
        if cand.len() < 8 {
            self.cancel_layout();
            return;
        }
        cand.sort_by_key(|&(d, _)| d);
        let total = cand.len();
        cand.truncate(MAX_LAYOUT_NODES);
        self.layout_ids = cand.iter().map(|&(_, id)| id).collect();

        let mut idx = HashMap::with_capacity(cand.len());
        for (i, &(_, id)) in cand.iter().enumerate() {
            idx.insert(id, i as u32);
        }
        let mut start = Vec::with_capacity(cand.len());
        for &(_, id) in &cand {
            start.push(self.pos[id as usize]);
        }
        let edges = with_view!(self, |v| {
            let mut e = Vec::new();
            for (i, &(_, gid)) in cand.iter().enumerate() {
                v.out_edges(gid, &mut |t| {
                    if let Some(&lt) = idx.get(&t) {
                        e.push((i as u32, lt));
                    }
                });
            }
            e
        });

        // Collapse SCCs inside the neighborhood: mutually-dependent nodes
        // are laid out as one super-node, then re-expanded with a tiny
        // deterministic offset so members don't perfectly overlap.
        let n_loc = cand.len();
        let mut pg = petgraph::graph::DiGraph::<(), ()>::new();
        for _ in 0..n_loc {
            pg.add_node(());
        }
        for &(a, b) in &edges {
            pg.add_edge(
                petgraph::graph::NodeIndex::new(a as usize),
                petgraph::graph::NodeIndex::new(b as usize),
                (),
            );
        }
        let sccs = petgraph::algo::tarjan_scc(&pg);
        let mut layout_map: Vec<(u32, f32, f32)> = Vec::new();
        let (w_start, w_edges) = if sccs.len() == n_loc {
            (start, edges)
        } else {
            let mut comp_of = vec![0u32; n_loc];
            let mut rank_of = vec![0u32; n_loc];
            let mut size_of = vec![0u32; sccs.len()];
            for (si, scc) in sccs.iter().enumerate() {
                size_of[si] = scc.len() as u32;
                for (rank, ni) in scc.iter().enumerate() {
                    comp_of[ni.index()] = si as u32;
                    rank_of[ni.index()] = rank as u32;
                }
            }
            let ns = sccs.len();
            let mut sstart = vec![(0f32, 0f32); ns];
            let mut scount = vec![0f32; ns];
            for i in 0..n_loc {
                let c = comp_of[i] as usize;
                sstart[c].0 += start[i].0;
                sstart[c].1 += start[i].1;
                scount[c] += 1.0;
            }
            for c in 0..ns {
                sstart[c].0 /= scount[c];
                sstart[c].1 /= scount[c];
            }
            let mut seset: HashSet<(u32, u32)> = HashSet::new();
            for &(a, b) in &edges {
                let (ca, cb) = (comp_of[a as usize], comp_of[b as usize]);
                if ca != cb {
                    seset.insert((ca.min(cb), ca.max(cb)));
                }
            }
            layout_map = (0..n_loc)
                .map(|i| {
                    let c = comp_of[i] as usize;
                    let r = rank_of[i] as f32;
                    let ang = r * 2.399_963;
                    // Bigger components spread wider (still tiny).
                    let rad = 0.003 * (size_of[c] as f32).sqrt().min(4.0);
                    (comp_of[i], rad * ang.cos(), rad * ang.sin())
                })
                .collect();
            (sstart, seset.into_iter().collect())
        };
        self.layout_map = layout_map;

        self.layout_gen += 1;
        let gen = self.layout_gen;
        let flag = Arc::new(AtomicBool::new(false));
        self.layout_flag = flag.clone();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let res = force_layout(&w_start, &w_edges, &flag);
            let _ = tx.send((gen, res));
        });
        self.layout_rx = Some(rx);
        self.status = format!("organizing {} of {} nodes…", self.layout_ids.len(), total);
    }

    /// Apply a finished layout result if it's still current.
    fn poll_layout(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.layout_rx else { return };
        match rx.try_recv() {
            Ok((gen, coords)) if gen == self.layout_gen => {
                let ids = std::mem::take(&mut self.layout_ids);
                let w = self.canvas_size.x.max(400.0);
                let h = self.canvas_size.y.max(300.0);
                let (cx, cy) = (w / 2.0, h / 2.0);
                let s = w.min(h) * 0.7;
                for (i, &id) in ids.iter().enumerate() {
                    // With SCC collapse, coords are per super-node; map
                    // back through layout_map (comp idx + micro-offset).
                    let xy = if self.layout_map.is_empty() {
                        coords.get(i).copied()
                    } else {
                        self.layout_map.get(i).and_then(|&(c, ox, oy)| {
                            coords.get(c as usize).map(|&(x, y)| (x + ox, y + oy))
                        })
                    };
                    if let Some((x, y)) = xy {
                        let p = id as usize;
                        if p < self.pos.len() {
                            self.pos[p] = (cx + x * s, cy + y * s);
                        }
                    }
                }
                self.layout_rx = None;
                self.status = format!("organic layout: {} nodes", ids.len());
                ctx.request_repaint();
            }
            Ok(_) => self.layout_rx = None, // stale generation
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
            Err(TryRecvError::Disconnected) => self.layout_rx = None,
        }
    }

    fn paint_canvas(&mut self, ui: &mut egui::Ui, rect: egui::Rect) {
        if self.viz_dirty {
            self.rebuild_viz();
        }
        self.poll_layout(ui.ctx());
        let response = ui.interact(
            rect,
            ui.id().with("graph_canvas"),
            egui::Sense::click_and_drag(),
        );

        // Scroll zooms toward the cursor; drag pans; double-click resets.
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        let hover = ui.input(|i| i.pointer.hover_pos());
        if scroll != 0.0 && hover.is_some_and(|p| rect.contains(p)) {
            let cursor = hover.unwrap();
            let factor = if scroll > 0.0 { 1.01 } else { 1.0 / 1.01 };
            let new_zoom = (self.zoom * factor).clamp(0.05, 200.0);
            // Keep the world point under the cursor stationary.
            let world = (cursor - rect.min - self.pan) / self.zoom;
            self.pan = cursor - rect.min - world * new_zoom;
            self.zoom = new_zoom;
        }
        if response.dragged() {
            self.pan += response.drag_delta();
        }
        // Trackpad pinch / ctrl+scroll zooms around the viewport center.
        let zd = ui.input(|i| i.zoom_delta());
        if (zd - 1.0).abs() > 0.001 {
            // Dampen pinch/ctrl-scroll: raw deltas are twitchy.
            let zd = zd.powf(0.2);
            let new_zoom = (self.zoom * zd).clamp(0.05, 200.0);
            let center = rect.center();
            let world = (center - rect.min - self.pan) / self.zoom;
            self.pan = center - rect.min - world * new_zoom;
            self.zoom = new_zoom;
        }
        if response.double_clicked() {
            self.zoom = 1.0;
            self.pan = egui::Vec2::ZERO;
        }
        // Click a node to select it: click = A, shift+click = B.
        if response.clicked() {
            if let Some(click) = ui.input(|i| i.pointer.interact_pos()) {
                if let Some(id) = nearest_node(&self.pos, self.pan, self.zoom, rect.min, click) {
                    let name = with_view!(self, |v| nm(v, id));
                    if ui.input(|i| i.modifiers.shift) {
                        self.sel_b = Some(id);
                        self.node_b = name;
                    } else {
                        self.sel_a = Some(id);
                        self.node_a = name;
                        self.focus_a();
                    }
                    self.status = format!("selected node {id} on canvas");
                    self.viz_dirty = true;
                }
            }
        }

        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, egui::Color32::from_gray(24));

        let to_screen =
            |p: (f32, f32)| rect.min + self.pan + egui::vec2(p.0 * self.zoom, p.1 * self.zoom);

        // Edges. LOD: past EDGE_DRAW_MAX only edges touching the
        // highlight/selection are drawn. Three tiers, drawn back-to-front:
        //   0 = cold (dim gray)
        //   1 = touches the highlighted set (amber)
        //   2 = touches the A/B selection (bright yellow + glow)
        // Hot tiers get a dark underlay stroke so they stay readable over
        // the hairball.
        let draw_all = self.edge_ids.len() <= EDGE_DRAW_MAX;
        let tiers = &self.edge_tiers;
        debug_assert_eq!(tiers.len(), self.edge_ids.len());
        // If the highlighted set touches too many edges, drawing them all
        // just repaints the hairball - skip tier 1 entirely (nodes stay
        // highlighted; only selection edges remain). Tier 2 always draws.
        let draw_tier1 = self.tier1_draw;
        // Batch into a handful of Shape::Vec draws instead of one painter
        // shape per edge: [cold, t1 outline, t1 core, t2 outline, t2 core].
        let mut groups: [Vec<egui::Shape>; 5] = Default::default();
        let group_strokes = [
            egui::Stroke::new(1.0, egui::Color32::from_gray(60)),
            egui::Stroke::new(2.2, egui::Color32::from_black_alpha(230)),
            egui::Stroke::new(1.1, egui::Color32::from_rgb(235, 160, 50)),
            egui::Stroke::new(3.0, egui::Color32::from_black_alpha(230)),
            egui::Stroke::new(1.6, egui::Color32::from_rgb(255, 225, 80)),
        ];
        for (i, &(s, t)) in self.edge_ids.iter().enumerate() {
            let tr = tiers[i];
            if (tr == 1 && !draw_tier1) || (!draw_all && tr == 0) {
                continue;
            }
            let (Some(&ps), Some(&pt)) = (self.pos.get(s as usize), self.pos.get(t as usize))
            else {
                continue;
            };
            let seg = [to_screen(ps), to_screen(pt)];
            match tr {
                0 => groups[0].push(egui::Shape::line_segment(seg, group_strokes[0])),
                1 => {
                    groups[1].push(egui::Shape::line_segment(seg, group_strokes[1]));
                    groups[2].push(egui::Shape::line_segment(seg, group_strokes[2]));
                }
                _ => {
                    groups[3].push(egui::Shape::line_segment(seg, group_strokes[3]));
                    groups[4].push(egui::Shape::line_segment(seg, group_strokes[4]));
                }
            }
        }
        // Real edges incident to A/B that the sample missed. Neighbors
        // outside the node cap get a deterministic spot on a ring around
        // the selected node so the line has somewhere to land.
        for &(s, t) in &self.sel_nbr_edges {
            let Some(&ps) = self.pos.get(s as usize) else {
                continue;
            };
            let pt = match self.pos.get(t as usize) {
                Some(&p) => p,
                None => {
                    let h = t.wrapping_mul(0x9E37_79B9);
                    let ang = (h % 6283) as f32 / 1000.0;
                    (ps.0 + 60.0 * ang.cos(), ps.1 + 60.0 * ang.sin())
                }
            };
            let seg = [to_screen(ps), to_screen(pt)];
            groups[3].push(egui::Shape::line_segment(seg, group_strokes[3]));
            groups[4].push(egui::Shape::line_segment(seg, group_strokes[4]));
        }
        for group in groups {
            if !group.is_empty() {
                painter.add(egui::Shape::Vec(group));
            }
        }

        // Nodes. LOD: small graphs get circles; large graphs get cheap
        // 3px rects so 100k nodes stay interactive.
        let detail = self.pos.len() <= NODE_CIRCLE_MAX;
        for (i, &p) in self.pos.iter().enumerate() {
            let id = i as u32;
            let c = to_screen(p);
            let color = if Some(id) == self.sel_a || Some(id) == self.sel_b {
                egui::Color32::from_rgb(80, 200, 120)
            } else if self.highlight.contains(&id) {
                egui::Color32::from_rgb(230, 140, 50)
            } else {
                egui::Color32::from_rgb(90, 110, 160)
            };
            // Dark halo behind each node so it stays visible through edges.
            let halo = egui::Color32::from_gray(24);
            if detail {
                painter.circle_filled(c, 5.0, halo);
                painter.circle_filled(c, 3.5, color);
            } else {
                painter.rect_filled(
                    egui::Rect::from_center_size(c, egui::vec2(5.0, 5.0)),
                    0.0,
                    halo,
                );
                painter.rect_filled(
                    egui::Rect::from_center_size(c, egui::vec2(3.0, 3.0)),
                    0.0,
                    color,
                );
            }
        }

        // Dots for selection neighbors that have no canvas node -
        // they sit on the deterministic ring around their anchor.
        for &(nid, anchor) in &self.sel_nbr_extra {
            let Some(&as_) = self.pos.get(anchor as usize) else {
                continue;
            };
            let h = nid.wrapping_mul(0x9E37_79B9);
            let ang = (h % 6283) as f32 / 1000.0;
            let p = (as_.0 + 60.0 * ang.cos(), as_.1 + 60.0 * ang.sin());
            let c = to_screen(p);
            painter.circle_filled(c, 4.0, egui::Color32::from_gray(24));
            painter.circle_filled(c, 2.5, egui::Color32::from_rgb(140, 170, 220));
        }

        // Hover tooltip: name + degrees for the node under the cursor.
        if let Some(hover) = ui.input(|i| i.pointer.hover_pos()) {
            if rect.contains(hover) {
                if let Some(id) = nearest_node(&self.pos, self.pan, self.zoom, rect.min, hover) {
                    if self.hover_tip.as_ref().map(|(i, _)| *i) != Some(id) {
                        let name = with_view!(self, |v| nm(v, id));
                        let (outd, ind) = with_view!(self, |v| (v.out_degree(id), v.in_degree(id)));
                        self.hover_tip =
                            Some((id, format!("{name}\n{outd} deps, {ind} dependents")));
                    }
                    let text = &self.hover_tip.as_ref().unwrap().1;
                    let font = egui::FontId::monospace(12.0);
                    let galley = painter.layout_no_wrap(text.clone(), font, egui::Color32::WHITE);
                    let pad = egui::vec2(8.0, 4.0);
                    let tip_pos = hover + egui::vec2(14.0, 14.0);
                    let bg = egui::Rect::from_min_size(tip_pos, galley.size() + pad);
                    painter.rect_filled(bg, 4.0, egui::Color32::from_black_alpha(220));
                    painter.galley(tip_pos + egui::vec2(4.0, 2.0), galley, egui::Color32::WHITE);
                }
            }
        }

        painter.text(
            rect.right_bottom() + egui::vec2(-8.0, -8.0),
            egui::Align2::RIGHT_BOTTOM,
            format!(
                "{:.0}%  (scroll=zoom, drag=pan, click=A, shift+click=B, 2x-click=reset)",
                self.zoom * 100.0
            ),
            egui::FontId::proportional(11.0),
            egui::Color32::GRAY,
        );

        if self.viz_nodes > MAX_VIZ_NODES {
            painter.text(
                rect.left_bottom() + egui::vec2(8.0, -8.0),
                egui::Align2::LEFT_BOTTOM,
                format!(
                    "showing {} of {} nodes, {} of {} edges",
                    MAX_VIZ_NODES,
                    self.viz_nodes,
                    self.viz_edges,
                    self.edge_ids.len()
                ),
                egui::FontId::proportional(11.0),
                egui::Color32::GRAY,
            );
        }
    }
}

impl eframe::App for StrandApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // crates.io update check resolves once in the background.
        if let Some(rx) = &self.update_rx {
            match rx.try_recv() {
                Ok(Some(updates)) => {
                    self.update_note = Some(
                        updates
                            .iter()
                            .map(|u| {
                                format!(
                                    "{} {} -> {} available - run `cargo install {}`",
                                    u.name, u.installed, u.latest, u.name
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                    self.update_rx = None;
                }
                Ok(None) => self.update_rx = None,
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.update_rx = None,
            }
        }

        // Re-check crates.io every 10 minutes while the app is open -
        // there is no command to trigger it like the CLI has.
        if self.update_rx.is_none() && std::time::Instant::now() >= self.update_next_check {
            self.update_rx = Some(update_check::spawn());
            self.update_next_check =
                std::time::Instant::now() + std::time::Duration::from_secs(600);
        }

        self.poll_workers();

        // Panels must be added outermost-first, CentralPanel last.
        egui::Panel::top("menu").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Strand");
                if ui.button("Open .strand...").clicked() {
                    self.open_strand();
                }
                if ui.button("Open store...").clicked() {
                    self.open_store();
                }
                if ui.button("Close").clicked() {
                    self.close_graph();
                }
                if ui.button("Instructions").clicked() {
                    self.show_instructions = true;
                }
                ui.separator();
                ui.label(&self.source_label);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.backend.is_some() {
                        if let Some(n) = &self.update_note {
                            ui.colored_label(egui::Color32::from_rgb(255, 200, 80), n);
                        }
                    }
                    if !self.status.is_empty() {
                        ui.label(&self.status);
                    }
                });
            });
        });

        egui::Panel::left("controls")
            .default_size(240.0)
            .show(ui, |ui| {
                ui.heading("Nodes");
                ui.label("A:");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.node_a);
                    if ui.button("select").clicked() {
                        self.resolve(0);
                    }
                });
                if let Some(m) = self.suggestion_row(ui, 0) {
                    self.node_a = m;
                    self.resolve(0);
                }
                ui.label("B:");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.node_b);
                    if ui.button("select").clicked() {
                        self.resolve(1);
                    }
                });
                if let Some(m) = self.suggestion_row(ui, 1) {
                    self.node_b = m;
                    self.resolve(1);
                }
                ui.add_space(4.0);
                // Browse every node name - click picks A, shift+click B.
                ui.collapsing("Browse nodes", |ui| {
                    ui.text_edit_singleline(&mut self.node_filter);
                    let q = self.node_filter.trim().to_lowercase();
                    let mut picked: Option<(String, bool)> = None;
                    let mut shown = 0usize;
                    egui::ScrollArea::vertical()
                        .max_height(160.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for name in &self.names {
                                if !q.is_empty() && !name.to_lowercase().contains(&q) {
                                    continue;
                                }
                                if shown >= 1000 {
                                    break;
                                }
                                shown += 1;
                                let resp = ui.selectable_label(false, name);
                                if resp.clicked() {
                                    picked = Some((name.clone(), ui.input(|i| i.modifiers.shift)));
                                }
                            }
                        });
                    if shown >= 1000 {
                        ui.label("… first 1000 matches - refine the filter");
                    }
                    if let Some((name, to_b)) = picked {
                        let id = with_view!(self, |v| v.node_id(name.as_str()));
                        match id {
                            Some(id) => {
                                if to_b {
                                    self.sel_b = Some(id);
                                    self.node_b = name.clone();
                                } else {
                                    self.sel_a = Some(id);
                                    self.node_a = name.clone();
                                    self.focus_a();
                                }
                                self.status = format!("'{name}' -> node {id}");
                                self.viz_dirty = true;
                            }
                            None => self.status = format!("no node named '{name}'"),
                        }
                    }
                });
                ui.label(format!(
                    "A = {}, B = {}",
                    self.sel_a.map(|i| i.to_string()).unwrap_or("-".into()),
                    self.sel_b.map(|i| i.to_string()).unwrap_or("-".into())
                ));
                ui.add_space(8.0);
                ui.label("max depth (blank = all):");
                ui.text_edit_singleline(&mut self.depth_limit);

                ui.add_space(12.0);
                ui.heading("Analyze");
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Deps of A").clicked() {
                        self.run_deps();
                    }
                    if ui.button("Deps of B").clicked() {
                        self.run_deps_b();
                    }
                    if ui.button("Impact of A").clicked() {
                        self.run_impact();
                    }
                    if ui.button("Impact of B").clicked() {
                        self.run_impact_b();
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Why A->B").clicked() {
                        self.run_why();
                    }
                    if ui.button("Why B->A").clicked() {
                        self.run_why_rev();
                    }
                    if ui.button("swap A/B").clicked() {
                        self.swap_ab();
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Cycles").clicked() {
                        self.run_cycles();
                    }
                    if ui.button("Build order").clicked() {
                        self.run_order();
                    }
                    if ui.button("Roots").clicked() {
                        self.run_roots();
                    }
                    if ui.button("Leaves").clicked() {
                        self.run_leaves();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("top by");
                    egui::ComboBox::from_id_salt("metric")
                        .selected_text(match self.top_metric {
                            TopMetric::InDegree => "in-degree",
                            TopMetric::Impact => "impact",
                            TopMetric::PageRank => "pagerank",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.top_metric,
                                TopMetric::InDegree,
                                "in-degree",
                            );
                            ui.selectable_value(&mut self.top_metric, TopMetric::Impact, "impact");
                            ui.selectable_value(
                                &mut self.top_metric,
                                TopMetric::PageRank,
                                "pagerank",
                            );
                        });
                    ui.label("n:");
                    ui.add(egui::TextEdit::singleline(&mut self.top_n).desired_width(40.0));
                    if ui.button("Top").clicked() {
                        self.run_top();
                    }
                });
                if ui.button("Common deps/impact A,B").clicked() {
                    self.run_common();
                }

                ui.add_space(12.0);
                ui.heading("Graph");
                ui.horizontal(|ui| {
                    if ui.button("Rebuild view").clicked() {
                        self.viz_dirty = true;
                    }
                    if ui.button("Clear highlight").clicked() {
                        self.highlight.clear();
                        self.depths.clear();
                        self.sel_a = None;
                        self.sel_b = None;
                        self.node_a.clear();
                        self.node_b.clear();
                        self.report_lines.clear();
                        self.report_title.clear();
                        self.report_filter.clear();
                        self.layout_rx = None;
                        self.layout_ids.clear();
                        self.layout_map.clear();
                        self.viz_dirty = true;
                        self.status = "cleared".to_string();
                    }
                });
                if ui.checkbox(&mut self.organic, "organic layout").changed() && !self.organic {
                    self.viz_dirty = true;
                }
                if self.layout_rx.is_some() {
                    ui.label("organizing layout…");
                }
                ui.label(format!(
                    "{} nodes | {} edges drawn",
                    self.viz_nodes, self.viz_edges
                ));

                if matches!(&self.backend, Some(Backend::Store(s)) if s.is_writable()) {
                    ui.add_space(12.0);
                    ui.heading("Edit store");
                    ui.label("uses names in A / B boxes");
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Add edge A->B").clicked() {
                            self.store_edit(StoreOp::AddEdge);
                        }
                        if ui.button("Remove edge A->B").clicked() {
                            self.store_edit(StoreOp::RemoveEdge);
                        }
                        if ui.button("Add node A").clicked() {
                            self.store_edit(StoreOp::AddNode);
                        }
                        if ui.button("Remove node A").clicked() {
                            self.store_edit(StoreOp::RemoveNode);
                        }
                        if ui.button("Compact").clicked() {
                            self.store_compact();
                        }
                    });
                }
            });

        egui::Panel::bottom("report")
            .default_size(180.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("filter:");
                    ui.text_edit_singleline(&mut self.report_filter);
                    let q = self.report_filter.trim().to_lowercase();
                    let (shown, total) = if q.is_empty() {
                        (self.report_lines.len(), self.report_lines.len())
                    } else {
                        let s = self
                            .report_lines
                            .iter()
                            .filter(|r| r.text.to_lowercase().contains(&q))
                            .count();
                        (s, self.report_lines.len())
                    };
                    ui.label(format!("{shown} of {total}"));
                });
                ui.heading(&self.report_title);
                let q = self.report_filter.trim().to_lowercase();
                // Click = select as A, right-click = select as B.
                let mut pick: Option<(u32, String, bool)> = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for r in &self.report_lines {
                        if !q.is_empty() && !r.text.to_lowercase().contains(&q) {
                            continue;
                        }
                        if let Some((id, name)) = &r.node {
                            let resp = ui.selectable_label(
                                self.sel_a == Some(*id) || self.sel_b == Some(*id),
                                &r.text,
                            );
                            if resp.clicked() {
                                pick = Some((*id, name.clone(), false));
                            } else if resp.secondary_clicked() {
                                pick = Some((*id, name.clone(), true));
                            }
                        } else {
                            ui.monospace(&r.text);
                        }
                    }
                });
                if let Some((id, name, to_b)) = pick {
                    if to_b {
                        self.sel_b = Some(id);
                        self.node_b = name;
                    } else {
                        self.sel_a = Some(id);
                        self.node_a = name;
                        self.focus_a();
                    }
                    self.viz_dirty = true;
                }
            });

        egui::CentralPanel::default().show(ui, |ui| {
            let size = ui.available_size();
            self.canvas_size = size;
            let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
            self.paint_canvas(ui, rect);
        });

        if self.backend.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        // First-run tutorial cards.
        if let Some(i) = self.tutorial_idx {
            let last = i + 1 >= TUTORIAL.len();
            let mut advance = false;
            let mut finish = false;
            egui::Window::new(format!(
                "Welcome to Strand - {} of {}",
                i + 1,
                TUTORIAL.len()
            ))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(&ctx, |ui| {
                ui.set_max_width(500.0);
                let (title, body) = TUTORIAL[i];
                ui.heading(title);
                ui.add_space(6.0);
                ui.label(body);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if i > 0 && ui.button("< Back").clicked() {
                        self.tutorial_idx = Some(i - 1);
                    }
                    if last {
                        if ui.button("Done").clicked() {
                            finish = true;
                        }
                    } else if ui.button("Next >").clicked() {
                        advance = true;
                    }
                    ui.label("- or press → (right arrow) to proceed");
                });
            });
            // Right arrow advances, but not while a text field has focus
            // (it would just move the caret).
            if ctx.input(|inp| inp.key_pressed(egui::Key::ArrowRight))
                && !ctx.egui_wants_keyboard_input()
            {
                advance = true;
            }
            if advance {
                if last {
                    finish = true;
                } else {
                    self.tutorial_idx = Some(i + 1);
                }
            }
            if finish {
                mark_tutorial_seen();
                self.tutorial_idx = None;
            }
        }

        // Instructions reference window.
        if self.show_instructions {
            let mut open = true;
            egui::Window::new("Instructions")
                .open(&mut open)
                .default_size([680.0, 540.0])
                .show(&ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.add(
                            egui::Label::new(egui::RichText::new(INSTRUCTIONS).monospace()).wrap(),
                        );
                    });
                });
            self.show_instructions = open;
        }

        // Update notice: centered until a graph is open, then it lives
        // in the top bar instead.
        if self.backend.is_none() {
            if let Some(note) = &self.update_note {
                egui::Window::new("Update available")
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .collapsible(false)
                    .resizable(false)
                    .show(&ctx, |ui| {
                        ui.label(note);
                    });
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title("Strand - dependency & impact analysis"),
        ..Default::default()
    };
    eframe::run_native(
        "strand",
        options,
        Box::new(|_cc| Ok(Box::new(StrandApp::new()))),
    )
}
