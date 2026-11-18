//! `strand-app`: desktop GUI for Strand dependency/impact analysis.
//!
//! Opens an immutable `.strand` graph or a read-write `.strandb` store and
//! runs the `strand-core` analyses on a merged read view. Read-only: store
//! writes stay in the library/CLI domain for now.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::mpsc::{channel, Receiver, TryRecvError};

use eframe::egui;
use strand_core::algo::{self, Dir};
use strand_core::view::GraphView;
use strand_store::Store;

enum Backend {
    /// Immutable mmap'd `.strand` file.
    File(strand_core::Graph),
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
/// dead — callers may legitimately overwrite `status` right after.
fn set_status(status: &mut String, msg: String) {
    *status = msg;
}

/// Run `$body` with `v: &impl GraphView` bound to the concrete backend view.
/// For stores this pins a fresh read snapshot for the duration of the call.
macro_rules! with_view {
    ($app:expr, |$v:ident| $body:expr) => {
        match &$app.backend {
            Some(Backend::File(g)) => {
                let $v = g;
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

    /// All node names, sorted — powers the A/B autocomplete.
    names: Vec<String>,

    // Graph canvas state.
    viz_nodes: usize,
    viz_edges: usize,
    /// node id -> (x, y) in canvas coordinates, rebuilt on demand.
    pos: Vec<(f32, f32)>,
    /// (src, dst) id pairs for drawing (capped).
    edge_ids: Vec<(u32, u32)>,
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
}

const MAX_VIZ_NODES: usize = 100_000;
const MAX_VIZ_EDGES: usize = 300_000;
/// Below this many nodes we draw circles; above it we batch nodes into a
/// single triangle mesh (level-of-detail).
const NODE_CIRCLE_MAX: usize = 8_000;
/// Above this many edges we only draw edges touching the highlight set.
const EDGE_DRAW_MAX: usize = 150_000;
const MAX_REPORT_LINES: usize = 5_000;
/// Neighborhood size cap for the force-directed layout (O(n²) per iter).
const MAX_LAYOUT_NODES: usize = 1_500;
/// BFS hops included in the layout neighborhood.
const LAYOUT_DEPTH: u32 = 3;
/// Fruchterman-Reingold iterations (deterministic, single-threaded).
const LAYOUT_ITERS: usize = 100;

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
fn force_layout(start: &[(f32, f32)], edges: &[(u32, u32)]) -> Vec<(f32, f32)> {
    let n = start.len();
    if n == 0 {
        return Vec::new();
    }
    // Normalize start positions into a centered unit box.
    let (mut minx, mut miny, mut maxx, mut maxy) =
        (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
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
        .map(|&(x, y)| ((x - cx) / span, (y - cy) / span))
        .collect();

    let k = (1.0f32 / n as f32).sqrt() * 0.75;
    let k2 = k * k;
    let mut temp = 0.08f32;
    let mut disp = vec![(0.0f32, 0.0f32); n];
    for _ in 0..LAYOUT_ITERS {
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
                self.source_label = format!("{} ({} nodes, {} edges)", path.display(), g.n_nodes(), g.n_edges());
                self.backend = Some(Backend::File(g));
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

    /// Warn when the graph exceeds canvas caps — the view is then only a
    /// sample (queries still cover the full graph).
    fn cap_warning(&mut self) -> Option<String> {
        with_view!(self, |v| {
            let n = nn(v);
            let e = ne(v);
            if n > MAX_VIZ_NODES || e > MAX_VIZ_EDGES {
                Some(format!(
                    "warning: {n} nodes / {e} edges exceeds canvas caps \
                     ({MAX_VIZ_NODES} nodes / {MAX_VIZ_EDGES} edges) — \
                     canvas shows a partial sample; analyses cover everything"
                ))
            } else {
                None
            }
        })
    }

    /// Snapshot every node name (sorted, deduped) for autocomplete. Skipped
    /// on very large graphs where the index would cost too much memory.
    fn collect_names(&mut self) {
        self.names = with_view!(self, |v| {
            let n = nn(v);
            let mut set = BTreeSet::new();
            if n <= 200_000 {
                for id in 0..n as u32 {
                    set.insert(nm(v, id));
                }
            }
            set.into_iter().collect()
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
        let name = if which == 0 { self.node_a.clone() } else { self.node_b.clone() };
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
        let Some(a) = self.sel_a else {
            self.status = "select node A first".into();
            return;
        };
        let depth = self.depth_arg();
        let lines = with_view!(self, |v| {
            let d = algo::bfs(v, &[a], Dir::Out, depth);
            let mut out = Vec::new();
            let mut by_depth: BTreeMap<u32, Vec<(u32, String)>> = BTreeMap::new();
            for (id, &dep) in d.iter().enumerate() {
                if dep != algo::UNVISITED && dep > 0 {
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
            out
        });
        self.highlight_from_depths(a, Dir::Out, depth);
        self.set_report(format!("dependencies of node {a}"), lines);
    }

    fn run_impact(&mut self) {
        let Some(a) = self.sel_a else {
            self.status = "select node A first".into();
            return;
        };
        let depth = self.depth_arg();
        let lines = with_view!(self, |v| {
            let d = algo::bfs(v, &[a], Dir::In, depth);
            let mut out = Vec::new();
            let mut by_depth: BTreeMap<u32, Vec<(u32, String)>> = BTreeMap::new();
            for (id, &dep) in d.iter().enumerate() {
                if dep != algo::UNVISITED && dep > 0 {
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
            out
        });
        self.highlight_from_depths(a, Dir::In, depth);
        self.set_report(format!("impact of node {a} (who depends on it)"), lines);
    }

    /// Re-layout around the selected node: BFS a few hops in both
    /// directions so its neighborhood clusters into view. Does not touch
    /// the highlight set (that's analyses-only).
    fn focus_a(&mut self) {
        let Some(a) = self.sel_a else { return };
        self.depths = with_view!(self, |v| {
            let out = algo::bfs(v, &[a], Dir::Out, Some(3));
            let inn = algo::bfs(v, &[a], Dir::In, Some(3));
            out.iter()
                .zip(inn.iter())
                .map(|(&x, &y)| match (x, y) {
                    (algo::UNVISITED, d) | (d, algo::UNVISITED) => d,
                    (x, y) => x.min(y),
                })
                .collect()
        });
        self.viz_dirty = true;
    }

    /// Recompute depths for the ring layout and store the affected set.
    fn highlight_from_depths(&mut self, seed: u32, dir: Dir, max_depth: Option<u32>) {
        let (depths, names) = with_view!(self, |v| {
            let d = algo::bfs(v, &[seed], dir, max_depth);
            let affected: BTreeSet<u32> = d
                .iter()
                .enumerate()
                .filter(|&(_, &x)| x != algo::UNVISITED && x > 0)
                .map(|(i, _)| i as u32)
                .collect();
            (d, affected)
        });
        self.depths = depths;
        self.highlight = names;
        self.viz_dirty = true;
    }

    fn run_why(&mut self) {
        let (Some(a), Some(b)) = (self.sel_a, self.sel_b) else {
            self.status = "select nodes A and B first".into();
            return;
        };
        let lines = with_view!(self, |v| {
            match algo::shortest_path(v, a, b) {
                Some(path) => {
                    let names: Vec<String> =
                        path.iter().map(|&id| nm(v, id)).collect();
                    vec![row(names.join(" -> "))]
                }
                None => vec![row("no path")],
            }
        });
        self.set_report(format!("shortest dependency path {a} -> {b}"), lines);
    }

    fn run_cycles(&mut self) {
        let lines = with_view!(self, |v| {
            let sccs = algo::strongly_connected(v);
            let cycles: Vec<&Vec<u32>> = sccs.iter().filter(|c| c.len() > 1).collect();
            if cycles.is_empty() {
                vec![row("no cycles")]
            } else {
                let mut out = Vec::new();
                for c in cycles.iter().take(500) {
                    let names: Vec<String> =
                        c.iter().map(|&id| nm(v, id)).collect();
                    out.push(row(format!("cycle ({}): {}", c.len(), names.join(", "))));
                }
                if cycles.len() > 500 {
                    out.push(row(format!("... {} more cycles", cycles.len() - 500)));
                }
                out
            }
        });
        self.set_report("cycles (SCCs with >1 node)".into(), lines);
    }

    fn run_top(&mut self) {
        let n: usize = self.top_n.trim().parse().unwrap_or(20);
        let metric = self.top_metric;
        let lines = with_view!(self, |v| {
            let nv = nn(v);
            let mut scored: Vec<(f64, u32)> = match metric {
                TopMetric::InDegree => (0..nv as u32)
                    .map(|id| (v.in_degree(id) as f64, id))
                    .collect(),
                TopMetric::PageRank => {
                    let pr = algo::pagerank(v, false, 1e-9, 100);
                    pr.into_iter().enumerate().map(|(i, s)| (s, i as u32)).collect()
                }
                TopMetric::Impact => {
                    let imp = algo::impact_sizes(v);
                    imp.into_iter().enumerate().map(|(i, s)| (s as f64, i as u32)).collect()
                }
            };
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            scored
                .iter()
                .take(n)
                .map(|&(s, id)| {
                    let name = nm(v, id);
                    row_node(format!("{s:>10.4}\t{name}"), id, name)
                })
                .collect()
        });
        let label = match metric {
            TopMetric::InDegree => "in-degree",
            TopMetric::Impact => "impact size",
            TopMetric::PageRank => "pagerank",
        };
        self.set_report(format!("top {n} by {label}"), lines);
    }

    fn run_order(&mut self) {
        let lines = with_view!(self, |v| {
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
                        comp.iter().map(|&id| nm(v, id)).collect();
                    out.push(row(format!("{}. {{{}}}", i + 1, names.join(", "))));
                }
                if out.len() > MAX_REPORT_LINES {
                    out.push(row("... truncated"));
                    break;
                }
            }
            out
        });
        self.set_report("build order (dependencies first)".into(), lines);
    }

    fn run_roots(&mut self) {
        let lines = with_view!(self, |v| {
            let mut out = Vec::new();
            for id in 0..nn(v) as u32 {
                if v.in_degree(id) == 0 {
                    let name = nm(v, id);
                    out.push(row_node(name.clone(), id, name));
                }
            }
            out
        });
        self.set_report("roots (nothing depends on them)".into(), lines);
    }

    fn run_leaves(&mut self) {
        let lines = with_view!(self, |v| {
            let mut out = Vec::new();
            for id in 0..nn(v) as u32 {
                if v.out_degree(id) == 0 {
                    let name = nm(v, id);
                    out.push(row_node(name.clone(), id, name));
                }
            }
            out
        });
        self.set_report("leaves (depend on nothing)".into(), lines);
    }

    fn run_common(&mut self) {
        let (Some(a), Some(b)) = (self.sel_a, self.sel_b) else {
            self.status = "select nodes A and B first".into();
            return;
        };
        let mut out = Vec::new();
        for (dir, label) in [(Dir::Out, "common dependencies"), (Dir::In, "common impact")] {
            let names = with_view!(self, |v| {
                algo::common(v, a, b, dir)
                    .iter()
                    .map(|&id| {
                        let name = nm(v, id);
                        (id, name)
                    })
                    .collect::<Vec<_>>()
            });
            out.push(row(format!("== {label} ({}) ==", names.len())));
            for (id, name) in names {
                out.push(row_node(name.clone(), id, name));
            }
            out.push(row(""));
        }
        self.set_report(format!("common sets of {a} and {b}"), out);
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

    /// Fold the delta into a fresh base. Runs on the UI thread — fine for
    /// typical deltas; very large ones will pause the window briefly.
    fn store_compact(&mut self) {
        let res = match &self.backend {
            Some(Backend::Store(s)) => s.compact(),
            _ => return,
        };
        match res {
            Ok(()) => {
                self.status = "compacted".into();
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
        with_view!(self, |v| {
            let n = nn(v);
            self.viz_nodes = n;
            self.viz_edges = 0usize;
            let cap_n = n.min(MAX_VIZ_NODES);
            self.pos = vec![(0.0, 0.0); cap_n];
            self.edge_ids = Vec::with_capacity(MAX_VIZ_EDGES.min(1 << 16));
            for id in 0..cap_n as u32 {
                v.out_edges(id, &mut |t| {
                    if self.edge_ids.len() < MAX_VIZ_EDGES && (t as usize) < cap_n {
                        self.edge_ids.push((id, t));
                    }
                });
            }
            self.viz_edges = self.edge_ids.len();
        });

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
            let max_d = rings.keys().next_back().copied().unwrap_or(0);
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
    fn maybe_start_layout(&mut self) {
        if !self.organic || self.depths.is_empty() {
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
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let res = force_layout(&w_start, &w_edges);
            let _ = tx.send((gen, res));
        });
        self.layout_rx = Some(rx);
        self.status = format!(
            "organizing {} of {} nodes…",
            self.layout_ids.len(),
            total
        );
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
            let factor = if scroll > 0.0 { 1.15 } else { 1.0 / 1.15 };
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
                if let Some(id) =
                    nearest_node(&self.pos, self.pan, self.zoom, rect.min, click)
                {
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

        let to_screen = |p: (f32, f32)| {
            rect.min + self.pan + egui::vec2(p.0 * self.zoom, p.1 * self.zoom)
        };

        // Edges. LOD: past EDGE_DRAW_MAX only edges touching the
        // highlight/selection are drawn. Three tiers, drawn back-to-front:
        //   0 = cold (dim gray)
        //   1 = touches the highlighted set (amber)
        //   2 = touches the A/B selection (bright yellow + glow)
        // Hot tiers get a dark underlay stroke so they stay readable over
        // the hairball.
        let draw_all = self.edge_ids.len() <= EDGE_DRAW_MAX;
        let tiers: Vec<u8> = self
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
        // If the highlighted set touches too many edges, drawing them all
        // just repaints the hairball — skip tier 1 entirely (nodes stay
        // highlighted; only selection edges remain). Tier 2 always draws.
        let draw_tier1 = tiers.iter().filter(|&&t| t == 1).count() <= 20_000;
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
            let (Some(&ps), Some(&pt)) =
                (self.pos.get(s as usize), self.pos.get(t as usize))
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

        // Hover tooltip: name + degrees for the node under the cursor.
        if let Some(hover) = ui.input(|i| i.pointer.hover_pos()) {
            if rect.contains(hover) {
                if let Some(id) =
                    nearest_node(&self.pos, self.pan, self.zoom, rect.min, hover)
                {
                    let name = with_view!(self, |v| nm(v, id));
                    let (outd, ind) =
                        with_view!(self, |v| (v.out_degree(id), v.in_degree(id)));
                    let text = format!("{name}\n{outd} deps, {ind} dependents");
                    let font = egui::FontId::monospace(12.0);
                    let galley = painter.layout_no_wrap(
                        text,
                        font,
                        egui::Color32::WHITE,
                    );
                    let pad = egui::vec2(8.0, 4.0);
                    let tip_pos = hover + egui::vec2(14.0, 14.0);
                    let bg = egui::Rect::from_min_size(
                        tip_pos,
                        galley.size() + pad,
                    );
                    painter.rect_filled(bg, 4.0, egui::Color32::from_black_alpha(220));
                    painter.galley(
                        tip_pos + egui::vec2(4.0, 2.0),
                        galley,
                        egui::Color32::WHITE,
                    );
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
                    MAX_VIZ_NODES, self.viz_nodes, self.viz_edges, self.edge_ids.len()
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
                ui.separator();
                ui.label(&self.source_label);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
                // Browse every node name — click picks A, shift+click B.
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
                                if shown >= 300 {
                                    break;
                                }
                                shown += 1;
                                let resp = ui.selectable_label(false, name);
                                if resp.clicked() {
                                    picked = Some((
                                        name.clone(),
                                        ui.input(|i| i.modifiers.shift),
                                    ));
                                }
                            }
                        });
                    if shown >= 300 {
                        ui.label("… first 300 matches — refine the filter");
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
                    if ui.button("Impact of A").clicked() {
                        self.run_impact();
                    }
                    if ui.button("Why A->B").clicked() {
                        self.run_why();
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
                            ui.selectable_value(&mut self.top_metric, TopMetric::InDegree, "in-degree");
                            ui.selectable_value(&mut self.top_metric, TopMetric::Impact, "impact");
                            ui.selectable_value(&mut self.top_metric, TopMetric::PageRank, "pagerank");
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
                        self.layout_rx = None;
                        self.layout_ids.clear();
                        self.layout_map.clear();
                        self.viz_dirty = true;
                        self.status = "cleared".to_string();
                    }
                });
                if ui
                    .checkbox(&mut self.organic, "organic layout")
                    .changed()
                    && !self.organic
                {
                    self.viz_dirty = true;
                }
                if self.layout_rx.is_some() {
                    ui.label("organizing layout…");
                }
                ui.label(format!("{} nodes | {} edges drawn", self.viz_nodes, self.viz_edges));

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
                let mut pick: Option<(u32, String)> = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for r in &self.report_lines {
                        if !q.is_empty() && !r.text.to_lowercase().contains(&q) {
                            continue;
                        }
                        if let Some((id, name)) = &r.node {
                            // Clickable: selects the node as A.
                            if ui
                                .selectable_label(self.sel_a == Some(*id), &r.text)
                                .clicked()
                            {
                                pick = Some((*id, name.clone()));
                            }
                        } else {
                            ui.monospace(&r.text);
                        }
                    }
                });
                if let Some((id, name)) = pick {
                    self.sel_a = Some(id);
                    self.node_a = name;
                    self.focus_a();
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
