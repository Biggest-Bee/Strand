//! `strand-app`: desktop GUI for Strand dependency/impact analysis.
//!
//! Opens an immutable `.strand` graph or a read-write `.strandb` store and
//! runs the `strand-core` analyses on a merged read view. Read-only: store
//! writes stay in the library/CLI domain for now.

use std::collections::{BTreeMap, BTreeSet};

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
                    $app.status = format!("read snapshot failed: {e}");
                    Default::default()
                }
            },
            None => {
                $app.status = "no graph open".to_string();
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
    top_metric: TopMetric,
    top_n: String,

    // Last analysis output.
    report_title: String,
    report_lines: Vec<ReportRow>,

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
}

const MAX_VIZ_NODES: usize = 4_000;
const MAX_VIZ_EDGES: usize = 60_000;
const MAX_REPORT_LINES: usize = 5_000;

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
            top_metric: TopMetric::InDegree,
            top_n: "20".to_string(),
            report_title: String::new(),
            report_lines: Vec::new(),
            names: Vec::new(),
            viz_nodes: 0,
            viz_edges: 0,
            pos: Vec::new(),
            edge_ids: Vec::new(),
            highlight: BTreeSet::new(),
            depths: Vec::new(),
            viz_dirty: true,
            canvas_size: egui::Vec2::ZERO,
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
                self.status = "opened".to_string();
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
        match Store::open(&dir) {
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
                self.status = "opened".to_string();
            }
            Err(e) => self.status = format!("open failed: {e}"),
        }
    }

    fn reset_query_state(&mut self) {
        self.node_a.clear();
        self.node_b.clear();
        self.sel_a = None;
        self.sel_b = None;
        self.report_lines.clear();
        self.report_title.clear();
        self.names.clear();
        self.highlight.clear();
        self.depths.clear();
        self.viz_dirty = true;
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
    }

    fn paint_canvas(&mut self, ui: &mut egui::Ui, rect: egui::Rect) {
        if self.viz_dirty {
            self.rebuild_viz();
        }
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, egui::Color32::from_gray(24));

        let to_screen = |p: (f32, f32)| rect.min + egui::vec2(p.0, p.1);

        // Edges.
        for &(s, t) in &self.edge_ids {
            let (Some(&ps), Some(&pt)) = (self.pos.get(s as usize), self.pos.get(t as usize))
            else {
                continue;
            };
            let hot = self.highlight.contains(&s) || self.highlight.contains(&t);
            painter.line_segment(
                [to_screen(ps), to_screen(pt)],
                egui::Stroke::new(
                    1.0,
                    if hot {
                        egui::Color32::from_rgb(120, 90, 40)
                    } else {
                        egui::Color32::from_gray(60)
                    },
                ),
            );
        }

        // Nodes.
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
            painter.circle_filled(c, 3.5, color);
        }

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
                    if ui.button("go").clicked() {
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
                    if ui.button("go").clicked() {
                        self.resolve(1);
                    }
                });
                if let Some(m) = self.suggestion_row(ui, 1) {
                    self.node_b = m;
                    self.resolve(1);
                }
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
                if ui.button("Rebuild view").clicked() {
                    self.viz_dirty = true;
                }
                ui.label(format!("{} nodes | {} edges drawn", self.viz_nodes, self.viz_edges));
            });

        egui::Panel::bottom("report")
            .default_size(180.0)
            .show(ui, |ui| {
                ui.heading(&self.report_title);
                let mut pick: Option<(u32, String)> = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for r in &self.report_lines {
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
