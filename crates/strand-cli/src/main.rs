//! `strand` - dependency and impact analysis on memory-mapped CSR graphs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use strand_core::algo::{self, Dir};
use strand_core::view::{ConfidenceView, GraphView};
use strand_core::{EdgeKind, Graph, GraphBuilder, MergeOp};
use strand_import::{self, Format};

mod check;
mod deep;
mod export;
mod trace;
mod update_check;

#[derive(Parser)]
#[command(
    name = "strand",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("STRAND_GIT_DESCRIBE"), ")"),
    about = "Dependency and impact analysis on memory-mapped CSR graphs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a .strand graph from CSV/TSV edge lists or cargo metadata JSON.
    /// Accepts multiple input files; all edges are merged.
    Build(BuildArgs),
    /// Scan a directory of Rust sources and build a file-level
    /// dependency graph from `mod`/`use` statements.
    Scan(ScanArgs),
    /// Scan a project, run a command under a Python import tracer,
    /// and merge observed runtime edges into the graph.
    /// Usage: `strand trace <dir> -- <command...>` (e.g. `-- pytest`).
    Trace(TraceArgs),
    /// Deep scan: static graph plus Python interprocedural analysis
    /// (call graph, dynamic-import resolution, taint/null/leak
    /// findings). Slower than `scan`; use for security/bug review.
    Deep(DeepArgs),
    /// Show graph statistics.
    Info(InfoArgs),
    /// List every node name in the graph.
    Nodes(NodesArgs),
    /// List direct and transitive dependencies of a node.
    Deps(DepsArgs),
    /// Blast radius: everything affected if the given nodes change.
    Impact(ImpactArgs),
    /// Shortest dependency chain between two nodes.
    Why(WhyArgs),
    /// List strongly connected components (cycles).
    Cycles(CyclesArgs),
    /// Rank nodes by risk: in-degree, impact size, or PageRank.
    Top(TopArgs),
    /// Dependencies-first build order + critical path.
    Order(OrderArgs),
    /// Nodes nothing depends on (top-level apps).
    Roots(RootsArgs),
    /// Nodes that depend on nothing (leaf libraries).
    Leaves(LeavesArgs),
    /// Nodes shared between two nodes: common deps or common impact.
    Common(CommonArgs),
    /// Export an impact set or dependency path as a DOT/Mermaid diagram.
    Export(ExportArgs),
    /// Enforce architecture rules (`forbid A -> B`) from strand.rules.
    Check(CheckArgs),
    /// Diff two .strand graphs: nodes/edges added or removed.
    Diff(DiffArgs),
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
enum InFormat {
    Auto,
    Csv,
    Cargo,
    CargoLock,
    NpmLock,
    PoetryLock,
    GoMod,
    Pom,
    /// `webpack --json` stats output.
    Webpack,
    /// `esbuild --metafile` JSON output.
    Esbuild,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
enum MergeChoice {
    Sum,
    Max,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
enum TopBy {
    InDegree,
    Impact,
    Pagerank,
}

/// Edge-confidence threshold names, ordered by trust.
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
enum Confidence {
    /// Only directly parsed syntax edges.
    Static,
    /// Literal-derived resolutions: const-prop imports, globs,
    /// entry-point consumer links.
    Resolved,
    /// Explicit declarations: manual `depends-on` comments, config
    /// entry points, framework conventions.
    Declared,
    /// Runtime-observed edges (`strand trace`).
    Traced,
    /// Inferred edges (e.g. Rust parent modules from layout).
    /// Accepting everything - the default.
    Heuristic,
}

impl Confidence {
    fn min_tag(self) -> u8 {
        match self {
            Confidence::Static => 4,
            Confidence::Resolved => 3,
            Confidence::Declared => 2,
            Confidence::Traced => 1,
            Confidence::Heuristic => 0,
        }
    }
}

/// Shared `--min-confidence` flag for graph-traversal commands.
#[derive(clap::Args)]
struct ConfidenceArgs {
    /// Only traverse edges at least this confident. Edges below the
    /// threshold are invisible to the query (useful for reviewing
    /// only literal/static edges, or only human-declared ones).
    #[arg(long, value_enum)]
    min_confidence: Option<Confidence>,
}

impl ConfidenceArgs {
    fn min(&self) -> u8 {
        self.min_confidence.map_or(0, |c| c.min_tag())
    }
}

#[derive(Parser)]
struct BuildArgs {
    /// Input file(s): CSV/TSV edge lists or `cargo metadata` JSON.
    /// Repeatable; all edges are merged into one graph.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    /// Output .strand file.
    #[arg(short, long)]
    output: PathBuf,
    /// Input format (default: auto-detect).
    #[arg(long, value_enum, default_value_t = InFormat::Auto)]
    format: InFormat,
    /// Duplicate-edge merge policy.
    #[arg(long, value_enum, default_value_t = MergeChoice::Sum)]
    merge: MergeChoice,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
enum ScanLang {
    /// Rust sources (.rs): mod/use/#[path]/include! resolution.
    Rust,
    /// Python sources (.py): import/from resolution.
    Python,
    /// JavaScript/TypeScript (.ts/.tsx/.js/.jsx/.mjs/.cjs).
    Js,
    /// Go sources (.go): import specs resolved against go.mod modules.
    Go,
    /// All supported languages merged (default).
    All,
}

#[derive(Parser)]
struct ScanArgs {
    /// Project directory to scan for source files. A file path scans
    /// its project root (nearest ancestor with a manifest).
    dir: PathBuf,
    /// Output .strand file (default: <dir-name>.strand).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Language(s) to scan (default: all).
    #[arg(long, value_enum, default_value_t = ScanLang::All)]
    lang: ScanLang,
    /// Additional edge-list inputs merged into the scan: CSV/TSV,
    /// lockfiles, `cargo metadata`, `webpack --json` stats, or
    /// `esbuild --metafile` JSON (format auto-detected). Repeatable.
    /// Edges the static scan can't see (e.g. bundler-resolved dynamic
    /// imports) come from these files.
    #[arg(long = "import")]
    imports: Vec<PathBuf>,
}

#[derive(Parser)]
struct TraceArgs {
    /// Project directory to scan and trace within.
    dir: PathBuf,
    /// Output .strand file (default: <dir-name>.strand).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Command to run under the Python import tracer (after `--`).
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Parser)]
struct DeepArgs {
    /// Project directory to deep-scan (default: current directory).
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Output .strand file (default: <dir-name>.strand).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Only run IPA and the taint/null/leak solver; skip writing
    /// the graph.
    #[arg(long)]
    ipa_only: bool,
    /// Dump resolved call edges as `module.func -> module.func`.
    #[arg(long)]
    dump_callgraph: bool,
    /// Run taint/null/leak analysis and print findings.
    #[arg(long)]
    analyze: bool,
    /// Model directory for `--analyze` (default: embedded python.toml).
    #[arg(long)]
    models: Option<PathBuf>,
}

#[derive(Parser)]
struct InfoArgs {
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct NodesArgs {
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct DiffArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    /// Older graph (the "before" side).
    old: PathBuf,
    /// Newer graph (the "after" side).
    new: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct DepsArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    node: String,
    #[arg(long)]
    depth: Option<u32>,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ImpactArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    /// Seed node names. Optional when --git-diff is given.
    nodes: Vec<String>,
    #[arg(long)]
    depth: Option<u32>,
    /// Group affected nodes by depth level.
    #[arg(long)]
    by_depth: bool,
    /// Only report nodes with this node_meta kind.
    #[arg(long)]
    kind: Option<String>,
    /// Seed from files changed vs a git ref: runs
    /// `git diff --name-only <REF>` and maps changed paths onto graph
    /// nodes (exact path, package/dir-name segment, or path suffix).
    #[arg(long)]
    git_diff: Option<String>,
    /// Directory to run git in (default: current directory).
    #[arg(long)]
    git_dir: Option<PathBuf>,
    /// Exit non-zero if the affected count exceeds N (CI gate).
    #[arg(long)]
    max_impact: Option<usize>,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct WhyArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    from: String,
    to: String,
    /// Enumerate dependency chains: up to --limit alternative *shortest*
    /// chains, or every simple chain up to --max-depth hops when given.
    #[arg(long)]
    all_paths: bool,
    /// Use edge weights (Dijkstra) instead of hop count. Requires a
    /// weighted graph; unweighted graphs count every edge as 1.0.
    #[arg(long)]
    weighted: bool,
    /// Max number of paths when --all-paths.
    #[arg(long, default_value_t = 5)]
    limit: usize,
    /// With --all-paths: enumerate every simple chain of at most this
    /// many hops instead of only shortest chains.
    #[arg(long)]
    max_depth: Option<u32>,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct CyclesArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct TopArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    #[arg(long, value_enum)]
    by: TopBy,
    #[arg(short = 'n', long, default_value_t = 20)]
    count: usize,
    /// For --by impact on huge graphs: landmark count for the
    /// approximate ranking (default: auto ~2G edge visits).
    #[arg(long)]
    samples: Option<usize>,
    /// For --by impact: force the exact algorithm even when it exceeds
    /// the bitset budget (per-node BFS fallback - can be very slow on
    /// huge mostly-acyclic graphs).
    #[arg(long)]
    exact: bool,
    /// For --by impact: force the landmark-sampling approximation even
    /// on graphs where exact is affordable (for benchmarking).
    #[arg(long)]
    approx: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct OrderArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    /// Also print the longest dependency chain.
    #[arg(long)]
    critical_path: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct RootsArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct LeavesArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq, Debug)]
enum DiagramFmt {
    /// Graphviz DOT.
    Dot,
    /// Mermaid flowchart.
    Mermaid,
}

#[derive(Parser)]
struct ExportArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    /// Diagram syntax.
    #[arg(long, value_enum)]
    format: DiagramFmt,
    /// Seed nodes: export everything that depends on them (repeatable).
    #[arg(long)]
    impact: Vec<String>,
    /// Export the shortest chain FROM -> TO instead of an impact set.
    #[arg(long, num_args = 2, value_names = ["FROM", "TO"])]
    why: Option<Vec<String>>,
    /// Use edge weights for --why (Dijkstra).
    #[arg(long)]
    weighted: bool,
    /// Max hops for --impact (default: unlimited).
    #[arg(long)]
    depth: Option<u32>,
    /// Max edges drawn (default 1000).
    #[arg(long, default_value_t = 1000)]
    max_edges: usize,
    /// Write to file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Parser)]
struct CheckArgs {
    file: PathBuf,
    /// Rules file (default: ./strand.rules).
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Max violations to resolve a target node + chain for.
    #[arg(long, default_value_t = 10)]
    max_chains: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct CommonArgs {
    #[command(flatten)]
    conf: ConfidenceArgs,
    file: PathBuf,
    /// `deps` = shared dependencies, `impact` = shared impact set.
    mode: String,
    a: String,
    b: String,
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    // Rust ignores SIGPIPE, so `strand nodes big.strand | head` would
    // panic on EPIPE (exit 101). Restore default disposition so piped
    // output terminates silently like every other Unix tool.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let update_rx = update_check::spawn();
    let cli = Cli::parse();
    let code = match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("strand: {e}");
            ExitCode::FAILURE
        }
    };
    // The check runs on a thread; long commands already gave it time.
    // Short commands get a small grace period. stderr keeps stdout
    // machine-readable (--json, pipes).
    if let Ok(Some(updates)) = update_rx.recv_timeout(std::time::Duration::from_millis(900)) {
        print_update_box(&updates);
    }
    code
}

/// Boxed update notice drawn with `-` and `|` so it stands out in
/// terminal output without ANSI colors. Lists every strand crate on
/// crates.io that is newer than the version compiled into this binary.
fn print_update_box(updates: &[update_check::Update]) {
    let mut lines = vec!["Updates available:".to_string()];
    for u in updates {
        lines.push(format!("{}: {} -> {}", u.name, u.installed, u.latest));
    }
    lines.push(format!(
        "update: cargo install {} (libraries: cargo update)",
        env!("CARGO_PKG_NAME")
    ));
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let bar = "-".repeat(width + 2);
    eprintln!(" {bar}");
    for line in &lines {
        let pad = width - line.chars().count();
        eprintln!("| {line}{} |", " ".repeat(pad));
    }
    eprintln!(" {bar}");
}

fn run(cmd: Commands) -> strand_core::Result<()> {
    match cmd {
        Commands::Build(a) => cmd_build(a),
        Commands::Scan(a) => cmd_scan(a),
        Commands::Trace(a) => cmd_trace(a),
        Commands::Deep(a) => cmd_deep(a),
        Commands::Info(a) => cmd_info(a),
        Commands::Nodes(a) => cmd_nodes(a),
        Commands::Deps(a) => cmd_deps(a),
        Commands::Impact(a) => cmd_impact(a),
        Commands::Why(a) => cmd_why(a),
        Commands::Cycles(a) => cmd_cycles(a),
        Commands::Top(a) => cmd_top(a),
        Commands::Order(a) => cmd_order(a),
        Commands::Roots(a) => cmd_roots(a),
        Commands::Leaves(a) => cmd_leaves(a),
        Commands::Common(a) => cmd_common(a),
        Commands::Export(a) => cmd_export(a),
        Commands::Check(a) => cmd_check(a),
        Commands::Diff(a) => cmd_diff(a),
    }
}

// ---------- helpers ----------

fn open_graph(path: &PathBuf) -> strand_core::Result<Graph> {
    Graph::open(path)
}

fn node_id(graph: &Graph, name: &str) -> strand_core::Result<u32> {
    graph
        .node_id(name)
        .ok_or_else(|| strand_core::Error::NodeNotFound(name.to_string()))
}

fn names_of(graph: &Graph, ids: &[u32]) -> Vec<String> {
    ids.iter()
        .map(|&i| graph.node_name(i).to_string())
        .collect()
}

fn print_json(v: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}

// ---------- commands ----------

fn cmd_build(a: BuildArgs) -> strand_core::Result<()> {
    let mut b = GraphBuilder::new();
    b.set_merge(match a.merge {
        MergeChoice::Sum => MergeOp::Sum,
        MergeChoice::Max => MergeOp::Max,
    });
    for input in &a.inputs {
        let text = std::fs::read_to_string(input)?;
        let format = match a.format {
            InFormat::Auto => strand_import::detect_format(input, &text),
            InFormat::Csv => Format::Csv,
            InFormat::Cargo => Format::Cargo,
            InFormat::CargoLock => Format::CargoLock,
            InFormat::NpmLock => Format::NpmLock,
            InFormat::PoetryLock => Format::PoetryLock,
            InFormat::GoMod => Format::GoMod,
            InFormat::Pom => Format::Pom,
            InFormat::Webpack => Format::WebpackStats,
            InFormat::Esbuild => Format::EsbuildMeta,
        };
        let edges = strand_import::parse(&text, format)?;
        eprintln!("{}: {} edges", input.display(), edges.len());
        strand_import::fill_builder(edges, &mut b)?;
    }
    let stats = b.build(&a.output)?;
    eprintln!(
        "built {}: {} nodes, {} edges, {} bytes",
        stats.path.display(),
        stats.n_nodes,
        stats.n_edges,
        stats.bytes
    );
    Ok(())
}

fn cmd_scan(a: ScanArgs) -> strand_core::Result<()> {
    // A file argument scans its project root (nearest ancestor with a
    // manifest) so imports and entry points resolve with full context.
    let root = if a.dir.is_file() {
        scan_root_for(&a.dir)
    } else {
        a.dir.clone()
    };
    let out = a.output.unwrap_or_else(|| {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "scan".to_string());
        PathBuf::from(format!("{name}.strand"))
    });
    use strand_import::scan::Lang;
    let langs: Vec<Lang> = match a.lang {
        ScanLang::Rust => vec![Lang::Rust],
        ScanLang::Python => vec![Lang::Python],
        ScanLang::Js => vec![Lang::Js],
        ScanLang::Go => vec![Lang::Go],
        ScanLang::All => vec![Lang::Rust, Lang::Python, Lang::Js, Lang::Go],
    };
    let scan = strand_import::scan::scan_project(&root, &langs)?;
    for w in &scan.warnings {
        eprintln!("warning: {w}");
    }
    let mut edges = scan.edges;
    for input in &a.imports {
        let text = std::fs::read_to_string(input)?;
        let format = strand_import::detect_format(input, &text);
        let extra = strand_import::parse(&text, format)?;
        eprintln!("{}: {} imported edge(s)", input.display(), extra.len());
        edges.extend(extra);
    }
    let mut b = GraphBuilder::new();
    for n in &scan.nodes {
        b.add_node(n.clone());
    }
    strand_import::fill_builder(edges, &mut b)?;
    let stats = b.build(&out)?;
    eprintln!(
        "scanned {}: {} nodes, {} edges -> {}",
        root.display(),
        stats.n_nodes,
        stats.n_edges,
        stats.path.display()
    );
    Ok(())
}

fn cmd_trace(a: TraceArgs) -> strand_core::Result<()> {
    let root = if a.dir.is_file() {
        scan_root_for(&a.dir)
    } else {
        a.dir.clone()
    };
    let out = a.output.unwrap_or_else(|| {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "trace".to_string());
        PathBuf::from(format!("{name}.strand"))
    });
    use strand_import::scan::Lang;
    let scan = strand_import::scan::scan_project(
        &root,
        &[Lang::Rust, Lang::Python, Lang::Js, Lang::Go],
    )?;
    for w in &scan.warnings {
        eprintln!("warning: {w}");
    }

    // Run the command under the import tracer, then fold observed
    // edges into the static scan. Only .py-to-.py edges where both
    // endpoints are scanned nodes are kept.
    let flags = trace::isolation_flags(&a.cmd);
    if !flags.is_empty() {
        eprintln!(
            "warning: traced command uses {} - the import shim may not \
             load (sitecustomize is skipped), so traced edges may be empty",
            flags.join(" ")
        );
    }
    let traced = trace::traced_edges(&root, &a.cmd)?;
    let root_canon = root.canonicalize().unwrap_or_else(|_| root.clone());
    let root_norm = strip_verbatim(root_canon)
        .to_string_lossy()
        .replace('\\', "/");
    let root_prefix = format!("{root_norm}/");
    let to_rel = |p: &Path| -> Option<String> {
        let s = p.to_string_lossy().replace('\\', "/");
        let s = s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string();
        s.strip_prefix(&root_prefix)
            .filter(|r| r.ends_with(".py"))
            .map(|r| r.to_string())
    };

    let node_set: std::collections::BTreeSet<&str> =
        scan.nodes.iter().map(String::as_str).collect();
    // Existing edge kinds: a traced edge only adds information when no
    // equal-or-stronger edge already exists (the builder merges
    // duplicate pairs by max kind anyway).
    let kinds: BTreeMap<(String, String), EdgeKind> = scan
        .edges
        .iter()
        .map(|(s, d, _, k)| ((s.clone(), d.clone()), *k))
        .collect();
    let mut edges = scan.edges;
    let mut observed = 0usize;
    let mut added = 0usize;
    // Files the interpreter actually loaded (seen set plus both edge
    // endpoints - an importer that only re-exports still counts).
    let mut exercised: std::collections::BTreeSet<String> =
        traced.seen.iter().filter_map(|p| to_rel(p)).collect();
    for (imp, org) in &traced.edges {
        if let (Some(i), Some(o)) = (to_rel(imp), to_rel(org)) {
            exercised.insert(i);
            exercised.insert(o);
        }
    }
    for (imp, org) in traced.edges {
        let (Some(i), Some(o)) = (to_rel(&imp), to_rel(&org)) else {
            continue;
        };
        if !node_set.contains(i.as_str()) || !node_set.contains(o.as_str()) {
            continue;
        }
        observed += 1;
        let dominated = kinds
            .get(&(i.clone(), o.clone()))
            .is_some_and(|k| *k >= EdgeKind::Traced);
        if !dominated {
            added += 1;
            edges.push((i, o, None, EdgeKind::Traced));
        }
    }
    eprintln!("trace: {observed} runtime import edge(s) observed, {added} new");

    // Coverage report: scanned .py files the command never loaded are
    // the "dark" set - their edges (static or dynamic) are unverified
    // by this run. Listed so silent gaps stay visible.
    let py_nodes: Vec<&str> = scan
        .nodes
        .iter()
        .map(String::as_str)
        .filter(|n| n.ends_with(".py"))
        .collect();
    if !py_nodes.is_empty() {
        let dark: Vec<&&str> = py_nodes
            .iter()
            .filter(|n| !exercised.contains(**n))
            .collect();
        if dark.is_empty() {
            eprintln!(
                "trace coverage: all {} .py file(s) exercised",
                py_nodes.len()
            );
        } else {
            eprintln!(
                "trace coverage: {} of {} .py file(s) exercised; {} never loaded",
                py_nodes.len() - dark.len(),
                py_nodes.len(),
                dark.len()
            );
            for n in dark.iter().take(10) {
                eprintln!("  dark: {n}");
            }
            if dark.len() > 10 {
                eprintln!("  ... and {} more", dark.len() - 10);
            }
        }
    }

    let mut b = GraphBuilder::new();
    for n in &scan.nodes {
        b.add_node(n.clone());
    }
    strand_import::fill_builder(edges, &mut b)?;
    let stats = b.build(&out)?;
    eprintln!(
        "traced {}: {} nodes, {} edges -> {}",
        root.display(),
        stats.n_nodes,
        stats.n_edges,
        stats.path.display()
    );
    Ok(())
}

/// Project root for a file argument: nearest ancestor directory
/// containing a manifest (`pyproject.toml`, `Cargo.toml`, ...),
/// falling back to the file's parent directory. The user's home
/// directory is never accepted as a root - a stray `package.json`
/// there would otherwise scan the whole home tree.
fn scan_root_for(file: &Path) -> PathBuf {
    const MARKERS: &[&str] = &[
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Cargo.toml",
        "package.json",
        "go.mod",
        "pom.xml",
    ];
    let parent = file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let fallback = parent.to_path_buf();
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .and_then(|h| h.canonicalize().ok());
    let mut dir = parent.canonicalize().unwrap_or_else(|_| fallback.clone());
    // A member crate's Cargo.toml (no [workspace]) is only a fallback:
    // keep climbing so a workspace root or higher manifest wins.
    let mut cargo_candidate: Option<PathBuf> = None;
    loop {
        let is_home = home.as_ref().is_some_and(|h| dir == *h);
        if !is_home {
            let mut hit = dir.join(".git").exists();
            let mut cargo_only = false;
            if !hit {
                for m in MARKERS {
                    if dir.join(m).is_file() {
                        hit = true;
                        if *m == "Cargo.toml" {
                            let ws = std::fs::read_to_string(dir.join(m))
                                .map(|t| t.contains("[workspace]"))
                                .unwrap_or(false);
                            cargo_only = !ws;
                        }
                        break;
                    }
                }
            }
            if hit {
                if cargo_only {
                    if cargo_candidate.is_none() {
                        cargo_candidate = Some(strip_verbatim(dir.clone()));
                    }
                } else {
                    return strip_verbatim(dir);
                }
            }
        }
        match dir.parent() {
            Some(p) if p != dir => dir = p.to_path_buf(),
            _ => return cargo_candidate.unwrap_or(fallback),
        }
    }
}

/// `canonicalize` on Windows yields `\\?\`-prefixed paths; strip the
/// prefix so scanned-root display stays readable.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    match p.to_string_lossy().strip_prefix("\\\\?\\") {
        Some(s) => PathBuf::from(s),
        None => p,
    }
}

fn cmd_deep(a: DeepArgs) -> strand_core::Result<()> {
    use deep::{callgraph, ipa, models, solver};
    use strand_import::scan::{scan_project_with_py, Lang};

    let t0 = std::time::Instant::now();
    let root = strip_verbatim(a.dir.canonicalize()?);
    let out = a
        .output
        .unwrap_or_else(|| root.join(format!("{}.strand", root_name(&root))));

    // Phase 0: static scan; the returned trees are reused by IPA so
    // no file is parsed twice.
    let t_scan = std::time::Instant::now();
    let (scan, py_src) =
        scan_project_with_py(&root, &[Lang::Python, Lang::Js, Lang::Rust, Lang::Go])?;
    eprintln!(
        "scan: {} nodes, {} edges, {} warnings ({:.1?}; total {:.1?})",
        scan.nodes.len(),
        scan.edges.len(),
        scan.warnings.len(),
        t_scan.elapsed(),
        t0.elapsed()
    );
    for w in &scan.warnings {
        eprintln!("  warn: {w}");
    }

    let file_set: BTreeSet<String> = scan
        .nodes
        .iter()
        .filter(|n| n.ends_with(".py"))
        .cloned()
        .collect();
    let t_parse = std::time::Instant::now();
    let parsed = ipa::parse_all_sources(py_src);
    eprintln!(
        "parse_all: {} files ({:.1?}; total {:.1?})",
        parsed.len(),
        t_parse.elapsed(),
        t0.elapsed()
    );

    let t_cg = std::time::Instant::now();
    let cg = callgraph::build(&parsed);
    eprintln!(
        "callgraph: {} edges, {} calls - {:.1}% resolved ({:.1?})",
        cg.edges.len(),
        cg.stats.total,
        cg.stats.resolution_rate() * 100.0,
        t_cg.elapsed()
    );
    eprintln!("  [stage] total {:.1?}", t0.elapsed());
    if a.dump_callgraph {
        for ((cm, cf), (tm, tf)) in &cg.edges {
            println!("{cm}.{cf} -> {tm}.{tf}");
        }
    }

    // JS/TS files: parsed once here, shared by `--analyze` (JS
    // solver) and JS IPA below. JS trees aren't shared by the scan
    // (only Python trees are), so JS files parse on demand;
    // projects without JS pay nothing.
    let js_names: BTreeSet<String> = scan
        .nodes
        .iter()
        .filter(|n| {
            let l = n.to_lowercase();
            l.ends_with(".json")
                || strand_import::scan::JS_EXTS
                    .iter()
                    .any(|e| l.ends_with(&format!(".{e}")))
        })
        .cloned()
        .collect();
    // .json stays in js_names (IPA resolution target) but is not
    // parsed as JS - it is data, not a module.
    let js_files: Vec<(String, PathBuf)> = js_names
        .iter()
        .filter(|n| !n.to_lowercase().ends_with(".json"))
        .map(|n| (n.clone(), root.join(n)))
        .collect();
    let js_parsed: Vec<deep::js_ipa::JsFile> = deep::js_ipa::analyze_files(&js_files)
        .into_iter()
        .filter_map(|(_, f)| f)
        .collect();

    // Go files: parsed once here for the Go solver under --analyze.
    // Module prefixes (go.mod) discovered once for import resolution.
    let go_files: Vec<(String, PathBuf)> = scan
        .nodes
        .iter()
        .filter(|n| n.to_lowercase().ends_with(".go"))
        .map(|n| (n.clone(), root.join(n)))
        .collect();
    let (go_parsed, go_mods) = if go_files.is_empty() {
        (Vec::new(), None)
    } else {
        let mods = deep::go_deep::discover_modules(&root);
        let parsed = deep::go_deep::analyze_files(&go_files)
            .into_iter()
            .filter_map(|(_, f)| f)
            .collect();
        (parsed, Some(mods))
    };

    // Rust files: parsed once here for the Rust solver under
    // --analyze. Module identity is the file path; cross-file
    // resolution uses a module-suffix index.
    let rs_files: Vec<(String, PathBuf)> = scan
        .nodes
        .iter()
        .filter(|n| n.to_lowercase().ends_with(".rs"))
        .map(|n| (n.clone(), root.join(n)))
        .collect();
    let rs_parsed: Vec<deep::rust_deep::RsFile> =
        deep::rust_deep::analyze_files(&rs_files)
            .into_iter()
            .filter_map(|(_, f)| f)
            .collect();

    if a.analyze {
        let model = match &a.models {
            Some(dir) => {
                let models = models::load_dir(dir).map_err(strand_core::Error::Usage)?;
                models
                    .get("python")
                    .cloned()
                    .or_else(|| models::python_default().ok())
                    .ok_or_else(|| {
                        strand_core::Error::Usage("no python model".to_string())
                    })?
            }
            None => models::python_default()
                .map_err(strand_core::Error::Usage)?,
        };
        let t1 = std::time::Instant::now();
        let sol = solver::solve(&parsed, &model);
        eprintln!(
            "solve: {} functions, {} SCCs ({} cyclic), {} iters, {} findings ({:.1?})",
            sol.stats.functions,
            sol.stats.sccs,
            sol.stats.cyclic_sccs,
            sol.stats.fixpoint_iters,
            sol.stats.findings,
            t1.elapsed()
        );
        let unknown_funcs = sol
            .summaries
            .values()
            .filter(|s| s.touches_unknown)
            .count();
        eprintln!(
            "blind spots: {} functions touched unresolvable calls; {} param-flow sinks pending instantiation",
            unknown_funcs,
            sol.summaries
                .values()
                .map(|s| s.param_sinks.values().map(|v| v.len()).sum::<usize>())
                .sum::<usize>()
        );
        for f in &sol.findings {
            println!(
                "[{:?}] {}:{} {} - {} (via {}) [{:.0}%]",
                f.class,
                f.file,
                f.line,
                f.sink,
                f.source,
                f.via.join(" -> "),
                f.confidence * 100.0
            );
        }
        // Summaries are dead weight until process exit; skipping the
        // drop saves teardown time on large repos (deep_exit reclaims).
        std::mem::forget(sol);

        // JS/TS solver: same Summary engine over JsFiles with the
        // js.toml model. Skipped entirely for Python-only projects.
        if !js_parsed.is_empty() {
            let js_model = match &a.models {
                Some(dir) => {
                    let models = models::load_dir(dir)
                        .map_err(strand_core::Error::Usage)?;
                    models
                        .get("js")
                        .or_else(|| models.get("javascript"))
                        .cloned()
                        .or_else(|| models::js_default().ok())
                        .ok_or_else(|| {
                            strand_core::Error::Usage("no js model".to_string())
                        })?
                }
                None => models::js_default()
                    .map_err(strand_core::Error::Usage)?,
            };
            let t_js = std::time::Instant::now();
            let jsol = deep::solver_js::solve_js(&js_parsed, &js_names, &js_model);
            eprintln!(
                "js solve: {} functions, {} SCCs ({} cyclic), {} iters, {} findings ({:.1?})",
                jsol.stats.functions,
                jsol.stats.sccs,
                jsol.stats.cyclic_sccs,
                jsol.stats.fixpoint_iters,
                jsol.stats.findings,
                t_js.elapsed()
            );
            for f in &jsol.findings {
                println!(
                    "[{:?}] {}:{} {} - {} (via {}) [{:.0}%]",
                    f.class,
                    f.file,
                    f.line,
                    f.sink,
                    f.source,
                    f.via.join(" -> "),
                    f.confidence * 100.0
                );
            }
            std::mem::forget(jsol);
        }

        // Go solver: same Summary engine over GoFiles with the
        // go.toml model. Skipped entirely for non-Go projects.
        if !go_parsed.is_empty() {
            if let Some(mods) = &go_mods {
                let go_model = match &a.models {
                    Some(dir) => {
                        let models = models::load_dir(dir)
                            .map_err(strand_core::Error::Usage)?;
                        models
                            .get("go")
                            .cloned()
                            .or_else(|| models::go_default().ok())
                            .ok_or_else(|| {
                                strand_core::Error::Usage("no go model".to_string())
                            })?
                    }
                    None => models::go_default()
                        .map_err(strand_core::Error::Usage)?,
                };
                let t_go = std::time::Instant::now();
                let gosol =
                    deep::solver_go::solve_go(&go_parsed, mods, &go_model);
                eprintln!(
                    "go solve: {} functions, {} SCCs ({} cyclic), {} iters, {} findings ({:.1?})",
                    gosol.stats.functions,
                    gosol.stats.sccs,
                    gosol.stats.cyclic_sccs,
                    gosol.stats.fixpoint_iters,
                    gosol.stats.findings,
                    t_go.elapsed()
                );
                for f in &gosol.findings {
                    println!(
                        "[{:?}] {}:{} {} - {} (via {}) [{:.0}%]",
                        f.class,
                        f.file,
                        f.line,
                        f.sink,
                        f.source,
                        f.via.join(" -> "),
                        f.confidence * 100.0
                    );
                }
                std::mem::forget(gosol);
            }
        }

        // Rust solver: same Summary engine over RsFiles with the
        // rust.toml model. Skipped entirely for non-Rust projects.
        if !rs_parsed.is_empty() {
            let rs_model = match &a.models {
                Some(dir) => {
                    let models = models::load_dir(dir)
                        .map_err(strand_core::Error::Usage)?;
                    models
                        .get("rust")
                        .or_else(|| models.get("rs"))
                        .cloned()
                        .or_else(|| models::rust_default().ok())
                        .ok_or_else(|| {
                            strand_core::Error::Usage("no rust model".to_string())
                        })?
                }
                None => models::rust_default()
                    .map_err(strand_core::Error::Usage)?,
            };
            let t_rs = std::time::Instant::now();
            let rssol = deep::solver_rs::solve_rs(&rs_parsed, &rs_model);
            eprintln!(
                "rust solve: {} functions, {} SCCs ({} cyclic), {} iters, {} findings ({:.1?})",
                rssol.stats.functions,
                rssol.stats.sccs,
                rssol.stats.cyclic_sccs,
                rssol.stats.fixpoint_iters,
                rssol.stats.findings,
                t_rs.elapsed()
            );
            for f in &rssol.findings {
                println!(
                    "[{:?}] {}:{} {} - {} (via {}) [{:.0}%]",
                    f.class,
                    f.file,
                    f.line,
                    f.sink,
                    f.source,
                    f.via.join(" -> "),
                    f.confidence * 100.0
                );
            }
            std::mem::forget(rssol);
        }
    }

    let t_ipa = std::time::Instant::now();
    let mut res = ipa::analyze_parsed(&parsed, &file_set);

    // JS/TS dynamic import()/require() IPA reuses js_parsed (built
    // above for --analyze); projects without JS pay nothing.
    if !js_parsed.is_empty() {
        let t_js = std::time::Instant::now();
        let js_res = deep::js_ipa::analyze_js_parsed(&js_parsed, &js_names);
        eprintln!(
            "js ipa: {} edges, {} resolved, {} unresolved ({:.1?})",
            js_res.edges.len(),
            js_res.resolved,
            js_res.unresolved.len(),
            t_js.elapsed()
        );
        res.edges.extend(js_res.edges);
        res.unresolved.extend(js_res.unresolved);
        res.resolved += js_res.resolved;
    }
    eprintln!(
        "ipa: {} edges inferred, {} resolved, {} unresolved ({:.1?})",
        res.edges.len(),
        res.resolved,
        res.unresolved.len(),
        t_ipa.elapsed()
    );
    eprintln!("  [stage] total {:.1?}", t0.elapsed());
    for u in res.unresolved.iter().take(20) {
        eprintln!("  unresolved: {u}");
    }

    if a.ipa_only {
        for (s, d, k) in &res.edges {
            println!("{s} -> {d} [{k:?}]");
        }
        deep_exit(t0);
    }

    let mut b = GraphBuilder::new();
    for n in &scan.nodes {
        b.add_node(n.clone());
    }
    strand_import::fill_builder(scan.edges, &mut b)?;
    for (s, d, k) in &res.edges {
        b.add_edge_weighted_kind(s.clone(), d.clone(), 1.0, *k);
    }
    let stats = b.build(&out)?;
    eprintln!(
        "wrote {} ({} nodes, {} edges)",
        out.display(),
        stats.n_nodes,
        stats.n_edges
    );
    deep_exit(t0)
}

/// `strand deep` holds every Python file's syntax tree plus the full
/// call graph in memory; on large repos dropping them costs >1s and
/// the Windows heap serializes the frees anyway. All remaining
/// values are plain memory (trees, strings, vecs) with no files,
/// locks, or sockets open, so exiting directly lets the OS reclaim
/// it - stdout is line-buffered so output is already flushed.
fn deep_exit(t0: std::time::Instant) -> ! {
    eprintln!("  [stage] total {:.1?}", t0.elapsed());
    std::process::exit(0);
}

fn root_name(root: &Path) -> String {
    root.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "deep".to_string())
}

fn cmd_info(a: InfoArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let size = std::fs::metadata(&a.file).map(|m| m.len()).unwrap_or(0);
    if a.json {
        print_json(serde_json::json!({
            "file": a.file.display().to_string(),
            "n_nodes": g.n_nodes(),
            "n_edges": g.n_edges(),
            "has_weights": g.has_weights(),
            "size_bytes": size,
        }));
    } else {
        println!("file:        {}", a.file.display());
        println!("nodes:       {}", g.n_nodes());
        println!("edges:       {}", g.n_edges());
        println!("weighted:    {}", g.has_weights());
        println!("size:        {} bytes", size);
    }
    Ok(())
}

fn cmd_nodes(a: NodesArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    if a.json {
        let names: Vec<&str> = (0..g.n_nodes() as u32).map(|i| g.node_name(i)).collect();
        print_json(serde_json::json!({"nodes": names}));
    } else {
        for i in 0..g.n_nodes() as u32 {
            println!("{}", g.node_name(i));
        }
    }
    Ok(())
}

/// (node names, dependency edges as name pairs) for diffing.
/// `min` filters edges below the confidence threshold.
fn graph_snapshot(g: &Graph, min: u8) -> (BTreeSet<String>, BTreeSet<(String, String)>) {
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for i in 0..g.n_nodes() as u32 {
        let src = g.node_name(i).to_string();
        nodes.insert(src.clone());
        let kinds = g.out_kinds(i);
        for (j, &t) in g.out_targets(i).iter().enumerate() {
            let tag = kinds.and_then(|ks| ks.get(j).copied()).unwrap_or(4);
            if EdgeKind::from_tag(tag).confidence() >= min {
                edges.insert((src.clone(), g.node_name(t).to_string()));
            }
        }
    }
    (nodes, edges)
}

fn cmd_diff(a: DiffArgs) -> strand_core::Result<()> {
    let old = open_graph(&a.old)?;
    let new = open_graph(&a.new)?;
    let min = a.conf.min();
    let (on, oe) = graph_snapshot(&old, min);
    let (nn, ne) = graph_snapshot(&new, min);

    let added_nodes: Vec<&String> = nn.difference(&on).collect();
    let removed_nodes: Vec<&String> = on.difference(&nn).collect();
    let added_edges: Vec<&(String, String)> = ne.difference(&oe).collect();
    let removed_edges: Vec<&(String, String)> = oe.difference(&ne).collect();

    if a.json {
        print_json(serde_json::json!({
            "old": a.old.display().to_string(),
            "new": a.new.display().to_string(),
            "nodes_added": added_nodes,
            "nodes_removed": removed_nodes,
            "edges_added": added_edges,
            "edges_removed": removed_edges,
        }));
        return Ok(());
    }

    println!("{} -> {}", a.old.display(), a.new.display());
    println!(
        "nodes: +{} added, -{} removed",
        added_nodes.len(),
        removed_nodes.len()
    );
    println!(
        "edges: +{} added, -{} removed",
        added_edges.len(),
        removed_edges.len()
    );

    const CAP: usize = 100;
    let show = |title: &str, items: &[String]| {
        if items.is_empty() {
            return;
        }
        println!("{title}:");
        for it in items.iter().take(CAP) {
            println!("  {it}");
        }
        if items.len() > CAP {
            println!("  ... and {} more", items.len() - CAP);
        }
    };
    show(
        "added nodes",
        &added_nodes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );
    show(
        "removed nodes",
        &removed_nodes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );
    show(
        "added edges",
        &added_edges
            .iter()
            .map(|(s, d)| format!("{s} -> {d}"))
            .collect::<Vec<_>>(),
    );
    show(
        "removed edges",
        &removed_edges
            .iter()
            .map(|(s, d)| format!("{s} -> {d}"))
            .collect::<Vec<_>>(),
    );
    Ok(())
}

fn cmd_deps(a: DepsArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    let id = node_id(&g, &a.node)?;
    let depths = algo::bfs(&gv, &[id], Dir::Out, a.depth);

    // Collect reached nodes sorted by (depth, name).
    let mut rows: Vec<(u32, u32)> = depths
        .iter()
        .enumerate()
        .filter(|&(_, &d)| d != algo::UNVISITED && d != 0)
        .map(|(i, &d)| (i as u32, d))
        .collect();
    rows.sort_by(|x, y| {
        x.1.cmp(&y.1)
            .then_with(|| g.node_name(x.0).cmp(g.node_name(y.0)))
    });

    if a.json {
        let deps: Vec<serde_json::Value> = rows
            .iter()
            .map(|&(id, d)| serde_json::json!({"name": g.node_name(id), "depth": d}))
            .collect();
        print_json(serde_json::json!({
            "node": a.node,
            "dependencies": deps,
            "count": deps.len(),
        }));
    } else {
        println!("dependencies of {}:", a.node);
        for (id, d) in &rows {
            println!("  depth {:>3}  {}", d, g.node_name(*id));
        }
        println!("{} transitive dependencies", rows.len());
    }
    Ok(())
}

fn cmd_impact(a: ImpactArgs) -> strand_core::Result<()> {
    if a.nodes.is_empty() && a.git_diff.is_none() {
        return Err(strand_core::Error::Usage(
            "impact requires at least one node or --git-diff".into(),
        ));
    }
    let g = open_graph(&a.file)?;

    // Seed names: positional nodes plus any resolved from --git-diff.
    let mut seed_names: Vec<String> = a.nodes.clone();
    if let Some(reference) = &a.git_diff {
        let git_dir = a.git_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        let (matched, unmatched) = git_diff_seeds(&g, &git_dir, reference)?;
        let no_git_matches = matched.is_empty() && a.nodes.is_empty();
        seed_names.extend(matched);
        seed_names.sort();
        seed_names.dedup();
        if !unmatched.is_empty() {
            eprintln!(
                "warning: {} changed file(s) matched no graph node: {}",
                unmatched.len(),
                unmatched[..unmatched.len().min(10)].join(", ")
            );
        }
        if no_git_matches {
            return Err(strand_core::Error::Usage(format!(
                "no graph nodes matched files changed vs {reference}"
            )));
        }
    }
    if seed_names.is_empty() {
        return Err(strand_core::Error::Usage(
            "impact requires at least one node or --git-diff".into(),
        ));
    }

    let seeds: Vec<u32> = seed_names
        .iter()
        .map(|n| node_id(&g, n))
        .collect::<strand_core::Result<_>>()?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    let depths = algo::bfs(&gv, &seeds, Dir::In, a.depth);
    let counts = algo::depth_counts(&depths);

    // Kind filter applies to reported nodes (seeds always count as depth 0).
    let kind_ok = |id: u32| -> bool {
        match &a.kind {
            Some(k) => g.node_kind(id) == Some(k.as_str()),
            None => true,
        }
    };

    let affected: Vec<(u32, u32)> = depths
        .iter()
        .enumerate()
        .filter(|&(i, &d)| d != algo::UNVISITED && d != 0 && kind_ok(i as u32))
        .map(|(i, &d)| (i as u32, d))
        .collect();
    let direct = affected.iter().filter(|&&(_, d)| d == 1).count();
    let transitive = affected.len() - direct;

    if a.json {
        let by_depth: BTreeMap<String, Vec<String>> = {
            let mut m: BTreeMap<u32, Vec<String>> = BTreeMap::new();
            for &(id, d) in &affected {
                m.entry(d).or_default().push(g.node_name(id).to_string());
            }
            m.into_iter().map(|(d, v)| (d.to_string(), v)).collect()
        };
        print_json(serde_json::json!({
            "seeds": seed_names,
            "total_affected": affected.len(),
            "direct": direct,
            "transitive": transitive,
            "by_depth": by_depth,
        }));
    } else {
        println!(
            "impact of [{}]: {} affected ({} direct, {} transitive)",
            seed_names.join(", "),
            affected.len(),
            direct,
            transitive
        );
        if a.by_depth {
            let mut by_d: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
            for &(id, d) in &affected {
                by_d.entry(d).or_default().push(id);
            }
            for (d, ids) in by_d {
                let mut names = names_of(&g, &ids);
                names.sort();
                println!("  depth {d} ({}):", ids.len());
                for n in names {
                    println!("    {n}");
                }
            }
        } else {
            let mut names: Vec<String> = affected
                .iter()
                .map(|&(id, _)| g.node_name(id).to_string())
                .collect();
            names.sort();
            for n in names.iter().take(200) {
                println!("  {n}");
            }
            if names.len() > 200 {
                println!("  ... and {} more", names.len() - 200);
            }
        }
        let _ = counts;
    }
    if let Some(max) = a.max_impact {
        if affected.len() > max {
            return Err(strand_core::Error::Usage(format!(
                "impact of {} node(s) = {}; exceeds --max-impact {}",
                seed_names.len(),
                affected.len(),
                max
            )));
        }
    }
    Ok(())
}

/// Map files changed vs a git ref onto graph node names.
///
/// Per changed file, tries in order:
/// 1. exact path match (scan graphs rooted at the repo root),
/// 2. directory-segment match (package graphs: `crates/foo/src/lib.rs`
///    matches node `foo`),
/// 3. path-suffix match (scan graphs rooted below the repo root:
///    `crates/app/src/lib.rs` matches node `src/lib.rs`).
///
/// Returns (matched node names, unmatched file paths).
fn git_diff_seeds(
    g: &Graph,
    git_dir: &Path,
    reference: &str,
) -> strand_core::Result<(Vec<String>, Vec<String>)> {
    use std::process::Command;

    let git = |dir: &Path, args: &[&str]| -> strand_core::Result<String> {
        let out = Command::new("git").arg("-C").arg(dir).args(args).output()?;
        if !out.status.success() {
            return Err(strand_core::Error::Usage(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };

    // Resolve the repo root so diff paths are repo-root-relative.
    let root = PathBuf::from(git(git_dir, &["rev-parse", "--show-toplevel"])?.trim());
    let diff = git(&root, &["diff", "--name-only", reference])?;
    let files: Vec<String> = diff
        .lines()
        .map(|l| l.trim().replace('\\', "/"))
        .filter(|l| !l.is_empty())
        .collect();

    // Index all node names for exact/segment lookup.
    let mut by_name: std::collections::HashMap<&str, u32> =
        std::collections::HashMap::with_capacity(g.n_nodes() as usize);
    for id in 0..g.n_nodes() as u32 {
        by_name.insert(g.node_name(id), id);
    }
    // Lazily built basename -> ids index for path-node suffix matching.
    let mut by_base: Option<std::collections::HashMap<String, Vec<u32>>> = None;

    let mut matched: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut unmatched: Vec<String> = Vec::new();

    for file in &files {
        let f = file.trim_start_matches("./");
        let mut hits: Vec<u32> = Vec::new();

        // 1. exact path match.
        if let Some(&id) = by_name.get(f) {
            hits.push(id);
        }
        // 2. directory-segment match (package/dir names).
        if let Some((dirs, _)) = f.rsplit_once('/') {
            for seg in dirs.split('/') {
                if let Some(&id) = by_name.get(seg) {
                    hits.push(id);
                }
            }
        }
        // 3. path-suffix match for nodes containing '/'.
        if hits.is_empty() {
            let base = f.rsplit('/').next().unwrap_or(f);
            let idx = by_base.get_or_insert_with(|| {
                let mut m: std::collections::HashMap<String, Vec<u32>> =
                    std::collections::HashMap::new();
                for id in 0..g.n_nodes() as u32 {
                    let name = g.node_name(id);
                    if name.contains('/') {
                        let b = name.rsplit('/').next().unwrap_or(name);
                        m.entry(b.to_string()).or_default().push(id);
                    }
                }
                m
            });
            if let Some(ids) = idx.get(base) {
                for &id in ids {
                    let name = g.node_name(id);
                    if f == name || f.ends_with(&format!("/{name}")) {
                        hits.push(id);
                    }
                }
            }
        }

        if hits.is_empty() {
            unmatched.push(file.clone());
        } else {
            for id in hits {
                matched.insert(g.node_name(id).to_string());
            }
        }
    }

    Ok((matched.into_iter().collect(), unmatched))
}

fn cmd_why(a: WhyArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let from = node_id(&g, &a.from)?;
    let to = node_id(&g, &a.to)?;

    if a.all_paths && a.weighted {
        return Err(strand_core::Error::Usage(
            "--all-paths and --weighted cannot be combined".into(),
        ));
    }
    if a.max_depth.is_some() && !a.all_paths {
        return Err(strand_core::Error::Usage(
            "--max-depth requires --all-paths".into(),
        ));
    }

    if a.weighted {
        return match algo::shortest_path_weighted_csr_min(&g, from, to, a.conf.min()) {
            Some((path, cost)) => {
                let names = names_of(&g, &path);
                if a.json {
                    print_json(serde_json::json!({
                        "from": a.from, "to": a.to, "path": names,
                        "cost": cost, "hops": path.len() - 1,
                    }));
                } else {
                    println!("{} (cost {:.4})", names.join(" -> "), cost);
                }
                Ok(())
            }
            None => {
                if a.json {
                    print_json(serde_json::json!({
                        "from": a.from, "to": a.to, "path": null,
                    }));
                } else {
                    println!("no dependency chain from {} to {}", a.from, a.to);
                }
                Ok(())
            }
        };
    }

    let gv = ConfidenceView::new(&g, a.conf.min());
    if a.all_paths {
        let res = match a.max_depth {
            Some(d) => algo::paths_within_depth(&gv, from, to, d, a.limit),
            None => algo::k_shortest_paths(&gv, from, to, a.limit),
        };
        let paths = &res.paths;
        if a.json {
            let ps: Vec<Vec<String>> = paths.iter().map(|p| names_of(&g, p)).collect();
            print_json(serde_json::json!({
                "from": a.from, "to": a.to, "paths": ps,
                "truncated": res.truncated,
            }));
        } else if paths.is_empty() {
            println!("no dependency chain from {} to {}", a.from, a.to);
        } else {
            for (i, p) in paths.iter().enumerate() {
                let names = names_of(&g, p);
                println!("path {}: {}", i + 1, names.join(" -> "));
            }
            if res.truncated {
                println!("(truncated: more chains exist; raise --limit or --max-depth)");
            }
        }
        return Ok(());
    }

    match algo::shortest_path(&gv, from, to) {
        Some(path) => {
            let names = names_of(&g, &path);
            if a.json {
                print_json(serde_json::json!({
                    "from": a.from, "to": a.to, "path": names, "length": path.len() - 1,
                }));
            } else {
                println!("{}", names.join(" -> "));
            }
        }
        None => {
            if a.json {
                print_json(serde_json::json!({
                    "from": a.from, "to": a.to, "path": null,
                }));
            } else {
                println!("no dependency chain from {} to {}", a.from, a.to);
            }
        }
    }
    Ok(())
}

fn cmd_cycles(a: CyclesArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    let sccs = algo::strongly_connected(&gv);
    // Cycles = SCCs with >1 member, or a single node with a self-loop.
    let cycles: Vec<&Vec<u32>> = sccs
        .iter()
        .filter(|c| c.len() > 1 || g.out_targets(c[0]).contains(&c[0]))
        .collect();

    if a.json {
        let cs: Vec<Vec<String>> = cycles.iter().map(|c| names_of(&g, c)).collect();
        print_json(serde_json::json!({"cycles": cs, "count": cs.len()}));
    } else if cycles.is_empty() {
        println!("no cycles");
    } else {
        println!("{} cycle(s):", cycles.len());
        for c in &cycles {
            let names = names_of(&g, c);
            println!("  {}", names.join(", "));
        }
    }
    Ok(())
}

/// Exact impact scores as `f64` (`--exact` path; may be very slow on
/// huge mostly-acyclic graphs).
fn scores_from_exact<G: GraphView>(g: &G) -> Vec<f64> {
    algo::impact_sizes(g)
        .into_iter()
        .map(|x| x as f64)
        .collect()
}

fn cmd_top(a: TopArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    let n = g.n_nodes() as usize;
    let mut impact_approx = false;
    let mut impact_samples = 0usize;
    let mut scores: Vec<f64> = match a.by {
        TopBy::InDegree => (0..n as u32).map(|i| gv.in_degree(i) as f64).collect(),
        TopBy::Impact => {
            if a.exact {
                scores_from_exact(&gv)
            } else if a.approx {
                let (v, k) = algo::impact_sizes_force_approx(&gv, a.samples);
                impact_approx = true;
                impact_samples = k;
                v
            } else {
                let (v, m, k) = algo::impact_sizes_auto_with(&gv, a.samples);
                impact_approx = m == algo::ImpactMethod::Approx;
                impact_samples = k;
                v
            }
        }
        // PageRank on the dependency graph: rank flows dependent ->
        // dependency, so heavily-depended-upon nodes score highest.
        TopBy::Pagerank => algo::pagerank(&gv, false, 1e-8, 100),
    };
    // Approximate impact: rerank the top candidates exactly so printed
    // numbers are exact counts, not estimates. The rerank budget scales
    // with graph size (~2G edge visits, same as sampling).
    let mut reranked_ids: Vec<u32> = Vec::new();
    if impact_approx {
        let want = (a.count.saturating_mul(4)).clamp(32, 512).min(n);
        let e = g.n_edges().max(1) as u64;
        let cap = ((2_000_000_000u64 / e) as usize).clamp(want, 8192).min(n);
        reranked_ids = algo::rerank_impact_exact(&gv, &mut scores, want, cap);
    }
    let reranked = reranked_ids.len();
    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_by(|&x, &y| {
        scores[y as usize]
            .partial_cmp(&scores[x as usize])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| g.node_name(x).cmp(g.node_name(y)))
    });
    order.truncate(a.count);

    let reranked_set: std::collections::BTreeSet<u32> = reranked_ids.iter().copied().collect();
    if a.json {
        let rows: Vec<serde_json::Value> = order
            .iter()
            .map(|&i| {
                let mut row = serde_json::json!({
                    "name": g.node_name(i),
                    "value": scores[i as usize],
                });
                if impact_approx {
                    row["exact"] = serde_json::json!(reranked_set.contains(&i));
                }
                row
            })
            .collect();
        let mut obj = serde_json::json!({
            "by": format!("{:?}", a.by).to_lowercase(),
            "method": if impact_approx { "approx" } else { "exact" },
            "nodes": rows,
        });
        if impact_approx {
            obj["samples"] = serde_json::json!(impact_samples);
            obj["reranked_exact"] = serde_json::json!(reranked);
        }
        print_json(obj);
    } else {
        let label = if impact_approx {
            format!(
                " (approximate: {} landmarks; top {} reranked exactly)",
                impact_samples, reranked
            )
        } else {
            String::new()
        };
        println!("top {} by {:?}{}:", a.count, a.by, label);
        for &i in &order {
            let exact_mark = if impact_approx && !reranked_set.contains(&i) {
                " ~"
            } else {
                ""
            };
            println!(
                "  {:>12}{}  {}",
                fmt_score(scores[i as usize]),
                exact_mark,
                g.node_name(i)
            );
        }
    }
    Ok(())
}

/// Whole-number scores print without decimals (`16`, not `16.0000`).
fn fmt_score(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 9e15 {
        format!("{}", v as i64)
    } else {
        format!("{v:.4}")
    }
}

fn cmd_order(a: OrderArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    let bo = algo::analyze(&gv);

    if a.json {
        let comps: Vec<serde_json::Value> = bo
            .sccs
            .iter()
            .map(|c| serde_json::json!({"members": names_of(&g, c)}))
            .collect();
        let mut out = serde_json::json!({
            "n_components": bo.sccs.len(),
            "order": comps,
        });
        if a.critical_path {
            out["critical_path"] = serde_json::json!({
                "length": bo.critical_len,
                "nodes": names_of(&g, &bo.critical_path),
            });
        }
        print_json(out);
    } else {
        println!("{} component(s), dependencies first:", bo.sccs.len());
        for (i, c) in bo.sccs.iter().enumerate() {
            let names = names_of(&g, c);
            if names.len() == 1 {
                println!("  {:>4}. {}", i + 1, names[0]);
            } else {
                println!("  {:>4}. {{{}}}", i + 1, names.join(", "));
            }
        }
        if a.critical_path {
            let names = names_of(&g, &bo.critical_path);
            println!("critical path length: {} nodes", bo.critical_len);
            println!("{}", names.join(" -> "));
        }
    }
    Ok(())
}

fn cmd_roots(a: RootsArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    // "Nothing depends on X" => no dependents => in_targets empty.
    let roots: Vec<u32> = (0..g.n_nodes() as u32)
        .filter(|&i| gv.in_degree(i) == 0)
        .collect();
    emit_name_list(&g, &roots, "roots", a.json);
    Ok(())
}

fn cmd_leaves(a: LeavesArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    // "X depends on nothing" => no dependencies => out_targets empty.
    let leaves: Vec<u32> = (0..g.n_nodes() as u32)
        .filter(|&i| gv.out_degree(i) == 0)
        .collect();
    emit_name_list(&g, &leaves, "leaves", a.json);
    Ok(())
}

fn emit_name_list(g: &Graph, ids: &[u32], label: &str, json: bool) {
    if json {
        print_json(serde_json::json!({
            label: names_of(g, ids),
            "count": ids.len(),
        }));
    } else {
        println!("{} ({}):", label, ids.len());
        let mut names = names_of(g, ids);
        names.sort();
        for n in names {
            println!("  {n}");
        }
    }
}

fn cmd_common(a: CommonArgs) -> strand_core::Result<()> {
    let dir = match a.mode.as_str() {
        "deps" => Dir::Out,
        "impact" => Dir::In,
        other => {
            return Err(strand_core::Error::Usage(format!(
                "common mode must be 'deps' or 'impact', got '{other}'"
            )))
        }
    };
    let g = open_graph(&a.file)?;
    let gv = ConfidenceView::new(&g, a.conf.min());
    let ia = node_id(&g, &a.a)?;
    let ib = node_id(&g, &a.b)?;
    let common = algo::common(&gv, ia, ib, dir);
    if a.json {
        print_json(serde_json::json!({
            "mode": a.mode, "a": a.a, "b": a.b,
            "common": names_of(&g, &common), "count": common.len(),
        }));
    } else {
        let mut names = names_of(&g, &common);
        names.sort();
        println!(
            "common {} of {} and {} ({}):",
            a.mode,
            a.a,
            a.b,
            names.len()
        );
        for n in names {
            println!("  {n}");
        }
    }
    Ok(())
}

fn cmd_export(a: ExportArgs) -> strand_core::Result<()> {
    if a.impact.is_empty() && a.why.is_none() {
        return Err(strand_core::Error::Usage(
            "export requires --impact or --why".into(),
        ));
    }
    if !a.impact.is_empty() && a.why.is_some() {
        return Err(strand_core::Error::Usage(
            "--impact and --why are mutually exclusive".into(),
        ));
    }
    let g = open_graph(&a.file)?;
    let fmt = match a.format {
        DiagramFmt::Dot => export::Diagram::Dot,
        DiagramFmt::Mermaid => export::Diagram::Mermaid,
    };

    let (nodes, edges, truncated) = if let Some(w) = &a.why {
        let from = node_id(&g, &w[0])?;
        let to = node_id(&g, &w[1])?;
        let path = if a.weighted {
            algo::shortest_path_weighted_csr_min(&g, from, to, a.conf.min()).map(|(p, _)| p)
        } else {
            algo::shortest_path(&ConfidenceView::new(&g, a.conf.min()), from, to)
        };
        let Some(path) = path else {
            return Err(strand_core::Error::Usage(format!(
                "no dependency chain from {} to {}",
                w[0], w[1]
            )));
        };
        let nodes: std::collections::BTreeSet<u32> = path.iter().copied().collect();
        let edges: Vec<(u32, u32)> = path.windows(2).map(|w| (w[0], w[1])).collect();
        (nodes, edges, false)
    } else {
        let seeds: Vec<u32> = a
            .impact
            .iter()
            .map(|n| node_id(&g, n))
            .collect::<strand_core::Result<_>>()?;
        let depths = algo::bfs(
            &ConfidenceView::new(&g, a.conf.min()),
            &seeds,
            Dir::In,
            a.depth,
        );
        let nodes: std::collections::BTreeSet<u32> = depths
            .iter()
            .enumerate()
            .filter(|&(_, &d)| d != algo::UNVISITED)
            .map(|(i, _)| i as u32)
            .collect();
        let (edges, truncated) = export::edges_within(&g, &nodes, a.max_edges, a.conf.min());
        (nodes, edges, truncated)
    };

    let text = export::render(&g, fmt, &nodes, &edges, truncated);
    match &a.output {
        Some(p) => {
            std::fs::write(p, &text)?;
            eprintln!("wrote {}", p.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

fn cmd_check(a: CheckArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let rules = check::load_rules(a.rules.as_deref(), Path::new("."))?;
    let results = check::check(&g, &rules, a.max_chains);
    let total: usize = results.iter().map(|v| v.len()).sum();

    if a.json {
        let rules_json: Vec<serde_json::Value> = rules
            .iter()
            .zip(&results)
            .map(|(r, viols)| {
                serde_json::json!({
                    "rule": format!("forbid {} -> {}", r.forbid, r.ban),
                    "violations": viols.iter().map(|v| {
                        let mut o = serde_json::json!({"node": g.node_name(v.a)});
                        if let Some(b) = v.b {
                            o["target"] = serde_json::json!(g.node_name(b));
                        }
                        if let Some(c) = &v.chain {
                            o["chain"] = serde_json::json!(names_of(&g, c));
                        }
                        o
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        print_json(serde_json::json!({
            "rules": rules.len(),
            "violations": total,
            "results": rules_json,
        }));
    } else {
        println!(
            "strand check: {} rule(s), {} violation(s)",
            rules.len(),
            total
        );
        for (r, viols) in rules.iter().zip(&results) {
            if viols.is_empty() {
                continue;
            }
            println!(
                "rule `forbid {} -> {}`: {} violation(s)",
                r.forbid,
                r.ban,
                viols.len()
            );
            for v in viols {
                if let Some(chain) = &v.chain {
                    let names = names_of(&g, chain);
                    println!("  {}", names.join(" -> "));
                } else {
                    println!(
                        "  {} (transitively depends on `{}`)",
                        g.node_name(v.a),
                        r.ban
                    );
                }
            }
        }
    }

    if total > 0 {
        return Err(strand_core::Error::Usage(format!(
            "{total} architecture rule violation(s)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn update_box_renders() {
        super::print_update_box(&[
            super::update_check::Update {
                name: "strand-cli".into(),
                installed: "0.3.0".into(),
                latest: "9.9.9".into(),
            },
            super::update_check::Update {
                name: "strand-store".into(),
                installed: "0.2.1".into(),
                latest: "0.2.2".into(),
            },
        ]);
    }
}
