//! `strand` — dependency and impact analysis on memory-mapped CSR graphs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use strand_core::algo::{self, Dir};
use strand_core::{Graph, GraphBuilder, MergeOp};
use strand_import::{self, Format};

mod check;
mod export;

#[derive(Parser)]
#[command(
    name = "strand",
    version,
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
    /// Show graph statistics.
    Info(InfoArgs),
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
    /// All supported languages merged (default).
    All,
}

#[derive(Parser)]
struct ScanArgs {
    /// Project directory to scan for source files.
    dir: PathBuf,
    /// Output .strand file (default: <dir-name>.strand).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Language(s) to scan (default: all).
    #[arg(long, value_enum, default_value_t = ScanLang::All)]
    lang: ScanLang,
}

#[derive(Parser)]
struct InfoArgs {
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct DepsArgs {
    file: PathBuf,
    node: String,
    #[arg(long)]
    depth: Option<u32>,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ImpactArgs {
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
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct TopArgs {
    file: PathBuf,
    #[arg(long, value_enum)]
    by: TopBy,
    #[arg(short = 'n', long, default_value_t = 20)]
    count: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct OrderArgs {
    file: PathBuf,
    /// Also print the longest dependency chain.
    #[arg(long)]
    critical_path: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct RootsArgs {
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct LeavesArgs {
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
    file: PathBuf,
    /// `deps` = shared dependencies, `impact` = shared impact set.
    mode: String,
    a: String,
    b: String,
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("strand: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cmd: Commands) -> strand_core::Result<()> {
    match cmd {
        Commands::Build(a) => cmd_build(a),
        Commands::Scan(a) => cmd_scan(a),
        Commands::Info(a) => cmd_info(a),
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
    ids.iter().map(|&i| graph.node_name(i).to_string()).collect()
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
    let out = a.output.unwrap_or_else(|| {
        let name = a
            .dir
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
        ScanLang::All => vec![Lang::Rust, Lang::Python, Lang::Js],
    };
    let scan = strand_import::scan::scan_project(&a.dir, &langs)?;
    let mut b = GraphBuilder::new();
    for n in &scan.nodes {
        b.add_node(n.clone());
    }
    strand_import::fill_builder(scan.edges, &mut b)?;
    let stats = b.build(&out)?;
    eprintln!(
        "scanned {}: {} nodes, {} edges -> {}",
        a.dir.display(),
        stats.n_nodes,
        stats.n_edges,
        stats.path.display()
    );
    Ok(())
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

fn cmd_deps(a: DepsArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let id = node_id(&g, &a.node)?;
    let depths = algo::bfs(&g, &[id], Dir::Out, a.depth);

    // Collect reached nodes sorted by (depth, name).
    let mut rows: Vec<(u32, u32)> = depths
        .iter()
        .enumerate()
        .filter(|&(_, &d)| d != algo::UNVISITED && d != 0)
        .map(|(i, &d)| (i as u32, d))
        .collect();
    rows.sort_by(|x, y| x.1.cmp(&y.1).then_with(|| g.node_name(x.0).cmp(g.node_name(y.0))));

    if a.json {
        let deps: Vec<serde_json::Value> = rows
            .iter()
            .map(|&(id, d)| {
                serde_json::json!({"name": g.node_name(id), "depth": d})
            })
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
    let depths = algo::bfs(&g, &seeds, Dir::In, a.depth);
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
            m.into_iter()
                .map(|(d, v)| (d.to_string(), v))
                .collect()
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
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()?;
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

    let mut matched: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
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
        return match algo::shortest_path_weighted_csr(&g, from, to) {
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

    if a.all_paths {
        let res = match a.max_depth {
            Some(d) => algo::paths_within_depth(&g, from, to, d, a.limit),
            None => algo::k_shortest_paths(&g, from, to, a.limit),
        };
        let paths = &res.paths;
        if a.json {
            let ps: Vec<Vec<String>> = paths
                .iter()
                .map(|p| names_of(&g, p))
                .collect();
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

    match algo::shortest_path(&g, from, to) {
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
    let sccs = algo::strongly_connected(&g);
    // Cycles = SCCs with >1 member, or a single node with a self-loop.
    let cycles: Vec<&Vec<u32>> = sccs
        .iter()
        .filter(|c| {
            c.len() > 1 || g.out_targets(c[0]).contains(&c[0])
        })
        .collect();

    if a.json {
        let cs: Vec<Vec<String>> = cycles
            .iter()
            .map(|c| names_of(&g, c))
            .collect();
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

fn cmd_top(a: TopArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let n = g.n_nodes() as usize;
    let mut impact_approx = false;
    let scores: Vec<f64> = match a.by {
        TopBy::InDegree => (0..n as u32).map(|i| g.in_degree(i) as f64).collect(),
        TopBy::Impact => {
            let (v, m) = algo::impact_sizes_auto(&g);
            impact_approx = m == algo::ImpactMethod::Approx;
            v
        }
        // PageRank on the dependency graph: rank flows dependent ->
        // dependency, so heavily-depended-upon nodes score highest.
        TopBy::Pagerank => algo::pagerank(&g, false, 1e-8, 100),
    };
    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_by(|&x, &y| {
        scores[y as usize]
            .partial_cmp(&scores[x as usize])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| g.node_name(x).cmp(g.node_name(y)))
    });
    order.truncate(a.count);

    if a.json {
        let rows: Vec<serde_json::Value> = order
            .iter()
            .map(|&i| {
                serde_json::json!({
                    "name": g.node_name(i),
                    "value": scores[i as usize],
                })
            })
            .collect();
        print_json(serde_json::json!({
            "by": format!("{:?}", a.by).to_lowercase(),
            "method": if impact_approx { "approx" } else { "exact" },
            "nodes": rows,
        }));
    } else {
        println!(
            "top {} by {:?}{}:",
            a.count,
            a.by,
            if impact_approx {
                " (approximate: landmark sampling)"
            } else {
                ""
            }
        );
        for &i in &order {
            println!("  {:>12.4}  {}", scores[i as usize], g.node_name(i));
        }
    }
    Ok(())
}

fn cmd_order(a: OrderArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    let bo = algo::analyze(&g);

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
    // "Nothing depends on X" => no dependents => in_targets empty.
    let roots: Vec<u32> = (0..g.n_nodes() as u32)
        .filter(|&i| g.in_degree(i) == 0)
        .collect();
    emit_name_list(&g, &roots, "roots", a.json);
    Ok(())
}

fn cmd_leaves(a: LeavesArgs) -> strand_core::Result<()> {
    let g = open_graph(&a.file)?;
    // "X depends on nothing" => no dependencies => out_targets empty.
    let leaves: Vec<u32> = (0..g.n_nodes() as u32)
        .filter(|&i| g.out_degree(i) == 0)
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
    let ia = node_id(&g, &a.a)?;
    let ib = node_id(&g, &a.b)?;
    let common = algo::common(&g, ia, ib, dir);
    if a.json {
        print_json(serde_json::json!({
            "mode": a.mode, "a": a.a, "b": a.b,
            "common": names_of(&g, &common), "count": common.len(),
        }));
    } else {
        let mut names = names_of(&g, &common);
        names.sort();
        println!("common {} of {} and {} ({}):", a.mode, a.a, a.b, names.len());
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
            algo::shortest_path_weighted_csr(&g, from, to).map(|(p, _)| p)
        } else {
            algo::shortest_path(&g, from, to)
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
        let depths = algo::bfs(&g, &seeds, Dir::In, a.depth);
        let nodes: std::collections::BTreeSet<u32> = depths
            .iter()
            .enumerate()
            .filter(|&(_, &d)| d != algo::UNVISITED)
            .map(|(i, _)| i as u32)
            .collect();
        let (edges, truncated) = export::edges_within(&g, &nodes, a.max_edges);
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
        println!("strand check: {} rule(s), {} violation(s)", rules.len(), total);
        for (r, viols) in rules.iter().zip(&results) {
            if viols.is_empty() {
                continue;
            }
            println!("rule `forbid {} -> {}`: {} violation(s)", r.forbid, r.ban, viols.len());
            for v in viols {
                if let Some(chain) = &v.chain {
                    let names = names_of(&g, chain);
                    println!("  {}", names.join(" -> "));
                } else {
                    println!("  {} (transitively depends on `{}`)", g.node_name(v.a), r.ban);
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
