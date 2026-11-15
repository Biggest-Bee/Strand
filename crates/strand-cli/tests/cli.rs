//! End-to-end CLI smoke tests using the built `strand` binary.

use std::process::Command;

fn strand() -> Command {
    Command::new(env!("CARGO_BIN_EXE_strand"))
}

fn write_csv(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let p = dir.path().join("deps.csv");
    std::fs::write(
        &p,
        "app,liba\napp,libb\nliba,core\nlibb,core\ncore,util\ntool,liba\n",
    )
    .unwrap();
    p
}

#[test]
fn cli_build_and_queries() {
    let dir = tempfile::tempdir().unwrap();
    let csv = write_csv(&dir);
    let graph = dir.path().join("deps.strand");

    let out = strand()
        .args(["build", csv.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let run = |args: &[&str]| {
        let o = strand().args(args).output().unwrap();
        assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    let g = graph.to_str().unwrap();

    let info = run(&["info", g]);
    assert!(info.contains("6 nodes") || info.contains("nodes:       6"));

    let deps = run(&["deps", g, "app"]);
    assert!(deps.contains("liba") && deps.contains("util"));

    let impact = run(&["impact", g, "core"]);
    assert!(impact.contains("4 affected"));

    let why = run(&["why", g, "app", "util"]);
    assert!(why.contains("app -> liba -> core -> util") || why.contains("app -> libb -> core -> util"));

    assert!(run(&["cycles", g]).contains("no cycles"));
    assert!(run(&["roots", g]).contains("app"));
    assert!(run(&["leaves", g]).contains("util"));

    let common = run(&["common", g, "deps", "app", "tool"]);
    assert!(common.contains("liba") && common.contains("core"));

    // JSON output parses.
    let j = run(&["impact", g, "core", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert_eq!(v["total_affected"], 4);
}

#[test]
fn cli_impact_counts_consistent() {
    // Regression: `direct` is a subset of `affected`, so it can never
    // exceed the total; direct + transitive must equal the total.
    let dir = tempfile::tempdir().unwrap();
    let csv = write_csv(&dir);
    let graph = dir.path().join("deps.strand");
    strand()
        .args(["build", csv.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();

    let o = strand()
        .args(["impact", graph.to_str().unwrap(), "core", "--json"])
        .output()
        .unwrap();
    assert!(o.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&o.stdout)).unwrap();
    let total = v["total_affected"].as_u64().unwrap();
    let direct = v["direct"].as_u64().unwrap();
    let transitive = v["transitive"].as_u64().unwrap();
    assert!(direct <= total, "direct {direct} > total {total}");
    assert_eq!(direct + transitive, total);
    assert_eq!((total, direct, transitive), (4, 2, 2));

    // Human-readable output agrees.
    let o = strand()
        .args(["impact", graph.to_str().unwrap(), "core"])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("4 affected (2 direct, 2 transitive)"), "{out}");
}

#[test]
fn cli_build_multiple_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.csv");
    let b = dir.path().join("b.csv");
    std::fs::write(&a, "app,liba\napp,libb\n").unwrap();
    std::fs::write(&b, "liba,core\nlibb,core\ncore,util\n").unwrap();
    let graph = dir.path().join("merged.strand");

    let o = strand()
        .args([
            "build",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "-o",
            graph.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    // Edges from both files are in one graph.
    let o = strand()
        .args(["impact", graph.to_str().unwrap(), "core"])
        .output()
        .unwrap();
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    // Dependents of core across both files: liba, libb, app.
    assert!(out.contains("3 affected"), "{out}");
    assert!(out.contains("liba") && out.contains("app"));
}

#[test]
fn cli_scan_rust_project() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    std::fs::create_dir_all(root.join("src/bar")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"proj\"\n").unwrap();
    std::fs::write(root.join("src/lib.rs"), "mod foo;\nmod bar;\n").unwrap();
    std::fs::write(root.join("src/foo.rs"), "use crate::bar::Thing;\npub struct X;\n").unwrap();
    std::fs::write(
        root.join("src/bar/mod.rs"),
        "use super::foo::X;\nmod inner;\npub struct Thing;\n",
    )
    .unwrap();
    std::fs::write(root.join("src/bar/inner.rs"), "pub struct Y;\n").unwrap();

    let graph = dir.path().join("scan.strand");
    let o = strand()
        .args(["scan", root.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    let o = strand()
        .args(["deps", graph.to_str().unwrap(), "src/foo.rs"])
        .output()
        .unwrap();
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("src/bar/mod.rs"), "{out}");
}

#[test]
fn cli_impact_git_diff() {
    // --git-diff maps changed files onto graph nodes; --max-impact gates CI.
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();

    let git = |args: &[&str]| {
        let o = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    };
    git(&["init", "-q"]);
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    std::fs::write(repo.join("app.rs"), "fn main() {}\n").unwrap();
    git(&["add", "-A"]);
    git(&["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]);
    // Uncommitted change -> shows up in `git diff --name-only HEAD`.
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\npub fn g() {}\n").unwrap();

    // app.rs depends on src/lib.rs.
    let csv = dir.path().join("deps.csv");
    std::fs::write(&csv, "app.rs,src/lib.rs\n").unwrap();
    let graph = dir.path().join("deps.strand");
    strand()
        .args(["build", csv.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();

    let g = graph.to_str().unwrap();
    let rd = repo.to_str().unwrap();
    let o = strand()
        .args(["impact", g, "--git-diff", "HEAD", "--git-dir", rd])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("src/lib.rs"), "{out}");
    assert!(out.contains("1 affected"), "{out}");
    assert!(out.contains("app.rs"), "{out}");

    // --max-impact turns the blast radius into a CI gate.
    let o = strand()
        .args(["impact", g, "--git-diff", "HEAD", "--git-dir", rd, "--max-impact", "0"])
        .output()
        .unwrap();
    assert!(!o.status.success());
}

#[test]
fn cli_export_diagrams() {
    let dir = tempfile::tempdir().unwrap();
    let csv = write_csv(&dir);
    let graph = dir.path().join("deps.strand");
    strand()
        .args(["build", csv.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();
    let g = graph.to_str().unwrap();

    let o = strand()
        .args(["export", g, "--format", "dot", "--why", "app", "util"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let dot = String::from_utf8_lossy(&o.stdout);
    assert!(dot.contains("digraph strand"), "{dot}");
    assert!(dot.contains("label=\"app\""), "{dot}");
    assert!(dot.contains("->"), "{dot}");

    let o = strand()
        .args(["export", g, "--format", "mermaid", "--impact", "core", "--depth", "1"])
        .output()
        .unwrap();
    assert!(o.status.success());
    let mm = String::from_utf8_lossy(&o.stdout);
    assert!(mm.contains("graph LR"), "{mm}");
    assert!(mm.contains("liba"), "{mm}");
    assert!(mm.contains("-->"), "{mm}");
}

#[test]
fn cli_check_rules() {
    let dir = tempfile::tempdir().unwrap();
    let csv = write_csv(&dir);
    let graph = dir.path().join("deps.strand");
    strand()
        .args(["build", csv.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();
    let rules = dir.path().join("strand.rules");
    // tool -> liba -> core: transitive violation; app -> liba direct.
    std::fs::write(&rules, "forbid tool -> core\nforbid app -> liba\n").unwrap();

    let o = strand()
        .args([
            "check",
            graph.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(out.contains("2 violation(s)"), "{out}");
    assert!(out.contains("tool -> liba -> core"), "{out}");
    assert!(out.contains("app -> liba"), "{out}");

    // A clean rules file passes.
    std::fs::write(&rules, "forbid zzz -> yyy\n").unwrap();
    let o = strand()
        .args([
            "check",
            graph.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn cli_missing_node_fails() {
    let dir = tempfile::tempdir().unwrap();
    let csv = write_csv(&dir);
    let graph = dir.path().join("deps.strand");
    strand()
        .args(["build", csv.to_str().unwrap(), "-o", graph.to_str().unwrap()])
        .output()
        .unwrap();
    let o = strand()
        .args(["deps", graph.to_str().unwrap(), "nosuchnode"])
        .output()
        .unwrap();
    assert!(!o.status.success());
}
