//! One-call project analysis: static scan + per-language parse +
//! taint/null/leak solvers, using the embedded default models.
//! Shared by `strand deep --analyze` callers and the GUI so both
//! report identical findings.

use std::collections::BTreeSet;
use std::path::Path;

use strand_import::scan::{scan_project_with_py, Lang};

use crate::facts::Finding;
use crate::go_deep::{self, GoModules};
use crate::ipa;
use crate::js_ipa::{self, JsFile};
use crate::models::{self, Model};
use crate::rust_deep::{self, RsFile};
use crate::solver::{self, SolveOutput, SolveStats};
use crate::{solver_go, solver_js, solver_rs};

/// Findings + stats for one language's solver run.
pub struct LanguageReport {
    /// `python`, `javascript`, `go`, or `rust`.
    pub language: &'static str,
    pub stats: SolveStats,
    pub findings: Vec<Finding>,
}

/// Full-project analysis result across every supported language.
pub struct ProjectReport {
    pub languages: Vec<LanguageReport>,
}

impl ProjectReport {
    /// All findings across languages, sorted by file then line.
    pub fn all_findings(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self
            .languages
            .iter()
            .flat_map(|l| l.findings.iter())
            .collect();
        v.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.sink.cmp(&b.sink))
        });
        v
    }
}

fn lang_report(language: &'static str, sol: SolveOutput) -> LanguageReport {
    LanguageReport {
        language,
        stats: sol.stats,
        findings: sol.findings,
    }
}

/// Scan `root` and run every language solver with embedded models.
/// Languages with no parsed files still report (empty) so callers
/// can show uniform stats; solvers on empty input are ~free.
pub fn analyze_project(root: &Path) -> strand_core::Result<ProjectReport> {
    analyze_project_with_models(root, None)
}

/// `models_dir`, when `Some`, overrides embedded defaults per
/// language key (`python`, `javascript`/`js`, `go`, `rust`).
pub fn analyze_project_with_models(
    root: &Path,
    models_dir: Option<&Path>,
) -> strand_core::Result<ProjectReport> {
    let (scan, py_src) =
        scan_project_with_py(root, &[Lang::Python, Lang::Js, Lang::Rust, Lang::Go])?;

    let pick = |keys: &[&str], default: fn() -> Result<Model, String>| -> Model {
        if let Some(dir) = models_dir {
            if let Ok(models) = models::load_dir(dir) {
                for k in keys {
                    if let Some(m) = models.get(*k).cloned() {
                        return m;
                    }
                }
            }
        }
        default().unwrap_or_default()
    };

    let mut languages = Vec::new();

    // Python.
    let parsed = ipa::parse_all_sources(py_src);
    let py_model = pick(&["python"], models::python_default);
    languages.push(lang_report("python", solver::solve(&parsed, &py_model)));

    // JS/TS: .json names stay in the resolution set but are not
    // parsed as modules.
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
    let js_files: Vec<(String, std::path::PathBuf)> = js_names
        .iter()
        .filter(|n| !n.to_lowercase().ends_with(".json"))
        .map(|n| (n.clone(), root.join(n)))
        .collect();
    let js_parsed: Vec<JsFile> = js_ipa::analyze_files(&js_files)
        .into_iter()
        .filter_map(|(_, f)| f)
        .collect();
    if !js_parsed.is_empty() {
        let js_model = pick(&["js", "javascript"], models::js_default);
        languages.push(lang_report(
            "javascript",
            solver_js::solve_js(&js_parsed, &js_names, &js_model),
        ));
    }

    // Go.
    let go_files: Vec<(String, std::path::PathBuf)> = scan
        .nodes
        .iter()
        .filter(|n| n.to_lowercase().ends_with(".go"))
        .map(|n| (n.clone(), root.join(n)))
        .collect();
    if !go_files.is_empty() {
        let mods: GoModules = go_deep::discover_modules(root);
        let go_parsed = go_deep::analyze_files(&go_files)
            .into_iter()
            .filter_map(|(_, f)| f)
            .collect::<Vec<_>>();
        if !go_parsed.is_empty() {
            let go_model = pick(&["go"], models::go_default);
            languages.push(lang_report(
                "go",
                solver_go::solve_go(&go_parsed, &mods, &go_model),
            ));
        }
    }

    // Rust.
    let rs_files: Vec<(String, std::path::PathBuf)> = scan
        .nodes
        .iter()
        .filter(|n| n.to_lowercase().ends_with(".rs"))
        .map(|n| (n.clone(), root.join(n)))
        .collect();
    let rs_parsed: Vec<RsFile> = rust_deep::analyze_files(&rs_files)
        .into_iter()
        .filter_map(|(_, f)| f)
        .collect();
    if !rs_parsed.is_empty() {
        let rs_model = pick(&["rust", "rs"], models::rust_default);
        languages.push(lang_report(
            "rust",
            solver_rs::solve_rs(&rs_parsed, &rs_model),
        ));
    }

    Ok(ProjectReport { languages })
}
