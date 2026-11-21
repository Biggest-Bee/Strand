//! Dump scan edges as sorted `src -> dst` lines - for diffing scanner
//! implementations and debugging resolution.
//!
//! Usage: cargo run -p strand-import --example edges -- <dir> [--lang rust|python|js|all]

use std::path::PathBuf;

use strand_import::scan::{self, Lang};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("usage: edges <dir> [lang]"));
    let lang = match args.next().as_deref() {
        Some("rust") => Lang::Rust,
        Some("python") => Lang::Python,
        Some("js") => Lang::Js,
        _ => {
            let out = scan::scan_project(&dir, &[Lang::Rust, Lang::Python, Lang::Js])
                .expect("scan failed");
            print_out(&out);
            return;
        }
    };
    let out = scan::scan_lang(&dir, lang).expect("scan failed");
    print_out(&out);
}

fn print_out(out: &scan::ScanOutput) {
    let mut edges: Vec<_> = out
        .edges
        .iter()
        .map(|(s, d, _)| (s.clone(), d.clone()))
        .collect();
    edges.sort();
    edges.dedup();
    for (s, d) in edges {
        println!("{s} -> {d}");
    }
    for w in &out.warnings {
        eprintln!("warning: {w}");
    }
}
