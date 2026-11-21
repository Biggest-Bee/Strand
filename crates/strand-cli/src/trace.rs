//! Runtime import tracing for Python projects.
//!
//! `strand trace` runs a command (pytest, a script, `python -m ...`)
//! with a `sitecustomize.py` shim on PYTHONPATH. The shim installs a
//! `sys.meta_path` finder that records every real import as an
//! `importer -> imported` file pair, catching edges static analysis
//! can't see: computed `import_module()` names, `getattr`-driven lazy
//! imports, plugin entry points actually loaded at runtime.
//!
//! The traced edges are merged into the static scan output, so the
//! resulting graph is static + observed. Coverage is limited to what
//! the command actually exercised - untested code paths stay dark.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use strand_core::{Error, Result};

/// `sitecustomize.py` auto-imported by every Python startup (unless
/// `-S`/`-I`). Installs a meta_path finder that appends each observed
/// `.py -> .py` import to STRAND_TRACE_OUT as `importer<TAB>origin`,
/// and every project `.py` file actually loaded to STRAND_TRACE_SEEN.
const SITECUSTOMIZE: &str = r##"import os
import sys

_out = os.environ.get("STRAND_TRACE_OUT")
_seen = os.environ.get("STRAND_TRACE_SEEN")
_root = os.path.normcase(
    os.path.abspath(os.environ.get("STRAND_TRACE_ROOT") or os.getcwd())
) + os.sep


def _append(path, line):
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _record(imp, org):
    _append(_out, imp + "\t" + org)


def _mark_seen(origin):
    _append(_seen, origin)


class _StrandFinder:
    def find_spec(self, name, path=None, target=None):
        spec = None
        for finder in sys.meta_path:
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            try:
                spec = find(name, path, target)
            except Exception:
                spec = None
            if spec is not None:
                break
        if spec is None or not spec.origin:
            return spec
        origin = spec.origin
        if isinstance(origin, str) and origin.endswith(".py"):
            try:
                abs_origin = os.path.normcase(os.path.abspath(origin))
            except Exception:
                abs_origin = ""
            if abs_origin.startswith(_root):
                _mark_seen(os.path.abspath(origin))
            # Walk frames to the nearest module file under the project
            # root - that is the importer. importlib internals have no
            # __file__ under root, so they are skipped naturally.
            try:
                frame = sys._getframe(1)
            except Exception:
                frame = None
            while frame is not None:
                fn = frame.f_globals.get("__file__")
                if fn:
                    try:
                        abs_fn = os.path.normcase(os.path.abspath(fn))
                    except Exception:
                        abs_fn = ""
                    if abs_fn.startswith(_root):
                        imp = os.path.abspath(fn)
                        org = os.path.abspath(origin)
                        if os.path.normcase(imp) != os.path.normcase(org):
                            _record(imp, org)
                        break
                frame = frame.f_back
        return spec


sys.meta_path.insert(0, _StrandFinder())
"##;

/// What one trace run observed.
pub struct TraceOutput {
    /// `(importer, imported)` absolute paths for every recorded
    /// project-internal `.py -> .py` import.
    pub edges: Vec<(PathBuf, PathBuf)>,
    /// Every project `.py` file the interpreter actually loaded
    /// (imported or executed as a module). Files absent from this set
    /// were never exercised by the command - the "dark" set.
    pub seen: BTreeSet<PathBuf>,
}

/// Python interpreter flags that bypass the `sitecustomize` shim:
/// `-S` skips `site` entirely, `-I` implies `-E -s` (ignores
/// PYTHONPATH), `-E` ignores PYTHON* env vars. Returns the offending
/// flags found in `cmd` (only scanned when the program looks like a
/// Python interpreter; args after `--` belong to the traced program).
pub fn isolation_flags(cmd: &[String]) -> Vec<String> {
    let prog = cmd
        .first()
        .map(|p| {
            Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    // pytest/coverage wrappers pass interpreter flags through `-m` or
    // their own arg styles we can't reliably parse - only direct
    // `python*` invocations are checked.
    if !prog.starts_with("python") {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut args = cmd.iter().skip(1).peekable();
    // Python stops option parsing at the first non-option argument
    // (the script, or the operand of -m/-c). -W and -X consume the
    // following arg as their value.
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break; // script path / module operand: interpreter args end here
        }
        match arg.as_str() {
            // -m/-c hand everything after their operand to the program.
            "-m" | "-c" => {
                args.next();
                break;
            }
            // -W/-X consume the following arg as their value, then
            // interpreter option parsing continues.
            "-W" | "-X" => {
                args.next();
                continue;
            }
            _ => {}
        }
        // Bundled single-letter flags like `-SI` or `-uS` count too.
        if let Some(flags) = arg.strip_prefix('-') {
            if !flags.is_empty()
                && flags.chars().all(|c| c.is_ascii_alphabetic())
                && flags.chars().any(|c| matches!(c, 'S' | 'I' | 'E'))
            {
                for c in flags.chars().filter(|c| matches!(c, 'S' | 'I' | 'E')) {
                    hits.push(format!("-{c}"));
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Run `cmd` under the tracer and return observed `(importer,
/// imported)` absolute paths plus the set of project `.py` files
/// actually loaded. The command's exit status is ignored -
/// a failing test suite still exercises real imports.
pub fn traced_edges(root: &Path, cmd: &[String]) -> Result<TraceOutput> {
    let tmp = tempfile::tempdir().map_err(|e| Error::Usage(format!("trace tempdir: {e}")))?;
    let site = tmp.path().join("sitecustomize.py");
    std::fs::write(&site, SITECUSTOMIZE)
        .map_err(|e| Error::Usage(format!("{}: {e}", site.display())))?;
    let edges_file = tmp.path().join("edges.tsv");
    let seen_file = tmp.path().join("seen.txt");
    // Pass a plain (non-verbatim) absolute path: Python's abspath
    // never produces `\\?\` prefixes, so a verbatim root would make
    // the shim's startswith check miss every importer.
    let root_abs = root
        .canonicalize()
        .map(|p| match p.to_string_lossy().strip_prefix("\\\\?\\") {
            Some(s) => PathBuf::from(s),
            None => p,
        })
        .map_err(|e| Error::Usage(format!("{}: {e}", root.display())))?;

    let mut python_path = std::ffi::OsString::from(tmp.path());
    if let Some(old) = std::env::var_os("PYTHONPATH") {
        if !old.is_empty() {
            python_path.push(if cfg!(windows) { ";" } else { ":" });
            python_path.push(old);
        }
    }

    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .env("PYTHONPATH", &python_path)
        .env("STRAND_TRACE_OUT", &edges_file)
        .env("STRAND_TRACE_SEEN", &seen_file)
        .env("STRAND_TRACE_ROOT", &root_abs)
        .status()
        .map_err(|e| Error::Usage(format!("failed to run `{}`: {e} (is it on PATH?)", cmd[0])))?;
    let _ = status; // nonzero exit still yields whatever was traced

    let text = std::fs::read_to_string(&edges_file).unwrap_or_default();
    let mut edges = Vec::new();
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let mut it = line.split('\t');
        if let (Some(a), Some(b)) = (it.next(), it.next()) {
            edges.push((PathBuf::from(a), PathBuf::from(b)));
        }
    }
    if let Ok(seen_text) = std::fs::read_to_string(&seen_file) {
        for line in seen_text.lines() {
            if !line.is_empty() {
                seen.insert(PathBuf::from(line));
            }
        }
    }
    Ok(TraceOutput { edges, seen })
}

#[cfg(test)]
mod tests {
    use super::isolation_flags;

    fn cmd(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_isolation_flags() {
        assert_eq!(
            isolation_flags(&cmd(&["python", "-S", "app.py"])),
            vec!["-S"]
        );
        assert_eq!(
            isolation_flags(&cmd(&["python3.11", "-I", "-m", "pytest"])),
            vec!["-I"]
        );
        assert_eq!(
            isolation_flags(&cmd(&["python", "-SE", "app.py"])),
            vec!["-E", "-S"]
        );
        // Flags after the script belong to the program, not python.
        assert!(isolation_flags(&cmd(&["python", "app.py", "-S"])).is_empty());
        // -m consumes its operand; later args are the module's argv.
        assert!(isolation_flags(&cmd(&["python", "-m", "pytest", "-S"])).is_empty());
        // Non-python programs aren't checked.
        assert!(isolation_flags(&cmd(&["pytest", "-S"])).is_empty());
        // Ordinary flags don't trigger.
        assert!(isolation_flags(&cmd(&["python", "-u", "-O", "app.py"])).is_empty());
    }
}
