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

use std::path::{Path, PathBuf};
use std::process::Command;

use strand_core::{Error, Result};

/// `sitecustomize.py` auto-imported by every Python startup (unless
/// `-S`/`-I`). Installs a meta_path finder that appends each observed
/// `.py -> .py` import to STRAND_TRACE_OUT as `importer<TAB>origin`.
const SITECUSTOMIZE: &str = r##"import os
import sys

_out = os.environ.get("STRAND_TRACE_OUT")
_root = os.path.normcase(
    os.path.abspath(os.environ.get("STRAND_TRACE_ROOT") or os.getcwd())
) + os.sep


def _record(imp, org):
    if not _out:
        return
    try:
        with open(_out, "a", encoding="utf-8") as f:
            f.write(imp + "\t" + org + "\n")
    except OSError:
        pass


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

/// Run `cmd` under the tracer and return observed `(importer,
/// imported)` absolute paths. The command's exit status is ignored -
/// a failing test suite still exercises real imports.
pub fn traced_edges(root: &Path, cmd: &[String]) -> Result<Vec<(PathBuf, PathBuf)>> {
    let tmp = tempfile::tempdir().map_err(|e| Error::Usage(format!("trace tempdir: {e}")))?;
    let site = tmp.path().join("sitecustomize.py");
    std::fs::write(&site, SITECUSTOMIZE)
        .map_err(|e| Error::Usage(format!("{}: {e}", site.display())))?;
    let edges_file = tmp.path().join("edges.tsv");
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
        .env("STRAND_TRACE_ROOT", &root_abs)
        .status()
        .map_err(|e| Error::Usage(format!("failed to run `{}`: {e} (is it on PATH?)", cmd[0])))?;
    let _ = status; // nonzero exit still yields whatever was traced

    let text = std::fs::read_to_string(&edges_file).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split('\t');
        if let (Some(a), Some(b)) = (it.next(), it.next()) {
            out.push((PathBuf::from(a), PathBuf::from(b)));
        }
    }
    Ok(out)
}
