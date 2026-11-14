//! The only `unsafe` code in strand-core lives here: mapping a file into
//! memory and casting byte slices into typed slices.
//!
//! Invariants relied upon by callers:
//! - The mapped file is immutable once written (the format is write-once),
//!   so the mapping never observes torn data.
//! - Every typed section starts at an 8-byte-aligned file offset and the
//!   mapping base is page-aligned, so `u64`/`u32`/`f32` casts are aligned.
//! - Section bounds are validated against the file length before any slice
//!   is produced, so no cast can read out of bounds.
//!
//! Residual risk: if the file is truncated *after* it is opened, touching a
//! page beyond the new EOF can raise SIGBUS. This is inherent to mmap and is
//! why strand files must be treated as immutable (writers always write a new
//! file and rename it into place).

use std::fs::File;
use std::io;

use memmap2::Mmap;

/// Memory-map `file` read-only.
///
/// # Safety
///
/// The caller guarantees the file is not concurrently truncated or rewritten
/// while the mapping is alive. Strand's write path satisfies this by always
/// writing a fresh file and atomically renaming it.
pub fn map_readonly(file: &File) -> io::Result<Mmap> {
    // SAFETY: see module docs. The file is opened read-only and strand files
    // are immutable, so no writes can race the mapping.
    unsafe { Mmap::map(file) }
}
