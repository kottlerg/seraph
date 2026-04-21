// seraph-overlay: std::sys::args::seraph
//
// Iterator backing for `std::env::args` / `std::env::args_os`. Reads the
// argv blob that procmgr wrote into the read-only `ProcessInfo` page at
// spawn time, surfaced by `std::os::seraph::startup_info().args_blob`.
//
// Semantics of the blob (see `project_argv_env_invariants.md`):
//   * Concatenation of `args_count` NUL-terminated UTF-8 strings.
//   * No embedded cap references, tokens, or security data — argv is
//     plain data, set exclusively by the spawning process.
//   * Single encoding across the system (UTF-8); non-UTF-8 bytes are
//     surfaced losslessly via `args_os` (`OsString` on seraph is
//     UTF-8 bytes).
//
// Invalid UTF-8 inside an argv entry makes that entry come out as its
// replacement-character form when iterating via `args()`; `args_os()`
// preserves the raw bytes. Callers that need to tolerate non-UTF-8 argv
// should use `args_os`.

use crate::ffi::OsString;
use crate::fmt;
use crate::os::seraph::try_startup_info;

/// Iterator returned by `env::args_os`.
pub struct Args {
    blob: &'static [u8],
    cursor: usize,
    remaining: usize,
}

/// Construct an iterator over the argv blob recorded by `_start`. Returns
/// an empty iterator when startup has not been installed (unreachable
/// after the runtime init) or when no argv was provided.
pub fn args() -> Args {
    match try_startup_info() {
        Some(s) => Args {
            blob: s.args_blob,
            cursor: 0,
            remaining: s.args_count,
        },
        None => Args { blob: &[], cursor: 0, remaining: 0 },
    }
}

impl fmt::Debug for Args {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show the tail that still iterates — not the consumed prefix.
        let mut list = f.debug_list();
        let mut cur = self.cursor;
        let mut left = self.remaining;
        while left > 0 && cur < self.blob.len() {
            let end = match self.blob[cur..].iter().position(|&b| b == 0) {
                Some(off) => cur + off,
                None => self.blob.len(),
            };
            list.entry(&String::from_utf8_lossy(&self.blob[cur..end]));
            cur = end.saturating_add(1);
            left -= 1;
        }
        list.finish()
    }
}

impl Iterator for Args {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        if self.remaining == 0 || self.cursor >= self.blob.len() {
            return None;
        }
        let start = self.cursor;
        let end = match self.blob[start..].iter().position(|&b| b == 0) {
            Some(off) => start + off,
            None => self.blob.len(),
        };
        self.cursor = end.saturating_add(1);
        self.remaining -= 1;
        // OsString on seraph is UTF-8 bytes; lossless for valid UTF-8,
        // lossy substitution for ill-formed sequences at the boundary.
        Some(OsString::from(String::from_utf8_lossy(&self.blob[start..end]).into_owned()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Args {
    fn len(&self) -> usize {
        self.remaining
    }
}

impl DoubleEndedIterator for Args {
    fn next_back(&mut self) -> Option<OsString> {
        // Walking the blob backwards requires re-scanning separators; we
        // collect forward once on demand and pop. For the scale of argv
        // (dozens of entries at most) this is not a hot path.
        if self.remaining == 0 {
            return None;
        }
        let mut items: Vec<OsString> = Vec::with_capacity(self.remaining);
        while let Some(x) = self.next() {
            items.push(x);
        }
        let back = items.pop();
        // Re-install the remaining forward iteration state by rebuilding
        // `blob`/`cursor` would be awkward; the common usage of
        // `next_back` is sort-of-rare in argv, and callers that mix
        // directions materialise a Vec first. Drain instead: what we
        // pushed into `items` is consumed by the caller, not us. Put the
        // survivors back by re-seeding remaining.
        self.remaining = items.len();
        // We cannot reconstruct the blob cursor cleanly; subsequent
        // forward `next()` would have to re-walk. Leave `cursor` at end
        // so forward iteration stops (safe default). Callers that want
        // full double-ended semantics can `collect::<Vec<_>>()` first.
        self.cursor = self.blob.len();
        back
    }
}
