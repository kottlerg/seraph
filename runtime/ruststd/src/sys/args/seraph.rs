// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/args/seraph.rs

//! Iterator backing for `std::env::args` / `std::env::args_os`. Reads the
//! argv blob that procmgr wrote into the read-only `ProcessInfo` page at
//! spawn time, surfaced by `std::os::seraph::startup_info().args_blob`.
//!
//! The blob format is defined by the argv section comment above
//! `ProcessInfo::args_offset` in `abi/process-abi/src/lib.rs`; the field walks
//! are `argv_env::next_field` and `argv_env::prev_field`.
//!
//! Each entry comes out of `args_os()` as its raw bytes, since an `OsString`
//! on this target is a byte string; `args()` panics on an entry that is not
//! valid UTF-8, per its std contract. Callers that need to tolerate
//! non-UTF-8 argv should use `args_os`. Both iterators are double-ended and
//! exact-size: the front and back walks consume disjoint entries.

use argv_env::{next_field, prev_field};

use crate::ffi::OsString;
use crate::fmt;
use crate::os::seraph::try_startup_info;

/// Iterator returned by `env::args_os`. Unconsumed entries lie in
/// `blob[cursor..end]`, `remaining` of them.
pub struct Args {
    blob: &'static [u8],
    cursor: usize,
    end: usize,
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
            end: s.args_blob.len(),
            remaining: s.args_count,
        },
        None => Args { blob: &[], cursor: 0, end: 0, remaining: 0 },
    }
}

/// An argv entry as an `OsString`, byte for byte.
fn entry(field: &[u8]) -> OsString {
    // SAFETY: this target's `OsStr` is the byte-string encoding, for which
    // every byte sequence is a valid encoded `OsStr`.
    unsafe { OsString::from_encoded_bytes_unchecked(field.to_vec()) }
}

impl fmt::Debug for Args {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show the entries that still iterate — not the consumed ends.
        let mut list = f.debug_list();
        let mut cur = self.cursor;
        let mut left = self.remaining;
        while left > 0 {
            let Some((field, next)) = next_field(&self.blob[..self.end], cur) else {
                break;
            };
            list.entry(&String::from_utf8_lossy(field));
            cur = next;
            left -= 1;
        }
        list.finish()
    }
}

impl Iterator for Args {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        if self.remaining == 0 {
            return None;
        }
        let (field, next) = next_field(&self.blob[..self.end], self.cursor)?;
        self.cursor = next;
        self.remaining -= 1;
        Some(entry(field))
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
        if self.remaining == 0 {
            return None;
        }
        let (field, start) = prev_field(self.blob, self.cursor, self.end)?;
        self.end = start;
        self.remaining -= 1;
        Some(entry(field))
    }
}
