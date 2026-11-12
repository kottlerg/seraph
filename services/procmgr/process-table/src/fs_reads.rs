// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/fs_reads.rs

//! Bounds for the fs-driver replies procmgr copies from while it loads an
//! ELF image from a file cap (`CREATE_FROM_FILE`).
//!
//! The counts and offsets in an `FS_READ` or `FS_READ_MEMORY` reply come from
//! the fs driver, which procmgr does not trust with its own memory: a count
//! larger than the request, or an in-page offset past the page, would make
//! procmgr read past the buffer it staged or the page it mapped. These
//! helpers clamp or reject such a reply before procmgr copies a byte (see
//! `services/fs/docs/fs-driver-protocol.md` for what the driver promises).
//! The driver also controls which caps a reply carries:
//! [`read_memory_reply_caps`] splits an `FS_READ_MEMORY` reply's caps into
//! the cache-page cap procmgr keeps and the surplus it deletes.

use core::cell::Cell;
use core::ops::Range;

use ipc::procmgr_errors;

/// Whether any read of a create's file failed: the server refused it, or
/// did not answer within procmgr's bound on a file-cap call.
///
/// procmgr makes every `FS_READ` past the ELF header through
/// [`ReadFailures::read`], which makes no read once one has failed, so a
/// file server that stops answering costs a create one bounded wait,
/// however many reads its parsers would still ask for. The parsers those
/// reads feed report a failed read as they report a malformed image, or,
/// for the stack note, as no note, so [`ReadFailures::code`] turns the reply
/// code of a create that fails after a failed read into `IO_ERROR`, and
/// [`ReadFailures::failed`] fails a create a failed read did not otherwise
/// stop (`services/procmgr/docs/ipc-interface.md` § Label 13).
#[derive(Default)]
pub struct ReadFailures
{
    failed: Cell<bool>,
}

impl ReadFailures
{
    /// No read has failed yet.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            failed: Cell::new(false),
        }
    }

    /// Make the read `read`, noting a failure (`None`), and pass its result
    /// through. Once a read has failed, answers `None` without making it.
    pub fn read<T>(&self, read: impl FnOnce() -> Option<T>) -> Option<T>
    {
        if self.failed.get()
        {
            return None;
        }
        let result = read();
        if result.is_none()
        {
            self.failed.set(true);
        }
        result
    }

    /// Whether a read noted so far failed.
    #[must_use]
    pub fn failed(&self) -> bool
    {
        self.failed.get()
    }

    /// The reply code for a create that fails with `code` after the reads
    /// noted so far: `IO_ERROR` when one of them failed, `code` otherwise.
    #[must_use]
    pub fn code(&self, code: u64) -> u64
    {
        if self.failed()
        {
            procmgr_errors::IO_ERROR
        }
        else
        {
            code
        }
    }
}

/// Fill `dst` from file offset `off` through `read`, one request at a time.
///
/// `read(offset, buf)` issues one `FS_READ` of `buf.len()` bytes at `offset`,
/// copies at most `buf.len()` payload bytes into `buf`, and returns the byte
/// count the server reported, which may exceed `buf.len()`. Each request asks
/// for at most `chunk` bytes, and `fill_exact` copies at most that many of the
/// reported bytes, so a server reporting more than it was asked for can
/// neither overrun `dst` nor stretch a copy past the staged chunk. A short
/// read continues the loop; a zero read (end of file) stops it.
///
/// Returns the number of bytes copied, short of `dst.len()` only at end of
/// file (or when `chunk` is zero, which issues no request), or `None` when a
/// request fails.
pub fn fill_exact<F>(dst: &mut [u8], off: u64, chunk: usize, mut read: F) -> Option<usize>
where
    F: FnMut(u64, &mut [u8]) -> Option<usize>,
{
    if chunk == 0
    {
        return Some(0);
    }
    let mut total = 0usize;
    while let Some(rest) = dst.get_mut(total..).filter(|rest| !rest.is_empty())
    {
        let want = rest.len().min(chunk);
        let (window, _) = rest.split_at_mut(want);
        // A file offset past `u64::MAX` cannot be read: the request fails.
        let reported = read(off.checked_add(total as u64)?, window)?;
        if reported == 0
        {
            break;
        }
        // `total` stays at most `dst.len()`.
        total = total.saturating_add(reported.min(want));
    }
    Some(total)
}

/// Split the caps of an `FS_READ_MEMORY` reply into the one procmgr keeps
/// and the ones it deletes.
///
/// A successful reply (`label == 0`, `bytes_valid > 0`) hands procmgr the
/// cache page's Memory cap at `caps[0]`; every other cap, and on any other
/// reply every cap, is surplus the untrusted server attached and procmgr
/// deletes. Returns `(kept, surplus)`: `kept` is `None` when the reply is not
/// a usable success (failure label, zero bytes, or no cap).
#[must_use]
pub fn read_memory_reply_caps(label: u64, bytes_valid: usize, caps: &[u64])
-> (Option<u64>, &[u64])
{
    match caps.split_first()
    {
        Some((&memory_cap, extra)) if label == 0 && bytes_valid > 0 => (Some(memory_cap), extra),
        _ => (None, caps),
    }
}

/// The byte range of a mapped cache page an `FS_READ_MEMORY` reply names:
/// `bytes_valid` bytes starting `data_offset` bytes into the page.
///
/// Returns `None` when the range does not lie within one `page_size` page
/// (including an offset or count whose sum overflows), so procmgr never
/// builds a slice past the single page it mapped.
#[must_use]
pub fn cache_page_range(
    data_offset: usize,
    bytes_valid: usize,
    page_size: usize,
) -> Option<Range<usize>>
{
    let end = data_offset.checked_add(bytes_valid)?;
    (end <= page_size).then_some(data_offset..end)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn fill_exact_clamps_an_oversized_reported_count_to_the_request()
    {
        // The server claims 504 bytes for a 64-byte request: only 64 count,
        // and the next request starts right after them.
        let mut dst = [0u8; 100];
        let mut offsets = [0u64; 4];
        let mut calls = 0usize;
        let got = fill_exact(&mut dst, 1000, 64, |off, buf| {
            offsets[calls] = off;
            calls += 1;
            buf.fill(0xAB);
            Some(504)
        });
        assert_eq!(got, Some(100));
        assert_eq!(&offsets[..calls], &[1000, 1064]);
        assert!(dst.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn fill_exact_continues_after_a_short_read_and_stops_at_end_of_file()
    {
        let mut dst = [0u8; 10];
        let mut served = 0usize;
        let got = fill_exact(&mut dst, 0, 8, |_, buf| {
            // 3 bytes per read until 6 bytes are served, then end of file.
            if served >= 6
            {
                return Some(0);
            }
            let n = 3.min(buf.len());
            buf[..n].fill(1);
            served += n;
            Some(n)
        });
        assert_eq!(got, Some(6));
        assert_eq!(&dst[..6], &[1; 6]);
        assert_eq!(&dst[6..], &[0; 4]);
    }

    #[test]
    fn fill_exact_with_a_zero_chunk_issues_no_request()
    {
        let mut dst = [0u8; 4];
        let got = fill_exact(&mut dst, 0, 0, |_, _| panic!("no request expected"));
        assert_eq!(got, Some(0));
    }

    // Defect guarded: a read whose file offset wraps past `u64::MAX`, which
    // would copy the file's first bytes in as the bytes past the end.
    #[test]
    fn fill_exact_fails_a_request_whose_offset_overflows()
    {
        let mut dst = [0u8; 4];
        let mut offsets = [0u64; 2];
        let mut calls = 0usize;
        let got = fill_exact(&mut dst, u64::MAX, 1, |off, buf| {
            offsets[calls] = off;
            calls += 1;
            buf.fill(0xAB);
            Some(1)
        });
        assert_eq!(got, None);
        assert_eq!(&offsets[..calls], &[u64::MAX]);
    }

    #[test]
    fn fill_exact_reports_a_failed_request()
    {
        let mut dst = [0u8; 10];
        assert_eq!(fill_exact(&mut dst, 0, 4, |_, _| None), None);
    }

    #[test]
    fn read_failures_keeps_the_code_while_every_read_succeeds()
    {
        let reads = ReadFailures::new();
        assert_eq!(reads.read(|| Some(4)), Some(4));
        assert_eq!(reads.read(|| Some(5)), Some(5));
        assert!(!reads.failed());
        assert_eq!(
            reads.code(procmgr_errors::INVALID_ELF),
            procmgr_errors::INVALID_ELF
        );
    }

    #[test]
    fn read_failures_answers_io_error_once_a_read_failed()
    {
        let reads = ReadFailures::new();
        assert_eq!(reads.read::<usize>(|| None), None);
        assert!(reads.failed());
        assert_eq!(
            reads.code(procmgr_errors::INVALID_ELF),
            procmgr_errors::IO_ERROR
        );
        assert_eq!(
            reads.code(procmgr_errors::OUT_OF_MEMORY),
            procmgr_errors::IO_ERROR
        );
    }

    #[test]
    fn read_failures_notes_a_failure_inside_fill_exact()
    {
        // The reader procmgr hands a parser: fill_exact over a server that
        // answers one chunk and then fails.
        let reads = ReadFailures::new();
        let mut dst = [0u8; 16];
        let mut calls = 0usize;
        let got = reads.read(|| {
            fill_exact(&mut dst, 0, 8, |_, buf| {
                calls += 1;
                (calls == 1).then_some(buf.len())
            })
        });
        assert_eq!(got, None);
        assert!(reads.failed());
    }

    #[test]
    fn read_failures_makes_no_read_after_one_failed()
    {
        // Each read would be a bounded wait on an unanswering server: after
        // the first failure, a parser asking for more costs nothing.
        let reads = ReadFailures::new();
        let mut made = 0usize;
        assert_eq!(
            reads.read::<usize>(|| {
                made += 1;
                None
            }),
            None
        );
        for _ in 0..3
        {
            assert_eq!(
                reads.read(|| {
                    made += 1;
                    Some(8usize)
                }),
                None
            );
        }
        assert_eq!(made, 1);
        assert!(reads.failed());
    }

    #[test]
    fn read_memory_reply_keeps_the_first_cap_of_a_success_and_drops_the_rest()
    {
        assert_eq!(
            read_memory_reply_caps(0, 64, &[5, 6, 7]),
            (Some(5), &[6, 7][..])
        );
        assert_eq!(read_memory_reply_caps(0, 64, &[5]), (Some(5), &[][..]));
    }

    #[test]
    fn read_memory_reply_drops_every_cap_of_a_failed_or_empty_reply()
    {
        // Failure label, zero bytes, and no cap at all: nothing is kept.
        assert_eq!(read_memory_reply_caps(3, 64, &[5, 6]), (None, &[5, 6][..]));
        assert_eq!(read_memory_reply_caps(0, 0, &[5]), (None, &[5][..]));
        assert_eq!(read_memory_reply_caps(0, 64, &[]), (None, &[][..]));
    }

    #[test]
    fn cache_page_range_accepts_a_range_ending_at_the_page_end()
    {
        assert_eq!(cache_page_range(0, 4096, 4096), Some(0..4096));
        assert_eq!(cache_page_range(4000, 96, 4096), Some(4000..4096));
    }

    #[test]
    fn cache_page_range_rejects_a_range_past_the_page_or_overflowing()
    {
        assert_eq!(cache_page_range(4000, 97, 4096), None);
        assert_eq!(cache_page_range(4097, 0, 4096), None);
        assert_eq!(cache_page_range(usize::MAX, 2, 4096), None);
    }
}
