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

use core::ops::Range;

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
    while total < dst.len()
    {
        let want = (dst.len() - total).min(chunk);
        let window = &mut dst[total..total + want];
        let reported = read(off + total as u64, window)?;
        if reported == 0
        {
            break;
        }
        total += reported.min(want);
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
pub fn read_memory_reply_caps(label: u64, bytes_valid: usize, caps: &[u32])
-> (Option<u32>, &[u32])
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

    #[test]
    fn fill_exact_reports_a_failed_request()
    {
        let mut dst = [0u8; 10];
        assert_eq!(fill_exact(&mut dst, 0, 4, |_, _| None), None);
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
