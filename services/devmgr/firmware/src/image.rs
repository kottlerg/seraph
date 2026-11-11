// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/image.rs

//! Bounded reads of a candidate driver binary, for the declaration devmgr
//! reads from it ([docs/driver-binding.md](../../../../docs/driver-binding.md)
//! § Declaration Bounds): the pages of a boot module that hold a byte range,
//! and the chunked `FS_READ` loop over a file on the root filesystem, whose
//! reply counts come from an fs driver devmgr does not trust with its
//! buffers.

/// The pages of a module that hold `len` bytes from byte `offset`: the first
/// page, the page count, and the range's offset in the first page. `None`
/// for an empty range or one whose end overflows.
#[must_use]
pub fn page_window(offset: u64, len: u64, page_size: u64) -> Option<(u64, u64, u64)>
{
    if len == 0 || page_size == 0
    {
        return None;
    }
    let end = offset.checked_add(len)?;
    let first = offset / page_size;
    let last = end.div_ceil(page_size);
    Some((first, last - first, offset % page_size))
}

/// Fill `dst` from file offset `off` through `read`, one request of at most
/// `chunk` bytes at a time.
///
/// `read(offset, buf)` issues one read of `buf.len()` bytes at `offset`,
/// copies at most `buf.len()` bytes into `buf`, and returns the count the
/// server reported, which may exceed `buf.len()`; at most the bytes asked
/// for are counted, so a server reporting more cannot overrun `dst`. A short
/// read continues the loop and a zero read (end of file) stops it.
///
/// Returns the bytes filled, short of `dst.len()` only at end of file, or
/// `None` when a request fails or `chunk` is zero.
pub fn fill<F>(dst: &mut [u8], off: u64, chunk: usize, mut read: F) -> Option<usize>
where
    F: FnMut(u64, &mut [u8]) -> Option<usize>,
{
    if chunk == 0
    {
        return None;
    }
    let mut total = 0usize;
    while total < dst.len()
    {
        let want = (dst.len() - total).min(chunk);
        let at = off.checked_add(u64::try_from(total).ok()?)?;
        let reported = read(at, &mut dst[total..total + want])?;
        if reported == 0
        {
            break;
        }
        total += reported.min(want);
    }
    Some(total)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_page_window_covers_every_page_the_range_touches()
    {
        assert_eq!(page_window(0, 64, 4096), Some((0, 1, 0)));
        assert_eq!(page_window(4090, 12, 4096), Some((0, 2, 4090)));
        assert_eq!(page_window(8192, 4096, 4096), Some((2, 1, 0)));
        assert_eq!(page_window(0, 0, 4096), None);
        assert_eq!(page_window(u64::MAX, 2, 4096), None);
    }

    #[test]
    fn fill_reads_in_chunks_and_counts_no_more_than_it_asked_for()
    {
        let file: Vec<u8> = (0..=255).collect();
        let mut requests = Vec::new();
        let mut dst = [0u8; 100];
        let got = fill(&mut dst, 10, 40, |at, buf| {
            requests.push((at, buf.len()));
            let at = usize::try_from(at).unwrap();
            buf.copy_from_slice(&file[at..at + buf.len()]);
            // A server over-reporting its count.
            Some(buf.len() + 1000)
        });
        assert_eq!(got, Some(100));
        assert_eq!(requests, [(10, 40), (50, 40), (90, 20)]);
        assert_eq!(dst[0], 10);
        assert_eq!(dst[99], 109);
    }

    #[test]
    fn fill_stops_at_end_of_file_and_reports_a_failed_request()
    {
        let mut dst = [0u8; 16];
        assert_eq!(fill(&mut dst, 0, 8, |_, _| Some(0)), Some(0));
        let mut calls = 0;
        assert_eq!(
            fill(&mut dst, 0, 8, |_, _| {
                calls += 1;
                (calls == 1).then_some(3)
            }),
            None
        );
        assert_eq!(fill(&mut dst, 0, 0, |_, _| Some(1)), None);
    }
}
