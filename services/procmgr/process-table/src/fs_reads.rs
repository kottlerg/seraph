// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/fs_reads.rs

//! Bounds for the fs-driver replies procmgr copies from while it reads a
//! signed object from a file cap (`CREATE_FROM_FILE`).
//!
//! The count and offset in an `FS_READ_MEMORY` reply come from the fs
//! driver, which procmgr does not trust with its own memory: an in-page
//! offset or count past the page would make procmgr read past the page it
//! mapped. [`cache_page_range`] rejects such a reply before procmgr copies a
//! byte (see `services/fs/docs/fs-driver-protocol.md` for what the driver
//! promises). The driver also controls which caps a reply carries:
//! [`read_memory_reply_caps`] splits an `FS_READ_MEMORY` reply's caps into
//! the cache-page cap procmgr keeps and the surplus it deletes.

use core::ops::Range;

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
