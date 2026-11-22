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
//! the cache-page cap procmgr keeps and the surplus it deletes, and
//! [`session_reply_caps`] and [`open_reply_caps`] do the same for the
//! `FS_SESSION` and `FS_OPEN` replies of the read's session. The session is
//! charged to a sub-node of the account the read's buffer is granted on, with
//! a max of [`READ_SESSION_MAX_PAGES`], and a refusal of its charge is
//! answered as [`fs_refusal`] says.

use core::ops::Range;

/// The max of the sub-node a file read's session is charged to, in pages.
/// The driver records the session, the read's one open and the one cache
/// page procmgr holds at a time in the session's first page
/// (services/fs/docs/fs-driver-protocol.md § Label 23), so one page is all
/// a read needs; it also bounds what a file server, which procmgr does not
/// trust, can charge the account per read. The node is not procmgr's own but
/// the creator's or the sender's, so procmgr sets the bound rather than
/// leaving it to that node.
pub const READ_SESSION_MAX_PAGES: u64 = 1;

/// The procmgr error for an `FS_SESSION` or `FS_OPEN` refusal of the file
/// server: `LIMIT` when the max of the session's node, or of an ancestor's,
/// refused the charge (`fs_errors::LIMIT`), `IO_ERROR` otherwise.
#[must_use]
pub const fn fs_refusal(label: u64) -> u64
{
    if label == ipc::fs_errors::LIMIT
    {
        ipc::procmgr_errors::LIMIT
    }
    else
    {
        ipc::procmgr_errors::IO_ERROR
    }
}

/// Split the caps of an `FS_SESSION` reply into the session cap and the
/// liveness cap procmgr keeps, `caps[0]` and `caps[1]` of a success, and the
/// surplus it deletes: every other cap, and on a failure every cap.
#[must_use]
pub fn session_reply_caps(label: u64, caps: &[u64]) -> (Option<(u64, u64)>, &[u64])
{
    match caps
    {
        [session, liveness, extra @ ..] if label == 0 => (Some((*session, *liveness)), extra),
        _ => (None, caps),
    }
}

/// Split the caps of an `FS_OPEN` reply into the open cap procmgr keeps,
/// `caps[0]` of a success, and the surplus it deletes.
#[must_use]
pub fn open_reply_caps(label: u64, caps: &[u64]) -> (Option<u64>, &[u64])
{
    match caps.split_first()
    {
        Some((&open, extra)) if label == 0 => (Some(open), extra),
        _ => (None, caps),
    }
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
    fn a_max_refusal_of_the_read_session_is_procmgr_s_limit()
    {
        assert_eq!(
            fs_refusal(ipc::fs_errors::LIMIT),
            ipc::procmgr_errors::LIMIT
        );
        for label in [
            ipc::fs_errors::INVALID_BADGE,
            ipc::fs_errors::INVALID_ARGUMENT,
            ipc::fs_errors::TOO_MANY_OPEN,
            ipc::fs_errors::IO_ERROR,
        ]
        {
            assert_eq!(fs_refusal(label), ipc::procmgr_errors::IO_ERROR);
        }
    }

    #[test]
    fn a_session_reply_keeps_its_two_caps_and_drops_the_rest()
    {
        assert_eq!(session_reply_caps(0, &[5, 6, 7]), (Some((5, 6)), &[7][..]));
        assert_eq!(session_reply_caps(0, &[5]), (None, &[5][..]));
        assert_eq!(session_reply_caps(14, &[5, 6]), (None, &[5, 6][..]));
    }

    #[test]
    fn an_open_reply_keeps_its_open_cap_and_drops_the_rest()
    {
        assert_eq!(open_reply_caps(0, &[5, 6]), (Some(5), &[6][..]));
        assert_eq!(open_reply_caps(0, &[]), (None, &[][..]));
        assert_eq!(open_reply_caps(15, &[5]), (None, &[5][..]));
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
