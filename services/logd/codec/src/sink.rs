// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/sink.rs

//! The rules of logd's sinks that hold no state of their own: the stall bound
//! and when a write has run past it, the retry hint a refused sender and a
//! pending flush are given, where a `skip` sink's cursor starts when its
//! driver comes up, and the line naming the entries a sink dropped.
//!
//! Each of logd's sinks reads logd's journal, its history, through a cursor of
//! its own, and its writer thread is the only thread that calls the sink's
//! driver (`services/logd/docs/sinks.md` § Sinks;
//! `services/logd/docs/ipc-interface.md` § Output sinks).

use crate::BoundedStr;

/// The bound, in milliseconds, past which a sink whose writer is still in
/// one entry's write is stalled: a stalled `hold` sink holds no sender
/// back, nor a flush, nor the kernel log reader's acknowledgement. Also the
/// bound on the whole inline write of the entries a sink with no writer has
/// not written, and on each call of logd's panic sink. Long enough that a
/// driver merely slowed by load completes an entry within it; equal to the
/// serial driver's `TX_STALL_MS`, after which it answers a write on a
/// transmitter that makes no progress `STALLED`.
pub const SINK_STALL_MS: u32 = 1000;

/// Whether a write the writer started at `started_us` (`None` while it
/// writes nothing) has run past [`SINK_STALL_MS`] at `now_us`, on one
/// microsecond clock: the sink is then stalled.
#[must_use]
pub const fn write_overdue(started_us: Option<u64>, now_us: u64) -> bool
{
    match started_us
    {
        Some(start) => now_us.saturating_sub(start) > SINK_STALL_MS as u64 * 1000,
        None => false,
    }
}

/// The retry hint, in milliseconds, of a wait on `entries` entries of a
/// `hold` sink whose writer took `entry_us` microseconds for its last entry:
/// their expected time, rounded up, at least 1 ms, so a waiter does not ask
/// again at once, and at most [`SINK_STALL_MS`], after which a writer that has
/// not finished is stalled and holds nobody. A refused sender's hint counts
/// the entries past its window, and a pending flush's those up to its token.
#[must_use]
pub fn hint_ms(entries: u64, entry_us: u64) -> u32
{
    let ms = entries.saturating_mul(entry_us).div_ceil(1000);
    u32::try_from(ms.clamp(1, u64::from(SINK_STALL_MS))).unwrap_or(SINK_STALL_MS)
}

/// The cursor of a `skip` sink at `cursor` when its driver comes up, with
/// `next` the `seq` the next retained entry takes: `backlog` entries
/// before it (the sink's `backlog` setting,
/// `services/logd/docs/sinks.md` § Device sinks) when the cursor is further
/// behind than that, otherwise where it is: the context a screen shows when
/// it attaches. The entries passed that the sink shows are counted as
/// dropped.
#[must_use]
pub const fn attach_cursor(cursor: u64, next: u64, backlog: u64) -> u64
{
    let start = next.saturating_sub(backlog);
    if cursor < start { start } else { cursor }
}

/// The text of the line naming the `dropped` entries sink `what` did not
/// write (`services/logd/docs/sinks.md` § Drops).
#[must_use]
pub fn drop_text(what: &str, dropped: u64) -> BoundedStr<64>
{
    use core::fmt::Write;
    let mut text = BoundedStr::new();
    let _ = write!(text, "{what}: {dropped} lines dropped");
    text
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a sink read as stalled before its bound, which lets a
    // flooding sender past a sink still writing, or never, which holds senders
    // on a stopped driver.
    #[test]
    fn a_write_is_overdue_only_past_the_stall_bound()
    {
        let bound_us = u64::from(SINK_STALL_MS) * 1000;
        assert!(!write_overdue(None, u64::MAX));
        assert!(!write_overdue(Some(5), 5 + bound_us));
        assert!(write_overdue(Some(5), 6 + bound_us));
        // A start after the reading (another thread's clock read) is not overdue.
        assert!(!write_overdue(Some(10), 5));
    }

    // Defect caught: a hint of 0 ms that makes a sender spin, or one past the
    // stall bound that oversleeps a sink that has since stalled.
    #[test]
    fn the_hint_is_the_expected_time_within_its_clamp()
    {
        assert_eq!(hint_ms(0, 500), 1);
        assert_eq!(hint_ms(3, 0), 1);
        assert_eq!(hint_ms(3, 400), 2);
        assert_eq!(hint_ms(10, 2_000), 20);
        assert_eq!(hint_ms(u64::MAX, u64::MAX), SINK_STALL_MS);
    }

    // Defect caught: a screen that attaches late replaying the whole history,
    // or one that moves its cursor back over entries it has written.
    #[test]
    fn an_attaching_skip_sink_starts_at_most_its_backlog_behind()
    {
        assert_eq!(attach_cursor(0, 1000, 64), 1000 - 64);
        assert_eq!(attach_cursor(990, 1000, 64), 990);
        assert_eq!(attach_cursor(0, 10, 64), 0);
        assert_eq!(attach_cursor(0, 1000, 0), 1000);
    }
}
