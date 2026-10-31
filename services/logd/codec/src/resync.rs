// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/resync.rs

//! logd's death-queue resync: the decisions behind evicting the slots of
//! senders whose death posts a full death queue dropped.
//!
//! logd snapshots its child slots ([`is_resync_candidate`]), walks procmgr's
//! live badges page by page (`procmgr_labels::QUERY_LIVE_PROCESSES`, each
//! reply checked by [`decode_live_page`]), and evicts the snapshot badges the
//! walk did not list ([`evictable`]). A slot created after the snapshot is
//! never a candidate, so a sender that starts during the walk keeps its slot.
//! [`WalkGate`] decides when a walk runs: one at a time, and one more after
//! it when a drain asked for a resync meanwhile.
//! The protocol is in `services/logd/docs/ipc-interface.md`
//! § Death-queue resync.

use ipc::IpcMessage;
use ipc::log_badges::LOG_BADGE_FIRST_CHILD;
use ipc::procmgr_labels::LIVE_PROCESSES_PAGE;

/// Whether a resync may evict the slot of `badge`: every badge at or above
/// `LOG_BADGE_FIRST_CHILD`, which only procmgr-spawned children carry. The
/// system specials below it (init, procmgr) have no procmgr table entry.
#[must_use]
pub const fn is_resync_candidate(badge: u64) -> bool
{
    badge >= LOG_BADGE_FIRST_CHILD
}

/// Check one `QUERY_LIVE_PROCESSES` reply against the cursor `after` the
/// request named, and return its badges and whether the walk continues.
///
/// The reply is wire input. `None` for an error label, a count over
/// [`LIVE_PROCESSES_PAGE`] or past the reply's data words, or badges that are
/// not strictly ascending from `after`; the last check also guarantees each
/// page moves the cursor forward, so a walk always ends. A page of exactly
/// [`LIVE_PROCESSES_PAGE`] badges continues the walk; a shorter one ends it.
#[must_use]
pub fn decode_live_page(reply: &IpcMessage, after: Option<u64>) -> Option<(&[u64], bool)>
{
    if reply.label != ipc::procmgr_errors::SUCCESS
    {
        return None;
    }
    let words = reply.words();
    let count = usize::try_from(*words.first()?).ok()?;
    if count > LIVE_PROCESSES_PAGE
    {
        return None;
    }
    let badges = words.get(1..=count)?;
    let mut prev = after;
    for &badge in badges
    {
        if prev.is_some_and(|p| badge <= p)
        {
            return None;
        }
        prev = Some(badge);
    }
    Some((badges, count == LIVE_PROCESSES_PAGE))
}

/// The snapshot badges absent from `live`: the senders that died while
/// their death post was lost. Both slices are sorted ascending (a full walk
/// lists `live` in order), so one merge pass finds them.
pub fn evictable<'a>(snapshot: &'a [u64], live: &'a [u64]) -> impl Iterator<Item = u64> + 'a
{
    let mut live = live.iter().peekable();
    snapshot.iter().copied().filter(move |&badge| {
        while live.next_if(|&&l| l < badge).is_some()
        {}
        live.peek() != Some(&&badge)
    })
}

/// When logd's live-process walks run: at most one at a time, and, when a
/// drain asks for a resync while one is in flight, exactly one more once it
/// ends, since the running walk's snapshot and list may miss the deaths
/// dropped meanwhile. Requests made during a walk coalesce into that one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkGate
{
    /// A walk has started and not yet ended.
    in_flight: bool,
    /// A resync was asked for while a walk was in flight.
    due: bool,
}

impl WalkGate
{
    /// A gate with no walk in flight and none due.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            in_flight: false,
            due: false,
        }
    }

    /// A drain asks for a resync. Returns `true` when the caller is to start
    /// a walk now (the gate then counts it in flight); `false` when one is in
    /// flight, which marks another due.
    pub fn request(&mut self) -> bool
    {
        if self.in_flight
        {
            self.due = true;
            return false;
        }
        self.in_flight = true;
        true
    }

    /// The walk the gate let start could not begin (no memory for the
    /// snapshot, or the helper thread did not spawn): nothing is in flight.
    pub fn abandon(&mut self)
    {
        self.in_flight = false;
    }

    /// The in-flight walk ended. Returns `true` when the caller is to start
    /// the walk marked due meanwhile, which the gate then counts in flight.
    pub fn finished(&mut self) -> bool
    {
        self.in_flight = false;
        if self.due
        {
            self.due = false;
            self.in_flight = true;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn page(label: u64, badges: &[u64]) -> IpcMessage
    {
        IpcMessage::builder(label)
            .word(0, badges.len() as u64)
            .words(1, badges)
            .build()
    }

    #[test]
    fn only_child_badges_are_resync_candidates()
    {
        assert!(!is_resync_candidate(ipc::log_badges::LOG_BADGE_INIT));
        assert!(!is_resync_candidate(ipc::log_badges::LOG_BADGE_PROCMGR));
        assert!(!is_resync_candidate(LOG_BADGE_FIRST_CHILD - 1));
        assert!(is_resync_candidate(LOG_BADGE_FIRST_CHILD));
    }

    #[test]
    fn a_short_page_ends_the_walk_and_a_full_page_continues_it()
    {
        let reply = page(ipc::procmgr_errors::SUCCESS, &[20, 30]);
        assert_eq!(
            decode_live_page(&reply, Some(10)),
            Some((&[20, 30][..], false))
        );
        let full: Vec<u64> = (1..=LIVE_PROCESSES_PAGE as u64).map(|i| i * 100).collect();
        let reply = page(ipc::procmgr_errors::SUCCESS, &full);
        assert_eq!(decode_live_page(&reply, None), Some((&full[..], true)));
        let reply = page(ipc::procmgr_errors::SUCCESS, &[]);
        assert_eq!(decode_live_page(&reply, Some(5)), Some((&[][..], false)));
    }

    #[test]
    fn a_page_that_does_not_advance_the_cursor_is_refused()
    {
        let ok = ipc::procmgr_errors::SUCCESS;
        // A badge at or below the cursor would let a walk loop forever.
        assert_eq!(decode_live_page(&page(ok, &[10]), Some(10)), None);
        assert_eq!(decode_live_page(&page(ok, &[30, 20]), None), None);
        assert_eq!(decode_live_page(&page(ok, &[20, 20]), Some(1)), None);
    }

    #[test]
    fn a_malformed_or_refused_reply_is_rejected()
    {
        let refused = page(ipc::procmgr_errors::UNAUTHORIZED, &[20]);
        assert_eq!(decode_live_page(&refused, None), None);
        // A count past the page bound, and one past the words carried.
        let over = IpcMessage::builder(ipc::procmgr_errors::SUCCESS)
            .word(0, LIVE_PROCESSES_PAGE as u64 + 1)
            .build();
        assert_eq!(decode_live_page(&over, None), None);
        let short = IpcMessage::builder(ipc::procmgr_errors::SUCCESS)
            .word(0, 3)
            .word(1, 20)
            .build();
        assert_eq!(decode_live_page(&short, None), None);
        let empty = IpcMessage::builder(ipc::procmgr_errors::SUCCESS).build();
        assert_eq!(decode_live_page(&empty, None), None);
    }

    #[test]
    fn evictable_lists_the_snapshot_badges_the_walk_did_not_find()
    {
        let ev = |snap: &[u64], live: &[u64]| evictable(snap, live).collect::<Vec<_>>();
        assert_eq!(ev(&[16, 40, 90, 120], &[16, 17, 90, 200]), [40, 120]);
        assert_eq!(ev(&[16, 40], &[]), [16, 40]);
        assert!(ev(&[], &[16]).is_empty());
        assert!(ev(&[16, 40], &[16, 40]).is_empty());
    }

    #[test]
    fn an_idle_gate_starts_a_walk_and_a_quiet_finish_starts_none()
    {
        let mut gate = WalkGate::new();
        assert!(gate.request());
        assert!(!gate.finished());
        // Idle again: the next request starts a walk.
        assert!(gate.request());
    }

    #[test]
    fn requests_during_a_walk_coalesce_into_one_more_walk()
    {
        let mut gate = WalkGate::new();
        assert!(gate.request());
        assert!(!gate.request());
        assert!(!gate.request());
        // The walk ends: exactly one more starts, and its end starts none.
        assert!(gate.finished());
        assert!(!gate.finished());
    }

    #[test]
    fn a_request_during_the_follow_up_walk_is_honoured_too()
    {
        let mut gate = WalkGate::new();
        assert!(gate.request());
        assert!(!gate.request());
        assert!(gate.finished());
        assert!(!gate.request());
        assert!(gate.finished());
        assert!(!gate.finished());
    }

    #[test]
    fn an_abandoned_walk_leaves_the_gate_idle()
    {
        let mut gate = WalkGate::new();
        assert!(gate.request());
        gate.abandon();
        assert!(gate.request());
    }
}
