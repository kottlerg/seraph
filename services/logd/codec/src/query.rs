// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/query.rs

//! Which entries a logd query page carries (`services/logd/docs/ipc-interface.md`
//! § Queries): [`slot_page`] for `QUERY_SLOTS`, [`history_page`] for
//! `QUERY_HISTORY`. Each selects from logd's state, without allocating, the
//! page after the request's resume point, so a logd receive worker answers a
//! query from the state logd owns. The pages are built with `ipc::log_query`,
//! the wire format the client reads.

use ipc::log_query::{
    HISTORY_BYTES_MAX, HistoryEntryView, HistoryPage, HistoryRequest, SLOT_NAME_MAX, SlotCursor,
    SlotFields, SlotPage,
};
use ipc::log_record::RECORD_MAX_BYTES;

use crate::{LINE_BUF_SIZE, MAX_NAME_LEN};

// A slot entry carries a whole name, and a history reply a whole entry of
// either kind, so a page is never empty while entries are left.
const _: () = assert!(MAX_NAME_LEN == SLOT_NAME_MAX);
const _: () = assert!(HISTORY_BYTES_MAX >= LINE_BUF_SIZE && HISTORY_BYTES_MAX >= RECORD_MAX_BYTES);

/// The `QUERY_SLOTS` page after `after` (from the first entry when `None`):
/// the rows `rows()` yields, ascending by badge and then state, as many as one
/// page holds, and whether any row follows them. `rows` walks logd's slots
/// afresh, in any order; it is called once per entry the page takes, and once
/// more.
pub fn slot_page<'a, F, I>(rows: F, after: Option<SlotCursor>) -> (SlotPage, bool)
where
    F: Fn() -> I,
    I: Iterator<Item = SlotFields<'a>>,
{
    let key = |r: &SlotFields<'_>| (r.badge, r.state);
    let mut page = SlotPage::default();
    let mut cursor = after.map(|c| (c.badge, c.state));
    loop
    {
        let next = rows()
            .filter(|r| cursor.is_none_or(|c| key(r) > c))
            .min_by_key(key);
        let Some(row) = next
        else
        {
            return (page, false);
        };
        if !page.push(&row)
        {
            return (page, true);
        }
        cursor = Some(key(&row));
    }
}

/// One history entry as [`history_page`] reads it: the entry, and its
/// sender's badge, which the entry's wire form names by its slot serial.
#[derive(Clone, Copy, Debug)]
pub struct HistoryRow<'a>
{
    pub badge: u64,
    pub entry: HistoryEntryView<'a>,
}

/// The `QUERY_HISTORY` page for `req`: of `walk`, logd's entries in the
/// order of `req`'s walk from its start (newest first from before its
/// `before`, or oldest first from its `from`), those that match its badge
/// and its level, as many whole entries as one reply holds, and whether a
/// matching entry follows them.
pub fn history_page<'a>(
    walk: impl Iterator<Item = HistoryRow<'a>>,
    req: &HistoryRequest,
) -> (HistoryPage, bool)
{
    let mut page = HistoryPage::default();
    let matching = walk
        .filter(|r| req.badge.is_none_or(|b| r.badge == b))
        .filter(|r| req.least.is_none_or(|least| r.entry.level <= least));
    for row in matching
    {
        if !page.push(&row.entry)
        {
            return (page, true);
        }
    }
    (page, false)
}

#[cfg(test)]
mod tests
{
    use ipc::log_query::{
        ENTRY_RECORD, ENTRY_TEXT, HistoryEntries, ORIGIN_LIVE, SLOT_EVICTED_DEATH,
        SLOT_EVICTED_RESYNC, SLOT_LIVE, SLOTS_PAGE, Walk, reply_count, reply_more, slot_entry,
    };

    use super::*;

    fn slots() -> Vec<(u64, u8, u64, Vec<u8>)>
    {
        // Out of order, a badge live and retired, more than one page.
        let mut v = vec![
            (40, SLOT_EVICTED_DEATH, 0x17, b"child".to_vec()),
            (40, SLOT_LIVE, 0, b"reborn".to_vec()),
            (3, SLOT_LIVE, 0, Vec::new()),
            (u64::MAX, SLOT_EVICTED_RESYNC, 0, b"last".to_vec()),
        ];
        for b in 100..110
        {
            v.push((b, SLOT_LIVE, 0, format!("s{b}").into_bytes()));
        }
        v
    }

    fn walk_slots(table: &[(u64, u8, u64, Vec<u8>)]) -> Vec<(u64, u8, u64, Vec<u8>)>
    {
        let rows = || {
            table
                .iter()
                .map(|(badge, state, exit_reason, name)| SlotFields {
                    badge: *badge,
                    state: *state,
                    exit_reason: *exit_reason,
                    serial: badge.wrapping_add(1),
                    generation: 0,
                    name,
                })
        };
        let mut out = Vec::new();
        let mut after = None;
        loop
        {
            let (page, more) = slot_page(rows, after);
            let reply = page.reply(more);
            assert!(reply_count(reply.label) <= SLOTS_PAGE);
            for i in 0..reply_count(reply.label)
            {
                let e = slot_entry(&reply, i).expect("entry");
                out.push((e.badge, e.state, e.exit_reason, e.name().to_vec()));
                after = Some(e.cursor());
            }
            if !reply_more(reply.label)
            {
                return out;
            }
        }
    }

    #[test]
    fn slot_walk_visits_every_slot_once_in_order()
    {
        let table = slots();
        let out = walk_slots(&table);
        let mut want = table.clone();
        want.sort_by_key(|r| (r.0, r.1));
        assert_eq!(out, want);
    }

    #[test]
    fn slot_walk_of_an_empty_table_is_one_empty_page()
    {
        assert_eq!(walk_slots(&[]), [] as [(u64, u8, u64, Vec<u8>); 0]);
        let (page, more) = slot_page(core::iter::empty, None);
        assert!(!more);
        assert_eq!(reply_count(page.reply(more).label), 0);
    }

    #[test]
    fn slot_walk_of_exactly_one_page_reports_no_more()
    {
        let table: Vec<_> = (0..SLOTS_PAGE as u64)
            .map(|b| (b, SLOT_LIVE, 0, Vec::new()))
            .collect();
        let rows = || {
            table
                .iter()
                .map(|(badge, state, exit_reason, name)| SlotFields {
                    badge: *badge,
                    state: *state,
                    exit_reason: *exit_reason,
                    serial: badge.wrapping_add(1),
                    generation: 0,
                    name,
                })
        };
        let (page, more) = slot_page(rows, None);
        assert!(!more);
        assert!(page.is_full());
    }

    struct Entry
    {
        seq: u64,
        badge: u64,
        level: u8,
        kind: u8,
        bytes: Vec<u8>,
    }

    fn history() -> Vec<Entry>
    {
        // Two senders interleaved, with entries long enough that a page holds
        // few of them, at levels 0 to 7 by seq; the store is in seq order, as
        // logd's history is.
        let mut v = Vec::new();
        for (badge, seqs) in [(7u64, [1u64, 4, 5, 9]), (8, [2, 3, 6, 8])]
        {
            for seq in seqs
            {
                let len = if seq % 2 == 0 { 200 } else { 13 };
                v.push(Entry {
                    seq,
                    badge,
                    level: u8::try_from(seq % 8).unwrap(),
                    kind: if seq == 9 { ENTRY_RECORD } else { ENTRY_TEXT },
                    bytes: vec![u8::try_from(seq).unwrap(); len],
                });
            }
        }
        v.push(Entry {
            seq: 7,
            badge: 7,
            level: 7,
            kind: ENTRY_RECORD,
            bytes: vec![0xEE; RECORD_MAX_BYTES],
        });
        v.sort_by_key(|e| e.seq);
        v
    }

    fn row(e: &Entry) -> HistoryRow<'_>
    {
        HistoryRow {
            badge: e.badge,
            entry: HistoryEntryView {
                seq: e.seq,
                us: e.seq * 1000,
                serial: e.badge * 10,
                generation: 1,
                level: e.level,
                kind: e.kind,
                origin: ORIGIN_LIVE,
                bytes: &e.bytes,
            },
        }
    }

    /// The walk logd's history gives `history_page` for `walk`.
    fn walk_of(store: &[Entry], walk: Walk) -> Vec<HistoryRow<'_>>
    {
        match walk
        {
            Walk::Down { before } => store
                .iter()
                .rev()
                .filter(|e| before.is_none_or(|b| e.seq < b))
                .map(row)
                .collect(),
            Walk::Up { from, .. } => store.iter().filter(|e| e.seq >= from).map(row).collect(),
        }
    }

    /// Walk `store` page by page as a client does: the seq, badge (by
    /// serial), kind and length of each entry read.
    fn walk_history(
        store: &[Entry],
        badge: Option<u64>,
        least: Option<u8>,
        mut walk: Walk,
    ) -> Vec<(u64, u64, u8, usize)>
    {
        let mut out = Vec::new();
        loop
        {
            let req = HistoryRequest { badge, walk, least };
            let (page, more) = history_page(walk_of(store, walk).into_iter(), &req);
            let reply = page.reply(more);
            let read: Vec<_> = HistoryEntries::new(&reply).collect();
            assert_eq!(read.len(), reply_count(reply.label));
            assert!(!read.is_empty() || !more, "an empty page that claims more");
            for e in &read
            {
                assert_eq!(e.us, e.seq * 1000);
                assert!(e.bytes.iter().all(|&b| b == e.bytes[0]));
                assert!(least.is_none_or(|l| e.level <= l));
                out.push((e.seq, e.serial / 10, e.kind, e.bytes.len()));
                walk = match walk
                {
                    Walk::Down { .. } => Walk::Down {
                        before: Some(e.seq),
                    },
                    Walk::Up { epoch, .. } => Walk::Up {
                        from: e.seq + 1,
                        epoch,
                    },
                };
            }
            if !more
            {
                return out;
            }
        }
    }

    const DOWN: Walk = Walk::Down { before: None };
    const UP: Walk = Walk::Up { from: 0, epoch: 0 };

    fn seqs(out: &[(u64, u64, u8, usize)]) -> Vec<u64>
    {
        out.iter().map(|e| e.0).collect()
    }

    #[test]
    fn history_walk_is_newest_first_across_senders()
    {
        let out = walk_history(&history(), None, None, DOWN);
        assert_eq!(seqs(&out), [9, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(out[2], (7, 7, ENTRY_RECORD, RECORD_MAX_BYTES));
    }

    #[test]
    fn history_walk_of_one_badge()
    {
        let out = walk_history(&history(), Some(8), None, DOWN);
        assert_eq!(seqs(&out), [8, 6, 3, 2]);
        assert!(out.iter().all(|e| e.1 == 8));
        assert_eq!(
            walk_history(&history(), Some(99), None, DOWN),
            [] as [(u64, u64, u8, usize); 0]
        );
    }

    #[test]
    fn history_walk_resumes_before_a_seq()
    {
        let store = history();
        let req = HistoryRequest {
            walk: Walk::Down { before: Some(3) },
            ..HistoryRequest::default()
        };
        let (page, more) = history_page(walk_of(&store, req.walk).into_iter(), &req);
        assert!(!more);
        let reply = page.reply(more);
        let seqs: Vec<u64> = HistoryEntries::new(&reply).map(|e| e.seq).collect();
        assert_eq!(seqs, [2, 1]);
    }

    // Defect caught: a follower's ascending walk that skips, repeats or
    // reorders entries across its pages, or loses the entry it resumes from.
    #[test]
    fn ascending_walk_is_oldest_first_and_resumes_at_its_from()
    {
        let store = history();
        let out = walk_history(&store, None, None, UP);
        assert_eq!(seqs(&out), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(out[6], (7, 7, ENTRY_RECORD, RECORD_MAX_BYTES));
        let from_7 = walk_history(&store, None, None, Walk::Up { from: 7, epoch: 5 });
        assert_eq!(seqs(&from_7), [7, 8, 9]);
        let past = walk_history(&store, None, None, Walk::Up { from: 10, epoch: 5 });
        assert_eq!(past, [] as [(u64, u64, u8, usize); 0]);
        let one = walk_history(&store, Some(7), None, UP);
        assert_eq!(seqs(&one), [1, 4, 5, 7, 9]);
    }

    // Defect caught: the severity filter letting a less severe entry through,
    // dropping a more severe one, or ending a walk early at a filtered entry.
    #[test]
    fn severity_filter_keeps_the_level_and_the_more_severe_both_ways()
    {
        let store = history();
        // Levels by seq: seq % 8, and 7 for the record at seq 7.
        let up = walk_history(&store, None, Some(3), UP);
        assert_eq!(seqs(&up), [1, 2, 3, 8, 9]);
        let down = walk_history(&store, None, Some(3), DOWN);
        assert_eq!(seqs(&down), [9, 8, 3, 2, 1]);
        let emerg = walk_history(&store, Some(8), Some(0), DOWN);
        assert_eq!(seqs(&emerg), [8]);
        let all = walk_history(&store, None, Some(7), UP);
        assert_eq!(all.len(), store.len());
    }

    #[test]
    fn page_ends_with_more_only_when_a_matching_entry_is_left()
    {
        // A page that fills on the last matching entry says no more, though
        // entries the filter drops follow it.
        let store: Vec<Entry> = (1..=4)
            .map(|seq| Entry {
                seq,
                badge: 1,
                level: if seq == 1 { 0 } else { 7 },
                kind: ENTRY_TEXT,
                bytes: vec![1; HISTORY_BYTES_MAX],
            })
            .collect();
        let req = HistoryRequest {
            least: Some(0),
            walk: UP,
            ..HistoryRequest::default()
        };
        let (page, more) = history_page(walk_of(&store, UP).into_iter(), &req);
        assert!(!more);
        assert_eq!(reply_count(page.reply(more).label), 1);
    }
}
