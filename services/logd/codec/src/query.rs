// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/query.rs

//! Which entries a logd query page carries (`services/logd/docs/ipc-interface.md`
//! § Queries): [`slot_page`] for `QUERY_SLOTS`, [`history_page`] for
//! `QUERY_HISTORY`. Both take a closure that walks logd's state afresh, in
//! any order, and select from it the page after the request's resume point,
//! without allocating, so logd's main thread answers a query from the state
//! it owns. The pages are built with `ipc::log_query`, the wire format the
//! client reads.

use ipc::log_query::{
    HISTORY_BYTES_MAX, HistoryEntryView, HistoryPage, HistoryRequest, SLOT_NAME_MAX, SlotCursor,
    SlotPage,
};
use ipc::log_record::RECORD_MAX_BYTES;

use crate::{LINE_BUF_SIZE, MAX_NAME_LEN};

// A slot entry carries a whole name, and a history reply a whole entry of
// either kind, so a page is never empty while entries are left.
const _: () = assert!(MAX_NAME_LEN == SLOT_NAME_MAX);
const _: () = assert!(HISTORY_BYTES_MAX >= LINE_BUF_SIZE && HISTORY_BYTES_MAX >= RECORD_MAX_BYTES);

/// One slot as [`slot_page`] reads it.
#[derive(Clone, Copy, Debug)]
pub struct SlotRow<'a>
{
    pub badge: u64,
    /// `ipc::log_query::SLOT_*`.
    pub state: u8,
    pub exit_reason: u64,
    pub name: &'a [u8],
}

impl SlotRow<'_>
{
    const fn key(&self) -> (u64, u8)
    {
        (self.badge, self.state)
    }
}

/// The `QUERY_SLOTS` page after `after` (from the first entry when `None`):
/// the rows `rows()` yields, ascending by badge and then state, as many as one
/// page holds, and whether any row follows them. `rows` is called once per
/// entry the page takes, and once more.
pub fn slot_page<'a, F, I>(rows: F, after: Option<SlotCursor>) -> (SlotPage, bool)
where
    F: Fn() -> I,
    I: Iterator<Item = SlotRow<'a>>,
{
    let mut page = SlotPage::default();
    let mut cursor = after.map(|c| (c.badge, c.state));
    loop
    {
        let next = rows()
            .filter(|r| cursor.is_none_or(|c| r.key() > c))
            .min_by_key(SlotRow::key);
        let Some(row) = next
        else
        {
            return (page, false);
        };
        if !page.push(row.badge, row.state, row.exit_reason, row.name)
        {
            return (page, true);
        }
        cursor = Some(row.key());
    }
}

/// The `QUERY_HISTORY` page for `req`: the entries `entries()` yields that
/// match its badge and are older than its `before`, newest first (by `seq`),
/// as many whole entries as one reply holds, and whether any entry follows
/// them. `entries` is called once per entry the page takes, and once more.
pub fn history_page<'a, F, I>(entries: F, req: &HistoryRequest) -> (HistoryPage, bool)
where
    F: Fn() -> I,
    I: Iterator<Item = HistoryEntryView<'a>>,
{
    let mut page = HistoryPage::default();
    let mut before = req.before;
    loop
    {
        let next = entries()
            .filter(|e| req.badge.is_none_or(|b| e.badge == b))
            .filter(|e| before.is_none_or(|s| e.seq < s))
            .max_by_key(|e| e.seq);
        let Some(entry) = next
        else
        {
            return (page, false);
        };
        if !page.push(&entry)
        {
            return (page, true);
        }
        before = Some(entry.seq);
    }
}

#[cfg(test)]
mod tests
{
    use ipc::log_query::{
        ENTRY_RECORD, ENTRY_TEXT, HistoryEntries, SLOT_EVICTED_DEATH, SLOT_EVICTED_RESYNC,
        SLOT_LIVE, SLOTS_PAGE, reply_count, reply_more, slot_entry,
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
                .map(|(badge, state, exit_reason, name)| SlotRow {
                    badge: *badge,
                    state: *state,
                    exit_reason: *exit_reason,
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
        assert!(walk_slots(&[]).is_empty());
        let (page, more) = slot_page(|| core::iter::empty(), None);
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
                .map(|(badge, state, exit_reason, name)| SlotRow {
                    badge: *badge,
                    state: *state,
                    exit_reason: *exit_reason,
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
        kind: u8,
        bytes: Vec<u8>,
    }

    fn history() -> Vec<Entry>
    {
        // Two senders interleaved, stored per sender (not in seq order), with
        // entries long enough that a page holds few of them.
        let mut v = Vec::new();
        for (badge, seqs) in [(7u64, [1u64, 4, 5, 9]), (8, [2, 3, 6, 8])]
        {
            for seq in seqs
            {
                let len = if seq % 2 == 0 { 200 } else { 13 };
                v.push(Entry {
                    seq,
                    badge,
                    kind: if seq == 9 { ENTRY_RECORD } else { ENTRY_TEXT },
                    bytes: vec![seq as u8; len],
                });
            }
        }
        v.push(Entry {
            seq: 7,
            badge: 7,
            kind: ENTRY_RECORD,
            bytes: vec![0xEE; RECORD_MAX_BYTES],
        });
        v
    }

    fn walk_history(store: &[Entry], badge: Option<u64>) -> Vec<(u64, u64, u8, usize)>
    {
        let entries = || {
            store.iter().map(|e| HistoryEntryView {
                seq: e.seq,
                us: e.seq * 1000,
                badge: e.badge,
                level: 3,
                kind: e.kind,
                bytes: &e.bytes,
            })
        };
        let mut out = Vec::new();
        let mut req = HistoryRequest {
            badge,
            before: None,
        };
        loop
        {
            let (page, more) = history_page(entries, &req);
            let reply = page.reply(more);
            let read: Vec<_> = HistoryEntries::new(&reply).collect();
            assert_eq!(read.len(), reply_count(reply.label));
            assert!(!read.is_empty() || !more, "an empty page that claims more");
            for e in &read
            {
                assert_eq!(e.us, e.seq * 1000);
                assert!(e.bytes.iter().all(|&b| b == e.bytes[0]));
                out.push((e.seq, e.badge, e.kind, e.bytes.len()));
                req.before = Some(e.seq);
            }
            if !more
            {
                return out;
            }
        }
    }

    #[test]
    fn history_walk_is_newest_first_across_senders()
    {
        let out = walk_history(&history(), None);
        let seqs: Vec<u64> = out.iter().map(|e| e.0).collect();
        assert_eq!(seqs, [9, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(out[2], (7, 7, ENTRY_RECORD, RECORD_MAX_BYTES));
    }

    #[test]
    fn history_walk_of_one_badge()
    {
        let out = walk_history(&history(), Some(8));
        let seqs: Vec<u64> = out.iter().map(|e| e.0).collect();
        assert_eq!(seqs, [8, 6, 3, 2]);
        assert!(out.iter().all(|e| e.1 == 8));
        assert!(walk_history(&history(), Some(99)).is_empty());
    }

    #[test]
    fn history_walk_resumes_before_a_seq()
    {
        let store = history();
        let entries = || {
            store.iter().map(|e| HistoryEntryView {
                seq: e.seq,
                us: 0,
                badge: e.badge,
                level: 1,
                kind: e.kind,
                bytes: &e.bytes,
            })
        };
        let req = HistoryRequest {
            badge: None,
            before: Some(3),
        };
        let (page, more) = history_page(entries, &req);
        assert!(!more);
        let reply = page.reply(more);
        let seqs: Vec<u64> = HistoryEntries::new(&reply).map(|e| e.seq).collect();
        assert_eq!(seqs, [2, 1]);
    }
}
