// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/anchor.rs

//! How a restarted driver's commit makes one entry of a unit's anchor hold
//! the value it staged (`iommu_labels::COMMIT`).
//!
//! A unit keeps translating from its anchor, the root page devmgr keeps for
//! the boot, while a restarted driver builds devmgr's replayed domains under
//! a staging root of its own. The commit then copies each staged entry into
//! the anchor while the unit walks it: a VT-d root entry, a RISC-V non-leaf
//! directory entry, or a RISC-V one-level directory's device context. Each
//! is one to eight 64-bit words whose first word holds the valid (present)
//! bit in bit 0, and the unit reads each 64-bit word of it atomically (VT-d
//! specification chapter 9; RISC-V IOMMU specification § Updating in-memory
//! data structure entries). [`entry_steps`] gives the stores, and the
//! invalidation, that make the anchor's entry hold the staged value, from
//! the value it holds, in an order that never lets the unit read a valid
//! entry beside a stale word:
//!
//! 1. equal: nothing is written;
//! 2. valid in both, differing in one word: that one store, which the unit
//!    sees whole, old or new, both naming tables of the same ranges under
//!    the same domain ID;
//! 3. valid to not valid (a function the replay did not attach again): the
//!    valid-bearing word first, the function blocked from that store on,
//!    then the others;
//! 4. not valid to valid, or not valid in both: the other words first, the
//!    valid-bearing word last;
//! 5. valid in both, differing in more than one word, which only an entry
//!    the dead instance left unlike devmgr's records reaches: the entry is
//!    made not valid, the unit's cached copy invalidated, then written as in
//!    case 4. That one function's requests fault for the window.
//!
//! [`table_steps`] gives them for a whole table page, entry by entry.
//!
//! A driver building an entry wider than 64 bits whose words must change
//! together (a VT-d scalable-mode root or context entry) would need a
//! 128-bit atomic store in place of case 2; neither driver builds one.

use alloc::vec::Vec;

/// The valid bit of an anchor entry's first word.
const VALID: u64 = 1;

/// The most words one anchor entry has: a RISC-V extended-format device
/// context.
pub const MAX_ENTRY_WORDS: usize = 8;

/// The most steps one entry's update takes: case 5's invalidation and two
/// stores of the first word, beside one store of each other word.
const MAX_STEPS: usize = MAX_ENTRY_WORDS + 2;

/// What making an anchor entry hold its staged value takes
/// ([`entry_steps`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryUpdate
{
    /// The entry holds the staged value already.
    Equal,
    /// Both are valid and differ in the one word at this index.
    Word(usize),
    /// The entry is valid and the staged value is not.
    Clear,
    /// The entry is not valid.
    Fill,
    /// Both are valid and differ in more than one word.
    Replace,
}

/// One step of an entry's update, made in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step
{
    /// Store `value` to word `word` of the entry: one volatile 64-bit
    /// store, ordered before every later step.
    Store
    {
        /// The word's index in the entry.
        word: usize,
        /// What it holds from the store on.
        value: u64,
    },
    /// Invalidate the unit's cached copy of the entry and wait for the
    /// invalidation to complete.
    Invalidate,
}

/// The steps that make one anchor entry hold its staged value, and the case
/// they make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Steps
{
    update: EntryUpdate,
    list: [Step; MAX_STEPS],
    len: usize,
}

impl Steps
{
    /// The case the steps make.
    #[must_use]
    pub fn update(&self) -> EntryUpdate
    {
        self.update
    }

    /// The steps, in the order they are made.
    pub fn iter(&self) -> impl Iterator<Item = Step> + '_
    {
        self.list.iter().take(self.len).copied()
    }

    fn push(&mut self, step: Step)
    {
        // Every update takes at most `MAX_STEPS` steps.
        if let Some(slot) = self.list.get_mut(self.len)
        {
            *slot = step;
            self.len = self.len.saturating_add(1);
        }
    }

    /// A store of each word but the first that differs, highest first.
    fn others(&mut self, old: &[u64], new: &[u64])
    {
        for (word, (o, n)) in old.iter().zip(new).enumerate().skip(1).rev()
        {
            if o != n
            {
                self.push(Step::Store { word, value: *n });
            }
        }
    }
}

/// The steps that make an anchor entry holding `old` hold `new`, of the
/// same width, at most [`MAX_ENTRY_WORDS`] words; words past it are not
/// looked at.
#[must_use]
pub fn entry_steps(old: &[u64], new: &[u64]) -> Steps
{
    let old = old.get(..MAX_ENTRY_WORDS).unwrap_or(old);
    let new = new.get(..MAX_ENTRY_WORDS).unwrap_or(new);
    let valid = |e: &[u64]| e.first().is_some_and(|w| w & VALID != 0);
    let first = new.first().copied().unwrap_or(0);
    let mut differing = old.iter().zip(new).enumerate().filter(|(_, (o, n))| o != n);
    let mut steps = Steps {
        update: EntryUpdate::Equal,
        list: [Step::Invalidate; MAX_STEPS],
        len: 0,
    };
    let Some((at, _)) = differing.next()
    else
    {
        return steps;
    };
    steps.update = match (valid(old), valid(new))
    {
        (true, false) =>
        {
            steps.push(Step::Store {
                word: 0,
                value: first,
            });
            steps.others(old, new);
            EntryUpdate::Clear
        }
        (false, _) =>
        {
            steps.others(old, new);
            if old.first() != new.first()
            {
                steps.push(Step::Store {
                    word: 0,
                    value: first,
                });
            }
            EntryUpdate::Fill
        }
        (true, true) if differing.next().is_none() =>
        {
            let value = new.get(at).copied().unwrap_or(0);
            steps.push(Step::Store { word: at, value });
            EntryUpdate::Word(at)
        }
        (true, true) =>
        {
            steps.push(Step::Store { word: 0, value: 0 });
            steps.push(Step::Invalidate);
            steps.others(old, new);
            steps.push(Step::Store {
                word: 0,
                value: first,
            });
            EntryUpdate::Replace
        }
    };
    steps
}

/// Every step that makes the table page `held` hold `staged`, entry by
/// entry of `width` words ([`entry_steps`]), each with the index of its
/// entry, a store naming its word's index in the page; none for a `width`
/// of 0 or past [`MAX_ENTRY_WORDS`]. Entries past the shorter page, and a
/// last entry either page holds only part of, are not looked at.
#[must_use]
pub fn table_steps(held: &[u64], staged: &[u64], width: usize) -> Vec<(usize, Step)>
{
    if width == 0 || width > MAX_ENTRY_WORDS
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    let entries = held.chunks_exact(width).zip(staged.chunks_exact(width));
    for (entry, (old, new)) in entries.enumerate()
    {
        let base = entry.saturating_mul(width);
        for step in entry_steps(old, new).iter()
        {
            let step = match step
            {
                Step::Store { word, value } => Step::Store {
                    word: base.saturating_add(word),
                    value,
                },
                Step::Invalidate => Step::Invalidate,
            };
            out.push((entry, step));
        }
    }
    out
}

#[cfg(test)]
mod tests
{
    use alloc::vec;

    use super::*;

    /// The case and steps from `old` to `new`, and the entry they leave.
    fn apply(old: &[u64], new: &[u64]) -> (EntryUpdate, Vec<Step>, Vec<u64>)
    {
        let steps = entry_steps(old, new);
        let mut entry = old.to_vec();
        for step in steps.iter()
        {
            if let Step::Store { word, value } = step
            {
                entry[word] = value;
            }
        }
        (steps.update(), steps.iter().collect(), entry)
    }

    fn store(word: usize, value: u64) -> Step
    {
        Step::Store { word, value }
    }

    #[test]
    fn an_equal_entry_takes_no_step()
    {
        assert_eq!(apply(&[0x1001, 0], &[0x1001, 0]).1, []);
        assert_eq!(apply(&[0, 0], &[0, 0]).1, []);
        assert_eq!(apply(&[0, 0], &[0, 0]).0, EntryUpdate::Equal);
    }

    #[test]
    fn a_valid_entry_differing_in_one_word_takes_that_store_alone()
    {
        // A VT-d root entry or a RISC-V non-leaf entry: a new table.
        let (update, steps, entry) = apply(&[0x1001, 0], &[0x2001, 0]);
        assert_eq!(update, EntryUpdate::Word(0));
        assert_eq!(steps, [store(0, 0x2001)]);
        assert_eq!(entry, [0x2001, 0]);
        // A RISC-V device context whose first-stage root moved: `fsc` alone.
        let fsc = |root: u64| (0x8 << 60) | root;
        let (update, steps, _) = apply(&[1, 0, 7 << 12, fsc(5)], &[1, 0, 7 << 12, fsc(9)]);
        assert_eq!(update, EntryUpdate::Word(3));
        assert_eq!(steps, [store(3, fsc(9))]);
    }

    #[test]
    fn a_valid_entry_staged_not_valid_is_blocked_by_its_first_store()
    {
        let (update, steps, entry) = apply(&[1, 0, 7 << 12, 5], &[0, 0, 0, 0]);
        assert_eq!(update, EntryUpdate::Clear);
        assert_eq!(steps, [store(0, 0), store(3, 0), store(2, 0)]);
        assert_eq!(entry, [0, 0, 0, 0]);
    }

    #[test]
    fn a_not_valid_entry_takes_its_valid_word_last()
    {
        let (update, steps, entry) = apply(&[0, 0, 0, 0], &[1, 0, 7 << 12, 5]);
        assert_eq!(update, EntryUpdate::Fill);
        assert_eq!(steps, [store(3, 5), store(2, 7 << 12), store(0, 1)]);
        assert_eq!(entry, [1, 0, 7 << 12, 5]);
        // Stale words beside a clear valid bit are rewritten, the entry left
        // not valid and its first word not stored.
        let (update, steps, entry) = apply(&[0, 0, 3 << 12, 4], &[0, 0, 0, 0]);
        assert_eq!(update, EntryUpdate::Fill);
        assert_eq!(steps, [store(3, 0), store(2, 0)]);
        assert_eq!(entry, [0, 0, 0, 0]);
    }

    #[test]
    fn a_valid_entry_differing_in_two_words_is_invalidated_before_its_rewrite()
    {
        let (update, steps, entry) = apply(&[1, 0, 6 << 12, 5], &[1, 0, 7 << 12, 9]);
        assert_eq!(update, EntryUpdate::Replace);
        assert_eq!(
            steps,
            [
                store(0, 0),
                Step::Invalidate,
                store(3, 9),
                store(2, 7 << 12),
                store(0, 1)
            ]
        );
        assert_eq!(entry, [1, 0, 7 << 12, 9]);
    }

    /// Apply `steps` to `table`, checking each entry's steps are
    /// contiguous and in entry order.
    fn apply_table(table: &mut [u64], steps: &[(usize, Step)], width: usize)
    {
        let mut last = 0;
        for &(entry, step) in steps
        {
            assert!(entry >= last);
            last = entry;
            if let Step::Store { word, value } = step
            {
                assert_eq!(word / width, entry);
                table[word] = value;
            }
        }
    }

    #[test]
    fn a_table_takes_each_entrys_steps_in_entry_order()
    {
        // A VT-d root table: bus 0 moved to a new context table, bus 1
        // dropped, bus 2 new, bus 3 kept.
        let mut held = vec![0u64; 512];
        let mut staged = vec![0u64; 512];
        held[..8].copy_from_slice(&[0x1001, 0, 0x2001, 0, 0, 0, 0x4001, 0]);
        staged[..8].copy_from_slice(&[0x5001, 0, 0, 0, 0x6001, 0, 0x4001, 0]);
        let steps = table_steps(&held, &staged, 2);
        assert_eq!(
            steps,
            [
                (0, store(0, 0x5001)),
                (1, store(2, 0)),
                (2, store(4, 0x6001))
            ]
        );
        apply_table(&mut held, &steps, 2);
        assert_eq!(held, staged);
    }

    #[test]
    fn a_table_of_wide_entries_is_copied_whole()
    {
        // A RISC-V one-level directory of 4-word device contexts.
        let mut held = vec![0u64; 512];
        let mut staged = vec![0u64; 512];
        held[..8].copy_from_slice(&[1, 0, 6 << 12, 5, 1, 0, 0, 8]);
        staged[..12].copy_from_slice(&[1, 0, 7 << 12, 9, 1, 0, 0, 9, 1, 0, 0, 3]);
        let steps = table_steps(&held, &staged, 4);
        assert_eq!(
            steps,
            [
                (0, store(0, 0)),
                (0, Step::Invalidate),
                (0, store(3, 9)),
                (0, store(2, 7 << 12)),
                (0, store(0, 1)),
                (1, store(7, 9)),
                (2, store(11, 3)),
                (2, store(8, 1))
            ]
        );
        apply_table(&mut held, &steps, 4);
        assert_eq!(held, staged);
        assert_eq!(table_steps(&held, &staged, 0), []);
        assert_eq!(table_steps(&held, &staged, MAX_ENTRY_WORDS + 1), []);
    }

    #[test]
    fn the_widest_entry_fits_its_steps()
    {
        let old = [1u64, 1, 1, 1, 1, 1, 1, 1];
        let new = [3u64, 2, 2, 2, 2, 2, 2, 2];
        let (update, steps, entry) = apply(&old, &new);
        assert_eq!(update, EntryUpdate::Replace);
        assert_eq!(steps.len(), MAX_STEPS);
        assert_eq!(entry, new);
    }
}
