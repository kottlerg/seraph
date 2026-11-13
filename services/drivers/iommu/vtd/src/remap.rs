// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/remap.rs

//! Interrupt remapping: the remapping table's entries (IRTEs) and the
//! `IRTA` register value that points a unit at the table (Intel VT-d
//! specification rev. 4.1, section 9.10, "Interrupt Remapping Table Entry
//! (IRTE) for Remapped Interrupts", and section 11.4.10).
//!
//! With remapping on, a remappable-format interrupt names a table entry by
//! its handle, and the entry alone says which CPU, vector, and trigger mode
//! the interrupt is delivered with, and which requester may send it.

use iommu_core::RemapEntry;

/// Bytes one remapping table entry takes.
pub const ENTRY_BYTES: u64 = 16;

/// `IRTE` low word: present.
pub const IRTE_PRESENT: u64 = 1;
/// `IRTE` low word: level-triggered (`TM`, bit 4); edge when clear.
const IRTE_LEVEL: u64 = 1 << 4;
/// `IRTE` high word: verify the requester's full source ID (`SVT` = 01,
/// bits 19:18) against the entry's, with every bit compared (`SQ` = 0).
const IRTE_VERIFY_SOURCE_ID: u64 = 1 << 18;
/// `IRTA`: extended interrupt mode, 32-bit (x2APIC) destination IDs
/// (bit 11).
const IRTA_EIME: u64 = 1 << 11;

/// The two words of a present entry delivering `entry`: fixed delivery,
/// physical destination mode, redirection hint clear, faults recorded, and
/// the requester verified by its full source ID. `extended` selects the
/// 32-bit destination field (extended interrupt mode); without it the 8-bit
/// xAPIC ID sits in bits 15:8 of the field.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`extended` is the IRTA EIME mode, which defines the destination field's format"
)]
pub const fn entry(entry: RemapEntry, extended: bool) -> [u64; 2]
{
    let destination = if extended
    {
        entry.destination as u64
    }
    else
    {
        ((entry.destination & 0xff) as u64) << 8
    };
    let level = if entry.level { IRTE_LEVEL } else { 0 };
    [
        IRTE_PRESENT | level | ((entry.vector as u64) << 16) | (destination << 32),
        IRTE_VERIFY_SOURCE_ID | entry.source_id as u64,
    ]
}

/// The `IRTA` value for a table of `entries` entries (a power of two from 2
/// to [`iommu_core::MAX_REMAP_ENTRIES`]) at the physical address `base`, page-aligned:
/// the size field (bits 3:0) holds `log2(entries) - 1`, and `extended` sets
/// extended interrupt mode.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`extended` is the IRTA EIME bit the function encodes"
)]
pub const fn irta(base: u64, entries: u32, extended: bool) -> u64
{
    let eime = if extended { IRTA_EIME } else { 0 };
    // `entries` is 2 at least, so `log2(entries)` is 1 at least.
    (base & !0xfff) | eime | entries.trailing_zeros().saturating_sub(1) as u64
}

/// What making a table entry hold the words `new` takes, given the words
/// it `held` ([`update`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update
{
    /// The entry holds `new` already: nothing is written or invalidated, so
    /// an interrupt it is delivering meets no gap.
    Unchanged,
    /// The entry is not present: `new` is written, high word first.
    Write,
    /// The entry is present with other contents: it is made not present
    /// and invalidated before `new` is written, so no unit reads an entry
    /// whose two words disagree.
    Replace,
}

/// What making an entry that holds `held` hold `new` takes.
#[must_use]
pub fn update(held: [u64; 2], new: [u64; 2]) -> Update
{
    if held[0] & IRTE_PRESENT == 0
    {
        Update::Write
    }
    else if held == new
    {
        Update::Unchanged
    }
    else
    {
        Update::Replace
    }
}

/// Entries one 4 KiB page of the table holds: 4096 / [`ENTRY_BYTES`].
const ENTRIES_PER_PAGE: u16 = 256;

/// Where entry `handle` lies in a table: the byte offset of its page from
/// the table's first page, and the word index of its low word in that page.
#[must_use]
pub const fn entry_place(handle: u16) -> (u64, usize)
{
    let page = (handle / ENTRIES_PER_PAGE) as u64;
    let entry = (handle % ENTRIES_PER_PAGE) as usize;
    // At most 255 pages of 4 KiB, and 255 entries of two words: neither
    // product nears its type's bound.
    (page.saturating_mul(4096), entry.saturating_mul(2))
}

/// Pages a table of `entries` entries takes.
#[must_use]
pub const fn table_pages(entries: u32) -> u64
{
    (entries as u64 * ENTRY_BYTES).div_ceil(4096)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use iommu_core::MAX_REMAP_ENTRIES;

    const UART: RemapEntry = RemapEntry {
        destination: 3,
        vector: 0x41,
        level: false,
        source_id: 0xf0f8,
    };

    #[test]
    fn an_xapic_entry_holds_the_destination_in_bits_15_to_8_of_its_field()
    {
        let [lo, hi] = entry(UART, false);
        assert_eq!(lo & 1, 1);
        assert_eq!((lo >> 16) & 0xff, 0x41);
        assert_eq!(lo >> 32, 3 << 8);
        // Fixed delivery, physical mode, no redirection hint, edge.
        assert_eq!(lo & 0xfe, 0);
        assert_eq!(hi & 0xffff, 0xf0f8);
        assert_eq!((hi >> 16) & 0x3, 0);
        assert_eq!((hi >> 18) & 0x3, 1);
    }

    #[test]
    fn an_extended_entry_holds_the_whole_x2apic_id()
    {
        let e = RemapEntry {
            destination: 0x1_0203,
            level: true,
            ..UART
        };
        let [lo, _] = entry(e, true);
        assert_eq!(lo >> 32, 0x1_0203);
        assert_eq!(lo & (1 << 4), 1 << 4);
    }

    #[test]
    fn irta_encodes_base_size_and_extended_mode()
    {
        assert_eq!(irta(0x7f00_0000, 1024, false), 0x7f00_0000 | 9);
        assert_eq!(
            irta(0x7f00_0000, MAX_REMAP_ENTRIES, true),
            0x7f00_0000 | (1 << 11) | 15
        );
        assert_eq!(irta(0x7f00_0000, 2, false) & 0xf, 0);
    }

    #[test]
    fn an_entry_already_holding_the_words_is_left_alone()
    {
        let words = entry(UART, false);
        assert_eq!(update(words, words), Update::Unchanged);
    }

    #[test]
    fn a_present_entry_with_other_words_is_replaced_and_an_absent_one_written()
    {
        let words = entry(UART, false);
        let other = entry(
            RemapEntry {
                vector: 0x42,
                ..UART
            },
            false,
        );
        assert_eq!(update(other, words), Update::Replace);
        assert_eq!(update([0, 0], words), Update::Write);
        // A not-present entry is written whatever stale words it keeps.
        assert_eq!(
            update([words[0] & !IRTE_PRESENT, words[1]], words),
            Update::Write
        );
    }

    #[test]
    fn an_entry_lies_two_words_after_the_one_before_it_and_a_page_holds_256()
    {
        assert_eq!(entry_place(0), (0, 0));
        assert_eq!(entry_place(255), (0, 510));
        assert_eq!(entry_place(256), (4096, 0));
        assert_eq!(entry_place(u16::MAX), (255 * 4096, 510));
    }

    #[test]
    fn a_table_takes_whole_pages()
    {
        assert_eq!(table_pages(2), 1);
        assert_eq!(table_pages(256), 1);
        assert_eq!(table_pages(1024), 4);
        assert_eq!(table_pages(MAX_REMAP_ENTRIES), 256);
    }
}
