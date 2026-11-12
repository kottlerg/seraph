// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/riscv/src/tables.rs

//! RISC-V IOMMU translation structures: the device directory, the device
//! context, and first-stage page tables (RISC-V IOMMU Architecture
//! Specification v1.0, chapter "Data Structures"; the page-table format is
//! the RISC-V Privileged Architecture's Sv39 and Sv48).
//!
//! The device context is a pure encoding. [`DeviceDirectory`] walks the
//! directory to a device's context, and [`FirstStage`] builds and walks one
//! domain's page tables, both over a [`TableStore`] that hands out zeroed
//! 4 KiB table pages with their physical addresses: memmgr frames in the
//! driver (`iommu-store`), heap pages in the host tests.

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
use alloc::vec::Vec;

use iommu_core::Access;
use iommu_core::table::TableStore;

use crate::regs::{ContextFormat, FirstStageMode, device_id_bits};

/// Bytes of one page and of one table.
pub const PAGE: u64 = 0x1000;

/// Entry valid: a non-leaf directory entry, a page-table entry.
const V: u64 = 1 << 0;
/// Page-table entry: the device may read.
const PTE_R: u64 = 1 << 1;
/// Page-table entry: the device may write.
const PTE_W: u64 = 1 << 2;
/// Page-table entry: reachable at user privilege, which every device access
/// without a supervisor-privileged process ID is.
const PTE_U: u64 = 1 << 4;
/// Page-table entry: accessed. Set in advance, since the driver leaves the
/// IOMMU's hardware A/D updating off and a clear bit would fault.
const PTE_A: u64 = 1 << 6;
/// Page-table entry: dirty, set in advance on a writable page as `PTE_A`.
const PTE_D: u64 = 1 << 7;
/// The physical page number of an entry: bits 10 through 53.
const PPN_MASK: u64 = ((1 << 44) - 1) << 10;
/// The highest physical address an entry's page number reaches.
const PHYS_LIMIT: u64 = 1 << 56;

/// The entry whose page number names the page at `phys`.
const fn ppn(phys: u64) -> u64
{
    (phys >> 12) << 10
}

/// The page an entry names.
const fn page_of(entry: u64) -> u64
{
    ((entry & PPN_MASK) >> 10) << 12
}

/// Entry `i` of the table page at `table`. Every `i` passed comes from an
/// `index` function that masks it below 512, the entries of a page, so the
/// [`TableError::Invalid`] is never returned.
fn entry(store: &mut impl TableStore, table: u64, i: usize) -> Result<&mut u64, TableError>
{
    store.table(table).get_mut(i).ok_or(TableError::Invalid)
}

/// How a walk treats a missing intermediate table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Walk
{
    /// Allocate it, so an entry can be installed.
    Create,
    /// Stop with [`TableError::NotMapped`]: the walk reads or clears only
    /// what is installed.
    Existing,
}

/// Why a table operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError
{
    /// The device ID, IOVA, physical address, or length is unaligned,
    /// empty, or past what the structure holds.
    Invalid,
    /// A page of the range is already mapped.
    InUse,
    /// A page of the range is not mapped.
    NotMapped,
    /// The store had no page for an intermediate table.
    OutOfMemory,
}

// ── Device directory ──────────────────────────────────────────────────

/// A device directory: its root page, depth, and device-context format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDirectory
{
    root: u64,
    levels: u32,
    format: ContextFormat,
}

impl DeviceDirectory
{
    /// A directory rooted at the zeroed page `root`, `levels` (1 to 3) deep,
    /// holding device contexts of `format`. `None` for another depth.
    #[must_use]
    pub fn new(root: u64, levels: u32, format: ContextFormat) -> Option<Self>
    {
        (1..=3).contains(&levels).then_some(Self {
            root,
            levels,
            format,
        })
    }

    /// 64-bit words of one device context.
    #[must_use]
    pub const fn context_words(&self) -> usize
    {
        self.format.words()
    }

    /// Whether the directory holds the device ID `id`.
    #[must_use]
    pub const fn holds(&self, id: u32) -> bool
    {
        id >> device_id_bits(self.levels, self.format) == 0
    }

    /// The directory index of `id` at `level` (0 for the leaf page, whose
    /// index counts device contexts).
    fn index(&self, id: u32, level: u32) -> usize
    {
        // `leaf_bits` is 6 or 7, so no sum or difference below saturates
        // and `bits` is at most 9.
        let leaf_bits = self.format.leaf_bits();
        let (shift, bits) = match level
        {
            0 => (0, leaf_bits),
            1 => (leaf_bits, 9),
            _ => (
                leaf_bits.saturating_add(9),
                24u32.saturating_sub(leaf_bits).saturating_sub(9),
            ),
        };
        ((id >> shift) & (1u32 << bits).saturating_sub(1)) as usize
    }

    /// The device context of `id`: its leaf page and the word index of its
    /// first word, with every directory page on the way allocated and
    /// linked.
    ///
    /// # Errors
    /// [`TableError::Invalid`] when the directory does not hold `id`;
    /// [`TableError::OutOfMemory`] when a directory page cannot be had.
    pub fn context(&self, store: &mut impl TableStore, id: u32)
    -> Result<(u64, usize), TableError>
    {
        if !self.holds(id)
        {
            return Err(TableError::Invalid);
        }
        let mut table = self.root;
        for level in (1..self.levels).rev()
        {
            let i = self.index(id, level);
            let held = *entry(store, table, i)?;
            table = if held & V != 0
            {
                page_of(held)
            }
            else
            {
                let next = store.alloc().ok_or(TableError::OutOfMemory)?;
                *entry(store, table, i)? = ppn(next) | V;
                store.written(table, i);
                next
            };
        }
        // A leaf page holds `2^leaf_bits` contexts of `context_words` words,
        // 512 words in all, so the product does not saturate.
        Ok((
            table,
            self.index(id, 0).saturating_mul(self.context_words()),
        ))
    }
}

/// The words of a valid device context that translates the device's
/// requests through first-stage tables of format `mode` rooted at
/// `table_phys`, in the address space `pscid`: `tc` with only `V` set,
/// `iohgatp` Bare, `ta.PSCID`, and `fsc` as the `iosatp`; an extended
/// context's further words (MSI translation Off) are zero. A blocked
/// device's context has `tc.V` clear, so every request from it faults.
#[must_use]
pub const fn device_context(table_phys: u64, mode: FirstStageMode, pscid: u32) -> [u64; 4]
{
    [
        V,
        0,
        ((pscid as u64) & 0xf_ffff) << 12,
        (mode.iosatp_mode() << 60) | (table_phys >> 12),
    ]
}

// ── First-stage page tables ───────────────────────────────────────────

/// One domain's first-stage page tables, mapping 4 KiB pages only.
pub struct FirstStage
{
    root: u64,
    mode: FirstStageMode,
}

impl FirstStage
{
    /// A domain of format `mode` with an empty top-level table from
    /// `store`; `None` when the store is empty.
    pub fn new(store: &mut impl TableStore, mode: FirstStageMode) -> Option<Self>
    {
        Some(Self {
            root: store.alloc()?,
            mode,
        })
    }

    /// Physical address of the top-level table, for the device context.
    #[must_use]
    pub fn root(&self) -> u64
    {
        self.root
    }

    /// The IOVAs the domain translates: `0..2^width_bits`
    /// ([`FirstStageMode::width_bits`]).
    #[must_use]
    pub fn width(&self) -> u64
    {
        1u64 << self.mode.width_bits()
    }

    /// The index of `iova` in a level-`level` table: 12 IOVA bits for the
    /// page offset, then 9 for each level from the leaf (level 1). A level
    /// is 1 to 4, so the shift stays far below `u32::MAX`.
    fn index(iova: u64, level: u32) -> usize
    {
        let shift = level.saturating_sub(1).saturating_mul(9).saturating_add(12);
        ((iova >> shift) & 0x1ff) as usize
    }

    fn check(&self, iova: u64, phys: u64, len: u64) -> Result<(), TableError>
    {
        let end = iova.checked_add(len).ok_or(TableError::Invalid)?;
        if len == 0
            || (iova | phys | len) & (PAGE - 1) != 0
            || end > self.width()
            || phys.checked_add(len).is_none_or(|e| e > PHYS_LIMIT)
        {
            return Err(TableError::Invalid);
        }
        Ok(())
    }

    /// The leaf entry slot of `iova`: (the leaf table's physical address,
    /// the index in it), creating the intermediate tables it lacks under
    /// [`Walk::Create`] and failing with [`TableError::NotMapped`] under
    /// [`Walk::Existing`].
    fn leaf(
        &self,
        store: &mut impl TableStore,
        iova: u64,
        walk: Walk,
    ) -> Result<(u64, usize), TableError>
    {
        let mut table = self.root;
        for level in (2..=self.mode.levels()).rev()
        {
            let i = Self::index(iova, level);
            let held = *entry(store, table, i)?;
            table = if held & V != 0
            {
                page_of(held)
            }
            else if walk == Walk::Create
            {
                let next = store.alloc().ok_or(TableError::OutOfMemory)?;
                // A non-leaf entry is the valid bit and the page number; its
                // R, W, X, U, A, and D bits stay clear.
                *entry(store, table, i)? = ppn(next) | V;
                store.written(table, i);
                next
            }
            else
            {
                return Err(TableError::NotMapped);
            };
        }
        Ok((table, Self::index(iova, 1)))
    }

    /// Map `len` bytes at `iova` to the physical frames from `phys`, with
    /// `access`. Nothing is mapped when any page of the range is already
    /// mapped.
    ///
    /// # Errors
    /// [`TableError::Invalid`], [`TableError::InUse`], or
    /// [`TableError::OutOfMemory`]; a partial range is undone first.
    pub fn map(
        &mut self,
        store: &mut impl TableStore,
        iova: u64,
        phys: u64,
        len: u64,
        access: Access,
    ) -> Result<(), TableError>
    {
        self.check(iova, phys, len)?;
        let rights = match access
        {
            Access::Read => PTE_R,
            Access::ReadWrite => PTE_R | PTE_W | PTE_D,
        };
        // `check` refused a range whose end passes `u64` from `iova` or from
        // `phys`, and `len` is a multiple of `PAGE`, so no sum below
        // saturates.
        let mut done = 0;
        while done < len
        {
            let step = self
                .leaf(store, iova.saturating_add(done), Walk::Create)
                .and_then(|(table, i)| {
                    let slot = entry(store, table, i)?;
                    if *slot & V != 0
                    {
                        return Err(TableError::InUse);
                    }
                    *slot = ppn(phys.saturating_add(done)) | V | PTE_U | PTE_A | rights;
                    store.written(table, i);
                    Ok(())
                });
            if let Err(e) = step
            {
                if done != 0
                {
                    let _ = self.unmap(store, iova, done);
                }
                return Err(e);
            }
            done = done.saturating_add(PAGE);
        }
        Ok(())
    }

    /// Unmap `len` bytes at `iova`. Intermediate tables stay, empty, for the
    /// domain's life.
    ///
    /// # Errors
    /// [`TableError::Invalid`], or [`TableError::NotMapped`] when a page of
    /// the range is not mapped; the pages before it are unmapped.
    pub fn unmap(
        &mut self,
        store: &mut impl TableStore,
        iova: u64,
        len: u64,
    ) -> Result<(), TableError>
    {
        self.check(iova, 0, len)?;
        // As in `map`, no sum below saturates.
        let mut done = 0;
        while done < len
        {
            let (table, i) = self.leaf(store, iova.saturating_add(done), Walk::Existing)?;
            let slot = entry(store, table, i)?;
            if *slot & V == 0
            {
                return Err(TableError::NotMapped);
            }
            *slot = 0;
            store.written(table, i);
            done = done.saturating_add(PAGE);
        }
        Ok(())
    }

    /// The (physical address, entry) `iova` translates to, or `None`; what
    /// the host tests check a walk against.
    #[cfg(test)]
    pub fn translate(&self, store: &mut impl TableStore, iova: u64) -> Option<(u64, u64)>
    {
        if iova >= self.width()
        {
            return None;
        }
        let (table, i) = self.leaf(store, iova & !(PAGE - 1), Walk::Existing).ok()?;
        let e = store.table(table)[i];
        (e & V != 0).then_some((page_of(e) | (iova & (PAGE - 1)), e))
    }

    /// Every table page the domain holds, top level first; what the host
    /// tests check a walk's allocations against.
    #[cfg(test)]
    pub fn pages(&self, store: &mut impl TableStore) -> Vec<u64>
    {
        let mut out = Vec::new();
        let mut frontier = alloc::vec![(self.root, self.mode.levels())];
        while let Some((table, level)) = frontier.pop()
        {
            out.push(table);
            if level > 1
            {
                for &e in store.table(table).iter()
                {
                    if e & V != 0
                    {
                        frontier.push((page_of(e), level - 1));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use iommu_core::table::TABLE_WORDS;

    /// Heap-backed table pages at fake physical addresses from 2 GiB.
    #[derive(Default)]
    struct Heap
    {
        pages: Vec<Box<[u64; TABLE_WORDS]>>,
        written: Vec<(u64, usize)>,
    }

    const BASE: u64 = 0x8000_0000;

    impl TableStore for Heap
    {
        fn alloc(&mut self) -> Option<u64>
        {
            if self.pages.len() >= 64
            {
                return None;
            }
            self.pages.push(Box::new([0; TABLE_WORDS]));
            Some(BASE + (self.pages.len() as u64 - 1) * PAGE)
        }

        fn table(&mut self, phys: u64) -> &mut [u64; TABLE_WORDS]
        {
            &mut self.pages[((phys - BASE) / PAGE) as usize]
        }

        fn written(&mut self, phys: u64, index: usize)
        {
            self.written.push((phys, index));
        }
    }

    #[test]
    fn a_device_context_translates_through_its_first_stage_root_in_its_domain()
    {
        let dc = device_context(0x8000_5000, FirstStageMode::Sv48, 7);
        assert_eq!(dc, [1, 0, 7 << 12, (9 << 60) | 0x80005]);
        let dc = device_context(0x8000_5000, FirstStageMode::Sv39, 7);
        assert_eq!(dc[3] >> 60, 8);
    }

    #[test]
    fn a_three_level_extended_directory_links_two_pages_to_the_context()
    {
        let mut s = Heap::default();
        let root = s.alloc().unwrap();
        let d = DeviceDirectory::new(root, 3, ContextFormat::Extended).unwrap();
        // Device 0x0128: DDI[2] = 0, DDI[1] = 4, DDI[0] = 0x28.
        let (leaf, word) = d.context(&mut s, 0x0128).unwrap();
        assert_eq!(word, 0x28 * 8);
        let mid = page_of(s.table(root)[0]);
        assert_eq!(s.table(root)[0] & V, V);
        assert_eq!(page_of(s.table(mid)[4]), leaf);
        // The same device reaches the same context without new pages.
        assert_eq!(d.context(&mut s, 0x0128), Ok((leaf, word)));
        assert_eq!(s.pages.len(), 3);
        assert_eq!(s.written, [(root, 0), (mid, 4)]);
    }

    #[test]
    fn a_two_level_base_directory_indexes_seven_then_nine_bits()
    {
        let mut s = Heap::default();
        let root = s.alloc().unwrap();
        let d = DeviceDirectory::new(root, 2, ContextFormat::Base).unwrap();
        // Device 0xffff: DDI[1] = 0x1ff, DDI[0] = 0x7f.
        let (leaf, word) = d.context(&mut s, 0xffff).unwrap();
        assert_eq!(word, 0x7f * 4);
        assert_eq!(page_of(s.table(root)[0x1ff]), leaf);
    }

    #[test]
    fn a_one_level_directory_is_its_own_leaf()
    {
        let mut s = Heap::default();
        let root = s.alloc().unwrap();
        let d = DeviceDirectory::new(root, 1, ContextFormat::Base).unwrap();
        assert_eq!(d.context(&mut s, 0x7f), Ok((root, 0x7f * 4)));
    }

    #[test]
    fn a_device_id_past_the_directory_or_a_full_store_gets_no_context()
    {
        let mut s = Heap::default();
        let root = s.alloc().unwrap();
        let d = DeviceDirectory::new(root, 2, ContextFormat::Extended).unwrap();
        assert_eq!(d.context(&mut s, 0x8000), Err(TableError::Invalid));
        while s.alloc().is_some()
        {}
        assert_eq!(d.context(&mut s, 0x10), Err(TableError::OutOfMemory));
        assert!(DeviceDirectory::new(root, 4, ContextFormat::Extended).is_none());
    }

    #[test]
    fn a_mapped_range_translates_with_its_access_and_preset_accessed_bits()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        d.map(&mut s, 0x20_0000, 0x9000_0000, 2 * PAGE, Access::Read)
            .unwrap();
        let (phys, e) = d.translate(&mut s, 0x20_1010).unwrap();
        assert_eq!(phys, 0x9000_1010);
        assert_eq!(e & 0xff, V | PTE_R | PTE_U | PTE_A);
        d.map(&mut s, 0x40_0000, 0x9100_0000, PAGE, Access::ReadWrite)
            .unwrap();
        let (_, e) = d.translate(&mut s, 0x40_0000).unwrap();
        assert_eq!(e & 0xff, V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
        assert_eq!(d.translate(&mut s, 0x20_2000), None);
    }

    #[test]
    fn intermediate_entries_carry_only_the_valid_bit_and_their_page()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv48).unwrap();
        d.map(&mut s, 0, 0x9000_0000, PAGE, Access::ReadWrite)
            .unwrap();
        let pages = d.pages(&mut s);
        assert_eq!(pages.len(), 4);
        let top = s.table(d.root())[0];
        assert_eq!(top & !PPN_MASK, V);
    }

    #[test]
    fn an_overlapping_map_is_refused_and_leaves_nothing_behind()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        d.map(&mut s, 0x1000, 0x9000_0000, PAGE, Access::Read)
            .unwrap();
        assert_eq!(
            d.map(&mut s, 0, 0x9100_0000, 2 * PAGE, Access::Read),
            Err(TableError::InUse)
        );
        assert_eq!(d.translate(&mut s, 0), None);
        assert_eq!(d.translate(&mut s, 0x1000).map(|t| t.0), Some(0x9000_0000));
    }

    #[test]
    fn an_empty_store_builds_no_domain()
    {
        let mut s = Heap::default();
        while s.alloc().is_some()
        {}
        assert!(FirstStage::new(&mut s, FirstStageMode::Sv39).is_none());
    }

    #[test]
    fn a_frame_reaches_the_highest_page_an_entry_names_and_no_further()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        assert_eq!(
            d.map(&mut s, 0, PHYS_LIMIT - PAGE, PAGE, Access::Read),
            Ok(())
        );
        assert_eq!(
            d.map(&mut s, PAGE, PHYS_LIMIT, PAGE, Access::Read),
            Err(TableError::Invalid)
        );
    }

    #[test]
    fn an_unaligned_or_empty_unmap_is_invalid()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        d.map(&mut s, 0, 0x9000_0000, PAGE, Access::Read).unwrap();
        assert_eq!(d.unmap(&mut s, 0x10, PAGE), Err(TableError::Invalid));
        assert_eq!(d.unmap(&mut s, 0, 0), Err(TableError::Invalid));
        assert!(d.translate(&mut s, 0).is_some());
    }

    #[test]
    fn an_unmapped_range_stops_translating()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv48).unwrap();
        d.map(&mut s, 0x4000_0000, 0x1_0000_0000, PAGE, Access::ReadWrite)
            .unwrap();
        d.unmap(&mut s, 0x4000_0000, PAGE).unwrap();
        assert_eq!(d.translate(&mut s, 0x4000_0000), None);
        assert_eq!(
            d.unmap(&mut s, 0x4000_0000, PAGE),
            Err(TableError::NotMapped)
        );
    }

    #[test]
    fn unaligned_empty_or_too_wide_ranges_are_invalid()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        assert_eq!(
            d.map(&mut s, 0x10, 0x1000, PAGE, Access::Read),
            Err(TableError::Invalid)
        );
        assert_eq!(
            d.map(&mut s, 0, 0x1000, 0, Access::Read),
            Err(TableError::Invalid)
        );
        // Bit 38 set is past the zero-extended width of Sv39.
        assert_eq!(
            d.map(&mut s, 1 << 38, 0x1000, PAGE, Access::Read),
            Err(TableError::Invalid)
        );
        assert!(
            d.map(&mut s, (1 << 38) - PAGE, 0x1000, PAGE, Access::Read)
                .is_ok()
        );
    }

    #[test]
    fn a_full_store_fails_the_map_and_undoes_its_part()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        d.map(&mut s, 0x3f_e000, 0x9000_0000, PAGE, Access::Read)
            .unwrap();
        while s.alloc().is_some()
        {}
        // The first page lands in the existing leaf table; the second, past
        // the 2 MiB that table spans, needs a new one the store cannot give.
        assert_eq!(
            d.map(&mut s, 0x3f_f000, 0x9100_0000, 2 * PAGE, Access::Read),
            Err(TableError::OutOfMemory)
        );
        assert_eq!(d.translate(&mut s, 0x3f_f000), None);
        assert_eq!(
            d.translate(&mut s, 0x3f_e000).map(|t| t.0),
            Some(0x9000_0000)
        );
    }

    #[test]
    fn every_entry_a_map_or_unmap_writes_is_reported_to_the_store()
    {
        let mut s = Heap::default();
        let mut d = FirstStage::new(&mut s, FirstStageMode::Sv39).unwrap();
        d.map(&mut s, 0, 0x9000_0000, 2 * PAGE, Access::Read)
            .unwrap();
        // Two intermediate entries (levels 3 and 2), then the two leaves.
        let pages = d.pages(&mut s);
        let leaf = pages[2];
        assert_eq!(
            s.written,
            [(d.root(), 0), (pages[1], 0), (leaf, 0), (leaf, 1)]
        );
        s.written.clear();
        d.unmap(&mut s, PAGE, PAGE).unwrap();
        assert_eq!(s.written, [(leaf, 1)]);
    }
}
