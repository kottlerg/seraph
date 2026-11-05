// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/tables.rs

//! VT-d legacy-mode translation structures: the root table, the context
//! tables, and second-level page tables (Intel VT-d specification rev. 4.1,
//! sections 9.1, 9.3, and 9.8).
//!
//! The entries are pure encodings, and [`SecondLevel`] builds and walks one
//! domain's page tables over a [`TableStore`] that hands out zeroed 4 KiB
//! table pages with their physical addresses. The driver backs the store
//! with memmgr frames mapped into its own address space; the host tests
//! back it with heap pages, so the encoding and the walk are host-tested.

use alloc::vec::Vec;

/// Entries in a root table (one per bus), a context table (one per device
/// and function), or a page table (one per 9 bits of IOVA).
pub const ENTRIES: usize = 512;
/// Bytes of one page and of one table.
pub const PAGE: u64 = 0x1000;

/// Root entry: present.
const ROOT_PRESENT: u64 = 1 << 0;
/// Context entry, low word: present.
const CTX_PRESENT: u64 = 1 << 0;
/// Second-level entry: the device may read.
pub const SL_READ: u64 = 1 << 0;
/// Second-level entry: the device may write.
pub const SL_WRITE: u64 = 1 << 1;
/// The address bits of an entry: 12 through 51.
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// A root entry's two words: present, pointing at the context table at
/// `context_phys`.
#[must_use]
pub const fn root_entry(context_phys: u64) -> [u64; 2]
{
    [(context_phys & ADDR_MASK) | ROOT_PRESENT, 0]
}

/// A context entry's two words: present, translating untranslated requests
/// through second-level tables (`TT` = 00) rooted at `table_phys`, `levels`
/// deep (3 or 4: `AW` 1 or 2), for domain `did`. A blocked function's entry
/// is the all-zero entry: not present, so every request from it faults.
#[must_use]
pub const fn context_entry(table_phys: u64, levels: u32, did: u16) -> [u64; 2]
{
    let aw = (levels as u64) - 2;
    [
        (table_phys & ADDR_MASK) | CTX_PRESENT,
        aw | ((did as u64) << 8),
    ]
}

/// The word index of function `devfn`'s context entry in its bus's context
/// table, the table holding 256 two-word entries.
#[must_use]
pub const fn context_index(device: u8, function: u8) -> usize
{
    (((device & 0x1f) as usize) << 3 | (function & 0x7) as usize) * 2
}

/// A source of zeroed page-table pages.
pub trait TableStore
{
    /// A new zeroed table page: its physical address, or `None` when no
    /// memory is left.
    fn alloc(&mut self) -> Option<u64>;
    /// The entries of the table page at `phys`, which `alloc` returned.
    fn table(&mut self, phys: u64) -> &mut [u64; ENTRIES];
    /// Entry `index` of the table page at `phys` was just written; a store
    /// whose unit does not snoop the caches flushes it to memory here. Does
    /// nothing by default.
    fn written(&mut self, phys: u64, index: usize)
    {
        let _ = (phys, index);
    }
}

/// Why a [`SecondLevel`] operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError
{
    /// The IOVA, physical address, or length is unaligned, empty, or past
    /// the domain's width.
    Invalid,
    /// A page of the range is already mapped.
    InUse,
    /// A page of the range is not mapped.
    NotMapped,
    /// The store had no page for an intermediate table.
    OutOfMemory,
}

/// One domain's second-level page tables, `levels` deep, mapping 4 KiB pages
/// only.
pub struct SecondLevel
{
    root: u64,
    levels: u32,
}

impl SecondLevel
{
    /// A domain with an empty top-level table from `store`, `levels` (3 or
    /// 4) deep. `None` when `levels` is unsupported or `store` is empty.
    pub fn new(store: &mut impl TableStore, levels: u32) -> Option<Self>
    {
        if !(3..=4).contains(&levels)
        {
            return None;
        }
        Some(Self {
            root: store.alloc()?,
            levels,
        })
    }

    /// Physical address of the top-level table, for the context entry.
    #[must_use]
    pub fn root(&self) -> u64
    {
        self.root
    }

    /// Page-table depth.
    #[must_use]
    pub fn levels(&self) -> u32
    {
        self.levels
    }

    /// The IOVAs the domain translates: `0..2^(12 + 9 * levels)`.
    #[must_use]
    pub fn width(&self) -> u64
    {
        1u64 << (12 + 9 * self.levels)
    }

    fn index(iova: u64, level: u32) -> usize
    {
        ((iova >> (12 + 9 * (level - 1))) & 0x1ff) as usize
    }

    fn check(&self, iova: u64, phys: u64, len: u64) -> Result<(), TableError>
    {
        let end = iova.checked_add(len).ok_or(TableError::Invalid)?;
        if len == 0
            || (iova | phys | len) & (PAGE - 1) != 0
            || end > self.width()
            || phys
                .checked_add(len)
                .is_none_or(|e| e - 1 > ADDR_MASK | 0xfff)
        {
            return Err(TableError::Invalid);
        }
        Ok(())
    }

    /// The leaf entry slot of `iova`: (the leaf table's physical address,
    /// the index in it), creating intermediate tables when `create`.
    fn leaf(
        &self,
        store: &mut impl TableStore,
        iova: u64,
        create: bool,
    ) -> Result<(u64, usize), TableError>
    {
        let mut table = self.root;
        for level in (2..=self.levels).rev()
        {
            let i = Self::index(iova, level);
            let entry = store.table(table)[i];
            table = if entry & (SL_READ | SL_WRITE) != 0
            {
                entry & ADDR_MASK
            }
            else if create
            {
                let next = store.alloc().ok_or(TableError::OutOfMemory)?;
                // A non-leaf entry grants both rights; the leaf narrows
                // them.
                store.table(table)[i] = next | SL_READ | SL_WRITE;
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
    /// `rights` ([`SL_READ`], [`SL_WRITE`]). Nothing is mapped when any page
    /// of the range is already mapped.
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
        rights: u64,
    ) -> Result<(), TableError>
    {
        self.check(iova, phys, len)?;
        if rights & (SL_READ | SL_WRITE) == 0 || rights & !(SL_READ | SL_WRITE) != 0
        {
            return Err(TableError::Invalid);
        }
        let mut done = 0;
        while done < len
        {
            let step = match self.leaf(store, iova + done, true)
            {
                Ok((table, i)) if store.table(table)[i] == 0 =>
                {
                    store.table(table)[i] = ((phys + done) & ADDR_MASK) | rights;
                    store.written(table, i);
                    Ok(())
                }
                Ok(_) => Err(TableError::InUse),
                Err(e) => Err(e),
            };
            if let Err(e) = step
            {
                if done != 0
                {
                    let _ = self.unmap(store, iova, done);
                }
                return Err(e);
            }
            done += PAGE;
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
        let mut done = 0;
        while done < len
        {
            let (table, i) = self.leaf(store, iova + done, false)?;
            if store.table(table)[i] == 0
            {
                return Err(TableError::NotMapped);
            }
            store.table(table)[i] = 0;
            store.written(table, i);
            done += PAGE;
        }
        Ok(())
    }

    /// The (physical address, rights) `iova` translates to, or `None`.
    pub fn translate(&self, store: &mut impl TableStore, iova: u64) -> Option<(u64, u64)>
    {
        if iova >= self.width()
        {
            return None;
        }
        let (table, i) = self.leaf(store, iova & !(PAGE - 1), false).ok()?;
        let e = store.table(table)[i];
        (e != 0).then_some((
            (e & ADDR_MASK) | (iova & (PAGE - 1)),
            e & (SL_READ | SL_WRITE),
        ))
    }

    /// Every table page the domain holds, top level first, so the driver
    /// can account for them.
    pub fn pages(&self, store: &mut impl TableStore) -> Vec<u64>
    {
        let mut out = Vec::new();
        let mut frontier = alloc::vec![(self.root, self.levels)];
        while let Some((table, level)) = frontier.pop()
        {
            out.push(table);
            if level > 1
            {
                for &e in store.table(table).iter()
                {
                    if e & (SL_READ | SL_WRITE) != 0
                    {
                        frontier.push((e & ADDR_MASK, level - 1));
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

    /// Heap-backed table pages at fake physical addresses from 1 MiB.
    #[derive(Default)]
    struct Heap(Vec<Box<[u64; ENTRIES]>>);

    impl TableStore for Heap
    {
        fn alloc(&mut self) -> Option<u64>
        {
            if self.0.len() >= 64
            {
                return None;
            }
            self.0.push(Box::new([0; ENTRIES]));
            Some(0x10_0000 + (self.0.len() as u64 - 1) * PAGE)
        }

        fn table(&mut self, phys: u64) -> &mut [u64; ENTRIES]
        {
            &mut self.0[((phys - 0x10_0000) / PAGE) as usize]
        }
    }

    #[test]
    fn a_root_entry_is_present_and_points_at_its_context_table()
    {
        assert_eq!(root_entry(0x5000), [0x5001, 0]);
    }

    #[test]
    fn a_context_entry_carries_its_table_depth_and_domain()
    {
        // 3-level: AW = 1; 4-level: AW = 2.
        assert_eq!(context_entry(0x7000, 3, 9), [0x7001, 1 | (9 << 8)]);
        assert_eq!(context_entry(0x7000, 4, 9)[1] & 0x7, 2);
    }

    #[test]
    fn a_function_has_two_words_in_its_bus_context_table()
    {
        assert_eq!(context_index(0, 0), 0);
        assert_eq!(context_index(3, 0), 48);
        assert_eq!(context_index(0x1f, 7), 510);
    }

    #[test]
    fn a_mapped_range_translates_with_its_rights()
    {
        let mut s = Heap::default();
        let mut d = SecondLevel::new(&mut s, 3).unwrap();
        d.map(&mut s, 0x20_0000, 0x8000_0000, 2 * PAGE, SL_READ)
            .unwrap();
        assert_eq!(d.translate(&mut s, 0x20_0010), Some((0x8000_0010, SL_READ)));
        assert_eq!(d.translate(&mut s, 0x20_1000), Some((0x8000_1000, SL_READ)));
        assert_eq!(d.translate(&mut s, 0x20_2000), None);
    }

    #[test]
    fn an_overlapping_map_is_refused_and_leaves_nothing_behind()
    {
        let mut s = Heap::default();
        let mut d = SecondLevel::new(&mut s, 3).unwrap();
        d.map(&mut s, 0x1000, 0x9000, PAGE, SL_READ | SL_WRITE)
            .unwrap();
        assert_eq!(
            d.map(&mut s, 0, 0xa000, 2 * PAGE, SL_READ),
            Err(TableError::InUse)
        );
        assert_eq!(d.translate(&mut s, 0), None);
        assert_eq!(
            d.translate(&mut s, 0x1000),
            Some((0x9000, SL_READ | SL_WRITE))
        );
    }

    #[test]
    fn an_unmapped_range_stops_translating()
    {
        let mut s = Heap::default();
        let mut d = SecondLevel::new(&mut s, 4).unwrap();
        d.map(&mut s, 0x4000_0000, 0x1_0000_0000, PAGE, SL_WRITE)
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
        let mut d = SecondLevel::new(&mut s, 3).unwrap();
        assert_eq!(
            d.map(&mut s, 0x10, 0x1000, PAGE, SL_READ),
            Err(TableError::Invalid)
        );
        assert_eq!(
            d.map(&mut s, 0, 0x1000, 0, SL_READ),
            Err(TableError::Invalid)
        );
        assert_eq!(
            d.map(&mut s, 1 << 39, 0x1000, PAGE, SL_READ),
            Err(TableError::Invalid)
        );
        assert_eq!(d.map(&mut s, 0, 0x1000, PAGE, 0), Err(TableError::Invalid));
    }

    #[test]
    fn a_full_store_fails_the_map_and_undoes_its_part()
    {
        let mut s = Heap::default();
        let mut d = SecondLevel::new(&mut s, 3).unwrap();
        // Fill the store, then map a range spanning a fresh 1 GiB region.
        while s.alloc().is_some()
        {}
        assert_eq!(
            d.map(&mut s, 0x4000_0000, 0x1000, PAGE, SL_READ),
            Err(TableError::OutOfMemory)
        );
        assert_eq!(d.translate(&mut s, 0x4000_0000), None);
    }

    #[test]
    fn the_domain_counts_its_table_pages()
    {
        let mut s = Heap::default();
        let mut d = SecondLevel::new(&mut s, 3).unwrap();
        assert_eq!(d.pages(&mut s).len(), 1);
        d.map(&mut s, 0, 0x1000, PAGE, SL_READ).unwrap();
        assert_eq!(d.pages(&mut s).len(), 3);
    }

    /// A heap store that records every entry the walk reports written.
    #[derive(Default)]
    struct Recording
    {
        heap: Heap,
        written: Vec<(u64, usize)>,
    }

    impl TableStore for Recording
    {
        fn alloc(&mut self) -> Option<u64>
        {
            self.heap.alloc()
        }

        fn table(&mut self, phys: u64) -> &mut [u64; ENTRIES]
        {
            self.heap.table(phys)
        }

        fn written(&mut self, phys: u64, index: usize)
        {
            self.written.push((phys, index));
        }
    }

    #[test]
    fn every_entry_a_map_or_unmap_writes_is_reported_to_the_store()
    {
        let mut s = Recording::default();
        let mut d = SecondLevel::new(&mut s, 3).unwrap();
        d.map(&mut s, 0, 0x1000, 2 * PAGE, SL_READ).unwrap();
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

    #[test]
    fn unsupported_depths_build_no_domain()
    {
        let mut s = Heap::default();
        assert!(SecondLevel::new(&mut s, 2).is_none());
        assert!(SecondLevel::new(&mut s, 5).is_none());
    }
}
