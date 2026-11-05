// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/table.rs

//! The page store every family's translation structures are built in.
//!
//! A family's tables (VT-d's root, context, and second-level tables; the
//! RISC-V IOMMU's device directory, first-stage tables, and queues) are 4 KiB
//! pages of 64-bit words that a unit reads by physical address. The family's
//! walks run over a [`TableStore`]: the driver backs it with memmgr frames
//! mapped into its own address space (the `iommu-store` crate), and the host
//! tests back it with heap pages.

/// 64-bit words in one table page, a 4 KiB page.
pub const TABLE_WORDS: usize = 512;

/// A source of zeroed table pages.
pub trait TableStore
{
    /// A new zeroed table page: its physical address, or `None` when no
    /// memory is left.
    fn alloc(&mut self) -> Option<u64>;
    /// The words of the table page at `phys`, which `alloc` returned.
    fn table(&mut self, phys: u64) -> &mut [u64; TABLE_WORDS];
    /// Word `index` of the table page at `phys` was just written. A store
    /// backing a unit's tables orders the write before every later one here,
    /// so a unit never sees a parent entry before the table it points at, and
    /// flushes it to memory when the unit does not snoop the caches. Does
    /// nothing by default.
    fn written(&mut self, phys: u64, index: usize)
    {
        let _ = (phys, index);
    }
}
