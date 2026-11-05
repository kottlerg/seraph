// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/store.rs

//! The page store behind every translation structure the driver builds:
//! zeroed 4 KiB pages from memmgr, mapped into the driver, with their
//! physical addresses.
//!
//! Pages come from memmgr in physically contiguous chunks
//! (`REQUIRE_CONTIGUOUS`), and the driver reads each chunk's physical base
//! with `CAP_INFO_MEMORY_PHYS_BASE`, since the unit is programmed with
//! physical addresses: the IOMMU driver is the one driver class that reads
//! them (`docs/device-management.md` § IOMMU Discovery and Programming). No
//! page is ever returned: the unit may walk any table page for as long as
//! translation stays on, so the pages stay with the driver for the boot, and
//! past its death, since devmgr spawns it `CREATE_DMA_HOLD` and never
//! releases the hold.

use iommu_vtd::tables::{ENTRIES, PAGE, TableStore};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use std::os::seraph::reserve_pages;

use crate::arch;

/// Pages one memmgr request takes for the store: a domain's first mapping
/// needs a few table pages and each bus a context table, so a chunk serves
/// several attaches and mappings per round trip.
const CHUNK_PAGES: u64 = 16;

/// One contiguous chunk of table pages, mapped from `va`.
struct Chunk
{
    phys: u64,
    va: u64,
    used: u64,
}

/// Table pages from memmgr, mapped writable into the driver.
pub struct Store
{
    memmgr_ep: u64,
    aspace: u64,
    /// Whether every unit snoops the caches; when one does not, each write
    /// is flushed ([`arch::current::flush`]).
    coherent: bool,
    chunks: Vec<Chunk>,
    /// The table [`TableStore::table`] returns for an address no chunk
    /// holds, which the walk never passes: no unit reads it.
    sink: Box<[u64; ENTRIES]>,
}

impl Store
{
    /// An empty store drawing from memmgr at `memmgr_ep`, mapping into
    /// `aspace`; `coherent` when every unit's page walks snoop the caches.
    pub fn new(memmgr_ep: u64, aspace: u64, coherent: bool) -> Self
    {
        Self {
            memmgr_ep,
            aspace,
            coherent,
            chunks: Vec::new(),
            sink: Box::new([0; ENTRIES]),
        }
    }

    /// Write `len` bytes from the table page `phys` (at byte `offset`) back
    /// to memory when a unit does not snoop the caches.
    pub fn flush(&self, phys: u64, offset: u64, len: u64)
    {
        if self.coherent
        {
            return;
        }
        if let Some(va) = self.va(phys)
        {
            // SAFETY: `va` maps the page `phys`, and `offset + len` stays in
            // it (every caller flushes inside one page).
            unsafe { arch::current::flush(va + offset, len) };
        }
    }

    fn va(&self, phys: u64) -> Option<u64>
    {
        self.chunks
            .iter()
            .find(|c| phys >= c.phys && phys < c.phys + c.used * PAGE)
            .map(|c| c.va + (phys - c.phys))
    }

    /// Take a chunk of [`CHUNK_PAGES`] contiguous pages from memmgr and map
    /// it; `false`, logged, when memmgr refuses or the mapping fails.
    fn grow(&mut self) -> bool
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let arg = CHUNK_PAGES | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
        let request = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, arg)
            .build();
        // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(self.memmgr_ep, &request, ipc_buf) })
        else
        {
            std::os::seraph::log!("table pages: memmgr call failed");
            return false;
        };
        let cap = reply.caps().first().copied();
        let Some(cap) = cap.filter(|_| reply.label == memmgr_errors::SUCCESS && reply.word(0) == 1)
        else
        {
            for &c in reply.caps()
            {
                let _ = syscall::cap_delete(c);
            }
            std::os::seraph::log!("table pages: memmgr refused {} pages", CHUNK_PAGES);
            return false;
        };
        let Ok(phys) = syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_PHYS_BASE)
        else
        {
            std::os::seraph::log!("table pages: no physical base");
            return false;
        };
        let Ok(range) = reserve_pages(CHUNK_PAGES)
        else
        {
            std::os::seraph::log!("table pages: no VA");
            return false;
        };
        let va = range.va_start();
        // SAFETY: `range` is a fresh reservation of CHUNK_PAGES pages from
        // the per-process arena, kept for the driver's life (the reservation
        // is never returned): VA no Rust object or IPC page occupies.
        let mapped = unsafe {
            syscall::mem_map(cap, self.aspace, va, 0, CHUNK_PAGES, syscall::MAP_WRITABLE)
        };
        if mapped.is_err() || self.chunks.try_reserve(1).is_err()
        {
            std::os::seraph::log!("table pages: mapping failed");
            return false;
        }
        self.chunks.push(Chunk { phys, va, used: 0 });
        true
    }
}

impl TableStore for Store
{
    fn alloc(&mut self) -> Option<u64>
    {
        if self.chunks.last().is_none_or(|c| c.used == CHUNK_PAGES) && !self.grow()
        {
            return None;
        }
        let chunk = self.chunks.last_mut()?;
        let phys = chunk.phys + chunk.used * PAGE;
        let va = chunk.va + chunk.used * PAGE;
        chunk.used += 1;
        // SAFETY: `va` is a page of the chunk mapped writable in `grow`, and
        // no table has been handed out over it yet.
        unsafe { core::ptr::write_bytes(va as *mut u64, 0, ENTRIES) };
        self.flush(phys, 0, PAGE);
        Some(phys)
    }

    fn table(&mut self, phys: u64) -> &mut [u64; ENTRIES]
    {
        let Some(va) = self.va(phys)
        else
        {
            std::os::seraph::log!("table pages: {:#x} is no table page", phys);
            *self.sink = [0; ENTRIES];
            return &mut self.sink;
        };
        // SAFETY: `va` is a page-aligned page of a chunk mapped writable for
        // the driver's life, one `alloc` handed out; the store is reached
        // only under the service lock and through `&mut self`, so no other
        // reference to the page lives while this one does.
        unsafe { &mut *(va as *mut [u64; ENTRIES]) }
    }

    fn written(&mut self, phys: u64, index: usize)
    {
        self.flush(phys, (index * 8) as u64, 8);
    }
}
