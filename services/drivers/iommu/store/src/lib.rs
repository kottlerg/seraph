// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/store/src/lib.rs

//! The page store behind every translation structure an IOMMU driver builds:
//! zeroed 4 KiB pages from memmgr, mapped into the driver, with their
//! physical addresses.
//!
//! A page a unit only reads is reached through [`TableStore::table`]; one it
//! writes (a queue it produces into) only through [`Store::page_ptr`].
//!
//! Pages come from memmgr in physically contiguous chunks
//! (`REQUIRE_CONTIGUOUS`), and the driver reads each chunk's physical base
//! with `CAP_INFO_MEMORY_PHYS_BASE`, since a unit is programmed with
//! physical addresses: the IOMMU driver is the one driver class that reads
//! them (`docs/device-management.md` § IOMMU Discovery and Programming). No
//! page is ever returned: a unit may walk any table page for as long as
//! translation stays on, so the pages stay with the driver for the boot, and
//! past its death, since devmgr spawns it `CREATE_DMA_HOLD` and never
//! releases the hold.

use iommu_core::table::{TABLE_WORDS, TableStore};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use std::os::seraph::reserve_pages;
use std::sync::atomic::{Ordering, fence};
use syscall_abi::PAGE_SIZE;

/// Pages one memmgr request takes for the store: a domain's first mapping
/// needs a few table pages and each bus or directory level a table of its
/// own, so a chunk serves several attaches and mappings per round trip.
/// `docs/limits.md` classifies it.
pub const CHUNK_PAGES: u64 = 16;

/// How a table write reaches the memory the units read.
#[derive(Clone, Copy)]
pub enum Flush
{
    /// Every unit's table reads snoop the processor caches: a write needs no
    /// write-back; the store's fence orders it before the next table store,
    /// and the driver's barrier on its register write before that write.
    Coherent,
    /// A unit reads memory past the caches: every write is written back
    /// with this function, which takes a mapped virtual address and a byte
    /// count, and whose caller must have that range mapped.
    Writeback(unsafe fn(u64, u64)),
}

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
    flush: Flush,
    chunks: Vec<Chunk>,
    /// The table [`TableStore::table`] returns for an address no chunk
    /// holds or that is not page-aligned, which the walks never pass: no
    /// unit reads it.
    sink: Box<[u64; TABLE_WORDS]>,
}

impl Store
{
    /// An empty store drawing from memmgr at `memmgr_ep`, mapping into
    /// `aspace`, its writes reaching the units as `flush` says.
    #[must_use]
    pub fn new(memmgr_ep: u64, aspace: u64, flush: Flush) -> Self
    {
        Self {
            memmgr_ep,
            aspace,
            flush,
            chunks: Vec::new(),
            sink: Box::new([0; TABLE_WORDS]),
        }
    }

    /// Write `len` bytes from the table page `phys` (at byte `offset`) back
    /// to memory when a unit does not snoop the caches
    /// ([`Flush::Writeback`]); nothing when every unit does. A span past the
    /// end of the page is refused, logged, and nothing is written back.
    pub fn flush(&self, phys: u64, offset: u64, len: u64)
    {
        let Flush::Writeback(write_back) = self.flush
        else
        {
            return;
        };
        if offset.checked_add(len).is_none_or(|end| end > PAGE_SIZE)
        {
            std::os::seraph::log!("table pages: flush past the end of {:#x} refused", phys);
            return;
        }
        if let Some(va) = self.va(phys)
        {
            // SAFETY: `va` maps the page `phys` for the driver's life, and
            // `offset + len` stays inside it (checked above).
            unsafe { write_back(va + offset, len) };
        }
    }

    /// The mapped address of the page at `phys`, for a page a unit itself
    /// writes (a queue the unit produces into): such a page may be reached
    /// only through raw accesses, never through a reference, since the unit
    /// writes it behind the compiler's back. `None` for an address no chunk
    /// holds or that is not page-aligned.
    #[must_use]
    pub fn page_ptr(&self, phys: u64) -> Option<*const u64>
    {
        self.va(phys).map(|va| va as *const u64)
    }

    /// The mapped address of the page at `phys`; `None` for an address that
    /// is not page-aligned or that no chunk's handed-out pages hold.
    fn va(&self, phys: u64) -> Option<u64>
    {
        if !phys.is_multiple_of(PAGE_SIZE)
        {
            return None;
        }
        self.chunks
            .iter()
            .find(|c| phys >= c.phys && phys < c.phys + c.used * PAGE_SIZE)
            .map(|c| c.va + (phys - c.phys))
    }

    /// Take a chunk of [`CHUNK_PAGES`] contiguous pages from memmgr and map
    /// it; `false`, logged, when memmgr refuses or the mapping fails.
    fn grow(&mut self) -> bool
    {
        // Room for the chunk's record first, so no failure past the mapping
        // has a live mapping to undo.
        if self.chunks.try_reserve(1).is_err()
        {
            std::os::seraph::log!("table pages: no memory for a chunk record");
            return false;
        }
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
            let _ = syscall::cap_delete(cap);
            return false;
        };
        let Ok(range) = reserve_pages(CHUNK_PAGES)
        else
        {
            std::os::seraph::log!("table pages: no VA");
            let _ = syscall::cap_delete(cap);
            return false;
        };
        let va = range.va_start();
        // SAFETY: `range` is a fresh reservation of CHUNK_PAGES pages from
        // the per-process arena, kept for the driver's life once mapped: VA
        // no Rust object or IPC page occupies.
        let mapped = unsafe {
            syscall::mem_map(cap, self.aspace, va, 0, CHUNK_PAGES, syscall::MAP_WRITABLE)
        };
        if mapped.is_err()
        {
            std::os::seraph::log!("table pages: mapping failed");
            // A failed map may leave the pages it mapped before failing, and
            // deleting a Memory cap does not unmap them, so they are unmapped
            // first; the range returns to the arena only once nothing is
            // mapped in it, and is kept otherwise.
            // SAFETY: the range is this call's own reservation, and no Rust
            // reference into it exists.
            let unmapped = unsafe { syscall::mem_unmap(self.aspace, va, CHUNK_PAGES) }.is_ok();
            let _ = syscall::cap_delete(cap);
            if unmapped
            {
                std::os::seraph::unreserve_pages(range);
            }
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
        let phys = chunk.phys + chunk.used * PAGE_SIZE;
        let va = chunk.va + chunk.used * PAGE_SIZE;
        chunk.used += 1;
        // SAFETY: `va` is a page of the chunk mapped writable in `grow`, and
        // no table has been handed out over it yet.
        unsafe { core::ptr::write_bytes(va as *mut u64, 0, TABLE_WORDS) };
        // The zeroed page reaches memory before any entry that points at it.
        fence(Ordering::SeqCst);
        self.flush(phys, 0, PAGE_SIZE);
        Some(phys)
    }

    fn table(&mut self, phys: u64) -> &mut [u64; TABLE_WORDS]
    {
        let Some(va) = self.va(phys)
        else
        {
            std::os::seraph::log!("table pages: {:#x} is no table page", phys);
            *self.sink = [0; TABLE_WORDS];
            return &mut self.sink;
        };
        // SAFETY: `va` is a page-aligned page of a chunk mapped writable for
        // the driver's life, one `alloc` handed out; the store is reached
        // only under the service lock and through `&mut self`, so no other
        // reference to the page lives while this one does.
        unsafe { &mut *(va as *mut [u64; TABLE_WORDS]) }
    }

    fn written(&mut self, phys: u64, index: usize)
    {
        // Every table store is ordered before the next one, on a snooping
        // unit too. The register write that makes a unit read the tables
        // orders them before itself with the memory-to-device barrier the
        // driver's register accessor supplies.
        fence(Ordering::SeqCst);
        self.flush(phys, (index * 8) as u64, 8);
    }
}
