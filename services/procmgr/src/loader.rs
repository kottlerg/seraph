// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/loader.rs

//! ELF segment loading into memory caps and child address spaces.
//!
//! Provides functions for mapping ELF module memory caps, deriving memory caps
//! with appropriate protection rights, and loading whole ELF segments into
//! freshly allocated memory caps at segment granularity — the caller's `fill`
//! sees the segment's full page span at once, so relocation targets that
//! straddle a page boundary are written in one piece.

use ipc::procmgr_errors;
use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use syscall_abi::PAGE_SIZE;

/// RAII handle for a transient scratch mapping in procmgr's own aspace.
///
/// `new` reserves a contiguous unmapped VA range, calls `mem_map` against
/// `memory_cap` with the requested rights, and stores the range so `Drop`
/// can mirror the cleanup. Forgets the range on map-failure (allocator
/// only tracks VA — the failed map leaves no kernel-side state).
pub struct ScratchMapping
{
    range: Option<ReservedRange>,
    self_aspace: u32,
    pages: u64,
    /// Optional Memory cap slot to `cap_delete` on drop. Used when the
    /// caller derived a temporary read-only cap solely for this mapping
    /// (see [`map_module`]).
    owns_cap: u32,
}

impl ScratchMapping
{
    /// Reserve `pages` VA pages, then `mem_map` the memory cap at the reserved
    /// base with the given protection flags. Returns `None` on either
    /// reservation or mapping failure.
    pub fn map(self_aspace: u32, memory_cap: u32, pages: u64, prot: u64) -> Option<Self>
    {
        let range = reserve_pages(pages).ok()?;
        let va = range.va_start();
        if syscall::mem_map(memory_cap, self_aspace, va, 0, pages, prot).is_err()
        {
            unreserve_pages(range);
            return None;
        }
        Some(Self {
            range: Some(range),
            self_aspace,
            pages,
            owns_cap: 0,
        })
    }

    /// Base VA of the mapping. Stable for the lifetime of `self`.
    #[inline]
    pub fn va(&self) -> u64
    {
        self.range
            .as_ref()
            .map_or(0, std::os::seraph::ReservedRange::va_start)
    }

    /// Transfer ownership of `cap_slot` to this mapping; the slot is
    /// `cap_delete`d when the mapping is dropped.
    pub fn set_owns_cap(&mut self, cap_slot: u32)
    {
        self.owns_cap = cap_slot;
    }
}

impl Drop for ScratchMapping
{
    fn drop(&mut self)
    {
        if let Some(range) = self.range.take()
        {
            let va = range.va_start();
            let _ = syscall::mem_unmap(self.self_aspace, va, self.pages);
            unreserve_pages(range);
        }
        if self.owns_cap != 0
        {
            let _ = syscall::cap_delete(self.owns_cap);
            self.owns_cap = 0;
        }
    }
}

/// Map a module memory cap read-only, probing for the exact mappable page count.
///
/// Starts from 128 pages and decrements until the mapping succeeds. The
/// returned [`ScratchMapping`] owns the reservation; dropping it unmaps
/// and releases the VA.
///
/// `module_memory_cap` is a borrowed derivation of the caller's full-rights
/// module-source memory cap. We derive a read-only child cap for the load-time
/// mapping; otherwise `mem_map`'s derive-from-cap path produces a
/// writable+executable mapping that violates W^X. The derived cap is owned by
/// the returned [`ScratchMapping`] and dropped alongside the unmap.
pub fn map_module(module_memory_cap: u32, self_aspace: u32) -> Option<(ScratchMapping, u64)>
{
    let module_ro = syscall::cap_derive(module_memory_cap, syscall::RIGHTS_MAP_READ).ok()?;
    let mut pages: u64 = 128;
    while pages > 0
    {
        if let Some(mut scratch) =
            ScratchMapping::map(self_aspace, module_ro, pages, syscall::MAP_READONLY)
        {
            scratch.set_owns_cap(module_ro);
            return Some((scratch, pages));
        }
        pages -= 1;
    }
    let _ = syscall::cap_delete(module_ro);
    None
}

/// Derive a memory cap with the given protection rights for mapping.
pub fn derive_memory_for_prot(memory_cap: u32, prot: u64) -> Option<u32>
{
    if prot == syscall::MAP_EXECUTABLE
    {
        syscall::cap_derive(memory_cap, syscall::RIGHTS_MAP_RX).ok()
    }
    else if prot == syscall::MAP_WRITABLE
    {
        syscall::cap_derive(memory_cap, syscall::RIGHTS_MAP_RW).ok()
    }
    else
    {
        syscall::cap_derive(memory_cap, syscall::RIGHTS_MAP_READ).ok()
    }
}

/// Load one ELF segment span into the child: allocate `num_pages` fresh
/// memory caps, map them contiguously writable at a transient scratch range,
/// zero the span, run `fill` over the whole span once, then map every page
/// into the child at `first_page_vaddr` with a `prot`-restricted cap.
///
/// Segment granularity (rather than per-page) lets `fill` write values that
/// straddle a page boundary — an 8-byte `RELATIVE` relocation target may
/// span two pages.
///
/// Memory caps are allocated against `child_memmgr_send` so memmgr accounts
/// them to the child from the moment they leave the pool — `PROCESS_DIED`
/// reclaims the entire set when the child exits. The transient procmgr-side
/// slots (memory caps and per-page derived caps) are released on every exit
/// path, success included: the mappings own no cap-refcount on the underlying
/// `MemoryObject` — memmgr's outer pins the pages until `PROCESS_DIED` — so
/// retained slots would accumulate across an unbounded create/destroy loop.
///
/// `fill` receives the zeroed writable span and writes the segment bytes and
/// relocation values in (in-memory slice copy or VFS stream); it is
/// infallible — a short read leaves the tail zeroed.
// too_many_lines: one transaction owning the scratch span, the per-page cap
// set, and the child mappings; splitting would thread the guard state through
// helpers that all need the same aspace + cap context.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn load_elf_segment_into_child(
    first_page_vaddr: u64,
    num_pages: u64,
    prot: u64,
    self_aspace: u32,
    child_aspace: u32,
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
    fill: impl FnOnce(&mut [u8]),
) -> Result<(), u64>
{
    /// Cleanup guard: unmaps whatever part of the scratch span is mapped,
    /// releases the VA reservation, and deletes the transient cap slots.
    struct SegmentScratch
    {
        range: Option<ReservedRange>,
        self_aspace: u32,
        mapped: u64,
        caps: Vec<u32>,
    }

    impl Drop for SegmentScratch
    {
        fn drop(&mut self)
        {
            if let Some(range) = self.range.take()
            {
                if self.mapped > 0
                {
                    let _ = syscall::mem_unmap(self.self_aspace, range.va_start(), self.mapped);
                }
                unreserve_pages(range);
            }
            for cap in self.caps.drain(..)
            {
                let _ = syscall::cap_delete(cap);
            }
        }
    }

    if num_pages == 0
    {
        return Ok(());
    }

    let Ok(range) = reserve_pages(num_pages)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_segment: VA reserve failed vaddr=0x{:x} pages={}",
            first_page_vaddr,
            num_pages
        );
        return Err(procmgr_errors::OUT_OF_MEMORY);
    };
    let scratch_base = range.va_start();
    let mut scratch = SegmentScratch {
        range: Some(range),
        self_aspace,
        mapped: 0,
        caps: Vec::with_capacity(num_pages as usize),
    };

    for i in 0..num_pages
    {
        let Some(memory_cap) = crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)
        else
        {
            std::os::seraph::log!(
                "procmgr: load_elf_segment: alloc None vaddr=0x{:x}",
                first_page_vaddr + i * PAGE_SIZE
            );
            return Err(procmgr_errors::OUT_OF_MEMORY);
        };
        scratch.caps.push(memory_cap);
        if syscall::mem_map(
            memory_cap,
            self_aspace,
            scratch_base + i * PAGE_SIZE,
            0,
            1,
            syscall::MAP_WRITABLE,
        )
        .is_err()
        {
            std::os::seraph::log!(
                "procmgr: load_elf_segment: scratch map failed vaddr=0x{:x}",
                first_page_vaddr + i * PAGE_SIZE
            );
            return Err(procmgr_errors::MAP_FAILED);
        }
        scratch.mapped += 1;
    }

    let span_len = (num_pages * PAGE_SIZE) as usize;
    // SAFETY: the whole span [scratch_base, scratch_base + span_len) was just
    // mapped writable, one fresh page per iteration.
    let span = unsafe { core::slice::from_raw_parts_mut(scratch_base as *mut u8, span_len) };
    span.fill(0);
    fill(span);

    // Drop the scratch mapping (keeping the caps) before mapping into the
    // child.
    if let Some(range) = scratch.range.take()
    {
        let _ = syscall::mem_unmap(self_aspace, range.va_start(), scratch.mapped);
        unreserve_pages(range);
        scratch.mapped = 0;
    }

    for (i, &memory_cap) in scratch.caps.iter().enumerate()
    {
        let page_vaddr = first_page_vaddr + i as u64 * PAGE_SIZE;
        let Some(derived) = derive_memory_for_prot(memory_cap, prot)
        else
        {
            std::os::seraph::log!(
                "procmgr: load_elf_segment: derive None vaddr=0x{:x} prot=0x{:x}",
                page_vaddr,
                prot
            );
            return Err(procmgr_errors::INSUFFICIENT_RIGHTS);
        };
        let mapped = syscall::mem_map(derived, child_aspace, page_vaddr, 0, 1, 0);
        let _ = syscall::cap_delete(derived);
        if let Err(e) = mapped
        {
            std::os::seraph::log!(
                "procmgr: load_elf_segment: mem_map err={} vaddr=0x{:x}",
                e,
                page_vaddr
            );
            return Err(procmgr_errors::MAP_FAILED);
        }
    }

    // `scratch`'s Drop deletes the transient memory-cap slots.
    Ok(())
}
