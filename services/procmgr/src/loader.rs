// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/loader.rs

//! ELF segment loading into memory caps and child address spaces.
//!
//! Provides functions for mapping ELF module memory caps, deriving memory caps with
//! appropriate protection rights, and loading ELF segment pages from memory
//! into freshly allocated memory caps.

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

/// Allocate one fresh memory cap, fill its zeroed scratch page via `fill`, then
/// derive a `prot`-restricted cap and map it into the child at `page_vaddr`.
///
/// Memory caps are allocated against `child_memmgr_send` so memmgr accounts them
/// to the child from the moment they leave the pool — `PROCESS_DIED` reclaims
/// the entire set when the child exits.
///
/// Every error exit deletes the caps it allocated (the `memory_cap`, plus the
/// `derived` cap once derivation succeeds). The success path drops the same
/// transient slots: the mapping owns no cap-refcount on the underlying
/// `MemoryObject` — memmgr's outer pins the page until `PROCESS_DIED` — so the
/// slots must be released either way or they accumulate across an unbounded
/// create/destroy loop.
///
/// `fill` receives the writable scratch VA of the zeroed page and writes the
/// segment bytes in (in-memory slice copy or VFS stream); it is infallible — a
/// short read leaves the page tail zeroed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_elf_page_into_child(
    page_vaddr: u64,
    prot: u64,
    self_aspace: u32,
    child_aspace: u32,
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
    fill: impl FnOnce(u64),
) -> Result<(), u64>
{
    let Some(memory_cap) = crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page: alloc None vaddr=0x{:x}",
            page_vaddr
        );
        return Err(procmgr_errors::OUT_OF_MEMORY);
    };

    let Some(scratch) = ScratchMapping::map(self_aspace, memory_cap, 1, syscall::MAP_WRITABLE)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page: scratch map None vaddr=0x{:x}",
            page_vaddr
        );
        let _ = syscall::cap_delete(memory_cap);
        return Err(procmgr_errors::MAP_FAILED);
    };
    let scratch_va = scratch.va();
    // SAFETY: scratch_va is mapped writable, one page.
    unsafe { core::ptr::write_bytes(scratch_va as *mut u8, 0, PAGE_SIZE as usize) };

    fill(scratch_va);

    drop(scratch);

    let Some(derived) = derive_memory_for_prot(memory_cap, prot)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page: derive None vaddr=0x{:x} prot=0x{:x}",
            page_vaddr,
            prot
        );
        let _ = syscall::cap_delete(memory_cap);
        return Err(procmgr_errors::INSUFFICIENT_RIGHTS);
    };
    if let Err(e) = syscall::mem_map(derived, child_aspace, page_vaddr, 0, 1, 0)
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page: mem_map err={} vaddr=0x{:x}",
            e,
            page_vaddr
        );
        let _ = syscall::cap_delete(derived);
        let _ = syscall::cap_delete(memory_cap);
        return Err(procmgr_errors::MAP_FAILED);
    }

    let _ = syscall::cap_delete(derived);
    let _ = syscall::cap_delete(memory_cap);

    Ok(())
}

/// Copy one in-memory ELF segment page into a fresh memory cap and map it into
/// the child. Thin wrapper over [`load_elf_page_into_child`] supplying the
/// in-memory slice-copy fill.
#[allow(clippy::too_many_arguments)]
pub fn load_elf_page(
    page_vaddr: u64,
    seg_vaddr: u64,
    file_data: &[u8],
    prot: u64,
    self_aspace: u32,
    child_aspace: u32,
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
) -> Option<()>
{
    load_elf_page_into_child(
        page_vaddr,
        prot,
        self_aspace,
        child_aspace,
        child_memmgr_send,
        ipc_buf,
        |scratch_va| copy_segment_data(scratch_va, page_vaddr, seg_vaddr, file_data),
    )
    .ok()
}

/// Copy file data for one segment page into the memory cap mapped at `scratch_va`.
fn copy_segment_data(scratch_va: u64, page_vaddr: u64, seg_vaddr: u64, file_data: &[u8])
{
    let page_start_in_seg = page_vaddr.saturating_sub(seg_vaddr) as usize;
    let page_end_in_seg = page_start_in_seg + PAGE_SIZE as usize;
    let file_start = page_start_in_seg.min(file_data.len());
    let file_end = page_end_in_seg.min(file_data.len());
    if file_start < file_end
    {
        let dest_offset = if page_vaddr < seg_vaddr
        {
            (seg_vaddr - page_vaddr) as usize
        }
        else
        {
            0
        };
        let avail = PAGE_SIZE as usize - dest_offset;
        let copy_len = (file_end - file_start).min(avail);
        let src = &file_data[file_start..file_start + copy_len];
        // SAFETY: scratch_va mapped writable; copy stays within one page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                (scratch_va as *mut u8).add(dest_offset),
                src.len(),
            );
        }
    }
}
