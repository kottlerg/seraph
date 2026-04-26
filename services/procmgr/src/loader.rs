// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/loader.rs

//! ELF segment loading into frames and child address spaces.
//!
//! Provides functions for mapping ELF module frames, deriving frame caps with
//! appropriate protection rights, and loading ELF segment pages from memory
//! into freshly allocated frames.

use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use syscall_abi::PAGE_SIZE;

/// RAII handle for a transient scratch mapping in procmgr's own aspace.
///
/// `new` reserves a contiguous unmapped VA range, calls `mem_map` against
/// `frame_cap` with the requested rights, and stores the range so `Drop`
/// can mirror the cleanup. Forgets the range on map-failure (allocator
/// only tracks VA — the failed map leaves no kernel-side state).
pub struct ScratchMapping
{
    range: Option<ReservedRange>,
    self_aspace: u32,
    pages: u64,
}

impl ScratchMapping
{
    /// Reserve `pages` VA pages, then `mem_map` the frame at the reserved
    /// base with the given protection flags. Returns `None` on either
    /// reservation or mapping failure.
    pub fn map(self_aspace: u32, frame_cap: u32, pages: u64, prot: u64) -> Option<Self>
    {
        let range = reserve_pages(pages).ok()?;
        let va = range.va_start();
        if syscall::mem_map(frame_cap, self_aspace, va, 0, pages, prot).is_err()
        {
            unreserve_pages(range);
            return None;
        }
        Some(Self {
            range: Some(range),
            self_aspace,
            pages,
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
    }
}

/// Map a module frame read-only, probing for the exact mappable page count.
///
/// Starts from 128 pages and decrements until the mapping succeeds. The
/// returned [`ScratchMapping`] owns the reservation; dropping it unmaps
/// and releases the VA.
pub fn map_module(module_frame_cap: u32, self_aspace: u32) -> Option<(ScratchMapping, u64)>
{
    let mut pages: u64 = 128;
    while pages > 0
    {
        if let Some(scratch) =
            ScratchMapping::map(self_aspace, module_frame_cap, pages, syscall::MAP_READONLY)
        {
            return Some((scratch, pages));
        }
        pages -= 1;
    }
    None
}

/// Derive a frame cap with the given protection rights for mapping.
pub fn derive_frame_for_prot(frame_cap: u32, prot: u64) -> Option<u32>
{
    if prot == syscall::MAP_EXECUTABLE
    {
        syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_RX).ok()
    }
    else if prot == syscall::MAP_WRITABLE
    {
        syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_RW).ok()
    }
    else
    {
        syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_READ).ok()
    }
}

/// Copy one ELF segment page into a fresh frame and map it into the child.
///
/// Frames are allocated against `child_memmgr_send` so memmgr accounts them
/// to the child from the moment they leave the pool — `PROCESS_DIED`
/// reclaims the entire set when the child exits.
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
    let frame_cap = crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)?;

    let scratch = ScratchMapping::map(self_aspace, frame_cap, 1, syscall::MAP_WRITABLE)?;
    let scratch_va = scratch.va();
    // SAFETY: scratch_va is mapped writable, one page.
    unsafe { core::ptr::write_bytes(scratch_va as *mut u8, 0, PAGE_SIZE as usize) };

    copy_segment_data(scratch_va, page_vaddr, seg_vaddr, file_data);

    drop(scratch);

    let derived = derive_frame_for_prot(frame_cap, prot)?;
    syscall::mem_map(derived, child_aspace, page_vaddr, 0, 1, 0).ok()?;

    Some(())
}

/// Copy file data for one segment page into the frame mapped at `scratch_va`.
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
