// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/loader.rs

//! ELF segment loading into frames and child address spaces.
//!
//! Provides functions for mapping ELF module frames, deriving frame caps with
//! appropriate protection rights, and loading ELF segment pages from memory
//! into freshly allocated frames.

use crate::frames::{FramePool, PAGE_SIZE};

pub use va_layout::{
    PROCMGR_TEMP_FRAME_VA as TEMP_FRAME_VA, PROCMGR_TEMP_MODULE_VA as TEMP_MODULE_VA,
    PROCMGR_TEMP_VFS_VA as TEMP_VFS_VA,
};

/// Map a module frame read-only, probing for the exact mappable page count.
///
/// Starts from 128 pages and decrements until the mapping succeeds.
pub fn map_module(module_frame_cap: u32, self_aspace: u32) -> Option<u64>
{
    let mut pages: u64 = 128;
    while pages > 0
    {
        if syscall::mem_map(
            module_frame_cap,
            self_aspace,
            TEMP_MODULE_VA,
            0,
            pages,
            syscall::MAP_READONLY,
        )
        .is_ok()
        {
            return Some(pages);
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
pub fn load_elf_page(
    page_vaddr: u64,
    seg_vaddr: u64,
    file_data: &[u8],
    prot: u64,
    pool: &mut FramePool,
    self_aspace: u32,
    child_aspace: u32,
) -> Option<()>
{
    let frame_cap = pool.alloc_page()?;

    syscall::mem_map(
        frame_cap,
        self_aspace,
        TEMP_FRAME_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .ok()?;
    // SAFETY: TEMP_FRAME_VA mapped writable, one page.
    unsafe { core::ptr::write_bytes(TEMP_FRAME_VA as *mut u8, 0, PAGE_SIZE as usize) };

    copy_segment_data(page_vaddr, seg_vaddr, file_data);

    let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);

    let derived = derive_frame_for_prot(frame_cap, prot)?;
    syscall::mem_map(derived, child_aspace, page_vaddr, 0, 1, 0).ok()?;

    Some(())
}

/// Copy file data for one segment page into the frame mapped at `TEMP_FRAME_VA`.
fn copy_segment_data(page_vaddr: u64, seg_vaddr: u64, file_data: &[u8])
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
        // SAFETY: TEMP_FRAME_VA mapped writable; copy stays within one page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                (TEMP_FRAME_VA as *mut u8).add(dest_offset),
                src.len(),
            );
        }
    }
}
