// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/stack_guard.rs

//! Guard pages below the kernel stacks, as holes in the direct map.
//!
//! Every kernel stack runs through the direct map, and the page below each is
//! left unmapped there, so an overflow faults instead of writing the memory
//! beneath the stack (`core/kernel/docs/memory-internals.md` § Kernel Stack
//! Guards). Phase 3 builds the handoff stack's hole into the direct map
//! (`mm::paging::init_kernel_page_tables`); this module makes the others: each
//! idle stack's guard in Phase 4 ([`hole_on_boot_cpu`]) and each Thread slot's
//! guard page while the thread exists ([`hole`], [`close`]).
//!
//! A hole in a 2 MiB chunk mapped by one large leaf splits the chunk into a
//! leaf table first. The leaf tables come from a reserve seeded in Phase 4
//! from the pristine buddy, one frame for each 2 MiB chunk of RAM
//! ([`reserve_frames`]), so a split never fails. A split chunk stays split and
//! its table stays consumed; the reserve's unused frames are never returned.

use boot_protocol::{MemoryMapEntry, MemoryType};

use crate::mm::paging::LARGE_PAGE_SIZE;

/// Leaf tables the reserve holds for a memory map: one for each 2 MiB chunk a
/// RAM region (`Usable`, `Loaded`, `AcpiReclaimable` or `Persistent`, the
/// regions the direct map covers as RAM) touches, counted once when regions
/// share a chunk. Every guard page is RAM, so the count bounds the chunks any
/// set of guards can split. Entries are in ascending base order, as the boot
/// protocol guarantees (`MemoryMapSlice`).
#[must_use]
pub fn reserve_frames(entries: &[MemoryMapEntry]) -> usize
{
    let mut frames = 0u64;
    // Exclusive end, in chunks, of the last chunk counted.
    let mut counted_end = 0u64;
    for e in entries
    {
        let ram = matches!(
            e.memory_type,
            MemoryType::Usable
                | MemoryType::Loaded
                | MemoryType::AcpiReclaimable
                | MemoryType::Persistent
        );
        if !ram || e.size == 0
        {
            continue;
        }
        let first = e.physical_base / LARGE_PAGE_SIZE;
        let end = (e.physical_base + e.size).div_ceil(LARGE_PAGE_SIZE);
        let from = first.max(counted_end);
        if end > from
        {
            frames += end - from;
        }
        counted_end = counted_end.max(end);
    }
    // The chunk count of any memory map the 64-bit kernel can map fits usize.
    #[allow(clippy::cast_possible_truncation)]
    let frames = frames as usize;
    frames
}

#[cfg(not(test))]
mod live
{
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::mm::paging::{PagingError, phys_to_virt};
    use crate::sync::Spinlock;

    /// Serialises every direct-map edit this module makes and the reserve's
    /// free list. A leaf lock: nothing is acquired while it is held
    /// (`core/kernel/docs/scheduling-internals.md` § Lock Hierarchy).
    static LOCK: Spinlock = Spinlock::new();

    /// Head of the reserve's free list, or 0 when empty. Each free frame's
    /// first 8 bytes, reached through the direct map, hold the next frame's
    /// address. Owned by [`LOCK`].
    static mut FREE_HEAD: u64 = 0;

    /// Frames [`seed`] put in the reserve.
    static SEEDED: AtomicUsize = AtomicUsize::new(0);

    /// Frames still in the reserve. Diagnostic only.
    static REMAINING: AtomicUsize = AtomicUsize::new(0);

    /// Seed the reserve with `frames` frames from the buddy.
    ///
    /// # Safety
    /// Phase 4, on the single boot thread, once, before any hole is made.
    ///
    /// # Panics
    /// Halts via `crate::fatal` when the buddy cannot supply a frame.
    pub unsafe fn seed(frames: usize, allocator: &mut crate::mm::BuddyAllocator)
    {
        for _ in 0..frames
        {
            let frame = allocator.alloc(0).unwrap_or_else(|| {
                crate::fatal("Phase 4: out of memory for the guard-table reserve")
            });
            // SAFETY: single boot thread before any hole (caller contract), so
            // nothing else reads the list; the frame is fresh from the buddy
            // and reached through the direct map.
            unsafe {
                (phys_to_virt(frame) as *mut u64).write(FREE_HEAD);
                FREE_HEAD = frame;
            }
        }
        SEEDED.store(frames, Ordering::Relaxed);
        REMAINING.store(frames, Ordering::Relaxed);
    }

    /// Frames the reserve was seeded with.
    pub fn seeded_frames() -> usize
    {
        SEEDED.load(Ordering::Relaxed)
    }

    /// Frames the reserve still holds.
    pub fn remaining_frames() -> usize
    {
        REMAINING.load(Ordering::Relaxed)
    }

    /// Pop a frame from the reserve.
    ///
    /// # Safety
    /// [`LOCK`] is held.
    unsafe fn take_frame() -> Option<u64>
    {
        // SAFETY: LOCK held (caller contract); the head and each link are
        // frames this module seeded, reached through the direct map.
        unsafe {
            let head = FREE_HEAD;
            if head == 0
            {
                return None;
            }
            FREE_HEAD = (phys_to_virt(head) as *const u64).read();
            REMAINING.fetch_sub(1, Ordering::Relaxed);
            Some(head)
        }
    }

    /// Unmap the page at `phys` from the direct map under [`LOCK`].
    ///
    /// # Safety
    /// As [`hole`].
    unsafe fn hole_locked(phys: u64) -> Result<(), PagingError>
    {
        // The arch walk calls this only during the edit, under LOCK.
        let mut take = || {
            // SAFETY: LOCK is held for the whole edit below.
            unsafe { take_frame() }
        };
        // SAFETY: LOCK serialises the edit and the reserve; the caller owns
        // the page and keeps everything off it.
        unsafe {
            let saved = LOCK.lock_raw();
            let r =
                crate::arch::current::paging::hole_direct_map_page(phys_to_virt(phys), &mut take);
            LOCK.unlock_raw(saved);
            r
        }
    }

    /// Unmap the RAM page at `phys` from the direct map while only the boot
    /// CPU runs, flushing this CPU's TLB.
    ///
    /// # Errors
    /// The arch walk's [`PagingError`]: `OutOfFrames` when the reserve is
    /// empty (a defect in [`super::reserve_frames`]), `NotMapped` when the
    /// direct map does not cover `phys`.
    ///
    /// # Safety
    /// Before any other CPU starts (Phase 4). `phys` is a page-aligned RAM
    /// page the caller owns, which nothing reaches through the direct map
    /// until [`close`].
    pub unsafe fn hole_on_boot_cpu(phys: u64) -> Result<(), PagingError>
    {
        // SAFETY: caller contract.
        unsafe { hole_locked(phys) }?;
        // SAFETY: ring 0 / S-mode; no other CPU has run, so none caches the
        // translation.
        unsafe { crate::arch::current::paging::flush_kernel_page(phys_to_virt(phys)) };
        Ok(())
    }

    /// Unmap the RAM page at `phys` from the direct map and drop every
    /// CPU's cached translation of it, with every CPU online.
    ///
    /// # Errors
    /// As [`hole_on_boot_cpu`].
    ///
    /// # Safety
    /// After SMP bringup (Phase 8 on), with no lock held. `phys` is a
    /// page-aligned RAM page the caller owns, which nothing reaches through
    /// the direct map until [`close`].
    pub unsafe fn hole(phys: u64) -> Result<(), PagingError>
    {
        let virt = phys_to_virt(phys);
        // Pinned to this CPU from the edit to the end of the broadcast, so
        // the local flush and the excluded CPU are the same.
        crate::percpu::preempt_disable();
        // SAFETY: caller contract.
        let r = unsafe { hole_locked(phys) };
        if r.is_ok()
        {
            // SAFETY: ring 0 / S-mode.
            unsafe { crate::arch::current::paging::flush_kernel_page(virt) };
            let cpu_count =
                crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
            let mut remote = crate::cpu_mask::CpuMask::range(cpu_count);
            remote.clear(crate::arch::current::cpu::current_cpu() as usize);
            // SAFETY: the kernel root is the active kernel half of every
            // address space; `remote` holds only online CPUs, not this one;
            // preemption is disabled. A request on the kernel root makes each
            // target drop the translation in every address space
            // (`tlb_shootdown::service_shootdowns`).
            unsafe {
                crate::mm::tlb_shootdown::shootdown(
                    crate::mm::paging::kernel_root_table_pa(),
                    &remote,
                    virt,
                    0,
                );
            }
        }
        crate::percpu::preempt_enable();
        debug_assert!(
            r.is_err() || !is_mapped(phys),
            "stack_guard: a holed guard is mapped"
        );
        r
    }

    /// Map the page at `phys`, holed by [`hole`], into the direct map again,
    /// so the page can hold anything once more.
    ///
    /// x86-64 caches no not-present entry, so no CPU needs a flush. A riscv64
    /// hart may hold the invalid one: this hart fences, and another one that
    /// reaches the page takes the S-mode spurious-fault retry
    /// (`arch::riscv64::paging::kernel_fault_is_spurious`).
    ///
    /// # Safety
    /// `phys` was holed by [`hole`] or [`hole_on_boot_cpu`] and is not holed
    /// again until this returns.
    pub unsafe fn close(phys: u64)
    {
        let virt = phys_to_virt(phys);
        // SAFETY: LOCK serialises the edit; the hole left a leaf table.
        unsafe {
            let saved = LOCK.lock_raw();
            crate::arch::current::paging::fill_direct_map_page(virt, phys);
            LOCK.unlock_raw(saved);
            crate::arch::current::paging::flush_kernel_page(virt);
        }
    }

    /// Whether the direct map maps the page at `phys`.
    pub fn is_mapped(phys: u64) -> bool
    {
        // SAFETY: LOCK serialises the read against the edits.
        unsafe {
            let saved = LOCK.lock_raw();
            let mapped = crate::arch::current::paging::direct_map_page_present(phys_to_virt(phys));
            LOCK.unlock_raw(saved);
            mapped
        }
    }
}

#[cfg(not(test))]
pub use live::{close, hole, hole_on_boot_cpu, is_mapped, remaining_frames, seed, seeded_frames};

#[cfg(test)]
mod tests
{
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn ram(base: u64, size: u64) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base: base,
            size,
            memory_type: MemoryType::Usable,
        }
    }

    // The defect caught: a region whose ends are not 2 MiB-aligned counted by
    // its size alone, which misses the partial chunk at each end and leaves a
    // split without a table.
    #[test]
    fn a_region_counts_every_chunk_it_touches_partial_ends_included()
    {
        assert_eq!(reserve_frames(&[ram(MIB, 4 * MIB)]), 3);
        assert_eq!(reserve_frames(&[ram(0, 4 * MIB)]), 2);
    }

    // The defect caught: two regions in one chunk counted twice (waste), or a
    // region inside the last counted chunk dropping the chunks past it.
    #[test]
    fn regions_sharing_a_chunk_count_it_once()
    {
        let map = [ram(0, MIB), ram(MIB + 4096, 3 * MIB)];
        assert_eq!(reserve_frames(&map), 3);
    }

    // The defect caught: a reserved or MMIO region counted, which would size
    // the reserve by the address space instead of RAM.
    #[test]
    fn non_ram_regions_take_no_table()
    {
        let mut mmio = ram(0x1_0000_0000, 512 * MIB);
        mmio.memory_type = MemoryType::Reserved;
        assert_eq!(reserve_frames(&[ram(0, 2 * MIB), mmio]), 1);
    }
}
