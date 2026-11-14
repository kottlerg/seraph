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
//! Neither a Thread guard's hole nor its fill sends a shootdown. [`hole`]
//! advances the guard epoch and returns it for the new thread's TCB; every
//! switch-in compares the incoming thread's stamp with the epoch the CPU last
//! flushed at and flushes the CPU's whole TLB first when the stamp is newer
//! ([`flush_before_run`]). A stale translation of a thread's guard lets an
//! overflow through only while that thread runs on that CPU, and every run
//! starts with a switch-in, or, for init's first, with `sched::enter`, which
//! makes the same check. A fill ([`close`]) flushes only its own CPU; see its
//! documentation for why the others need no flush.
//!
//! A hole in a 2 MiB chunk mapped by one large leaf splits the chunk into a
//! leaf table first. The leaf tables come from a reserve seeded in Phase 4
//! from the pristine buddy, one frame for each 2 MiB chunk of RAM
//! ([`reserve_frames`]), so a split never fails. A split chunk stays split and
//! its table stays consumed; the reserve's unused frames are never returned.

use boot_protocol::MemoryMapEntry;

use crate::mm::paging::LARGE_PAGE_SIZE;

/// Leaf tables the reserve holds for a memory map: one for each 2 MiB chunk a
/// RAM region (`mm::init::is_dram`, the regions the direct map covers as RAM)
/// touches, counted once when regions
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
        if !crate::mm::init::is_dram(e.memory_type) || e.size == 0
        {
            continue;
        }
        let first = e.physical_base / LARGE_PAGE_SIZE;
        // An entry past the end of the address space is cut at it, which can
        // only count one chunk more.
        let end = e
            .physical_base
            .saturating_add(e.size)
            .div_ceil(LARGE_PAGE_SIZE);
        let from = first.max(counted_end);
        // The chunks a 64-bit address space holds, far below the saturation
        // point; none when an earlier entry counted them.
        frames = frames.saturating_add(end.saturating_sub(from));
        counted_end = counted_end.max(end);
    }
    // The chunk count of any memory map the 64-bit kernel can map fits usize.
    usize::try_from(frames).unwrap_or(usize::MAX)
}

#[cfg(not(test))]
mod live
{
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use crate::mm::paging::{PagingError, phys_to_virt};
    use crate::sync::Spinlock;

    /// The reserve's free list and the lock that serialises it together with
    /// every direct-map edit this module makes. A leaf lock: nothing is
    /// acquired while it is held (`core/kernel/docs/scheduling-internals.md`
    /// § Lock Hierarchy).
    struct Reserve
    {
        lock: Spinlock,
        /// Head of the free list, or 0 when empty. Each free frame's first
        /// 8 bytes, reached through the direct map, hold the next frame's
        /// address. Reached only through [`Reserve::with`], under `lock`.
        head: UnsafeCell<u64>,
    }

    // SAFETY: `head` is reached only through `Reserve::with`, which holds
    // `lock` for the access.
    unsafe impl Sync for Reserve {}

    impl Reserve
    {
        /// Run `f` with the lock held, handing it the free list.
        fn with<R>(&self, f: impl FnOnce(&mut FreeList) -> R) -> R
        {
            // SAFETY: the lock is released below, after `f`, which cannot
            // retain the list past its call.
            let saved = unsafe { self.lock.lock_raw() };
            // SAFETY: the lock is held, so this is the head's only reference.
            let head = unsafe { self.head.as_mut_unchecked() };
            let mut list = FreeList { head };
            let r = f(&mut list);
            // SAFETY: paired with the acquisition above.
            unsafe { self.lock.unlock_raw(saved) };
            r
        }
    }

    /// The reserve's free list, borrowed under its lock ([`Reserve::with`]).
    struct FreeList<'a>
    {
        head: &'a mut u64,
    }

    impl FreeList<'_>
    {
        /// Push the frame at `frame`.
        ///
        /// # Safety
        /// `frame` is a page-aligned RAM frame the caller hands over, reached
        /// through the direct map, and on no list.
        unsafe fn push(&mut self, frame: u64)
        {
            // SAFETY: caller contract; the frame's first word is its link.
            unsafe { (phys_to_virt(frame) as *mut u64).write(*self.head) };
            *self.head = frame;
            REMAINING.fetch_add(1, Ordering::Relaxed);
        }

        /// Pop a frame, or `None` when the list is empty.
        fn pop(&mut self) -> Option<u64>
        {
            let frame = *self.head;
            if frame == 0
            {
                return None;
            }
            // SAFETY: every frame on the list was pushed by `push`, which
            // wrote its link through the direct map.
            *self.head = unsafe { (phys_to_virt(frame) as *const u64).read() };
            REMAINING.fetch_sub(1, Ordering::Relaxed);
            Some(frame)
        }
    }

    /// The guard-table reserve.
    static RESERVE: Reserve = Reserve {
        lock: Spinlock::new(),
        head: UnsafeCell::new(0),
    };

    /// Frames [`seed`] put in the reserve.
    static SEEDED: AtomicUsize = AtomicUsize::new(0);

    /// Frames still in the reserve. Diagnostic only.
    static REMAINING: AtomicUsize = AtomicUsize::new(0);

    /// Thread-guard holes made so far: [`hole`] advances it after each edit
    /// and stamps the new value in the thread's TCB. A CPU whose last flush
    /// read an epoch at or past a thread's stamp holds no stale translation
    /// of that thread's guard, nor a stale not-present entry for a page a
    /// [`close`] filled before that hole (both edits are made under the
    /// reserve's lock, so the fill precedes the advance; [`flush_before_run`]).
    static GUARD_EPOCH: AtomicU64 = AtomicU64::new(0);

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
            // Each frame is pushed under its own hold, so the lock's hold is
            // the push alone, never a buddy allocation.
            RESERVE.with(|list| {
                // SAFETY: the frame is fresh from the buddy, this call's
                // alone, and reached through the direct map.
                unsafe { list.push(frame) };
            });
        }
        SEEDED.store(frames, Ordering::Relaxed);
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

    /// Unmap the page at `guard` from the direct map, and give the page at
    /// `shadow`, if any, the shadow-stack encoding, under one hold of the
    /// reserve's lock.
    ///
    /// # Safety
    /// As [`hole`].
    unsafe fn hole_locked(guard: u64, shadow: Option<u64>) -> Result<(), PagingError>
    {
        use crate::arch::current::paging::{
            fill_direct_map_page, hole_direct_map_page, shadow_direct_map_page,
        };

        RESERVE.with(|list| {
            // SAFETY: the lock serialises the edits and the reserve; the
            // caller owns the pages and keeps everything off the guard, and
            // every store but the shadow stack's off the shadow page.
            unsafe { hole_direct_map_page(phys_to_virt(guard), &mut || list.pop()) }?;
            let Some(shadow) = shadow
            else
            {
                return Ok(());
            };
            // SAFETY: as above.
            let made =
                unsafe { shadow_direct_map_page(phys_to_virt(shadow), shadow, &mut || list.pop()) };
            if made.is_err()
            {
                // The caller sees the error with neither page changed.
                // SAFETY: the hole above left a leaf table; the lock is held.
                unsafe { fill_direct_map_page(phys_to_virt(guard), guard) };
            }
            made
        })
    }

    /// Give the RAM page at `phys` the shadow-stack encoding in the direct map
    /// while only the boot CPU runs, flushing this CPU's TLB. A per-CPU or the
    /// handoff shadow stack, kept for good.
    ///
    /// # Errors
    /// As [`hole_on_boot_cpu`].
    ///
    /// # Safety
    /// Before any other CPU starts (Phase 4 or 5). `phys` is a page-aligned
    /// RAM page the caller owns, which nothing but its shadow stack writes from
    /// here on.
    pub unsafe fn shadow_on_boot_cpu(phys: u64) -> Result<(), PagingError>
    {
        let virt = phys_to_virt(phys);
        RESERVE.with(|list| {
            // SAFETY: the lock serialises the edit and the reserve; caller
            // contract for the page.
            unsafe {
                crate::arch::current::paging::shadow_direct_map_page(virt, phys, &mut || list.pop())
            }
        })?;
        // SAFETY: ring 0 / S-mode; no other CPU has run, so none caches the
        // translation.
        unsafe { crate::arch::current::paging::flush_kernel_page(virt) };
        Ok(())
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
    /// while it is holed.
    pub unsafe fn hole_on_boot_cpu(phys: u64) -> Result<(), PagingError>
    {
        // SAFETY: caller contract.
        unsafe { hole_locked(phys, None) }?;
        // SAFETY: ring 0 / S-mode; no other CPU has run, so none caches the
        // translation.
        unsafe { crate::arch::current::paging::flush_kernel_page(phys_to_virt(phys)) };
        Ok(())
    }

    /// Unmap the RAM page at `guard`, a new thread's guard page, from the
    /// direct map, give the page at `shadow`, the thread's shadow stack when
    /// shadow stacks are on, the shadow-stack encoding, and return the guard
    /// epoch to stamp in the thread's TCB. On an error neither page changed.
    /// No CPU's TLB is flushed here, this one's included: nothing reaches the
    /// guard page, nor runs on the shadow stack, before the new thread first
    /// runs, and every CPU's record, this one's too, predates the stamp, so
    /// each flushes before it runs the thread ([`flush_before_run`], at a
    /// switch-in or in `sched::enter`). Until a CPU flushes, a stale writable
    /// translation of the shadow page lets an ordinary store from that CPU
    /// through, as a stale translation of the guard lets an overflow through.
    ///
    /// # Errors
    /// As [`hole_on_boot_cpu`].
    ///
    /// # Safety
    /// After SMP bringup (Phase 8 on), with no lock held. `guard` and `shadow`
    /// are distinct page-aligned RAM pages the caller owns: nothing reaches
    /// `guard` through the direct map, and nothing but the thread's shadow
    /// stack writes `shadow`, until [`close`]. The returned epoch is stamped
    /// in the TCB of the thread whose stack lies above `guard` before the
    /// thread first runs.
    pub unsafe fn hole(guard: u64, shadow: Option<u64>) -> Result<u64, PagingError>
    {
        // SAFETY: caller contract.
        unsafe { hole_locked(guard, shadow) }?;
        debug_assert!(!is_mapped(guard), "stack_guard: a holed guard is mapped");
        // After the edit, which the reserve lock's release published: a CPU
        // that reads this epoch or a later one sees the hole.
        // The epoch wraps, as `fetch_add` does.
        Ok(GUARD_EPOCH.fetch_add(1, Ordering::AcqRel).wrapping_add(1))
    }

    /// Flush this CPU's whole TLB, in every address space, when `stamp`, the
    /// incoming thread's guard epoch, is newer than the epoch this CPU last
    /// flushed at, so no stale translation of that thread's guard page
    /// outlives the switch-in. Called by `schedule()` on every switch-in and
    /// by `sched::enter` before init's first run.
    ///
    /// The flush also drops every stale not-present entry this CPU kept for a
    /// page a [`close`] filled before the thread's hole, which [`close`]
    /// relies on instead of a shootdown: such a page may now be the incoming
    /// thread's kernel stack, where a fault would nest its trap frame on the
    /// faulting page. That is why the flush is the whole TLB, not the guard
    /// page alone.
    ///
    /// The flush is `flush_all_contexts`: INVPCID's all-context form on
    /// x86-64 with tagged TLBs, a CR3 reload without them, and
    /// `sfence.vma zero, zero` on riscv64.
    ///
    /// # Safety
    /// Ring 0 / S-mode with interrupts disabled, so this CPU's per-CPU record
    /// is read and written on the CPU that flushes; after `percpu::init_bsp`
    /// or `percpu::init_ap` installed the CPU's per-CPU pointer.
    pub unsafe fn flush_before_run(stamp: u64)
    {
        // SAFETY: interrupts disabled and this CPU's per-CPU pointer installed
        // (caller contract).
        if stamp <= unsafe { crate::percpu::guard_epoch_flushed() }
        {
            return;
        }
        // Read before the flush: every hole up to this epoch was published
        // before it was advanced, so the flush drops each one's stale entry.
        let epoch = GUARD_EPOCH.load(Ordering::Acquire);
        // SAFETY: ring 0 / S-mode with interrupts disabled (caller contract);
        // dropping every cached translation is always safe.
        unsafe { crate::arch::current::paging::flush_all_contexts() };
        // SAFETY: interrupts disabled and this CPU's per-CPU pointer installed
        // (caller contract); the record is this CPU's, which the flush above
        // covers.
        unsafe { crate::percpu::set_guard_epoch_flushed(epoch) };
    }

    /// Map the page at `guard`, holed by [`hole`], and the shadow stack at
    /// `shadow` it made, read-write into the direct map again, so the pages
    /// can hold anything once more, and drop this CPU's cached entries for
    /// them: a guard's not-present entry where the architecture caches one
    /// (`CACHES_NOT_PRESENT_ENTRIES`: riscv64; x86-64 caches none), and a
    /// shadow stack's read-only entry. No other CPU is flushed: one that kept
    /// either entry flushes before it runs a thread whose kernel stack the
    /// page becomes (that thread's creation advances the guard epoch after
    /// this fill; [`flush_before_run`]), and any other use of the page faults
    /// on a different stack, where the kernel's spurious-fault retry flushes
    /// the entry and re-executes (`core/kernel/docs/memory-internals.md`
    /// § Kernel Stack Guards).
    ///
    /// # Safety
    /// With no lock held. `guard` and `shadow` were holed and made a shadow
    /// stack by one [`hole`], whose thread no longer runs, and are not passed
    /// to it again until this returns.
    pub unsafe fn close(guard: u64, shadow: Option<u64>)
    {
        use crate::arch::current::paging::{
            CACHES_NOT_PRESENT_ENTRIES, fill_direct_map_page, flush_kernel_page,
        };

        RESERVE.with(|_| {
            // SAFETY: the reserve's lock serialises the edit; the hole left a
            // leaf table.
            unsafe { fill_direct_map_page(phys_to_virt(guard), guard) };
            if let Some(shadow) = shadow
            {
                // SAFETY: as above; the shadow stack left a leaf table.
                unsafe { fill_direct_map_page(phys_to_virt(shadow), shadow) };
            }
        });
        // A migration between the fill and these flushes is harmless: the
        // CPU left behind is covered as every other one is (above).
        if CACHES_NOT_PRESENT_ENTRIES
        {
            // SAFETY: ring 0 / S-mode; dropping this CPU's cached entry for a
            // kernel address is always safe.
            unsafe { flush_kernel_page(phys_to_virt(guard)) };
        }
        if let Some(shadow) = shadow
        {
            // SAFETY: as above.
            unsafe { flush_kernel_page(phys_to_virt(shadow)) };
        }
    }

    /// Whether the direct map maps the page at `phys`.
    pub fn is_mapped(phys: u64) -> bool
    {
        RESERVE.with(|_| {
            // SAFETY: the reserve's lock serialises the read against the
            // edits.
            unsafe { crate::arch::current::paging::direct_map_page_present(phys_to_virt(phys)) }
        })
    }
}

#[cfg(not(test))]
pub use live::{
    close, flush_before_run, hole, hole_on_boot_cpu, is_mapped, remaining_frames, seed,
    seeded_frames, shadow_on_boot_cpu,
};

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::MemoryType;

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
