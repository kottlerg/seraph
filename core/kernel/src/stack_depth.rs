// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/stack_depth.rs

//! Kernel stack depth measurement.
//!
//! Every kernel stack is painted with [`STACK_PAINT`] when it is allocated:
//! the bootloader paints the handoff stack, and the kernel paints each idle
//! stack and each thread's kernel stack. A stack's deepest use is then the
//! span from its top down to its lowest word that no longer holds the paint.
//! [`high_water`] reports that span per stack class to
//! `SYS_SYSTEM_INFO(StackHighWater)`. The mechanism and its limits are in
//! core/kernel/docs/memory-internals.md § Kernel Stack Depth.

use core::sync::atomic::{AtomicU64, Ordering};

pub use boot_protocol::layout::{HANDOFF_STACK_BASE_MARK, STACK_PAINT};
#[cfg(not(test))]
use syscall::{STACK_CLASS_HANDOFF, STACK_CLASS_IDLE, STACK_CLASS_THREAD};

/// Deepest use of any thread kernel stack whose thread has been freed, in
/// bytes; raised by [`record_thread_stack`] at each thread's teardown.
static THREAD_HIGH_WATER: AtomicU64 = AtomicU64::new(0);

/// Deepest use of the handoff stack, in bytes, recorded by
/// [`record_handoff_stack`] when the BSP leaves it. `u64::MAX` while unknown
/// (not yet recorded, or the stack's base mark was not where the kernel
/// derived it).
static HANDOFF_HIGH_WATER: AtomicU64 = AtomicU64::new(u64::MAX);

/// Stack pointer at the first statement of `kernel_entry`, an identity-mapped
/// address inside the handoff stack. Written once by [`note_boot_entry`].
static BOOT_ENTRY_SP: AtomicU64 = AtomicU64::new(0);

/// Fill `bytes` bytes at `base` with [`STACK_PAINT`].
///
/// # Safety
/// `[base, base + bytes)` is writable, 8-byte aligned, and exclusively owned
/// by the caller (a stack no thread runs on yet).
pub unsafe fn paint(base: u64, bytes: usize)
{
    let words = bytes / core::mem::size_of::<u64>();
    let p = base as *mut u64;
    for i in 0..words
    {
        // SAFETY: i < words, so the write stays inside the caller's span.
        unsafe { p.add(i).write(STACK_PAINT) };
    }
}

/// Bytes used of the stack `[base, base + bytes)`: its size less the run of
/// [`STACK_PAINT`] words at its low end.
///
/// The reads are volatile because an idle stack is scanned while its CPU may
/// be running on it; a word written during the scan lies above the run either
/// way, so the result is the depth at some instant of the scan.
///
/// # Safety
/// `[base, base + bytes)` is mapped, readable, and 8-byte aligned.
pub unsafe fn used_bytes(base: u64, bytes: usize) -> u64
{
    let words = bytes / core::mem::size_of::<u64>();
    let p = base as *const u64;
    let mut untouched = 0usize;
    while untouched < words
    {
        // SAFETY: untouched < words, inside the caller's span.
        if unsafe { p.add(untouched).read_volatile() } != STACK_PAINT
        {
            break;
        }
        untouched += 1;
    }
    ((words - untouched) * core::mem::size_of::<u64>()) as u64
}

/// Record the stack pointer at `kernel_entry`'s first statement, from which
/// [`record_handoff_stack`] derives the handoff stack's span.
pub fn note_boot_entry(sp: u64)
{
    BOOT_ENTRY_SP.store(sp, Ordering::Relaxed);
}

/// Raise the thread-stack high-water mark with the stack at `base`
/// (`KERNEL_STACK_PAGES` pages), at the teardown of the thread it served.
///
/// # Safety
/// `base` is the direct-map address of a thread kernel stack no thread runs on.
#[cfg(not(test))]
pub unsafe fn record_thread_stack(base: u64)
{
    // SAFETY: per the contract, the stack is mapped and no longer in use.
    let used = unsafe { used_bytes(base, thread_stack_bytes()) };
    THREAD_HIGH_WATER.fetch_max(used, Ordering::Relaxed);
}

/// Record the handoff stack's deepest use. Called on the handoff stack itself,
/// by the BSP just before it leaves the stack for good (`sched::enter`).
///
/// The stack's top is the entry stack pointer rounded up to a page: the
/// bootloader allocates the stack in whole pages and enters the kernel with
/// the stack pointer at its top (core/boot/docs/boot-flow.md, the handoff
/// stack allocation), and `kernel_entry`'s frame is smaller than a page. The
/// base mark at the derived bottom confirms the span; when it is absent (an
/// overflow, or a bootloader that does not mark the stack) the class stays
/// unknown.
#[cfg(not(test))]
pub fn record_handoff_stack()
{
    let bytes = boot_protocol::layout::HANDOFF_STACK_BYTES;
    let page = crate::mm::PAGE_SIZE as u64;
    let entry = BOOT_ENTRY_SP.load(Ordering::Relaxed);
    if entry == 0
    {
        return;
    }
    let top_phys = (entry + page - 1) & !(page - 1);
    let base_phys = top_phys - bytes as u64;
    // The handoff stack's identity address is its physical address (VA == PA
    // until Phase 3), so the direct map reaches it after the rebase.
    let base = crate::mm::paging::phys_to_virt(base_phys);
    // SAFETY: base is the direct-map view of the handoff stack's lowest page,
    // which the bootloader allocated in RAM the direct map covers.
    let mark = unsafe { (base as *const u64).read_volatile() };
    if mark != HANDOFF_STACK_BASE_MARK
    {
        return;
    }
    let word = core::mem::size_of::<u64>();
    // SAFETY: as above; the words above the mark are the painted stack.
    let used = unsafe { used_bytes(base + word as u64, bytes - word) };
    HANDOFF_HIGH_WATER.store(used, Ordering::Relaxed);
}

/// Size of one idle or thread kernel stack, in bytes.
#[cfg(not(test))]
fn thread_stack_bytes() -> usize
{
    crate::sched::KERNEL_STACK_PAGES * crate::mm::PAGE_SIZE
}

/// Deepest use of a stack class, in bytes, or `None` for an unknown class.
///
/// - `STACK_CLASS_IDLE`: the deepest of every CPU's idle stack, scanned now.
/// - `STACK_CLASS_THREAD`: the deepest of every freed thread's stack and the
///   calling thread's own stack, scanned now. Another live thread's stack is
///   counted when that thread is freed.
/// - `STACK_CLASS_HANDOFF`: the handoff stack's deepest use, recorded when the
///   BSP left it; `u64::MAX` when it could not be located.
#[cfg(not(test))]
pub fn high_water(class: u64) -> Option<u64>
{
    let bytes = thread_stack_bytes();
    match class
    {
        STACK_CLASS_IDLE =>
        {
            let cpus = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
            let mut deepest = 0;
            for cpu in 0..cpus
            {
                // SAFETY: cpu < CPU_COUNT, and the scheduler is initialised
                // before any syscall runs.
                let top = unsafe { crate::sched::idle_stack_top_for(cpu) };
                // SAFETY: an idle stack is the `bytes` bytes below its top,
                // mapped through the direct map for the kernel's lifetime.
                deepest = deepest.max(unsafe { used_bytes(top - bytes as u64, bytes) });
            }
            Some(deepest)
        }
        STACK_CLASS_THREAD =>
        {
            // SAFETY: syscall context: the current TCB is the caller's.
            let tcb = unsafe { crate::syscall::current_tcb() };
            let own = if tcb.is_null()
            {
                0
            }
            else
            {
                // SAFETY: tcb is the live caller; its kernel stack is the
                // `bytes` bytes below `kernel_stack_top`.
                let top = unsafe { (*tcb).kernel_stack_top };
                // SAFETY: as above.
                unsafe { used_bytes(top - bytes as u64, bytes) }
            };
            Some(own.max(THREAD_HIGH_WATER.load(Ordering::Relaxed)))
        }
        STACK_CLASS_HANDOFF => Some(HANDOFF_HIGH_WATER.load(Ordering::Relaxed)),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    fn painted(words: usize) -> Vec<u64>
    {
        let mut v = vec![0u64; words];
        // SAFETY: v owns `words` u64s, 8-aligned.
        unsafe { paint(v.as_mut_ptr() as u64, words * 8) };
        v
    }

    #[test]
    fn an_untouched_stack_uses_nothing_and_a_full_one_everything()
    {
        let v = painted(512);
        assert!(v.iter().all(|&w| w == STACK_PAINT));
        // SAFETY: v is 512 readable words.
        assert_eq!(unsafe { used_bytes(v.as_ptr() as u64, 512 * 8) }, 0);
        let full = vec![0u64; 512];
        // SAFETY: as above.
        assert_eq!(unsafe { used_bytes(full.as_ptr() as u64, 512 * 8) }, 4096);
    }

    #[test]
    fn depth_is_measured_from_the_lowest_overwritten_word()
    {
        // Stacks grow down: the top 100 words used, then a deeper excursion
        // that wrote one word at index 300 with paint left between.
        let mut v = painted(512);
        for w in &mut v[412..]
        {
            *w = 0;
        }
        v[300] = 7;
        // SAFETY: v is 512 readable words.
        assert_eq!(
            unsafe { used_bytes(v.as_ptr() as u64, 512 * 8) },
            (512 - 300) * 8
        );
    }

    #[test]
    fn paint_and_mark_are_distinct_from_zero_and_each_other()
    {
        assert_ne!(STACK_PAINT, 0);
        assert_ne!(HANDOFF_STACK_BASE_MARK, 0);
        assert_ne!(STACK_PAINT, HANDOFF_STACK_BASE_MARK);
    }
}
