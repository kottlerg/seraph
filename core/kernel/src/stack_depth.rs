// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/stack_depth.rs

//! Kernel stack depth measurement.
//!
//! Every idle, thread, and handoff stack is painted with [`STACK_PAINT`] when
//! it is allocated: the bootloader paints the handoff stack, and the kernel
//! paints each idle stack and each thread's kernel stack. A stack's deepest
//! use is then the span from its top down to its lowest word that no longer
//! holds the paint. [`high_water`] reports that span per stack class to
//! `SYS_SYSTEM_INFO(StackHighWater)`. The mechanism and its limits are in
//! core/kernel/docs/memory-internals.md § Kernel Stack Depth.

use core::sync::atomic::{AtomicU64, Ordering};

use boot_protocol::layout::STACK_PAINT;
#[cfg(not(test))]
use boot_protocol::layout::{HANDOFF_STACK_BASE_MARK, HANDOFF_STACK_BYTES};
#[cfg(not(test))]
use syscall::{STACK_CLASS_HANDOFF, STACK_CLASS_IDLE, STACK_CLASS_THREAD, SyscallError};

/// Deepest use of any thread kernel stack whose thread has been freed, in
/// bytes; raised by [`record_thread_stack`] at each thread's teardown.
static THREAD_HIGH_WATER: AtomicU64 = AtomicU64::new(0);

/// Deepest use of the handoff stack, in bytes, recorded by
/// [`record_handoff_stack`] when the BSP leaves it. [`HANDOFF_UNLOCATED`]
/// while unknown (not yet recorded, or the stack's base mark was not where
/// the kernel derived it).
static HANDOFF_HIGH_WATER: AtomicU64 = AtomicU64::new(HANDOFF_UNLOCATED);

/// [`HANDOFF_HIGH_WATER`] value for a handoff stack that could not be located;
/// never a depth, since no depth exceeds the stack's size.
const HANDOFF_UNLOCATED: u64 = u64::MAX;

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

/// Bytes used of a stack of `words` words: its size less the run of
/// [`STACK_PAINT`] words at its low end, where `word(i)` reads word `i`
/// counted from the low end.
fn used_bytes_with(words: usize, mut word: impl FnMut(usize) -> u64) -> u64
{
    let mut untouched = 0usize;
    while untouched < words && word(untouched) == STACK_PAINT
    {
        untouched += 1;
    }
    ((words - untouched) * core::mem::size_of::<u64>()) as u64
}

/// Bytes used of the stack `[base, base + bytes)`, which no other CPU writes
/// during the call: a freed thread's stack, the caller's own stack below its
/// stack pointer, or the handoff stack scanned on the stack itself.
///
/// # Safety
/// `[base, base + bytes)` is mapped, readable, and 8-byte aligned, and no
/// other CPU writes it during the call.
pub unsafe fn used_bytes(base: u64, bytes: usize) -> u64
{
    let p = base as *const u64;
    // SAFETY: each index is below `bytes / 8`, inside the caller's span.
    used_bytes_with(bytes / core::mem::size_of::<u64>(), |i| unsafe {
        p.add(i).read()
    })
}

/// The handoff stack's `(base, bytes)` for an entry stack pointer: its top is
/// `entry_sp` rounded up to a page, and it spans `stack_bytes` below that top.
fn handoff_span(entry_sp: u64, page: u64, stack_bytes: u64) -> (u64, u64)
{
    let top = entry_sp.next_multiple_of(page);
    (top - stack_bytes, stack_bytes)
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
/// by the BSP in `sched::enter` after its last call on that stack and just
/// before it leaves for init's kernel stack.
///
/// The stack's top is the entry stack pointer rounded up to a page: the
/// reference bootloader allocates the stack in whole pages and enters the
/// kernel with the stack pointer at its top (core/boot/docs/boot-flow.md
/// § Step 6), and `kernel_entry`'s frame is smaller than a page. The base mark
/// at the derived bottom confirms the span; when it is absent (an overflow,
/// or a bootloader that does not mark the stack) the class stays unlocated.
#[cfg(not(test))]
pub fn record_handoff_stack()
{
    let entry = BOOT_ENTRY_SP.load(Ordering::Relaxed);
    if entry == 0
    {
        return;
    }
    let (base_phys, bytes) = handoff_span(
        entry,
        crate::mm::PAGE_SIZE as u64,
        HANDOFF_STACK_BYTES as u64,
    );
    // The handoff stack's identity address is its physical address (VA == PA
    // until Phase 3), so the direct map reaches it after the rebase.
    let base = crate::mm::paging::phys_to_virt(base_phys);
    // SAFETY: base is the direct-map view of the handoff stack's lowest page,
    // which the bootloader allocated in RAM the direct map covers.
    let mark = unsafe { (base as *const u64).read() };
    if mark != HANDOFF_STACK_BASE_MARK
    {
        return;
    }
    let word = core::mem::size_of::<u64>();
    // SAFETY: as above; the words above the mark are the painted stack, and
    // only this CPU, running on it, writes it.
    let used = unsafe { used_bytes(base + word as u64, HANDOFF_STACK_BYTES - word) };
    debug_assert_eq!(bytes, HANDOFF_STACK_BYTES as u64);
    HANDOFF_HIGH_WATER.store(used, Ordering::Relaxed);
}

/// Size of one idle or thread kernel stack, in bytes.
#[cfg(not(test))]
fn thread_stack_bytes() -> usize
{
    crate::sched::KERNEL_STACK_PAGES * crate::mm::PAGE_SIZE
}

/// Deepest use of CPU `cpu`'s idle stack, in bytes, sampled while that CPU
/// may be running on it. Each word is read with the arch's opaque racy load
/// (`load_word_racy`), since the owning CPU writes the stack with plain
/// stores; the result is a depth the stack reached at some point of the scan.
///
/// Runs with interrupts enabled and preemption disabled, so a scan of every
/// CPU does not hold interrupts masked for its whole length
/// (core/kernel/docs/syscalls.md § Atomicity and Preemption Guarantees).
#[cfg(not(test))]
fn idle_used_bytes(cpu: usize) -> u64
{
    let bytes = thread_stack_bytes();
    // SAFETY: cpu < CPU_COUNT (the caller's loop bound), and the scheduler is
    // initialised before any syscall runs.
    let top = unsafe { crate::sched::idle_stack_top_for(cpu) };
    let p = (top - bytes as u64) as *const u64;
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; interrupt handlers are installed; preemption is disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    // SAFETY: an idle stack is the `bytes` bytes below its top, mapped through
    // the direct map for the kernel's lifetime and 8-byte aligned.
    let used = used_bytes_with(bytes / core::mem::size_of::<u64>(), |i| unsafe {
        crate::arch::current::cpu::load_word_racy(p.add(i))
    });
    // SAFETY: saved came from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved) };
    crate::percpu::preempt_enable();
    used
}

/// Deepest use of a stack class, in bytes.
///
/// - `STACK_CLASS_IDLE`: the deepest of every CPU's idle stack, sampled now.
/// - `STACK_CLASS_THREAD`: the deepest of every freed thread's stack and the
///   calling thread's own stack, scanned now. Another live thread's stack is
///   counted when that thread is freed.
/// - `STACK_CLASS_HANDOFF`: the handoff stack's deepest use, recorded when the
///   BSP left it.
///
/// # Errors
/// `InvalidArgument` for an unknown class; `NotSupported` for the handoff
/// class when the kernel could not locate the handoff stack (its base mark was
/// absent at the derived bottom: an overflow, or a bootloader that does not
/// mark the stack).
#[cfg(not(test))]
pub fn high_water(class: u64) -> Result<u64, SyscallError>
{
    match class
    {
        STACK_CLASS_IDLE =>
        {
            let cpus = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
            Ok((0..cpus).map(idle_used_bytes).max().unwrap_or(0))
        }
        STACK_CLASS_THREAD =>
        {
            let bytes = thread_stack_bytes();
            // SAFETY: syscall context: the current TCB is the caller's.
            let tcb = unsafe { crate::syscall::current_tcb() };
            let own = if tcb.is_null()
            {
                0
            }
            else
            {
                // SAFETY: tcb is the live caller; its kernel stack is the
                // `bytes` bytes below `kernel_stack_top`, written during the
                // call only by this CPU, above the scan's stack pointer.
                let top = unsafe { (*tcb).kernel_stack_top };
                // SAFETY: as above.
                unsafe { used_bytes(top - bytes as u64, bytes) }
            };
            Ok(own.max(THREAD_HIGH_WATER.load(Ordering::Relaxed)))
        }
        STACK_CLASS_HANDOFF =>
        {
            let used = HANDOFF_HIGH_WATER.load(Ordering::Relaxed);
            if used == HANDOFF_UNLOCATED
            {
                Err(SyscallError::NotSupported)
            }
            else
            {
                Ok(used)
            }
        }
        _ => Err(SyscallError::InvalidArgument),
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
    fn the_handoff_span_ends_at_the_page_above_the_entry_stack_pointer()
    {
        const PAGE: u64 = 4096;
        const STACK: u64 = 64 * 1024;
        // The reference bootloader enters at the page-aligned top itself.
        assert_eq!(
            handoff_span(0x8_0000, PAGE, STACK),
            (0x8_0000 - STACK, STACK)
        );
        // A first statement below the top by less than a page (the entry
        // function's frame) rounds back up to it.
        assert_eq!(
            handoff_span(0x8_0000 - 2624, PAGE, STACK),
            (0x8_0000 - STACK, STACK)
        );
        assert_eq!(
            handoff_span(0x7_F001, PAGE, STACK),
            (0x8_0000 - STACK, STACK)
        );
        // One byte below a page boundary is a different page's top.
        assert_eq!(
            handoff_span(0x7_F000, PAGE, STACK),
            (0x7_F000 - STACK, STACK)
        );
    }
}
