// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/stack_depth.rs

//! Kernel stack depth measurement.
//!
//! Every idle, thread, and handoff stack is painted with [`STACK_PAINT`] when
//! it is allocated: the bootloader paints the handoff stack, and the kernel
//! paints each idle stack and each thread's kernel stack. A stack's deepest
//! use is then the span from its top down to its lowest word that no longer
//! holds the paint, as a scan that samples one word per 64-byte line finds it
//! ([`used_bytes`]). [`high_water`] reports that span per stack class to
//! `SYS_SYSTEM_INFO(StackHighWater)`. The mechanism and its limits are in
//! core/kernel/docs/memory-internals.md § Kernel Stack Depth.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(test))]
use boot_protocol::layout::HANDOFF_STACK_BYTES;
use boot_protocol::layout::STACK_PAINT;
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

/// Bytes of one stack word.
const WORD: usize = core::mem::size_of::<u64>();

/// Words in one 64-byte line, the unit the depth scan samples.
const LINE_WORDS: usize = 8;

/// Clears a word index down to the first word of its line.
const LINE_MASK: usize = !(LINE_WORDS - 1);

/// Wholly painted lines in a row (512 bytes) that end the scan's walk down: a
/// gap a frame left unwritten up to this size does not hide a write below it.
const GAP_LINES: usize = 8;

/// Fill `bytes` bytes at `base` with [`STACK_PAINT`].
///
/// # Safety
/// `[base, base + bytes)` is writable, 8-byte aligned, and exclusively owned
/// by the caller (a stack no thread runs on yet).
pub unsafe fn paint(base: u64, bytes: usize)
{
    // SAFETY: the caller's span is `bytes / WORD` writable, aligned words that
    // are the caller's alone.
    unsafe { crate::arch::current::cpu::fill_words(base as *mut u64, bytes / WORD, STACK_PAINT) };
}

/// Bytes used of a stack of `words` words, where `word(i)` reads word `i`
/// counted from the low end: its size less the words below the lowest written
/// word [`lowest_written`] finds.
fn used_bytes_with(words: usize, mut word: impl FnMut(usize) -> u64) -> u64
{
    let lowest = lowest_written(words, &mut word);
    // `lowest <= words`, and the stack's `words * WORD` bytes fit a `usize`,
    // so neither step saturates.
    words.saturating_sub(lowest).saturating_mul(WORD) as u64
}

/// Index of the lowest word no longer holding [`STACK_PAINT`] that the line
/// scan finds, or `words` when it finds none.
///
/// The scan reads the first word of each line from the low end up to the
/// lowest line whose first word was written, then walks down from the line
/// below it word by word, line after line, and stops after [`GAP_LINES`]
/// consecutive lines every word of which still holds the paint. It finds the
/// lowest written word unless that many wholly painted lines lie together
/// between that word and the lowest written first word above it, and it never
/// names a painted word (core/kernel/docs/memory-internals.md § Kernel Stack
/// Depth).
fn lowest_written(words: usize, word: &mut impl FnMut(usize) -> u64) -> usize
{
    let mut hi = (0..words)
        .step_by(LINE_WORDS)
        .find(|&i| word(i) != STACK_PAINT)
        .unwrap_or(words);
    let mut lowest = hi;
    let mut painted_run = 0;
    // Each pass examines the line `[lo, hi)` directly below `hi`: a whole line,
    // or the last, shorter one when `hi` is a span's end that no line ends at.
    while hi > 0 && painted_run < GAP_LINES
    {
        let lo = hi.saturating_sub(1) & LINE_MASK;
        match (lo..hi).find(|&i| word(i) != STACK_PAINT)
        {
            Some(i) =>
            {
                lowest = i;
                painted_run = 0;
            }
            None => painted_run = painted_run.saturating_add(1),
        }
        hi = lo;
    }
    lowest
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
    used_bytes_with(bytes / WORD, |i| {
        // SAFETY: each index is below `bytes / 8`, so the offset stays inside
        // the caller's span.
        let word = unsafe { p.add(i) };
        // SAFETY: `word` lies in the caller's span, which is mapped, readable
        // and aligned, and which no other CPU writes during the call.
        unsafe { word.read() }
    })
}

/// The handoff stack's base for an entry stack pointer: its top is `entry_sp`
/// rounded up to a page, and it spans `stack_bytes` below that top. The
/// kernel's Phase 3 identity window over the stack starts here too
/// (`mm::paging::handoff_stack_window`).
///
/// No stack has its top past the last page of the address space or holds more
/// bytes than lie below its top; for such an `entry_sp` the top is cut at the
/// end of the address space and the base at zero, so the base mark check that
/// follows finds no stack there.
pub fn handoff_base(entry_sp: u64, page: u64, stack_bytes: u64) -> u64
{
    entry_sp
        .checked_next_multiple_of(page)
        .unwrap_or(u64::MAX)
        .saturating_sub(stack_bytes)
}

/// The handoff class's answer for a recorded value: the depth, or
/// `NotSupported` when the stack was not located.
fn handoff_class(recorded: u64) -> Result<u64, syscall::SyscallError>
{
    if recorded == HANDOFF_UNLOCATED
    {
        Err(syscall::SyscallError::NotSupported)
    }
    else
    {
        Ok(recorded)
    }
}

/// Depth recorded for a handoff stack whose lowest word reads `mark` and whose
/// painted span above it reads as `used` bytes: the depth when the mark is
/// [`boot_protocol::layout::HANDOFF_STACK_BASE_MARK`], else unlocated.
fn handoff_record(mark: u64, used: impl FnOnce() -> u64) -> u64
{
    if mark == boot_protocol::layout::HANDOFF_STACK_BASE_MARK
    {
        used()
    }
    else
    {
        HANDOFF_UNLOCATED
    }
}

/// Record the stack pointer at `kernel_entry`'s first statement, from which
/// [`record_handoff_stack`] derives the handoff stack's span.
pub fn note_boot_entry(sp: u64)
{
    BOOT_ENTRY_SP.store(sp, Ordering::Relaxed);
}

/// The stack pointer [`note_boot_entry`] recorded, or 0 when none was.
#[cfg(not(test))]
pub fn boot_entry_sp() -> u64
{
    BOOT_ENTRY_SP.load(Ordering::Relaxed)
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
/// by the BSP in `sched::enter` after its deepest remaining call on that stack
/// and just before it leaves for init's kernel stack; the entry frames below
/// it (`first_entry_to_user`) are shallow and not counted.
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
    let base_phys = handoff_base(
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
    let recorded = handoff_record(mark, || {
        // SAFETY: as above; the words above the mark are the painted stack,
        // and only this CPU, running on it, writes it. The mark confirmed the
        // stack at `base`, so the word above it does not wrap.
        unsafe { used_bytes(base.wrapping_add(WORD as u64), HANDOFF_STACK_BYTES - WORD) }
    });
    HANDOFF_HIGH_WATER.store(recorded, Ordering::Relaxed);
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
    // The idle stack is the `bytes` bytes below its top, so its base does not
    // wrap.
    let p = top.wrapping_sub(bytes as u64) as *const u64;
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; interrupt handlers are installed; preemption is disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    let used = used_bytes_with(bytes / WORD, |i| {
        // SAFETY: i < bytes / 8, so the offset stays inside the idle stack, the
        // `bytes` bytes below its top.
        let word = unsafe { p.add(i) };
        // SAFETY: `word` lies in the idle stack, mapped through the direct map
        // for the kernel's lifetime and 8-byte aligned.
        unsafe { crate::arch::current::cpu::load_word_racy(word) }
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
// Kept out of line: inlined, its scans' loops widen the frame of
// `sys_system_info`, whose every selector, the null-syscall benchmark's
// among them, then pays the larger prologue.
#[cfg(not(test))]
#[inline(never)]
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
                // SAFETY: as above; the stack's base, `bytes` below its top,
                // does not wrap.
                unsafe { used_bytes(top.wrapping_sub(bytes as u64), bytes) }
            };
            Ok(own.max(THREAD_HIGH_WATER.load(Ordering::Relaxed)))
        }
        STACK_CLASS_HANDOFF => handoff_class(HANDOFF_HIGH_WATER.load(Ordering::Relaxed)),
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

    /// A stack of `words` words whose words from `deepest` up were written.
    fn used_from(words: usize, deepest: usize) -> Vec<u64>
    {
        let mut v = painted(words);
        for w in &mut v[deepest..]
        {
            *w = 0;
        }
        v
    }

    fn used(v: &[u64]) -> u64
    {
        // SAFETY: v is v.len() readable, aligned words.
        unsafe { used_bytes(v.as_ptr() as u64, v.len() * 8) }
    }

    // Defect caught: a fill that stops short of its span or runs past it.
    #[test]
    fn paint_fills_exactly_its_span()
    {
        for words in [512, 13]
        {
            let mut v = vec![0u64; words + 1];
            // SAFETY: v owns words + 1 u64s, 8-aligned; the paint covers the
            // first `words`.
            unsafe { paint(v.as_mut_ptr() as u64, words * 8) };
            assert!(v[..words].iter().all(|&w| w == STACK_PAINT));
            assert_eq!(v[words], 0, "the word past the span is left alone");
        }
    }

    // Defect caught: a line scan that misplaces the boundary inside a line
    // (each of its eight words), at the base or the top, or on a span whose
    // last line is short, for a stack used from its top down without a gap.
    #[test]
    fn a_stack_used_without_a_gap_is_measured_to_the_word()
    {
        for words in [512, 509]
        {
            for deepest in 0..=words
            {
                let v = used_from(words, deepest);
                assert_eq!(
                    used(&v),
                    ((words - deepest) * 8) as u64,
                    "{words} words from {deepest}"
                );
            }
        }
    }

    // Defect caught: a scan that checks only the one line below the lowest
    // written first word, and so stops short of a deeper write reached through
    // lines whose first word was left unwritten.
    #[test]
    fn the_walk_down_crosses_lines_whose_first_word_is_unwritten()
    {
        let mut v = painted(512);
        for (i, w) in v.iter_mut().enumerate().skip(297)
        {
            if i % 8 != 0
            {
                *w = 0;
            }
        }
        assert_eq!(used(&v), (512 - 297) * 8);
    }

    // Defect caught: a walk down that stops at a gap shorter than
    // `GAP_LINES` lines, or one that never stops at a longer one.
    #[test]
    fn a_write_below_a_painted_gap_is_seen_up_to_gap_lines()
    {
        // The top 100 words used (from line 51 word 4), then one deeper word
        // with whole painted lines between.
        let mut v = used_from(512, 412);
        // Line 43: lines 44 to 50, seven, are wholly painted.
        v[347] = 7;
        assert_eq!(used(&v), (512 - 347) * 8);
        // Line 42 only: lines 43 to 50, eight, are wholly painted, so the
        // walk stops above it.
        v[347] = STACK_PAINT;
        v[339] = 7;
        assert_eq!(used(&v), (512 - 412) * 8);
        // A line's first word is read by the sampling, whatever the gap.
        v[296] = 7;
        assert_eq!(used(&v), (512 - 296) * 8);
    }

    #[test]
    fn the_handoff_top_is_the_entry_stack_pointer_rounded_up_to_a_page()
    {
        const PAGE: u64 = 4096;
        const STACK: u64 = 64 * 1024;
        // The reference bootloader enters at the page-aligned top itself.
        assert_eq!(handoff_base(0x8_0000, PAGE, STACK), 0x8_0000 - STACK);
        // A first statement below the top by less than a page (the entry
        // function's frame) rounds back up to it.
        assert_eq!(handoff_base(0x8_0000 - 2624, PAGE, STACK), 0x8_0000 - STACK);
        assert_eq!(handoff_base(0x7_F001, PAGE, STACK), 0x8_0000 - STACK);
        // An entry stack pointer on a page boundary is that page's top.
        assert_eq!(handoff_base(0x7_F000, PAGE, STACK), 0x7_F000 - STACK);
    }

    // Defect caught: a base derived by wrapping, for an entry stack pointer no
    // stack can have, so the base-mark read and the Phase 3 identity window
    // land near the top of the address space instead of finding no stack.
    #[test]
    fn a_handoff_base_past_either_end_of_the_address_space_is_cut_at_it()
    {
        const PAGE: u64 = 4096;
        const STACK: u64 = 64 * 1024;
        // A top below the stack's size: the base is cut at zero.
        assert_eq!(handoff_base(0x9000, PAGE, STACK), 0);
        // A top exactly the stack's size is a stack based at zero.
        assert_eq!(handoff_base(STACK, PAGE, STACK), 0);
        // A pointer in the last page: the top is cut at the end.
        assert_eq!(handoff_base(u64::MAX - 5, PAGE, STACK), u64::MAX - STACK);
    }

    #[test]
    fn an_absent_base_mark_makes_the_handoff_class_not_supported()
    {
        use boot_protocol::layout::HANDOFF_STACK_BASE_MARK;
        // The mark present: the scanned depth is recorded and answered.
        let recorded = handoff_record(HANDOFF_STACK_BASE_MARK, || 7248);
        assert_eq!(handoff_class(recorded), Ok(7248));
        // The mark overwritten (an overflow) or never written: unlocated, and
        // the scan is not run.
        let recorded = handoff_record(0, || unreachable!("no scan without the mark"));
        assert_eq!(
            handoff_class(recorded),
            Err(syscall::SyscallError::NotSupported)
        );
        assert_eq!(
            handoff_class(handoff_record(STACK_PAINT, || 0)),
            Err(syscall::SyscallError::NotSupported)
        );
    }
}
