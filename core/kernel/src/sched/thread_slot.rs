// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/thread_slot.rs

//! Size of a Thread's retype slot, set at boot from the extended-state area
//! the boot CPU needs.
//!
//! A Thread slot is one guard page ([`GUARD_PAGES`]), the kernel stack
//! ([`KERNEL_STACK_PAGES`]), one page holding the `ThreadObject` wrapper and
//! the TCB, then the per-thread extended-state (FPU, SIMD, vector) save area,
//! rounded up to whole pages, then, with shadow stacks on, the thread's
//! shadow-stack page ([`shadow_page`]), which thread creation gives the
//! shadow-stack encoding in the direct map (`mm::stack_guard::hole`) until
//! the slot is freed. The guard page is the caller's memory, debited
//! like the rest of the slot, and unusable while the thread exists: thread
//! creation removes it from the direct map (`mm::stack_guard`), so an
//! overflow of the stack faults instead of writing below the slot.
//! The area's size is a property of the hardware, so the boot CPU's
//! architecture init reports it once, before any thread is created
//! ([`set_extended_bytes`]): on x86-64 the XSAVE size of the components XCR0
//! enables (CPUID leaf 0xD), on riscv64 the F/D and vector-CSR prefix plus 32
//! vector registers of `vlenb` bytes (`arch::riscv64::fpu::cache_vlenb`). Every Thread
//! retype debits [`thread_slot_bytes`] (`dispatch_for(Thread)` in
//! `cap/retype.rs`, the Phase 9 init Thread), and userspace reads the same
//! value through `SystemInfoType::ThreadRetypeBytes`. Every CPU's save area
//! must be the size the boot CPU reports (docs/platform-requirements.md
//! § riscv64 Classification; riscv64 halts the boot at a hart whose `vlenb`
//! differs).

use core::sync::atomic::{AtomicU64, Ordering};

use super::KERNEL_STACK_PAGES;
use crate::mm::PAGE_SIZE;

/// Pages below the kernel stack in a Thread slot: the guard, which the direct
/// map leaves unmapped while the thread exists.
pub const GUARD_PAGES: usize = 1;

/// Offset of the kernel stack's base in a Thread slot: above the guard.
pub const STACK_OFFSET: u64 = (GUARD_PAGES * PAGE_SIZE) as u64;

/// Offset of the page holding the `ThreadObject` wrapper and the TCB: the
/// kernel stack's top.
pub const WRAPPER_OFFSET: u64 = ((GUARD_PAGES + KERNEL_STACK_PAGES) * PAGE_SIZE) as u64;

/// Offset of the extended-state save area: the page after the wrapper's.
pub const EXTENDED_OFFSET: u64 = WRAPPER_OFFSET + PAGE_SIZE as u64;

/// Pages the save area of `extended_bytes` takes, at least one: an area the
/// boot has not reported yet takes the one page every supported CPU needs at
/// minimum.
pub const fn extended_pages(extended_bytes: u64) -> u64
{
    let pages = extended_bytes.div_ceil(PAGE_SIZE as u64);
    if pages == 0 { 1 } else { pages }
}

/// Offset of the shadow-stack page in a Thread slot whose save area is
/// `extended_bytes`: the page after the save area's. Saturates as
/// [`slot_bytes`] does.
pub const fn shadow_offset(extended_bytes: u64) -> u64
{
    extended_pages(extended_bytes)
        .saturating_mul(PAGE_SIZE as u64)
        .saturating_add(EXTENDED_OFFSET)
}

/// Bytes of a Thread slot whose save area is `extended_bytes` and which ends
/// in `shadow_pages` shadow-stack pages (1 with shadow stacks on, else 0):
/// the guard, the kernel stack, the wrapper and TCB page, the save area's
/// pages, and the shadow stack. Saturates at `u64::MAX`, a size no Memory
/// cap can supply, so a save area too large to address fails the retype.
pub const fn slot_bytes(extended_bytes: u64, shadow_pages: u64) -> u64
{
    shadow_offset(extended_bytes).saturating_add(shadow_pages.saturating_mul(PAGE_SIZE as u64))
}

/// The save-area size the boot CPU reported, in bytes; zero before the
/// report.
static EXTENDED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Shadow-stack pages a Thread slot ends in: 1 once the boot decided shadow
/// stacks are on (`arch::current::shadow_stack::decide`, Phase 4), else 0.
static SHADOW_PAGES: AtomicU64 = AtomicU64::new(0);

/// Record the shadow-stack pages a Thread slot ends in: 1 with shadow stacks
/// on, else 0. Called once on the boot CPU in Phase 4, after the shadow-stack
/// decision and before any Thread is retyped or the seed reserve is sized.
pub fn set_shadow_stack_pages(pages: u64)
{
    SHADOW_PAGES.store(pages, Ordering::Relaxed);
}

/// The physical address of the shadow-stack page of the Thread slot at
/// `block_phys`, or `None` when slots carry none.
pub fn shadow_page(block_phys: u64) -> Option<u64>
{
    if SHADOW_PAGES.load(Ordering::Relaxed) == 0
    {
        return None;
    }
    // Inside the slot, which lies inside its Memory cap's range.
    Some(block_phys.wrapping_add(shadow_offset(EXTENDED_BYTES.load(Ordering::Relaxed))))
}

/// Record the boot CPU's extended-state area size. Called once on the boot
/// CPU during architecture init (Phase 5), before any Thread is retyped.
pub fn set_extended_bytes(bytes: u64)
{
    EXTENDED_BYTES.store(bytes, Ordering::Relaxed);
}

/// The save area's size, in bytes, as the boot CPU reported it: the size of
/// the extended-state image `SYS_THREAD_READ_EXT_REGS` reads.
pub fn extended_bytes() -> u64
{
    EXTENDED_BYTES.load(Ordering::Relaxed)
}

/// The part of a save area of `size` bytes that a `SYS_THREAD_READ_EXT_REGS`
/// of `len` bytes from `offset` copies: its start and length. The length is
/// 0 for an offset at or past the end. The span is clamped to the area as data
/// (`nospec::mask_span_u64`), so a copy past a mispredicted bound reads
/// nothing outside it.
pub fn extended_span(offset: u64, len: usize, size: u64) -> (u64, usize)
{
    let n = size.saturating_sub(offset).min(len as u64);
    let (from, n) = crate::arch::nospec::mask_span_u64(offset, n, size);
    (from, usize::try_from(n).unwrap_or(0))
}

/// Bytes of the per-thread save area's pages, into which thread creation
/// writes the initial extended state (`arch::current::fpu::init_save_area`).
/// Saturates as [`slot_bytes`] does; a slot that size is never retyped.
pub fn extended_area_bytes() -> u64
{
    extended_pages(EXTENDED_BYTES.load(Ordering::Relaxed)).saturating_mul(PAGE_SIZE as u64)
}

/// Bytes every Thread retype debits from its source Memory cap.
pub fn thread_slot_bytes() -> u64
{
    slot_bytes(
        EXTENDED_BYTES.load(Ordering::Relaxed),
        SHADOW_PAGES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests
{
    use super::*;

    const PAGE: u64 = PAGE_SIZE as u64;
    const BASE: u64 = (GUARD_PAGES + KERNEL_STACK_PAGES) as u64 + 1;

    #[test]
    fn an_unreported_area_takes_one_page()
    {
        assert_eq!(slot_bytes(0, 0), (BASE + 1) * PAGE);
    }

    // The defect caught: a shadow-stack page that overlaps the save area's
    // last page, or a slot that does not grow by it, so the retype debits
    // too little and the shadow stack lands past the slot.
    #[test]
    fn the_shadow_stack_page_ends_the_slot_after_the_save_area()
    {
        assert_eq!(shadow_offset(PAGE + 1), (BASE + 2) * PAGE);
        assert_eq!(slot_bytes(PAGE + 1, 1), shadow_offset(PAGE + 1) + PAGE);
        assert_eq!(slot_bytes(PAGE + 1, 0), shadow_offset(PAGE + 1));
    }

    // The defect caught: a save area that spills past its last page by a
    // byte, or a page added where the area still fits.
    #[test]
    fn an_area_one_byte_past_a_page_takes_a_second()
    {
        assert_eq!(extended_pages(PAGE), 1);
        assert_eq!(extended_pages(PAGE + 1), 2);
    }

    // The largest area a riscv64 hart can report (VLEN 65536, 262448 bytes:
    // `VLENB_SPEC_MAX` bounds it), composed into a whole slot.
    #[test]
    fn the_largest_riscv_area_composes_into_whole_pages()
    {
        assert_eq!(slot_bytes(262_448, 0), (BASE + 65) * PAGE);
    }

    // The defect caught: a read that runs past the area's end, copies a byte
    // at the end, or wraps for an offset near `u64::MAX`.
    #[test]
    fn an_extended_read_copies_only_bytes_inside_the_area()
    {
        assert_eq!(extended_span(0, 4096, 832), (0, 832));
        assert_eq!(extended_span(512, 64, 832), (512, 64));
        assert_eq!(extended_span(800, 64, 832), (800, 32));
        assert_eq!(extended_span(832, 64, 832).1, 0);
        assert_eq!(extended_span(u64::MAX, 4096, 832).1, 0);
        assert_eq!(extended_span(4096, 4096, 262_448), (4096, 4096));
    }

    // The defect caught: a save area whose page-rounded size passes `u64`
    // wrapped to a small slot size, so a retype debited too few bytes.
    #[test]
    fn an_area_too_large_to_address_saturates_the_slot()
    {
        assert_eq!(slot_bytes(u64::MAX, 0), u64::MAX);
        assert_eq!(slot_bytes(u64::MAX - EXTENDED_OFFSET, 1), u64::MAX);
    }
}
