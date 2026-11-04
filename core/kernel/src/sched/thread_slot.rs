// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/thread_slot.rs

//! Size of a Thread's retype slot, set at boot from the extended-state area
//! the boot CPU needs.
//!
//! A Thread slot is one guard page ([`GUARD_PAGES`]), the kernel stack
//! ([`KERNEL_STACK_PAGES`]), one page holding the `ThreadObject` wrapper and
//! the TCB, then the per-thread extended-state (FPU, SIMD, vector) save area,
//! rounded up to whole pages. The guard page is the caller's memory, debited
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

/// Bytes of a Thread slot whose save area is `extended_bytes`: the guard,
/// the kernel stack, the wrapper and TCB page, and the save area's pages.
pub const fn slot_bytes(extended_bytes: u64) -> u64
{
    EXTENDED_OFFSET + extended_pages(extended_bytes) * PAGE_SIZE as u64
}

/// The save-area size the boot CPU reported, in bytes; zero before the
/// report.
static EXTENDED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Record the boot CPU's extended-state area size. Called once on the boot
/// CPU during architecture init (Phase 5), before any Thread is retyped.
pub fn set_extended_bytes(bytes: u64)
{
    EXTENDED_BYTES.store(bytes, Ordering::Relaxed);
}

/// Bytes of the per-thread save area's pages, which thread creation zeroes.
pub fn extended_area_bytes() -> u64
{
    extended_pages(EXTENDED_BYTES.load(Ordering::Relaxed)) * PAGE_SIZE as u64
}

/// Bytes every Thread retype debits from its source Memory cap.
pub fn thread_slot_bytes() -> u64
{
    slot_bytes(EXTENDED_BYTES.load(Ordering::Relaxed))
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
        assert_eq!(slot_bytes(0), (BASE + 1) * PAGE);
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
        assert_eq!(slot_bytes(262_448), (BASE + 65) * PAGE);
    }
}
