// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/thread_slot.rs

//! Size of a Thread's retype slot, set at boot from the extended-state area
//! the boot CPU needs.
//!
//! A Thread slot is the kernel stack ([`KERNEL_STACK_PAGES`]), one page
//! holding the `ThreadObject` wrapper and the TCB, then the per-thread
//! extended-state (FPU, SIMD, vector) save area, rounded up to whole pages.
//! The area's size is a property of the hardware, so the boot CPU reports it
//! once, before any thread is created ([`set_extended_bytes`]): on x86-64 the
//! XSAVE size of the components XCR0 enables (CPUID leaf 0xD), on riscv64
//! [`riscv_extended_bytes`] of the hart's `vlenb`. Every Thread retype debits
//! [`thread_slot_bytes`] (`dispatch_for(Thread)` in `cap/retype.rs`, the
//! Phase 9 init Thread), and userspace reads the same value through
//! `SystemInfoType::ThreadRetypeBytes`. Harts and cores are assumed uniform
//! (docs/platform-requirements.md).

use core::sync::atomic::{AtomicU64, Ordering};

use super::KERNEL_STACK_PAGES;
use crate::mm::PAGE_SIZE;

/// Bytes of the riscv64 save area before the vector registers: the 32 F/D
/// registers and `fcsr` (264), then `vstart`, `vl`, `vtype` and `vcsr`, padded
/// to 304 (the layout `arch::riscv64::fpu` saves to). riscv64 builds and the
/// host tests only.
#[cfg(any(target_arch = "riscv64", test))]
pub const RISCV_VECTOR_REGS_OFFSET: u64 = 304;

/// Bytes of the riscv64 extended-state area for a hart whose vector
/// registers are `vlenb` bytes each: the F/D and vector-CSR prefix, then the
/// 32 vector registers.
#[cfg(any(target_arch = "riscv64", test))]
pub const fn riscv_extended_bytes(vlenb: u64) -> u64
{
    RISCV_VECTOR_REGS_OFFSET + 32 * vlenb
}

/// Pages the save area of `extended_bytes` takes, at least one: an area the
/// boot has not reported yet takes the one page every supported CPU needs at
/// minimum.
pub const fn extended_pages(extended_bytes: u64) -> u64
{
    let pages = extended_bytes.div_ceil(PAGE_SIZE as u64);
    if pages == 0 { 1 } else { pages }
}

/// Bytes of a Thread slot whose save area is `extended_bytes`: the kernel
/// stack, the wrapper and TCB page, and the save area's pages.
pub const fn slot_bytes(extended_bytes: u64) -> u64
{
    (KERNEL_STACK_PAGES as u64 + 1 + extended_pages(extended_bytes)) * PAGE_SIZE as u64
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
    const BASE: u64 = KERNEL_STACK_PAGES as u64 + 1;

    // The defect caught: a save area that spills past its last page by a
    // byte, or a page added where the area still fits (the vlenb at which
    // the riscv64 area leaves one page: 304 + 32 * 118 = 4080, 119 = 4112).
    #[test]
    fn the_riscv_area_takes_a_second_page_past_vlenb_118()
    {
        assert_eq!(riscv_extended_bytes(118), 4080);
        assert_eq!(extended_pages(riscv_extended_bytes(118)), 1);
        assert_eq!(riscv_extended_bytes(119), 4112);
        assert_eq!(extended_pages(riscv_extended_bytes(119)), 2);
    }

    #[test]
    fn riscv_slots_at_common_and_largest_vector_lengths()
    {
        // VLEN 128, 512: one page; VLEN 1024: two.
        assert_eq!(slot_bytes(riscv_extended_bytes(16)), (BASE + 1) * PAGE);
        assert_eq!(slot_bytes(riscv_extended_bytes(64)), (BASE + 1) * PAGE);
        assert_eq!(slot_bytes(riscv_extended_bytes(128)), (BASE + 2) * PAGE);
        // VLEN 65536, the V specification's largest: 304 + 262144 bytes.
        assert_eq!(riscv_extended_bytes(8192), 262_448);
        assert_eq!(extended_pages(riscv_extended_bytes(8192)), 65);
        assert_eq!(slot_bytes(riscv_extended_bytes(8192)), (BASE + 65) * PAGE);
    }

    #[test]
    fn x86_xsave_sizes_round_up_to_pages()
    {
        // x87 + SSE + AVX (832), a full page, a byte past it, and an
        // AMX-sized area.
        assert_eq!(extended_pages(832), 1);
        assert_eq!(extended_pages(4096), 1);
        assert_eq!(extended_pages(4097), 2);
        assert_eq!(extended_pages(11_008), 3);
    }

    #[test]
    fn an_unreported_area_takes_one_page()
    {
        assert_eq!(extended_pages(0), 1);
        assert_eq!(slot_bytes(0), (BASE + 1) * PAGE);
    }
}
