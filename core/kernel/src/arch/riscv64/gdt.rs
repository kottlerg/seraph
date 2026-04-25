// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/gdt.rs

//! GDT stub for RISC-V.
//!
//! RISC-V has no GDT/TSS concept. This stub satisfies the `arch::current::gdt`
//! interface called by `percpu::init_bsp()` so the common per-CPU init path
//! compiles on both architectures without conditional compilation at the call site.
//!
//! `tss_ptr` in `PerCpuData` is unused on RISC-V; this returns 0.

/// I/O Permission Bitmap size. Zero on RISC-V (no I/O port space).
// dead_code: IOPB_SIZE is used by x86_64 but not riscv64; it must exist here
// to satisfy the shared arch interface without conditional compilation at call sites.
#[allow(dead_code)]
pub const IOPB_SIZE: usize = 0;

/// Return the BSP TSS pointer. On RISC-V this is always 0 — there is no TSS.
pub fn bsp_tss_ptr() -> u64
{
    0
}

/// Per-AP GDT/TSS init stub for RISC-V.
///
/// RISC-V has no GDT or TSS. This no-op exists so that `kernel_entry_ap`
/// compiles unchanged on both x86-64 and RISC-V. All arguments are ignored.
#[cfg(not(test))]
#[allow(unused_variables)]
pub unsafe fn init_ap(_cpu_id: u32, _rsp0: u64, _ist1_top: u64, _ist2_top: u64) {}
