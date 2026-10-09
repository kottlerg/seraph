// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/gdt.rs

//! GDT stub for RISC-V.
//!
//! RISC-V has no GDT/TSS concept. This stub satisfies the `arch::current::gdt`
//! interface called by `percpu::init_bsp()` so the common per-CPU init path
//! compiles on both architectures without conditional compilation at the call site.
//!
//! `tss_ptr` in `PerCpuData` is unused on RISC-V; this returns 0.

/// I/O Permission Bitmap size. Zero on RISC-V (no I/O port space).
// dead_code: part of the shared arch surface; on riscv64 `gdt::IOPB_SIZE`
// is referenced only by `syscall::hw::sys_ioport_bind` (non-test builds,
// unreachable past its `HAS_IO_PORTS` gate) and by the IOPB stub
// signatures in this file.
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
///
/// # Safety
/// No preconditions — the body is empty. The `unsafe` qualifier exists only to
/// match the x86-64 surface signature.
#[cfg(not(test))]
// unused_variables: inert — every parameter is `_`-prefixed to mirror the x86-64
// `gdt::init_ap` signature, so the lint does not fire (#438).
#[allow(unused_variables)]
pub unsafe fn init_ap(_cpu_id: u32, _rsp0: u64, _ist1_top: u64, _ist2_top: u64) {}

/// Load the per-thread IOPB into the TSS — no-op on RISC-V.
///
/// RISC-V has no TSS or I/O permission bitmap (no I/O port space). Present so
/// the context-switch path calls it unconditionally on both arches.
///
/// # Safety
/// No preconditions — the body is empty. The `unsafe` qualifier exists only to
/// match the x86-64 surface signature.
#[cfg(not(test))]
pub unsafe fn load_iopb(_iopb: Option<&[u8; IOPB_SIZE]>) {}

/// Permit an I/O port range in a thread's IOPB — no-op on RISC-V.
///
/// RISC-V has no I/O port space, so there is nothing to permit. Present so
/// `sys_ioport_bind` compiles on both arches; the `HAS_IO_PORTS` gate makes
/// this unreachable on RISC-V.
pub fn permit_port_range_u32(_iopb: &mut [u8; IOPB_SIZE], _base: u32, _count: u32) {}
