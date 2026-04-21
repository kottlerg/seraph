// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/x86_64/mod.rs

//! x86-64 architecture module for the bootloader.
//!
//! Exports the expected ELF machine type constant and the kernel handoff
//! function. Page table implementation is in [`paging`].

pub mod handoff;
pub mod paging;
pub mod serial;
pub use handoff::{perform_handoff, trampoline_page_range};
pub use paging::BootPageTable;

use crate::elf::EM_X86_64;
use crate::uefi::EfiSystemTable;

/// ELF machine type expected for x86-64 kernel binaries.
pub const EXPECTED_ELF_MACHINE: u16 = EM_X86_64;

/// No-op on x86-64: the UART is already initialized by the serial module.
///
/// # Safety
/// `_st` is unused; the function is safe to call at any point.
pub unsafe fn pre_serial_init(_st: *mut EfiSystemTable) {}

/// Returns 0: x86-64 has no UART MMIO region to identity-map.
pub fn uart_mmio_region() -> u64
{
    0
}

/// Returns 0: x86-64 has no boot hart ID concept.
///
/// # Safety
/// `_st` is unused.
pub unsafe fn discover_boot_hart_id(_st: *mut EfiSystemTable) -> u64
{
    0
}

/// Return the APIC ID of the current (bootstrap) processor.
///
/// Reads CPUID leaf 01H: EBX[31:24] contains the initial APIC ID of the
/// processor executing the instruction. This is the xAPIC ID, which is 8
/// bits and valid for systems with up to 256 logical CPUs.
///
/// For x2APIC systems (> 256 CPUs), CPUID leaf 0x0B would be needed, but
/// Seraph is capped at 64 CPUs (`MAX_CPUS`) so xAPIC IDs suffice.
#[cfg(not(test))]
pub fn bsp_hardware_id() -> u32
{
    let ebx: u32;
    // SAFETY: CPUID is always available on x86-64; leaf 1 is required.
    // rbx is callee-saved and used by LLVM as the base register in some
    // codegen modes. We must save/restore it manually when using CPUID.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            inout("eax") 1u32 => _,
            ebx = out(reg) ebx,
            out("ecx") _,
            out("edx") _,
            options(nostack, nomem),
        );
    }
    // APIC ID is in EBX[31:24].
    (ebx >> 24) & 0xFF
}

#[cfg(test)]
pub fn bsp_hardware_id() -> u32
{
    0
}
