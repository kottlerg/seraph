// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/x86_64/mod.rs

//! x86-64 architecture module for the bootloader.
//!
//! Exports the expected ELF machine type constant and the kernel handoff
//! function. Page table implementation is in [`paging`].

pub mod acpi_kernel_mmio;
pub mod handoff;
pub mod paging;
pub mod serial;
pub use handoff::{perform_handoff, trampoline_page_range};
pub use paging::BootPageTable;

use crate::elf::EM_X86_64;
use crate::firmware::FirmwareInfo;
use crate::uefi::{EfiBootServices, EfiSystemTable, allocate_pages_max_addr};
use boot_protocol::KernelMmio;

/// ELF machine type expected for x86-64 kernel binaries.
pub const EXPECTED_ELF_MACHINE: u16 = EM_X86_64;

/// Reserve a 4 KiB page for the AP startup trampoline.
///
/// On x86-64 the SIPI vector encodes the real-mode start address in
/// bits `[19:12]` of the IPI ICR, so the page MUST live below 1 MiB.
/// Returns `None` if no qualifying page can be reserved (SMP is then
/// disabled).
///
/// # Safety
/// `bs` must be valid UEFI boot services; call before `ExitBootServices`.
pub unsafe fn allocate_ap_trampoline(bs: *mut EfiBootServices) -> Option<u64>
{
    // SAFETY: bs is valid per the caller's contract.
    unsafe { allocate_pages_max_addr(bs, 0xFFFFF, 1).ok() }
}

/// No-op on x86-64: the UART is already initialized by the serial module.
///
/// # Safety
/// `_st` is unused; the function is safe to call at any point.
pub unsafe fn pre_serial_init(_st: *mut EfiSystemTable) {}

/// Populate `km` from firmware tables for x86-64.
///
/// The only firmware source on UEFI x86-64 is ACPI; DTB is not published
/// on this architecture. Fields left zero cause the kernel to fall back
/// to its compiled-in defaults.
///
/// # Safety
/// `firmware.acpi_rsdp`, if non-zero, must be the physical address of a
/// valid, identity-mapped ACPI RSDP.
pub unsafe fn populate_kernel_mmio(firmware: &FirmwareInfo, km: &mut KernelMmio)
{
    if firmware.acpi_rsdp != 0
    {
        // SAFETY: caller guarantees acpi_rsdp is valid when non-zero.
        unsafe { acpi_kernel_mmio::parse_kernel_mmio(firmware.acpi_rsdp, km) };
    }
}

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

/// Return the hardware identifier of the bootstrap processor.
///
/// On x86-64 the BSP identifier is the APIC ID read from CPUID leaf 01H
/// (EBX[31:24]). `_boot_hart_id` is unused on this arch — it exists so
/// the arch-dispatch surface is identical between architectures.
///
/// Only the 8-bit xAPIC ID is read; platforms whose BSP has an APIC ID
/// ≥ 256 require x2APIC (CPUID leaf 0x0B), which this reader does not
/// return. Every board currently targeted by Seraph fits in xAPIC.
#[cfg(not(test))]
pub fn bsp_hardware_id(_boot_hart_id: u64) -> u32
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
pub fn bsp_hardware_id(_boot_hart_id: u64) -> u32
{
    0
}
