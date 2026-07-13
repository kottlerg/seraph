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

/// No-op on x86-64: 4-level paging is the only supported mode, so there is
/// nothing to negotiate. Cross-arch hook for RISC-V, where the bootloader
/// selects Sv39/Sv48/Sv57 from the DTB `mmu-type` plus a `satp` write-probe.
///
/// # Safety
/// Safe to call at any point; the arguments are unused.
// unnecessary_wraps: Result signature is the cross-arch contract with the
// riscv64 hook, whose probe can genuinely fail.
#[allow(clippy::unnecessary_wraps)]
pub unsafe fn negotiate_paging(
    _bs: *mut EfiBootServices,
    _dtb_addr: u64,
    _boot_hart_id: u64,
) -> Result<(), crate::error::BootError>
{
    Ok(())
}

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

/// Execute `CPUID(leaf, subleaf)`, returning `(eax, ebx, ecx, edx)`.
///
/// `rbx` is callee-saved and reserved by LLVM as a base register in some
/// codegen modes, so it is preserved with a push/pop pair. `nostack` is
/// intentionally absent: the push/pop has net-zero RSP delta but
/// transiently writes [RSP-8], latent only because the bootloader target
/// is `x86_64-unknown-uefi` (MS x64 ABI, no red zone). Mirrors the
/// kernel-side `cpu::cpuid` discipline.
#[cfg(not(test))]
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32)
{
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is universally available on x86-64; rbx preserved.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            ebx = out(reg) ebx,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nomem),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Return the hardware identifier of the bootstrap processor.
///
/// On x86-64 the BSP identifier is its local APIC ID. When CPUID leaf
/// `0x0B` (Extended Topology Enumeration) is present its EDX carries the
/// full 32-bit x2APIC ID; otherwise the 8-bit xAPIC ID from CPUID leaf
/// 01H (EBX[31:24]) is used. `_boot_hart_id` is unused on this arch — it
/// exists so the arch-dispatch surface is identical between architectures.
#[cfg(not(test))]
pub fn bsp_hardware_id(_boot_hart_id: u64) -> u32
{
    let (max_leaf, ..) = cpuid(0, 0);
    if max_leaf >= 0x0B
    {
        let (_, ebx, _, edx) = cpuid(0x0B, 0);
        // Leaf 0x0B is valid only when its level field (EBX[15:0]) is
        // non-zero; EDX then holds the full 32-bit x2APIC ID.
        if ebx & 0xFFFF != 0
        {
            return edx;
        }
    }
    let (_, ebx, ..) = cpuid(1, 0);
    // 8-bit xAPIC ID is in EBX[31:24].
    (ebx >> 24) & 0xFF
}

#[cfg(test)]
pub fn bsp_hardware_id(_boot_hart_id: u64) -> u32
{
    0
}

/// No platform-default PCI apertures on x86-64.
///
/// q35 firmware always publishes MCFG, and BAR placement varies by
/// machine and CPU MAXPHYADDR, so no single fixed seed makes sense.
pub fn default_pci_apertures() -> &'static [(u64, u64)]
{
    &[]
}

/// Return the platform's maximum physical address width in bits.
///
/// Read from CPUID extended leaf `0x80000008`, EAX[7:0]. When the
/// extended leaf is not advertised by the CPU (very old hardware), fall
/// back to the IA-32e architectural minimum of 36 bits. The result
/// determines where firmware and hypervisors place the 64-bit PCI MMIO
/// window — see [`crate::acpi::parse_aperture_seed`].
#[cfg(not(test))]
pub fn max_phys_addr_bits() -> u8
{
    let (max_ext, ..) = cpuid(0x8000_0000, 0);
    if max_ext < 0x8000_0008
    {
        return 36;
    }
    let (eax, ..) = cpuid(0x8000_0008, 0);
    let bits = (eax & 0xff) as u8;
    if bits == 0 { 36 } else { bits }
}

#[cfg(test)]
pub fn max_phys_addr_bits() -> u8
{
    48
}
