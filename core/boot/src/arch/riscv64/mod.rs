// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/mod.rs

//! RISC-V 64-bit architecture module for the bootloader.
//!
//! Exports arch-specific constants, the kernel handoff function, and
//! pre-serial-init / boot-hart-ID discovery helpers.

// Hand-crafted PE/COFF header for RISC-V UEFI builds. LLVM has no PE/COFF
// backend for RISC-V, so we prepend this header and convert with
// llvm-objcopy. See boot/src/arch/riscv64/header.S and
// boot/linker/riscv64-uefi.ld. The assembly is emitted at crate top-level
// regardless of where the `global_asm!` invocation lives; placing it inside
// this arch module keeps `#[cfg(target_arch)]` discipline clean.
core::arch::global_asm!(include_str!("header.S"));

pub mod acpi_kernel_mmio;
pub mod acpi_spcr;
pub mod dtb_kernel_mmio;
pub mod handoff;
pub mod paging;
pub mod serial;
pub use handoff::{perform_handoff, trampoline_page_range};
pub use paging::BootPageTable;

use crate::elf::EM_RISCV;
use crate::firmware::FirmwareInfo;
use crate::uefi::{
    EFI_SUCCESS, EfiBootServices, EfiGuid, EfiStatus, EfiSystemTable, allocate_pages,
};
use boot_protocol::KernelMmio;

/// `EFI_RISCV_BOOT_PROTOCOL_GUID`
/// `{CCD15FEC-6F73-4EEC-8395-3E69E4B940BF}`
static EFI_RISCV_BOOT_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0xCCD1_5FEC,
    data2: 0x6F73,
    data3: 0x4EEC,
    data4: [0x83, 0x95, 0x3E, 0x69, 0xE4, 0xB9, 0x40, 0xBF],
};

/// `EFI_RISCV_BOOT_PROTOCOL` — provides the boot hart ID on RISC-V platforms.
///
/// Located via `LocateProtocol` using [`EFI_RISCV_BOOT_PROTOCOL_GUID`].
#[repr(C)]
struct EfiRiscvBootProtocol
{
    /// Protocol revision (unused by us).
    pub revision: u64,
    /// Query the boot hart ID.
    pub get_boot_hartid: unsafe extern "efiapi" fn(this: *mut Self, hart_id: *mut u64) -> EfiStatus,
}

/// ELF machine type expected for RISC-V 64-bit kernel binaries.
pub const EXPECTED_ELF_MACHINE: u16 = EM_RISCV;

/// Discover UART base and update the serial backend before `serial_init()`.
///
/// Tries ACPI SPCR first, then DTB, then falls back to the QEMU default.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table.
pub unsafe fn pre_serial_init(st: *mut EfiSystemTable)
{
    // SAFETY: st is valid; discover_uart reads UEFI configuration tables.
    unsafe { serial::discover_uart(st) };
}

/// Return the MMIO base address of the discovered UART for identity mapping.
///
/// Call after `pre_serial_init` has run. Returns the QEMU default if discovery
/// was not performed.
pub fn uart_mmio_region() -> u64
{
    serial::uart_base() as u64
}

/// Populate `km` from firmware tables for RISC-V.
///
/// ACPI is consulted first; DTB then fills any field ACPI left zero.
/// Both sources are consulted because UEFI RISC-V firmware may publish
/// either (or both) of [`crate::uefi::EFI_ACPI_20_TABLE_GUID`] and
/// [`crate::uefi::EFI_DTB_TABLE_GUID`]. Fields neither source populates
/// stay zero; the kernel falls back to its compiled-in defaults.
///
/// # Safety
/// `firmware.acpi_rsdp` and `firmware.device_tree`, when non-zero, must
/// each be the physical address of a valid, identity-mapped RSDP / FDT.
pub unsafe fn populate_kernel_mmio(firmware: &FirmwareInfo, km: &mut KernelMmio)
{
    if firmware.acpi_rsdp != 0
    {
        // SAFETY: caller guarantees acpi_rsdp is valid when non-zero.
        unsafe { acpi_kernel_mmio::parse_kernel_mmio(firmware.acpi_rsdp, km) };
    }
    if firmware.device_tree != 0
    {
        // SAFETY: caller guarantees device_tree is valid when non-zero.
        unsafe { dtb_kernel_mmio::parse_kernel_mmio(firmware.device_tree, km) };
    }
}

/// Query `EFI_RISCV_BOOT_PROTOCOL` for the boot hart ID.
///
/// Returns 0 if the protocol is not available or the call fails.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table, with valid boot
/// services (before `ExitBootServices`).
pub unsafe fn discover_boot_hart_id(st: *mut EfiSystemTable) -> u64
{
    // SAFETY: st is a valid UEFI system table pointer; caller guarantees validity.
    let bs = unsafe { (*st).boot_services };
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: bs is valid; locate_protocol fills iface on success.
    let status: EfiStatus = unsafe {
        ((*bs).locate_protocol)(
            core::ptr::addr_of!(EFI_RISCV_BOOT_PROTOCOL_GUID),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(iface),
        )
    };
    if status != EFI_SUCCESS || iface.is_null()
    {
        return 0;
    }
    let proto = iface.cast::<EfiRiscvBootProtocol>();
    let mut hart_id: u64 = 0;
    // SAFETY: proto is a valid protocol pointer returned by LocateProtocol.
    let s: EfiStatus =
        unsafe { ((*proto).get_boot_hartid)(proto, core::ptr::addr_of_mut!(hart_id)) };
    if s == EFI_SUCCESS { hart_id } else { 0 }
}

/// Return the hardware identifier of the bootstrap processor.
///
/// On RISC-V the BSP identifier is the boot hart ID, which the caller has
/// already obtained via [`discover_boot_hart_id`]. Hart IDs are `u64` in
/// the SBI ABI but fit in `u32` for every platform Seraph targets; the
/// lower 32 bits are taken.
#[allow(clippy::cast_possible_truncation)]
pub fn bsp_hardware_id(boot_hart_id: u64) -> u32
{
    boot_hart_id as u32
}

/// Reserve a 4 KiB page for the AP startup trampoline.
///
/// On RISC-V SBI `HART_START` accepts any physical address for the AP
/// entry point, so no placement constraint applies beyond page alignment
/// (guaranteed by `allocate_pages`). Returns `None` if the allocation
/// fails (SMP is then disabled).
///
/// # Safety
/// `bs` must be valid UEFI boot services; call before `ExitBootServices`.
pub unsafe fn allocate_ap_trampoline(bs: *mut EfiBootServices) -> Option<u64>
{
    // SAFETY: bs is valid per the caller's contract.
    unsafe { allocate_pages(bs, 1).ok() }
}

/// QEMU virt RISC-V default MMIO apertures: PCI ECAM + 32-bit + 64-bit
/// PCI windows, plus the Goldfish RTC register page at `0x101000`.
///
/// Seeded unconditionally because EDK2 on the seraph boot path neither
/// re-publishes the DTB via a UEFI configuration table nor emits ACPI
/// entries for these regions, so neither
/// [`crate::dtb::parse_aperture_seed`] nor MCFG / `_HID` walks can
/// discover them at runtime. Merged with anything firmware does happen
/// to publish in [`crate::memory_map::derive_mmio_apertures`].
///
/// The Goldfish RTC entry covers a single 4 KiB page; devmgr identifies
/// it by base address (`0x101000` is part of the QEMU `virt` machine
/// model contract) and spawns the `goldfish-rtc` driver on it.
pub fn default_pci_apertures() -> &'static [(u64, u64)]
{
    const ENTRIES: &[(u64, u64)] = &[
        (0x10_1000, 0x1000),
        (0x3000_0000, 0x1000_0000),
        (0x4000_0000, 0x4000_0000),
        (0x4_0000_0000, 0x4_0000_0000),
    ];
    ENTRIES
}

/// Return the platform's maximum physical address width in bits.
///
/// On RISC-V the Privileged spec caps physical addresses at 56 bits
/// across Sv39, Sv48, and Sv57 page-table modes, and no in-band ISA
/// mechanism exists for querying the implementation-supported width
/// (no CPUID analogue). Real implementations can be narrower; 56 is
/// the safe upper bound.
///
/// Provided for arch-dispatch symmetry with x86-64. The current
/// QEMU virt RISC-V machine has a fixed, well-known PCI MMIO layout
/// that [`crate::acpi::parse_aperture_seed`] handles via its
/// virt-machine branch, so this value is not consumed today. When
/// RISC-V boards diverge from QEMU virt and need MAXPHYADDR-derived
/// apertures, this function is the dispatch point.
pub fn max_phys_addr_bits() -> u8
{
    56
}
