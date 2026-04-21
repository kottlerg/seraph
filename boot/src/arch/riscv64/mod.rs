// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/mod.rs

//! RISC-V 64-bit architecture module for the bootloader.
//!
//! Exports arch-specific constants, the kernel handoff function, and
//! pre-serial-init / boot-hart-ID discovery helpers.

pub mod handoff;
pub mod paging;
pub mod serial;
pub use handoff::{perform_handoff, trampoline_page_range};
pub use paging::BootPageTable;

use crate::elf::EM_RISCV;
use crate::uefi::{EFI_SUCCESS, EfiGuid, EfiStatus, EfiSystemTable};

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

/// Return 0: on RISC-V, the BSP hardware ID (hart ID) comes from
/// `discover_boot_hart_id` (`EFI_RISCV_BOOT_PROTOCOL`). This function is a
/// placeholder to satisfy the x86-64 arch interface; callers should use
/// the value from `discover_boot_hart_id` directly.
#[allow(dead_code)]
pub fn bsp_hardware_id() -> u32
{
    0
}
