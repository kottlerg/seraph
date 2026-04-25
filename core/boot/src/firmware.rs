// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/firmware.rs

//! Firmware table discovery: ACPI RSDP and Device Tree blob addresses.
//!
//! Scans the UEFI configuration table unconditionally for both
//! `EFI_ACPI_20_TABLE_GUID` and `EFI_DTB_TABLE_GUID`, recording whichever
//! are present. Full ACPI and Device Tree parsing is deferred to userspace
//! (`devmgr`).

use crate::uefi::{EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID, EfiSystemTable, find_config_table};

/// Physical addresses of firmware tables discovered from the UEFI configuration table.
pub struct FirmwareInfo
{
    /// Physical address of the ACPI RSDP (x86-64). Zero if not present.
    pub acpi_rsdp: u64,
    /// Physical address of the Device Tree blob (RISC-V). Zero if not present.
    pub device_tree: u64,
}

/// Discover firmware table pointers from the UEFI configuration table.
///
/// Scans for the ACPI 2.0 RSDP GUID and the Device Tree GUID. Returns zero
/// for any table that is not present. Neither ACPI tables nor the Device Tree
/// blob are parsed here — that is the responsibility of `devmgr` in userspace.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table, with a valid
/// `configuration_table` array of `number_of_table_entries` entries.
pub unsafe fn discover_firmware(st: *mut EfiSystemTable) -> FirmwareInfo
{
    // SAFETY: caller guarantees st is a valid UEFI system table pointer.
    // Both GUIDs are searched unconditionally; absent entries yield zero.
    let acpi_rsdp =
        unsafe { find_config_table(st, &EFI_ACPI_20_TABLE_GUID) }.map_or(0, |ptr| ptr as u64);
    // SAFETY: st is valid.
    let device_tree =
        unsafe { find_config_table(st, &EFI_DTB_TABLE_GUID) }.map_or(0, |ptr| ptr as u64);

    FirmwareInfo {
        acpi_rsdp,
        device_tree,
    }
}
