// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/firmware.rs

//! Firmware table discovery: ACPI RSDP and Device Tree blob addresses.
//!
//! Scans the UEFI configuration table unconditionally for both
//! `EFI_ACPI_20_TABLE_GUID` and `EFI_DTB_TABLE_GUID`, recording whichever
//! are present. Full ACPI and Device Tree parsing is deferred to userspace
//! (`devmgr`). Also holds [`place_cpu_ids`], the BSP-first CPU placement
//! rule the MADT and DTB topology walks share.

use crate::uefi::{EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID, EfiSystemTable, find_config_table};
use boot_protocol::MAX_CPUS;

/// Physical addresses of firmware tables discovered from the UEFI configuration table.
pub struct FirmwareInfo
{
    /// Physical address of the ACPI RSDP (either architecture; see
    /// `core/boot/docs/firmware-parsing.md`). Zero if not present.
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

/// Place the enabled CPU hardware IDs a firmware table lists into the
/// `BootInfo.cpu_ids` layout: `bsp_id` at index 0, then each other distinct
/// ID once, in table order.
///
/// Returns `(cpu_count, cpu_ids, truncated)`. `cpu_count` is the number of
/// slots filled, so the BSP counts once whether or not the table lists it,
/// and `cpu_ids[1..cpu_count]` holds exactly the APs. `truncated` is set when
/// a distinct ID found no slot (more than [`MAX_CPUS`] CPUs, BSP included).
pub fn place_cpu_ids(bsp_id: u32, ids: &[u32]) -> (u32, [u32; MAX_CPUS], bool)
{
    let mut cpu_ids = [0u32; MAX_CPUS];
    cpu_ids[0] = bsp_id;
    let mut filled: usize = 1;
    let mut truncated = false;
    for &id in ids
    {
        if cpu_ids[..filled].contains(&id)
        {
            continue;
        }
        if filled < MAX_CPUS
        {
            cpu_ids[filled] = id;
            filled += 1;
        }
        else
        {
            truncated = true;
        }
    }
    // filled is at most MAX_CPUS, which fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let cpu_count = filled as u32;
    (cpu_count, cpu_ids, truncated)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn bsp_absent_from_the_list_still_counts_once()
    {
        let (count, ids, truncated) = place_cpu_ids(0, &[1, 2, 3]);
        assert_eq!(count, 4);
        assert_eq!(ids[..4], [0, 1, 2, 3]);
        assert!(!truncated);
    }

    #[test]
    fn listed_bsp_is_not_placed_again()
    {
        let (count, ids, _) = place_cpu_ids(2, &[0, 1, 2, 3]);
        assert_eq!(count, 4);
        assert_eq!(ids[..4], [2, 0, 1, 3]);
    }

    #[test]
    fn duplicated_id_is_placed_once()
    {
        let (count, ids, _) = place_cpu_ids(0, &[1, 2, 1]);
        assert_eq!(count, 3);
        assert_eq!(ids[..3], [0, 1, 2]);
    }

    #[test]
    fn empty_list_is_the_bsp_alone()
    {
        let (count, ids, truncated) = place_cpu_ids(7, &[]);
        assert_eq!((count, ids[0], truncated), (1, 7, false));
    }

    #[test]
    fn full_list_including_the_bsp_fits_exactly()
    {
        let ids: Vec<u32> = (0..MAX_CPUS as u32).collect();
        let (count, _, truncated) = place_cpu_ids(0, &ids);
        assert_eq!(count as usize, MAX_CPUS);
        assert!(!truncated);
    }

    #[test]
    fn full_list_omitting_the_bsp_drops_the_last_ap_and_says_so()
    {
        let ids: Vec<u32> = (1..=MAX_CPUS as u32).collect();
        let (count, placed, truncated) = place_cpu_ids(0, &ids);
        assert_eq!(count as usize, MAX_CPUS);
        assert_eq!(placed[MAX_CPUS - 1], MAX_CPUS as u32 - 1);
        assert!(truncated);
    }
}
