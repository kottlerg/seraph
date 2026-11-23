// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/boot_device.rs

//! Tier 1 test of the boot device record on its way to init.
//!
//! The bootloader reads the boot ESP's GPT `HardDrive` descriptor and its
//! controller's PCI location from the firmware while boot services run, and
//! the kernel checks the record and copies it into `InitInfo.boot_device` at
//! Phase 9 (`core/kernel/docs/initialization.md` § Phase 9). ktest is loaded
//! as init, so its own `InitInfo` holds the copy. Every ktest boot loads the
//! bootloader from the GPT disk image's ESP on a `virtio-blk-pci` device, so
//! the firmware reports both parts.

use init_protocol::{INIT_BOOT_DEVICE_ESP, INIT_BOOT_DEVICE_PCI, InitInfo};

use crate::{TestContext, TestResult};

/// `InitInfo.boot_device` carries both parts: an ESP descriptor of a nonzero
/// partition number and size and a nonzero unique GUID, and a PCI location
/// whose device and function numbers lie in their PCI ranges, with no other
/// flag bit or reserved byte set.
pub fn init_info_carries_the_boot_device(ctx: &TestContext) -> TestResult
{
    // SAFETY: the kernel maps the InitInfo page read-only at `init_info_va`
    // for ktest's lifetime (`_start` reads it through the same address).
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let device = info.boot_device;

    if device.flags != INIT_BOOT_DEVICE_ESP | INIT_BOOT_DEVICE_PCI
    {
        return Err(
            "boot device: the ESP or the PCI location is missing, or an unknown flag is set",
        );
    }
    if device.reserved != [0; 3]
    {
        return Err("boot device: reserved bytes are not zero");
    }
    if device.esp_partition_number == 0 || device.esp_size_lba == 0
    {
        return Err("boot device: the ESP has a zero partition number or size");
    }
    if device.esp_partition_guid == [0; 16]
    {
        return Err("boot device: the ESP's partition GUID is zero");
    }
    if device.pci_device > 31 || device.pci_function > 7
    {
        return Err("boot device: PCI device or function out of range");
    }
    Ok(())
}
