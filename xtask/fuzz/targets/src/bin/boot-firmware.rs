// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/boot-firmware.rs

//! The fuzz target of the bootloader's firmware-table decoding
//! (`core/boot/firmware`): its property `boot_firmware_holds` over inputs
//! read as a memory map with the range a table claims, a MADT structure, a
//! MADT, an RHCT, an SSDT, a TPM2, a DMAR, an SPCR, any ACPI table's
//! aperture seeds, a flattened device tree and a list of CPU IDs.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "boot-firmware",
        inputs: Some("core/boot/firmware/fuzz/boot-firmware"),
        // Room past the largest seed, QEMU virt's device tree of 9706 bytes,
        // for a tree of more harts and devices, or a MADT of a few hundred
        // interrupt controllers.
        max_len: 16384,
        property: boot_firmware::property::boot_firmware_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
