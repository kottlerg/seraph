// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/devmgr-firmware.rs

//! The fuzz target of devmgr's firmware-table decoders
//! (`services/devmgr/firmware`): its property `firmware_holds` over inputs
//! read as an RSDP, an SDT header, an XSDT, a FADT, an MCFG, a MADT, a DMAR
//! and a RIMT.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "devmgr-firmware",
        inputs: Some("services/devmgr/firmware/fuzz/devmgr-firmware"),
        // Room past the largest seed, a FADT of 276 bytes, for a MADT of
        // a few hundred interrupt controllers (8 bytes or more each) or a
        // DMAR of tens of units with their scopes.
        max_len: 4096,
        property: devmgr_firmware::property::firmware_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
