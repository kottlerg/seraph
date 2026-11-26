// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/firmware-tables.rs

//! The fuzz target of the firmware-table format decoders
//! (`shared/firmware-tables`): its property `tables_holds` over inputs read
//! as an RSDP, an SDT header, an XSDT, an MCFG, a MADT, a DMAR, an SPCR and
//! a flattened device tree.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "firmware-tables",
        inputs: Some("shared/firmware-tables/fuzz/firmware-tables"),
        // Room past the largest seed, QEMU virt's device tree of 5044 bytes,
        // for a larger tree, a MADT of a few hundred interrupt controllers (8
        // bytes or more each) or a DMAR of tens of units.
        max_len: 16384,
        property: firmware_tables::property::tables_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
