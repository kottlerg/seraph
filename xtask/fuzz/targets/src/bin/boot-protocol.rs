// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/boot-protocol.rs

//! The fuzz target of the boot protocol's parsers (`abi/boot-protocol`): its
//! property `boot_protocol_holds` over inputs read as a bundle file and as a
//! framebuffer record.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "boot-protocol",
        inputs: Some("abi/boot-protocol/fuzz/boot-protocol"),
        // A bundle of two entries, each body on a page of its own after the
        // page of the headers.
        max_len: 3 * 4096,
        property: boot_protocol::property::boot_protocol_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
