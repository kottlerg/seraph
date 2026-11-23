// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/elf.rs

//! The fuzz target of the ELF parsers (`shared/elf`): its property
//! `elf_holds` over inputs read as an image, and as a raw relocation table.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "elf",
        inputs: Some("shared/elf/fuzz/elf"),
        // Room past the largest seed (1344 bytes) for headers, sections and
        // records the engine adds, and for tables past a 256-byte note buffer.
        max_len: 4096,
        property: elf::property::elf_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
