// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/fat.rs

//! The fuzz target of the FAT decoders (`services/fs/fat/fat-parse`): its
//! property `fat_holds` over inputs read as sector 0, as a FAT sector and as
//! a directory sector.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "fat",
        inputs: Some("services/fs/fat/fat-parse/fuzz/fat"),
        // One sector of the largest size, `MAX_SECTOR_SIZE`: a 4Kn volume's
        // sector 0, a FAT sector of 1024 FAT32 entries, or a directory
        // sector of 128 slots.
        max_len: fatfs_parse::MAX_SECTOR_SIZE,
        property: fatfs_parse::property::fat_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
