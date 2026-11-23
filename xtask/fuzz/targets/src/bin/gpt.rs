// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/gpt.rs

//! The fuzz target of the GPT parser (`services/vfsd/gpt`): its property
//! `gpt_holds` over inputs read as a header block and as a whole disk.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "gpt",
        inputs: Some("services/vfsd/gpt/fuzz/gpt"),
        // A 4096-byte-block disk's protective MBR, header and four array
        // blocks.
        max_len: 6 * 4096,
        property: vfsd_gpt::property::gpt_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
