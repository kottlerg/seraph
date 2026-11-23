// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/planted-magic.rs

//! A planted defect of the engine's self-test (`cargo xtask fuzz
//! --self-test`): a panic behind an eight-byte magic compared as one `u64`,
//! which random mutation alone essentially never matches; the engine reaches
//! it through the compare operands it traces.

#![cfg_attr(
    fuzzing,
    expect(
        clippy::panic,
        reason = "a planted target of the engine's self-test exists to fail: its defect is a panic \
                  the engine must find"
    )
)]

/// The magic, `SEPLANT!` read as a little-endian `u64`.
#[cfg(fuzzing)]
const MAGIC: u64 = 0x2154_4E41_4C50_4553;

#[cfg(fuzzing)]
fn planted(data: &[u8])
{
    if let Some(word) = data.first_chunk::<8>()
        && u64::from_le_bytes(*word) == MAGIC
    {
        panic!("planted defect: the eight-byte magic matched");
    }
}

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "planted-magic",
        inputs: None,
        max_len: 64,
        property: planted,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
