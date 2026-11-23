// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/planted-length.rs

//! A planted defect of the engine's self-test (`cargo xtask fuzz
//! --self-test`): a record of a four-byte tag and a `u32` length whose end is
//! computed with an unchecked add, which overflows (and, with the fuzz
//! profile's overflow checks, panics) for a length within 8 of `u32::MAX`.

/// The record's tag, `LEN!` read as a little-endian `u32`.
#[cfg(fuzzing)]
const TAG: u32 = 0x214E_454C;

/// The length of the record's header: its tag and its length field.
#[cfg(fuzzing)]
const HEADER: u32 = 8;

#[cfg(fuzzing)]
fn planted(data: &[u8])
{
    let Some((tag, rest)) = data.split_first_chunk::<4>()
    else
    {
        return;
    };
    let Some((len, body)) = rest.split_first_chunk::<4>()
    else
    {
        return;
    };
    if u32::from_le_bytes(*tag) != TAG
    {
        return;
    }
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the planted defect: a length read from the input added without a check"
    )]
    let end = HEADER + u32::from_le_bytes(*len);
    if usize::try_from(end).is_ok_and(|end| end <= data.len())
    {
        std::hint::black_box(body);
    }
}

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "planted-length",
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
