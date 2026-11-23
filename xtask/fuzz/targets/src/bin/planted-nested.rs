// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/planted-nested.rs

//! A planted defect of the engine's self-test (`cargo xtask fuzz
//! --self-test`): a panic reached only through three nested levels of
//! type-length-value records with no checksum, each level parsed by its own
//! function, so the engine reaches it by keeping the inputs that reach each
//! level deeper.

#![cfg_attr(
    fuzzing,
    expect(
        clippy::panic,
        reason = "a planted target of the engine's self-test exists to fail: its defect is a panic \
                  the engine must find"
    )
)]

/// The record type each level looks for: outer, middle, inner.
#[cfg(fuzzing)]
const TYPES: [u8; 3] = [0x4F, 0x4D, 0x49];

/// The value of the inner record that reaches the defect.
#[cfg(fuzzing)]
const VALUE: u16 = 0xBEEF;

/// Call `each` with the type and payload of each record of `data`: a type
/// byte, a length byte, then that many payload bytes. A record that runs past
/// the end ends the walk.
#[cfg(fuzzing)]
fn records(data: &[u8], mut each: impl FnMut(u8, &[u8]))
{
    let mut rest = data;
    while let Some((&kind, tail)) = rest.split_first()
        && let Some((&len, tail)) = tail.split_first()
        && let Some((payload, tail)) = tail.split_at_checked(usize::from(len))
    {
        each(kind, payload);
        rest = tail;
    }
}

#[cfg(fuzzing)]
#[inline(never)]
fn outer(data: &[u8])
{
    records(data, |kind, payload| {
        if kind == TYPES[0]
        {
            middle(payload);
        }
    });
}

#[cfg(fuzzing)]
#[inline(never)]
fn middle(data: &[u8])
{
    records(data, |kind, payload| {
        if kind == TYPES[1]
        {
            inner(payload);
        }
    });
}

#[cfg(fuzzing)]
#[inline(never)]
fn inner(data: &[u8])
{
    records(data, |kind, payload| {
        if kind == TYPES[2]
            && let Some(value) = payload.first_chunk::<2>()
            && u16::from_le_bytes(*value) == VALUE
        {
            panic!("planted defect: the innermost record holds the value");
        }
    });
}

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "planted-nested",
        inputs: None,
        max_len: 64,
        property: outer,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
