// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/hwrng-protocol.rs

//! The fuzz target of the `hwrng` class protocol's parsers
//! (`shared/hwrng-protocol`): its property `hwrng_protocol_holds` over inputs
//! read as a request's and a reply's words.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "hwrng-protocol",
        inputs: Some("shared/hwrng-protocol/fuzz/hwrng-protocol"),
        // The buffer's length and one word past the 65 the property reads,
        // so the bytes a reply carries reach past the most it may.
        max_len: 2 + 66 * 8,
        property: hwrng_protocol::property::hwrng_protocol_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
