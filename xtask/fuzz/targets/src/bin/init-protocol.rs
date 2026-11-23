// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/init-protocol.rs

//! The fuzz target of the init protocol's module-name table parser
//! (`abi/init-protocol`): its property `init_protocol_holds` over inputs read
//! as a request and a table.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "init-protocol",
        inputs: Some("abi/init-protocol/fuzz/init-protocol"),
        // The request's length, the longest request, and the eight
        // 264-byte entries the property reads.
        max_len: 2 + 257 + 8 * 264,
        property: init_protocol::property::init_protocol_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
