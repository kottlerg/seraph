// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/driver-binding.rs

//! The fuzz target of the driver declaration decoder
//! (`shared/driver-binding`): its property `decl_holds` over inputs read as
//! a declaration note's descriptor.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "driver-binding",
        inputs: Some("shared/driver-binding/fuzz/driver-binding"),
        // Past the largest descriptor the decoder takes (512 bytes), so the
        // refusal of a longer one is reached.
        max_len: 1024,
        property: driver_binding::property::decl_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
