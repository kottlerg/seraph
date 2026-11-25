// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/objsig.rs

//! The fuzz target of the signed-object and trust-store parsers
//! (`shared/objsig`): its property `objsig_holds` over inputs read as a
//! signed object, signed attributes, a certificate, a trust store, an
//! enrolled store and a trust request.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "objsig",
        inputs: Some("shared/objsig/fuzz/objsig"),
        // Room past the largest seed, an object of two records (12,450
        // bytes), for a third record with a certificate (8,906 bytes at
        // least), and past a trust store of three anchors (6,090 bytes).
        max_len: 24_576,
        property: objsig::property::objsig_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
