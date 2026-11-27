// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/namespace-protocol.rs

//! The fuzz target of the namespace protocol's parsers
//! (`shared/namespace-protocol`): its property `namespace_protocol_holds` over
//! inputs read as a request's label, badge and data words, as a name, and as
//! a client's path and a server's replies.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "namespace-protocol",
        inputs: Some("shared/namespace-protocol/fuzz/namespace-protocol"),
        // A label, a badge, the 64 data words a message carries, and one word
        // past them, so a path, a name and a client's path reach past the
        // longest a request carries.
        max_len: (2 + 64 + 1) * 8,
        property: namespace_protocol::property::namespace_protocol_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
