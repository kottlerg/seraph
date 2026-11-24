// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/storage-statement.rs

//! The fuzz target of the storage statement's parser
//! (`shared/storage-statement`): its property `storage_statement_holds` over
//! inputs read as a whole statement and as each of its lines.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "storage-statement",
        inputs: Some("shared/storage-statement/fuzz/storage-statement"),
        // Several lines of each role, and a path past the longest a
        // statement takes (255 bytes).
        max_len: 1024,
        property: storage_statement::property::storage_statement_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
