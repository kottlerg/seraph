// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/spawn-target/src/main.rs

//! svctest's known-good spawn target: the image its procmgr, memmgr,
//! budget, process-tree, pipe and namespace phases create, spawn, read and
//! look up (services/fixtures/spawn-target/README.md).
//!
//! It prints [`LINE`] to its stdout and exits 0, whatever its arguments.

/// The line it prints.
const LINE: &str = "spawn-target ran";

fn main()
{
    println!("{LINE}");
}
