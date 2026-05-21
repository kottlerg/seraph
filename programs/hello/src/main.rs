// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/hello/src/main.rs

//! Hello-world program. Idiomatic Rust, no Seraph cap awareness.
//!
//! Demonstrates that a binary built against `std` with zero `std::os::seraph`
//! imports can produce stdout output via `println!`. The spawner wires the
//! child's stdout cap to the system log endpoint with a per-service token;
//! nothing in this binary knows or cares.

#![feature(restricted_std)]

fn main()
{
    println!("hello from seraph userspace");
}
