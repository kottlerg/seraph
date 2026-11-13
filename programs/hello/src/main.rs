// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/hello/src/main.rs

//! Hello-world program. Idiomatic Rust, no Seraph cap awareness.
//!
//! Demonstrates that a binary built against `std` with zero `std::os::seraph`
//! imports can produce stdout output via `println!`. The spawner wires the
//! child's stdout cap to the system log endpoint with a per-service badge;
//! nothing in this binary knows or cares.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(
    clippy::fn_params_excessive_bools,
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

fn main()
{
    println!("hello from seraph userspace");
}
