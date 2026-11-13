// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/stdiotest/src/main.rs

//! Stdin↔stdout proof. Reads a line from stdin, prints what it got plus an
//! uppercase echo, then exits.
//!
//! No Seraph cap awareness in this binary — only `std::io`. The spawner
//! creates an endpoint pair, hands the RECV side to this child as `stdin`,
//! keeps the SEND side, and writes a probe payload after this child has
//! started. This child blocks on `stdin().read_line(..)` until those bytes
//! arrive, processes them, and emits the result through `println!`.

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
    let mut line = String::new();
    let n = match std::io::stdin().read_line(&mut line)
    {
        Ok(n) => n,
        Err(e) =>
        {
            eprintln!("read stdin failed: {e}");
            return;
        }
    };
    let trimmed = line.trim_end_matches('\n');
    println!("got {n} bytes: {trimmed:?}");
    println!("shouted: {}", trimmed.to_uppercase());
    println!("PASS");
}
