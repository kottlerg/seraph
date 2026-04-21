// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/stdiotest/src/main.rs

//! Tier-2 stdin↔stdout proof. Reads a line from stdin, prints what it got
//! plus an uppercase echo, then exits.
//!
//! No Seraph cap awareness in this binary — only `std::io`. The spawner
//! (init in the current setup) creates an endpoint pair, hands the RECV side
//! to this child as `stdin`, keeps the SEND side, and writes a probe payload
//! after this child has started. This child blocks on `stdin().read_line(..)`
//! until those bytes arrive, processes them, and emits the result through
//! `println!`.

#![feature(restricted_std)]

use std::io::{BufRead, BufReader};

fn main()
{
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();
    let n = match reader.read_line(&mut line)
    {
        Ok(n) => n,
        Err(e) =>
        {
            eprintln!("stdiotest: read stdin failed: {e}");
            return;
        }
    };
    let trimmed = line.trim_end_matches('\n');
    println!("stdiotest: got {n} bytes: {trimmed:?}");
    println!("stdiotest: shouted: {}", trimmed.to_uppercase());
    println!("stdiotest: PASS");
}
