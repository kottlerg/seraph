// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/echosh/src/main.rs

//! Minimal placeholder child for `programs/terminal` (#111).
//!
//! Reads a line from stdin and writes it back to stdout prefixed with
//! `[echosh] ` until end of input, then exits. No Seraph cap awareness —
//! only `std::io` over the stdio pipes the terminal hands it. The prefix lets
//! the terminal's test distinguish child output (relayed back to the display)
//! from the terminal's own local echo on the shared serial stream.
//!
//! This is a throwaway stand-in for the real interactive shell, which lands as
//! `programs/shell` under #112; the terminal retargets its child there by
//! editing one line of `terminal.svc`.

use std::io::{BufRead, BufReader, Write};

fn main()
{
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = std::io::stdout();
    let mut line = String::new();
    loop
    {
        line.clear();
        match reader.read_line(&mut line)
        {
            Ok(0) | Err(_) => return,
            Ok(_) =>
            {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if writeln!(out, "[echosh] {trimmed}").is_err() || out.flush().is_err()
        {
            return;
        }
    }
}
