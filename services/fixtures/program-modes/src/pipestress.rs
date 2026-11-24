// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/program-modes/src/pipestress.rs

//! Pipe fixture for `services/svctest`'s `pipestress` phase, in two modes. By
//! default it echoes its first argument in one stdout line and returns
//! immediately (#360), so the interval between the write landing in the stdout
//! ring and process death is as short as the runtime allows — the shape that
//! races a parent draining the pipe against the death-bridge flipping
//! `peer_dead`. Given `sink`, it is the reader of the phase's doorbell trial:
//! it reads its stdin to EOF and reports the bytes it read and its pipe
//! counters (`std::os::seraph::pipe`).

use std::io::{Read, Write};

/// Bytes one read of the sink takes at most: more than the pipe's 2048-byte
/// ring holds, so no read leaves bytes it could have taken.
const SINK_READ_BYTES: usize = 4096;

pub fn main()
{
    let token = std::env::args().nth(2).unwrap_or_default();
    if token == "sink"
    {
        sink();
        return;
    }
    println!("pipestress: {token} ok");
}

/// Announce readiness, read stdin to EOF, and report the bytes read and this
/// thread's pipe notification sends and waits. A read error ends the count
/// where it stands; the phase's byte check reports it.
fn sink()
{
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "pipestress: sink ready");
    let _ = stdout.flush();
    let sends_before = std::os::seraph::pipe::notification_sends();
    let waits_before = std::os::seraph::pipe::waits();
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; SINK_READ_BYTES];
    let mut bytes: u64 = 0;
    while let Ok(n) = stdin.read(&mut buf)
    {
        if n == 0
        {
            break;
        }
        bytes = bytes.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    let sends = std::os::seraph::pipe::notification_sends().wrapping_sub(sends_before);
    let waits = std::os::seraph::pipe::waits().wrapping_sub(waits_before);
    let _ = writeln!(
        stdout,
        "pipestress: sink {bytes} bytes {sends} sends {waits} waits"
    );
}
