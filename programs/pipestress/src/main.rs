// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/pipestress/src/main.rs

//! Spawn-exit-drain stress fixture (#360). Echoes its first argument in one
//! stdout line and returns immediately, so the interval between the write
//! landing in the stdout ring and process death is as short as the runtime
//! allows — the shape that races a parent draining the pipe against the
//! death-bridge flipping `peer_dead`. Idiomatic Rust, no Seraph cap awareness.

fn main()
{
    let token = std::env::args().nth(1).unwrap_or_default();
    println!("pipestress: {token} ok");
}
