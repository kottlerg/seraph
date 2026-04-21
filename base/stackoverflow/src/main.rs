// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/stackoverflow/src/main.rs

//! Stack-overflow fixture for the `PROCESS_STACK_GUARD_VA` regression test.
//!
//! Recurses with a page-sized local in every frame until the stack pointer
//! descends past `PROCESS_STACK_BOTTOM` and writes into
//! `PROCESS_STACK_GUARD_VA`, which is unmapped by construction. The first
//! write hits an unmapped page and the kernel terminates the thread with
//! the architecture's page-fault exit reason.
//!
//! Driven by `base/usertest`'s `stack_overflow_phase`, which spawns this
//! binary, waits for exit, and asserts the non-zero fault reason.

#![feature(restricted_std)]

fn main()
{
    overflow(0);
}

// unconditional_recursion: deliberate — the intent is to overflow the stack.
// cast_possible_truncation: depth is used only as a never-read fill byte;
// truncation to u8 is fine and keeps the per-frame footprint at one page.
#[allow(unconditional_recursion, clippy::cast_possible_truncation)]
#[inline(never)]
fn overflow(depth: usize)
{
    // One full page of stack per frame guarantees that overflow reaches
    // the guard page in a bounded number of recursions
    // (`PROCESS_STACK_PAGES + 1` at most). `black_box` prevents the
    // optimiser from eliding the buffer or the tail call.
    let buf = [depth as u8; 4096];
    std::hint::black_box(&buf);
    overflow(depth + 1);
}
