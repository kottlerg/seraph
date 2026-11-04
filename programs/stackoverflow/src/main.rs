// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/stackoverflow/src/main.rs

//! Stack-overflow fixture for the main-thread stack guard page.
//!
//! Recurses with a page-sized local in every frame. The stack pointer
//! descends through the stack's committed pages and then through the
//! demand-growth range below them, which the pager backs on first touch,
//! until a write lands in the unregistered guard page below the range. The
//! pager declines that fault and the kernel terminates the thread with the
//! architecture's page-fault exit reason.
//!
//! Driven by `services/svctest`'s `stack_overflow_phase`, which spawns this
//! binary, waits for exit, and asserts the non-zero fault reason.

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
    // the guard page in a bounded number of recursions (about one per page
    // of the 512-page stack, plus one for the guard). `black_box` prevents the
    // optimiser from eliding the buffer or the tail call.
    let buf = [depth as u8; 4096];
    std::hint::black_box(&buf);
    overflow(depth + 1);
}
