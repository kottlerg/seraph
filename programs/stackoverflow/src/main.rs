// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/stackoverflow/src/main.rs

//! Stack-overflow fixture for the main-thread stack guard page: recursion
//! without bound until the main thread's stack overflows onto its guard page
//! and the thread is killed with a page-fault exit reason. The stack it
//! overflows is described in `programs/stackoverflow/README.md` and
//! docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs.
//!
//! Driven by `services/svctest`'s `stack_overflow_phase`, which spawns this
//! binary, waits for exit, and asserts the non-zero fault reason.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]

fn main()
{
    overflow(0);
}

#[expect(
    unconditional_recursion,
    reason = "deliberate — the intent is to overflow the stack"
)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "depth is used only as a never-read fill byte; truncation to u8 is fine and keeps the \
              per-frame footprint at one page"
)]
#[inline(never)]
fn overflow(depth: usize)
{
    // One full page of stack per frame guarantees that overflow reaches
    // the guard page in a bounded number of recursions: about one per page
    // of the `std::os::seraph::DEFAULT_DEMAND_STACK_PAGES` stack, plus one
    // for the guard. `black_box` prevents the optimiser from eliding the
    // buffer or the tail call.
    let buf = [depth as u8; 4096];
    std::hint::black_box(&buf);
    overflow(depth.wrapping_add(1));
}
