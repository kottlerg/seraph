// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/counter.rs

//! Empty-window benchmark: two counter reads with nothing between them.
//!
//! A sample is what the counter reads themselves put into every window, the
//! offset each other benchmark's samples include (docs/testing.md
//! § Benchmarks). It is reported, not subtracted from any line.

use super::Harness;

pub(super) fn bench_empty_window(_ctx: &crate::TestContext, h: &mut Harness)
{
    let iters = h.iters();
    let (mut samples, counters) = h.recorder();

    for _ in 0..iters
    {
        let t0 = counters.read();
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }

    let summary = samples.summary();
    h.report("empty_window", &[], summary, &[]);
}
