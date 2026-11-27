// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/ubench/src/empty_window.rs

//! `empty_window`: two counter reads with nothing between them.
//!
//! A sample is what the counter reads themselves put into every window, the
//! offset each other benchmark's samples include (docs/testing.md
//! § Benchmarks). It is reported, not subtracted from any line.

use bench::Counters;

use crate::harness::{IdleSpan, Outcome, report};

/// Untimed windows before the timed ones.
const WARMUP: usize = 64;

/// Timed windows.
const ITERS: usize = 1024;

/// Run the benchmark: one result line.
pub fn run(counters: &Counters, cpus: u32) -> Outcome
{
    let mut samples = Vec::with_capacity(ITERS);
    let idle = IdleSpan::open();
    for i in 0..WARMUP + ITERS
    {
        let start = counters.read();
        let cycles = counters.read().since(&start).cycles;
        if i >= WARMUP
        {
            samples.push(cycles);
        }
    }
    let idle_halts = idle.close();
    report("empty_window", &[], cpus, &mut samples, &[], idle_halts)
}
