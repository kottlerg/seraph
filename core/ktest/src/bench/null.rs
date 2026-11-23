// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/null.rs

//! Null-syscall round-trip benchmark.
//!
//! Measures the cost of a minimal kernel entry + exit. Uses
//! `SYS_SYSTEM_INFO(KernelVersion)` because it dispatches to a handler that
//! does effectively no work after the trap-frame decode.

use syscall_abi::SystemInfoType;

use super::Harness;

pub(super) fn bench_null_syscall(_ctx: &crate::TestContext, h: &mut Harness)
{
    let iters = h.iters();
    let (mut samples, counters) = h.recorder();

    for _ in 0..iters
    {
        let t0 = counters.read();
        let _ = syscall::system_info(SystemInfoType::KernelVersion as u64);
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }

    let summary = samples.summary();
    h.report("null_syscall_roundtrip", &[], summary, &[]);
}
