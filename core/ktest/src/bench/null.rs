// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Null-syscall round-trip benchmark.
//!
//! Measures the cost of a minimal kernel entry + exit. Uses
//! `SYS_SYSTEM_INFO(KernelVersion)` because it dispatches to a handler that
//! does effectively no work after the trap-frame decode.

use syscall_abi::SystemInfoType;

use super::{cycles_now, log_bench_header};

pub(super) fn bench_null_syscall(_ctx: &crate::TestContext, iters: u32)
{
    let n = u64::from(iters);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        let _ = syscall::system_info(SystemInfoType::KernelVersion as u64);
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    log_bench_header("null_syscall_roundtrip", iters);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
