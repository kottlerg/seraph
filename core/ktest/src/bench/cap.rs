// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/cap.rs

//! Capability operation benchmarks.

use syscall::{cap_create_notification, cap_delete, cap_info};
use syscall_abi::CAP_INFO_TAG_RIGHTS;

use super::Harness;

pub(super) fn bench_cap_create_delete(ctx: &crate::TestContext, h: &mut Harness)
{
    let iters = h.iters();
    let (mut samples, counters) = h.recorder();

    for _ in 0..iters
    {
        let t0 = counters.read();
        let Ok(sig) = cap_create_notification(ctx.memory_base)
        else
        {
            break;
        };
        cap_delete(sig).ok();
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }

    let summary = samples.summary();
    h.report("cap_create_delete", &[], summary, &[]);
}

/// `SYS_CAP_INFO(CAP_INFO_TAG_RIGHTS)` on a held Notification cap: one handle
/// resolution and pin (`syscall::pin_slot`) and its release, with no other
/// object work. Its distance from `null_syscall_roundtrip` is the cost of the
/// capability-lookup path.
pub(super) fn bench_cap_info_lookup(ctx: &crate::TestContext, h: &mut Harness)
{
    let Ok(sig) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip("cap_info_lookup", "cap_create_notification failed");
    };
    let iters = h.iters();
    let (mut samples, counters) = h.recorder();

    for _ in 0..iters
    {
        let t0 = counters.read();
        let _ = cap_info(sig, CAP_INFO_TAG_RIGHTS);
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }
    let summary = samples.summary();
    cap_delete(sig).ok();

    h.report("cap_info_lookup", &[], summary, &[]);
}
