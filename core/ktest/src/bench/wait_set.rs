// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/wait_set.rs

//! Wait-set create → add → wait → remove → delete cycle benchmark.

use syscall::{
    cap_create_notification, cap_delete, notification_send, notification_wait, wait_set_add,
    wait_set_remove, wait_set_wait,
};

use super::Harness;

// Thin wrapper — same as `cap_create_wait_set` in core/ktest/src/unit/cap.rs.
fn cap_create_wait_set(memory_cap: u64) -> Result<u64, i64>
{
    syscall::wait_set_create(memory_cap, crate::WS_CAPACITY)
}

pub(super) fn bench_wait_set(ctx: &crate::TestContext, h: &mut Harness)
{
    // Cap this benchmark at 100 iterations; each cycle retypes a wait set out
    // of `ctx.memory_base` and frees it on `cap_delete`.
    let n = u64::from(h.iters().min(100));

    let Ok(sig) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip("wait_set_cycle", "cap_create_notification failed");
    };

    let (mut samples, counters) = h.recorder();

    for _ in 0..n
    {
        // Pre-arm the notification so wait_set_wait returns immediately.
        notification_send(sig, 0x1).ok();

        let t0 = counters.read();
        let Ok(ws) = cap_create_wait_set(ctx.memory_base)
        else
        {
            break;
        };
        if wait_set_add(ws, sig, 42).is_err()
        {
            cap_delete(ws).ok();
            break;
        }
        let _ = wait_set_wait(ws);
        let _ = wait_set_remove(ws, sig);
        cap_delete(ws).ok();
        let t1 = counters.read();

        // Drain bits left by notification_send.
        notification_wait(sig).ok();

        samples.record(t1.since(&t0).cycles);
    }

    let summary = samples.summary();
    cap_delete(sig).ok();

    h.report("wait_set_cycle", &[], summary, &[]);
}
