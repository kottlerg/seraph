// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Wait-set create → add → wait → remove → delete cycle benchmark.

use syscall::{
    cap_create_notification, cap_delete, notification_send, notification_wait, wait_set_add,
    wait_set_remove, wait_set_wait,
};

use super::{cycles_now, log_bench_header};

// Thin wrapper — same as in unit/cap.rs.
fn cap_create_wait_set(frame_cap: u32) -> Result<u32, i64>
{
    syscall::wait_set_create(frame_cap)
}

pub(super) fn bench_wait_set(ctx: &crate::TestContext, iters: u32)
{
    // Cap this benchmark at 100 iterations; wait set create/delete involves
    // heap allocations that fragment under high churn.
    let n = u64::from(iters.min(100));

    let Ok(sig) = cap_create_notification(ctx.memory_frame_base)
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        // Pre-arm the notification so wait_set_wait returns immediately.
        notification_send(sig, 0x1).ok();

        let t0 = cycles_now();
        let Ok(ws) = cap_create_wait_set(ctx.memory_frame_base)
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
        let t1 = cycles_now();

        // Drain bits left by notification_send.
        notification_wait(sig).ok();

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

    cap_delete(sig).ok();

    // cast_possible_truncation: n is capped at 100; fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let actual_n = n as u32;
    log_bench_header("wait_set_cycle", actual_n);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
