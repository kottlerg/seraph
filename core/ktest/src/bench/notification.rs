// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Notification ping-pong round-trip benchmark.
//!
//! Parent and child ping-pong via two notifications. Per-iteration bracketing
//! on the parent side.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    thread_exit,
};

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

static mut BENCH_SIGNAL_STACK: ChildStack = ChildStack::ZERO;

fn notification_pong_entry(arg: u64) -> !
{
    let in_slot = (arg & 0xFFFF) as u32;
    let out_slot = ((arg >> 16) & 0xFFFF) as u32;
    let done_slot = ((arg >> 32) & 0xFFFF) as u32;
    let n = arg >> 48;

    for _ in 0..n
    {
        if notification_wait(in_slot).is_err()
        {
            break;
        }
        if notification_send(out_slot, 1).is_err()
        {
            break;
        }
    }
    notification_send(done_slot, 1).ok();
    thread_exit()
}

// similar_names: ping/pong are intentionally paired names for the two directions.
#[allow(clippy::similar_names)]
pub(super) fn bench_notification_roundtrip(ctx: &crate::TestContext, iters: u32)
{
    const RIGHTS_NOTIFY: u64 = 1 << 7;
    const RIGHTS_WAIT: u64 = 1 << 8;
    let n = u64::from(iters);

    let Ok(ping) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(pong) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };

    let Ok(child) = spawn::new_child(ctx)
    else
    {
        return;
    };
    let Ok(child_ping) = cap_copy(ping, child.cs, RIGHTS_WAIT)
    else
    {
        return;
    };
    let Ok(child_pong) = cap_copy(pong, child.cs, RIGHTS_NOTIFY)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, child.cs, RIGHTS_NOTIFY)
    else
    {
        return;
    };

    let arg = u64::from(child_ping)
        | (u64::from(child_pong) << 16)
        | (u64::from(child_done) << 32)
        | (n << 48);
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_SIGNAL_STACK));

    if spawn::configure_and_start(&child, notification_pong_entry, stack_top, arg).is_err()
    {
        return;
    }

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;
    for _ in 0..n
    {
        let t0 = cycles_now();
        if notification_send(ping, 1).is_err()
        {
            break;
        }
        if notification_wait(pong).is_err()
        {
            break;
        }
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
        completed += 1;
    }
    notification_wait(done).ok();

    log_bench_header("notification_roundtrip", iters);
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }

    cap_delete(child.th).ok();
    cap_delete(ping).ok();
    cap_delete(pong).ok();
    cap_delete(done).ok();
    cap_delete(child.cs).ok();
}
