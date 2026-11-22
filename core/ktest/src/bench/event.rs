// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/event.rs

//! Event-queue post/recv benchmark.

use syscall::{cap_delete, event_post, event_queue_create, event_recv};

use super::Harness;

pub(super) fn bench_event_post_recv(ctx: &crate::TestContext, h: &mut Harness)
{
    let iters = h.iters();

    let Ok(eq) = event_queue_create(ctx.memory_base, 4)
    else
    {
        return;
    };

    let (mut samples, counters) = h.recorder();

    for i in 0..u64::from(iters)
    {
        let t0 = counters.read();
        if event_post(eq, i).is_err()
        {
            break;
        }
        if event_recv(eq).is_err()
        {
            break;
        }
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }

    let summary = samples.summary();
    cap_delete(eq).ok();

    h.report("event_post_recv", &[], summary, &[]);
}
