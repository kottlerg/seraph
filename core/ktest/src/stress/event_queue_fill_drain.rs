// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: event queue fill/drain cycles.
//!
//! Fills a capacity-8 event queue to capacity, verifies overflow error,
//! drains in FIFO order, then repeats. Exercises ring buffer wrap-around.

use syscall::{cap_delete, event_post, event_queue_create, event_recv};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

const CAPACITY: u32 = 8;
const CYCLES: usize = 200;

pub fn run(_ctx: &TestContext) -> TestResult
{
    let eq =
        event_queue_create(CAPACITY).map_err(|_| "event_fill_drain: event_queue_create failed")?;

    for cycle in 0..CYCLES
    {
        let base = (cycle as u64) * 100;

        // Fill to capacity.
        for i in 0..CAPACITY
        {
            event_post(eq, base + u64::from(i))
                .map_err(|_| "event_fill_drain: event_post during fill failed")?;
        }

        // One more must fail with QueueFull.
        let overflow = event_post(eq, 0xDEAD);
        if overflow != Err(SyscallError::QueueFull as i64)
        {
            return Err("event_fill_drain: post to full queue did not return QueueFull");
        }

        // Drain and verify FIFO order.
        for i in 0..CAPACITY
        {
            let val =
                event_recv(eq).map_err(|_| "event_fill_drain: event_recv during drain failed")?;
            let expected = base + u64::from(i);
            if val != expected
            {
                return Err("event_fill_drain: FIFO order violation");
            }
        }
    }

    cap_delete(eq).map_err(|_| "event_fill_drain: cap_delete failed")?;
    Ok(())
}
