// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/ioport_withdraw_windows.rs

//! Tier 1 (x86-64): the withdrawal of a freed `IoPort` object's bindings takes
//! interrupts between the registry walk's batches.
//!
//! `ioport_bindings::withdraw_everywhere` walks every thread (its registry lock
//! held for one batch at a time, core/kernel/docs/scheduling-internals.md
//! § Lock Hierarchy, rules 3 and 5) when the object is freed. The case binds
//! [`BOUND`] never-started threads to an object of its own, a derivation of the
//! wide `IoPort` cap (a copy or derivation references an object of its own,
//! docs/capability-model.md § `IoPort`), and the worker deletes the one cap to
//! it. The walk changes nothing a guest can read, so the call is judged by its
//! first half.

use syscall::{cap_create_cspace, cap_create_thread, cap_derive, ioport_bind};
use syscall_abi::{IOPORT_BINDING_TABLE_PAGES, RIGHTS_ALL};

use crate::latency::{self, Call};
use crate::unit::locked_windows::{BOUND, ThreadSet};
use crate::unit::teardown_windows::{Owned, run};
use crate::{TestContext, TestResult};

/// `withdraw_everywhere` walks the registry past one batch of the threads bound
/// to the freed `IoPort` object.
pub fn withdraw_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    let Some(wide) = super::io_port_cap()
    else
    {
        crate::log("ktest: locked_windows call=ioport_withdraw SKIP (no IoPort cap)");
        return Ok(());
    };
    // One shared CSpace funds every thread's binding table: a slot page and
    // the tables' pages.
    let pages = u64::try_from(BOUND)
        .ok()
        .and_then(|bound| bound.checked_mul(IOPORT_BINDING_TABLE_PAGES))
        .and_then(|tables| tables.checked_add(1))
        .ok_or("locked_windows::ioport_withdraw: pool size out of range")?;
    run("ktest: locked_windows call=ioport_withdraw", || {
        let funder = Owned(
            cap_create_cspace(ctx.memory_base, 0, pages)
                .map_err(|_| "locked_windows::ioport_withdraw: create the funding CSpace failed")?,
        );
        let mut object = Owned(
            cap_derive(wide, RIGHTS_ALL)
                .map_err(|_| "locked_windows::ioport_withdraw: derive the object failed")?,
        );
        let mut bound = ThreadSet::new();
        for _ in 0..BOUND
        {
            let thread = cap_create_thread(ctx.memory_base, ctx.aspace_cap, funder.0, 0, 0)
                .map_err(|_| "locked_windows::ioport_withdraw: create a thread failed")?;
            bound.push(thread)?;
            ioport_bind(thread, object.0)
                .map_err(|_| "locked_windows::ioport_withdraw: bind a thread failed")?;
        }
        let m = latency::measure_call(ctx, Call::Delete(object.0))?.judged_by_first_half();
        if latency::worker_results().map(|r| r.0) == Some(0)
        {
            object.take();
        }
        if m.result == u64::MAX
        {
            return Err("locked_windows::ioport_withdraw: the worker's delete failed");
        }
        Ok(m)
    })
}
