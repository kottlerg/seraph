// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/split_delete_race.rs

//! Stress: a range split racing a delete of its original.
//!
//! A sibling thread sharing this thread's `CSpace` spins on a go flag and
//! deletes the original the moment the flag is raised, while this thread
//! raises it and splits the original in the same breath. The original's
//! child list is wider than one reparent batch (`MAX_REPARENT_EDITS`), so
//! the split releases the derivation lock between batches and the delete
//! can land before the split starts (`InvalidCapability`), between two
//! batches (`InvalidState`: both children rolled back after at least one
//! released hold — the arm no deterministic input reaches), or after the
//! split consumed the original (an idempotent no-op on the freed slot, or
//! `InvalidCapability` once the slot is recycled). The split's result
//! classifies the cycle, and a failed split requires the delete to have
//! landed; every outcome must leave the forest consistent, the children
//! deletable, and the slot count at its baseline. The per-outcome counts
//! are logged, not asserted: they depend on timing.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    RIGHTS_ALL, cap_create_notification, cap_create_thread, cap_delete, cap_derive,
    notification_send, notification_wait, sched_split, thread_configure, thread_exit,
    thread_set_affinity, thread_start,
};
use syscall_abi::{CAP_INFO_CSPACE_USED, SyscallError, SystemInfoType};

use crate::spawn::{ArgBlock, child_args};
use crate::{ChildStack, TestContext, TestResult, spawn};

const CYCLES: u32 = 40;
/// Wider than two reparent batches, so the split releases the lock twice.
const CHILDREN: usize = 600;
/// Split point inside the derived cap's band (as `unit::thread`'s splits).
const SPLIT_AT: u8 = 21;
const BIT_DELETED: u64 = 1 << 0;
const BIT_DELETE_FAILED: u64 = 1 << 1;

static mut SIBLING_STACK: ChildStack = ChildStack::ZERO;

/// Raised by the parent immediately before its split; the sibling spins on
/// it so its delete contends with the split's first lock releases.
static GO: AtomicU32 = AtomicU32::new(0);

/// The sibling's arguments, handed to `sibling_entry` by address.
#[derive(Clone, Copy)]
struct SiblingArgs
{
    orig: u32,
    done: u32,
}

static SIBLING_ARGS: ArgBlock<SiblingArgs, 1> = ArgBlock::new(SiblingArgs { orig: 0, done: 0 });

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::split_delete_race: system_info(CpuCount) failed")?;
    let used_before = syscall::cap_info(ctx.cspace_cap, CAP_INFO_CSPACE_USED)
        .map_err(|_| "stress::split_delete_race: cap_info(used) failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::split_delete_race: create done failed")?;

    let mut split_won = 0u64;
    let mut delete_before = 0u64;
    let mut delete_mid_split = 0u64;
    for _ in 0..CYCLES
    {
        let orig = cap_derive(ctx.sched_control_cap, RIGHTS_ALL)
            .map_err(|_| "stress::split_delete_race: derive original failed")?;
        let mut children = [0u32; CHILDREN];
        for child in &mut children
        {
            *child = cap_derive(orig, RIGHTS_ALL)
                .map_err(|_| "stress::split_delete_race: derive child failed")?;
        }

        GO.store(0, Ordering::Release);
        // The sibling shares this CSpace: it deletes `orig` by this handle.
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::split_delete_race: create sibling failed")?;
        // SAFETY: one sibling per cycle, reaped below before the next publish.
        let arg = unsafe { SIBLING_ARGS.publish(0, SiblingArgs { orig, done }) };
        let stack_top = ChildStack::top(core::ptr::addr_of!(SIBLING_STACK));
        thread_configure(th, sibling_entry as *const () as u64, stack_top, arg)
            .map_err(|_| "stress::split_delete_race: thread_configure failed")?;
        if cpus > 1
        {
            thread_set_affinity(th, 1)
                .map_err(|_| "stress::split_delete_race: thread_set_affinity failed")?;
        }
        thread_start(th).map_err(|_| "stress::split_delete_race: thread_start failed")?;

        GO.store(1, Ordering::Release);
        let split = sched_split(orig, SPLIT_AT);
        let bits =
            notification_wait(done).map_err(|_| "stress::split_delete_race: done wait failed")?;
        let deleted = bits & BIT_DELETED != 0;
        match split
        {
            Ok((lower, upper)) =>
            {
                split_won += 1;
                cap_delete(lower).map_err(|_| "stress::split_delete_race: delete lower failed")?;
                cap_delete(upper).map_err(|_| "stress::split_delete_race: delete upper failed")?;
            }
            Err(e) if e == SyscallError::InvalidState as i64 && deleted => delete_mid_split += 1,
            Err(e) if e == SyscallError::InvalidCapability as i64 && deleted => delete_before += 1,
            Err(_) => return Err("stress::split_delete_race: split failed without a delete"),
        }

        // Whoever consumed the original, its children now hang off the
        // sched cap and must still be deletable one by one.
        for child in children
        {
            cap_delete(child).map_err(|_| "stress::split_delete_race: delete child failed")?;
        }
        spawn::wait_until_exited(th, 100_000)?;
        cap_delete(th).map_err(|_| "stress::split_delete_race: reap sibling failed")?;
    }

    // Cleanup of a notification this test created; the verdict below rests
    // on the slot count, which a failed delete would fail on its own.
    cap_delete(done).ok();
    let used_after = syscall::cap_info(ctx.cspace_cap, CAP_INFO_CSPACE_USED)
        .map_err(|_| "stress::split_delete_race: cap_info(used after) failed")?;
    crate::log_u64("stress::split_delete_race: split_won=", split_won);
    crate::log_u64(
        "stress::split_delete_race: delete_before_split=",
        delete_before,
    );
    crate::log_u64(
        "stress::split_delete_race: delete_mid_split=",
        delete_mid_split,
    );
    if used_after != used_before
    {
        return Err("stress::split_delete_race: slot count did not return to baseline");
    }
    Ok(())
}

/// Sibling: spin until `GO`, delete the original once, report the outcome.
fn sibling_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this sibling.
    let SiblingArgs { orig, done } = unsafe { child_args(arg) };
    while GO.load(Ordering::Acquire) == 0
    {
        core::hint::spin_loop();
    }
    let bit = if cap_delete(orig).is_ok()
    {
        BIT_DELETED
    }
    else
    {
        BIT_DELETE_FAILED
    };
    // A failed report (a kernel defect on a valid cap) leaves the parent
    // waiting; the harness watchdog reports that hang, and this thread has
    // no other channel.
    notification_send(done, bit).ok();
    thread_exit()
}
