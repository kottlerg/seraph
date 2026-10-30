// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/fault_bind_race.rs

//! Stress: fault-handler bind, rebind, and unbind racing fault delivery on
//! another CPU.
//!
//! ## The hazard
//!
//! `ipc::fault::fault_dispatch` used to reload the faulting thread's
//! `fault_handler` and `fault_badge` lock-free, take no reference on the
//! endpoint, and dereference it. An unbind between the arch handler's
//! `has_handler` check and that reload made the reload null (a kernel null
//! read), a rebind whose release dropped the old endpoint's last reference
//! freed it under the delivery (a use-after-free), and a fault delivered
//! between a binder's badge store and its handler swap carried the new badge to
//! the old endpoint. The binding is now published as one unit under the
//! target's `sched_lock` and the dispatcher reads it once under the same lock
//! and pins the endpoint for the delivery (docs/fault-handling.md
//! § Fault-Handler Binding).
//!
//! ## How this exercises it
//!
//! Two handler threads, on CPU 2, each receive on their own endpoint (E1, E2)
//! and reply `RESUME` to every fault, checking that each fault message carries
//! the badge of the cap bound to their endpoint. Each round, a faulter on CPU 1
//! stores to an unmapped page in a loop, so every `RESUME` re-executes the
//! store and faults again. The controller, pinned to CPU 0, binds the
//! faulter to E1, rebinds it between E1 and E2 [`REBINDS`] times at varying
//! intervals, binds it to a fresh endpoint E3 whose caps it then deletes (so
//! the binding holds E3's last reference), rebinds it to E1 (dropping that
//! reference while a fault may be delivering on E3), and unbinds it. The
//! faulter dies in each round: killed by E3's teardown when a fault was queued
//! there, or, after the unbind, by its next fault finding no handler, or by
//! one whose delivery found the binding cleared. Required: every round's
//! faulter dies with a fault exit reason, no handler ever receives a fault
//! carrying another endpoint's badge, both handlers served faults (the race
//! armed), and the kernel survives.
//!
//! Needs **≥ 3 CPUs**.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::{
    RIGHTS_ALL, cap_create_endpoint, cap_create_thread, cap_delete, cap_derive_badge, raw_ipc_call,
    raw_ipc_recv, raw_ipc_reply, system_info, thread_configure, thread_exit, thread_set_affinity,
    thread_set_fault_handler, thread_start,
};
use syscall_abi::{
    EXIT_FAULT_BASE, FAULT_CLASS_ALL, FAULT_LABEL, FAULT_REPLY_RESUME, SyscallError, SystemInfoType,
};

use crate::spawn::{ArgBlock, child_args};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Rounds at up to [`crate::UNSCALED_CPUS`] CPUs.
const CYCLES: u32 = 100;
/// Fewest rounds at any width ([`super::scaled_attempts`]).
const MIN_CYCLES: u32 = 24;
/// E1/E2 rebinds per round.
const REBINDS: u32 = 64;
/// Fewest CPUs: controller, faulter, and handlers each on their own.
const MIN_CPUS: u64 = 3;
const CONTROLLER_CPU: u32 = 0;
const FAULTER_CPU: u32 = 1;
const HANDLER_CPU: u32 = 2;

/// Badges of the caps bound to E1, E2, and the transient E3.
const BADGES: [u64; 3] = [0xFB_0001, 0xFB_0002, 0xFB_0003];
/// Label the controller calls a handler with to end it.
const QUIT_LABEL: u64 = 0xFB_0099;

/// Unmapped scratch VA (crate docs § Scratch VAs) the faulter stores to.
const RESERVED_VA: u64 = 0x3E_B000_0000;

/// Polls (1 ms each) for a round's first served fault, and for a faulter's
/// death, through [`crate::scaled_polls`].
const WAIT_POLLS: u32 = 10_000;

/// Stacks: two handlers and the faulter.
static mut HANDLER_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];
static mut FAULTER_STACK: ChildStack = ChildStack::ZERO;

/// Faults each handler served.
static SERVED: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// Fault messages a handler received carrying a badge other than its own.
static MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// A handler's arguments: the endpoint it receives on, the badge its faults
/// must carry, and its index.
#[derive(Clone, Copy)]
struct HandlerArgs
{
    ep: u32,
    badge: u64,
    index: usize,
}

static HANDLER_ARGS: ArgBlock<HandlerArgs, 2> = ArgBlock::new(HandlerArgs {
    ep: 0,
    badge: 0,
    index: 0,
});

/// The objects the test holds; [`Parts::release`] deletes what exists.
#[derive(Default)]
struct Parts
{
    eps: [Option<u32>; 2],
    badged: [Option<u32>; 2],
    handlers: [Option<u32>; 2],
    faulter: Option<u32>,
}

impl Parts
{
    fn release(&mut self)
    {
        // Ending the handlers first lets their threads exit before the
        // endpoints go; a handler left blocked is released by the delete of
        // its endpoint (its receive returns InvalidCapability or Interrupted).
        for (i, badged) in self.badged.iter().enumerate()
        {
            if let (Some(cap), Some(_)) = (badged, self.handlers[i])
            {
                raw_ipc_call(*cap, QUIT_LABEL, 0, 0, 0, 0).ok();
            }
        }
        for cap in [self.faulter.take()]
            .into_iter()
            .chain(self.handlers.iter_mut().map(Option::take))
            .chain(self.badged.iter_mut().map(Option::take))
            .chain(self.eps.iter_mut().map(Option::take))
            .flatten()
        {
            cap_delete(cap).ok();
        }
    }
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::fault_bind_race: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::fault_bind_race SKIP (need 3+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::fault_bind_race: pin controller failed")?;
    let mut parts = Parts::default();
    let result = race(
        ctx,
        &mut parts,
        super::scaled_attempts(CYCLES, MIN_CYCLES, cpus),
    );
    parts.release();
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::fault_bind_race: restore controller affinity failed");
    result?;
    restore?;
    if MISMATCHES.load(Ordering::Acquire) != 0
    {
        return Err("stress::fault_bind_race: a fault carried another binding's badge");
    }
    Ok(())
}

/// Set up the handlers, then run `cycles` rounds.
fn race(ctx: &TestContext, parts: &mut Parts, cycles: u32) -> TestResult
{
    MISMATCHES.store(0, Ordering::Release);
    for i in 0..2
    {
        SERVED[i].store(0, Ordering::Release);
        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "stress::fault_bind_race: cap_create_endpoint failed")?;
        parts.eps[i] = Some(ep);
        let badged = cap_derive_badge(ep, RIGHTS_ALL, BADGES[i])
            .map_err(|_| "stress::fault_bind_race: cap_derive_badge failed")?;
        parts.badged[i] = Some(badged);
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::fault_bind_race: create handler failed")?;
        parts.handlers[i] = Some(th);
        // SAFETY: one publish per handler index, before that handler starts.
        let arg = unsafe {
            HANDLER_ARGS.publish(
                i,
                HandlerArgs {
                    ep,
                    badge: BADGES[i],
                    index: i,
                },
            )
        };
        // SAFETY: `HANDLER_STACKS[i]` is this handler's own stack; the
        // address is taken without forming a reference.
        let top = ChildStack::top(unsafe { core::ptr::addr_of!(HANDLER_STACKS[i]) });
        start_pinned(th, handler_entry, top, arg, HANDLER_CPU)?;
    }
    let badged = [
        parts.badged[0].ok_or("stress::fault_bind_race: no E1 cap")?,
        parts.badged[1].ok_or("stress::fault_bind_race: no E2 cap")?,
    ];
    for _ in 0..cycles
    {
        round(ctx, parts, badged)?;
    }
    crate::log_u64(
        "stress::fault_bind_race: e1_faults=",
        SERVED[0].load(Ordering::Acquire),
    );
    crate::log_u64(
        "stress::fault_bind_race: e2_faults=",
        SERVED[1].load(Ordering::Acquire),
    );
    if SERVED.iter().any(|s| s.load(Ordering::Acquire) == 0)
    {
        return Err("stress::fault_bind_race: a handler served no fault (race never armed)");
    }
    Ok(())
}

/// One round: start a faulter bound to E1, race rebinds, a last-reference
/// rebind, and an unbind against its deliveries, then reap it.
fn round(ctx: &TestContext, parts: &mut Parts, badged: [u32; 2]) -> TestResult
{
    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
        .map_err(|_| "stress::fault_bind_race: create faulter failed")?;
    parts.faulter = Some(th);
    thread_set_fault_handler(th, badged[0], FAULT_CLASS_ALL)
        .map_err(|_| "stress::fault_bind_race: initial bind failed")?;
    let served_before = SERVED[0].load(Ordering::Acquire);
    let top = ChildStack::top(core::ptr::addr_of!(FAULTER_STACK));
    start_pinned(th, faulter_entry, top, 0, FAULTER_CPU)?;

    // Wait for the first delivery so the races below meet a faulting thread.
    let mut polls = 0;
    while SERVED[0].load(Ordering::Acquire) == served_before
    {
        polls += 1;
        if polls > crate::scaled_polls(WAIT_POLLS)
        {
            return Err("stress::fault_bind_race: faulter's first fault never served");
        }
        syscall::thread_sleep(1).ok();
    }

    for n in 0..REBINDS
    {
        let target = badged[(n & 1) as usize ^ 1];
        // A refusal means the faulter already died, which no step before
        // the unbind below causes; report it.
        thread_set_fault_handler(th, target, FAULT_CLASS_ALL)
            .map_err(|_| "stress::fault_bind_race: rebind failed")?;
        for _ in 0..(n.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
    }

    // Bind a transient E3 and delete its caps, so the binding holds its last
    // reference; the rebind to E1 then drops it, while a fault may be queued
    // on E3 (no receiver) or delivering there.
    let e3 = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "stress::fault_bind_race: create E3 failed")?;
    let e3_badged = cap_derive_badge(e3, RIGHTS_ALL, BADGES[2]);
    let bound =
        e3_badged.and_then(|cap| thread_set_fault_handler(th, cap, FAULT_CLASS_ALL).map(|()| cap));
    cap_delete(e3).ok();
    if let Ok(cap) = e3_badged
    {
        cap_delete(cap).ok();
    }
    bound.map_err(|_| "stress::fault_bind_race: bind E3 failed")?;
    for _ in 0..4096
    {
        core::hint::spin_loop();
    }
    // The faulter may already be dead (killed by E3's teardown, which this
    // rebind or the faulter's own pin release runs); a refusal is then
    // expected.
    let _ = thread_set_fault_handler(th, badged[0], FAULT_CLASS_ALL);
    let _ = thread_set_fault_handler(th, 0, FAULT_CLASS_ALL);

    let reason = spawn::wait_until_exited(th, crate::scaled_polls(WAIT_POLLS))?;
    if reason < EXIT_FAULT_BASE
    {
        return Err("stress::fault_bind_race: faulter died without a fault exit reason");
    }
    if let Some(th) = parts.faulter.take()
    {
        cap_delete(th).map_err(|_| "stress::fault_bind_race: reap faulter failed")?;
    }
    Ok(())
}

/// Configure `th` to enter `entry(arg)` on `top`, pin it to `cpu`, start it.
fn start_pinned(th: u32, entry: extern "C" fn(u64) -> !, top: u64, arg: u64, cpu: u32)
-> TestResult
{
    // SAFETY: `entry` is an `extern "C" fn(u64) -> !` and `top` tops a stack
    // dedicated to this thread for its lifetime (the callers' statics, one
    // per thread, reused only after the thread is reaped).
    unsafe { thread_configure(th, entry as *const () as u64, top, arg) }
        .map_err(|_| "stress::fault_bind_race: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::fault_bind_race: set affinity failed")?;
    thread_start(th).map_err(|_| "stress::fault_bind_race: thread_start failed")
}

/// Faulter: store to the unmapped page forever. Every handler replies
/// `RESUME` without mapping it, so the store faults again; the thread ends
/// only when a fault is killed.
extern "C" fn faulter_entry(_arg: u64) -> !
{
    let page = RESERVED_VA as *mut u64;
    let mut n = 0u64;
    loop
    {
        n = n.wrapping_add(1);
        // SAFETY: deliberately faulting: `RESERVED_VA` is an unmapped scratch
        // VA (crate docs § Scratch VAs) that nothing in this test maps, so
        // the store never completes and touches no Rust object.
        unsafe { page.write_volatile(n) };
    }
}

/// Handler: receive on the endpoint and reply `RESUME` to each fault,
/// counting it and checking its badge; end on the quit call or the
/// endpoint's loss. No IPC buffer is registered: the badge and label arrive
/// in registers, and the replies carry no data words.
extern "C" fn handler_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `race` published for this handler.
    let args: HandlerArgs = unsafe { child_args(arg) };
    loop
    {
        match raw_ipc_recv(args.ep)
        {
            Ok((label, badge, _)) if label == FAULT_LABEL =>
            {
                if badge != args.badge
                {
                    MISMATCHES.fetch_add(1, Ordering::AcqRel);
                }
                SERVED[args.index].fetch_add(1, Ordering::AcqRel);
                // A reply that fails found the fault cancelled (its faulter
                // killed), which this test causes by design.
                raw_ipc_reply(FAULT_REPLY_RESUME, 0, 0, 0, 0).ok();
            }
            Ok((label, _, _)) =>
            {
                raw_ipc_reply(label, 0, 0, 0, 0).ok();
                if label == QUIT_LABEL
                {
                    break;
                }
            }
            Err(e) if e == SyscallError::InvalidCapability as i64 => break,
            Err(_) =>
            {}
        }
    }
    thread_exit()
}
