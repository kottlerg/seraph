// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/sole_reference.rs

//! Tier 1 tests for `SYS_CAP_BIND_SOLE_REFERENCE`.
//!
//! Each case binds an observer to a Notification and checks the posts the
//! binding makes: one `(0, correlator)` entry, the first time the kernel finds
//! the object at one reference after the bind, or at the object's death. A
//! post is made by the drain at the end of the syscall whose release left the
//! object there, or of a later one; a case that releases through a teardown
//! another CPU may finish waits for the post, bounded. Every case ends by
//! checking that its queue's observer pool has every node back.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use syscall::{
    RIGHTS_ALL, RIGHTS_EQ_RECV, cap_bind_sole_reference, cap_copy, cap_create_cspace,
    cap_create_notification, cap_delete, cap_derive, cap_info, cap_move,
    event_queue_create_observed, event_recv_entry, system_info, thread_exit, thread_set_affinity,
    thread_sleep,
};
use syscall_abi::{CAP_INFO_MEMORY_AVAILABLE, SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

/// Correlator of the first binding of a case; a case's other bindings set a
/// count in its low byte. Bits in both halves, so a truncated tag word fails the compare.
const CORRELATOR: u64 = 0x5013_0000_0000_0100;

/// Bound, in milliseconds, on a wait for a post, stretched by
/// [`crate::scaled_bound`].
const POST_WAIT_MS: u64 = 2000;

/// `event_recv_entry`'s non-blocking poll.
const TRY_ONCE: u64 = u64::MAX;

/// The wait for a post that is due: the drain that makes it may run on
/// another CPU, after the call whose release made it has returned.
fn post_wait() -> u64
{
    crate::scaled_bound(POST_WAIT_MS)
}

// Child stack for the racing-delete case.
static mut RACE_STACK: ChildStack = ChildStack::ZERO;

/// The next entry of `eq` within `timeout_ms` (`TRY_ONCE` polls), checked to
/// be a sole-reference post carrying `correlator`.
fn expect_post(eq: u64, correlator: u64, timeout_ms: u64, what: &'static str) -> TestResult
{
    let entry = event_recv_entry(eq, timeout_ms).map_err(|_| what)?;
    if entry.payload != 0 || entry.tag != correlator
    {
        return Err(what);
    }
    Ok(())
}

/// `eq` holds no entry.
fn expect_none(eq: u64, what: &'static str) -> TestResult
{
    if event_recv_entry(eq, TRY_ONCE).err() == Some(SyscallError::WouldBlock as i64)
    {
        Ok(())
    }
    else
    {
        Err(what)
    }
}

/// Every one of `eq`'s `nodes` observer nodes is free: as many bindings
/// succeed, onto an object held twice so that none posts yet, and one more
/// returns `OutOfMemory`; deleting the second hold posts each binding once.
/// `eq`'s capacity is at least `nodes`.
fn pool_restored(ctx: &TestContext, eq: u64, nodes: u64) -> TestResult
{
    let object =
        cap_create_notification(ctx.memory_base).map_err(|_| "pool_restored: create failed")?;
    let result = pool_restored_on(eq, nodes, object);
    cap_delete(object).ok();
    result
}

/// Body of [`pool_restored`] on `object`.
fn pool_restored_on(eq: u64, nodes: u64, object: u64) -> TestResult
{
    let hold = cap_derive(object, RIGHTS_ALL).map_err(|_| "pool_restored: derive failed")?;
    for i in 0..nodes
    {
        cap_bind_sole_reference(object, eq, CORRELATOR | i)
            .map_err(|_| "pool_restored: a node did not come back to the pool")?;
    }
    if cap_bind_sole_reference(object, eq, 0) != Err(SyscallError::OutOfMemory as i64)
    {
        return Err("pool_restored: a bind past the pool did not return OutOfMemory");
    }
    cap_delete(hold).map_err(|_| "pool_restored: delete failed")?;
    let mut seen = 0u64;
    for _ in 0..nodes
    {
        let entry = event_recv_entry(eq, post_wait())
            .map_err(|_| "pool_restored: a binding did not post at one reference")?;
        let i = entry.tag ^ CORRELATOR;
        if entry.payload != 0 || i >= nodes || seen & (1 << i) != 0
        {
            return Err("pool_restored: wrong or duplicate post");
        }
        seen |= 1 << i;
    }
    expect_none(eq, "pool_restored: a binding posted twice")
}

/// A queue of capacity 4 with `nodes` observer nodes, `f` run on it, and the
/// pool checked full after; the queue is deleted on every path.
fn with_queue(ctx: &TestContext, nodes: u32, f: impl FnOnce(u64) -> TestResult) -> TestResult
{
    let eq = event_queue_create_observed(ctx.memory_base, 4, nodes)
        .map_err(|_| "sole_reference: event_queue_create_observed failed")?;
    let result = f(eq).and_then(|()| pool_restored(ctx, eq, u64::from(nodes)));
    cap_delete(eq).ok();
    result
}

/// Bind, then delete the other copy: one post, with the correlator, after
/// the delete, and none while two references remain. Fails if the fall
/// to one reference is missed, posted twice, or posted early.
pub fn other_copy_deleted_posts_once(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 1, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "other_copy: create failed")?;
        let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "other_copy: derive failed")?;
        cap_bind_sole_reference(object, eq, CORRELATOR).map_err(|_| "other_copy: bind failed")?;
        expect_none(eq, "other_copy: a post at two references")?;
        cap_delete(copy).map_err(|_| "other_copy: delete failed")?;
        expect_post(
            eq,
            CORRELATOR,
            post_wait(),
            "other_copy: no post after the delete",
        )?;
        cap_delete(object).map_err(|_| "other_copy: delete of the last copy failed")?;
        expect_none(eq, "other_copy: a second post")
    })
}

/// Bind on the only reference: the bind's own pin release is the fall to one,
/// so the post follows the bind. Fails if the pin release is not
/// observed.
pub fn bind_on_sole_reference_posts_at_once(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 1, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "sole_bind: create failed")?;
        let bound = cap_bind_sole_reference(object, eq, CORRELATOR);
        let posted = expect_post(
            eq,
            CORRELATOR,
            post_wait(),
            "sole_bind: no post after the bind",
        );
        cap_delete(object).ok();
        bound.map_err(|_| "sole_bind: bind failed")?;
        posted?;
        expect_none(eq, "sole_bind: a second post")
    })
}

/// Child of [`bind_racing_delete_posts_once`]: delete the copy `handle` names
/// in its own `CSpace` and exit.
extern "C" fn delete_and_exit_entry(handle: u64) -> !
{
    cap_delete(handle).ok();
    thread_exit()
}

/// Bind while a thread on another CPU deletes the other copy: whichever comes
/// first, exactly one post. Fails if a release racing the bind is missed or
/// posted twice.
pub fn bind_racing_delete_posts_once(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "racing_delete: system_info(CpuCount) failed")?;
    let cpu = u32::from(cpus > 1);
    with_queue(ctx, 1, |eq| {
        for round in 0..8
        {
            race_once(ctx, eq, cpu, CORRELATOR | round)?;
        }
        Ok(())
    })
}

/// One round of [`bind_racing_delete_posts_once`].
fn race_once(ctx: &TestContext, eq: u64, cpu: u32, correlator: u64) -> TestResult
{
    let object =
        cap_create_notification(ctx.memory_base).map_err(|_| "racing_delete: create failed")?;
    let mut child = crate::spawn::new_child(ctx).map_err(|_| "racing_delete: new_child failed")?;
    let result = (|| {
        let copy =
            cap_copy(object, child.cs, RIGHTS_ALL).map_err(|_| "racing_delete: copy failed")?;
        // SAFETY: `RACE_STACK` is a static stack, reached only through `addr_of!`.
        let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(RACE_STACK)) };
        // SAFETY: the rounds run one at a time, each waiting for its child to
        // exit before the next starts, so no other live thread runs on
        // `RACE_STACK`.
        unsafe {
            crate::spawn::configure_and_start_pinned(
                &child,
                delete_and_exit_entry,
                stack_top,
                copy,
                cpu,
            )
        }?;
        cap_bind_sole_reference(object, eq, correlator)
            .map_err(|_| "racing_delete: bind failed")?;
        crate::spawn::wait_until_exited(child.th, crate::scaled_polls(2000))?;
        expect_post(eq, correlator, post_wait(), "racing_delete: no post")?;
        expect_none(eq, "racing_delete: a second post")
    })();
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(object).ok();
    result
}

/// Two observers on one object: each posts once at the fall to one. Fails if
/// a second binding on an observed object is lost or posted twice.
pub fn two_bindings_each_post_once(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 2, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "two_bindings: create failed")?;
        let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "two_bindings: derive failed")?;
        cap_bind_sole_reference(object, eq, CORRELATOR)
            .map_err(|_| "two_bindings: first bind failed")?;
        cap_bind_sole_reference(copy, eq, CORRELATOR | 1)
            .map_err(|_| "two_bindings: second bind failed")?;
        cap_delete(copy).map_err(|_| "two_bindings: delete failed")?;
        let first = event_recv_entry(eq, post_wait()).map_err(|_| "two_bindings: no first post")?;
        let second =
            event_recv_entry(eq, post_wait()).map_err(|_| "two_bindings: no second post")?;
        cap_delete(object).ok();
        let mut tags = [first.tag, second.tag];
        tags.sort_unstable();
        if first.payload != 0 || second.payload != 0 || tags != [CORRELATOR, CORRELATOR | 1]
        {
            return Err("two_bindings: wrong posts");
        }
        expect_none(eq, "two_bindings: a third post")
    })
}

/// Observer nodes bound to one object for [`bindings_past_the_budget_each_post_once`],
/// more than one drain pass posts (the kernel's `POST_BUDGET`, 64).
const PAST_BUDGET_NODES: u32 = 80;

/// More bindings on one object than one drain pass posts: at the fall to one,
/// every binding posts once, over several passes, and every node comes back,
/// which a second round of as many bindings shows. Fails if the nodes a pass
/// leaves on the fired list are lost, posted twice, or not returned.
pub fn bindings_past_the_budget_each_post_once(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create_observed(ctx.memory_base, PAST_BUDGET_NODES, PAST_BUDGET_NODES)
        .map_err(|_| "past_budget: event_queue_create_observed failed")?;
    let result = (|| {
        for _round in 0..2
        {
            past_budget_round(ctx, eq)?;
        }
        Ok(())
    })();
    cap_delete(eq).ok();
    result
}

/// One round of [`bindings_past_the_budget_each_post_once`].
fn past_budget_round(ctx: &TestContext, eq: u64) -> TestResult
{
    let object =
        cap_create_notification(ctx.memory_base).map_err(|_| "past_budget: create failed")?;
    let result = (|| {
        let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "past_budget: derive failed")?;
        for i in 0..u64::from(PAST_BUDGET_NODES)
        {
            cap_bind_sole_reference(object, eq, CORRELATOR | i)
                .map_err(|_| "past_budget: a bind failed (a node did not come back)")?;
        }
        cap_delete(copy).map_err(|_| "past_budget: delete failed")?;
        let mut seen = [false; PAST_BUDGET_NODES as usize];
        for _ in 0..PAST_BUDGET_NODES
        {
            let entry = event_recv_entry(eq, post_wait())
                .map_err(|_| "past_budget: a binding did not post")?;
            let slot = usize::try_from(entry.tag ^ CORRELATOR)
                .ok()
                .and_then(|i| seen.get_mut(i))
                .filter(|taken| !**taken)
                .ok_or("past_budget: wrong or duplicate post")?;
            if entry.payload != 0
            {
                return Err("past_budget: wrong payload");
            }
            *slot = true;
        }
        expect_none(eq, "past_budget: a binding posted twice")
    })();
    cap_delete(object).ok();
    result
}

/// The bindings one drain pass posts: the kernel's `POST_BUDGET`.
const FIRST_PASS_NODES: u32 = 64;

/// The bindings [`leftover_posts_reach_a_busy_cpu`] leaves past the first
/// pass.
const LEFTOVER_NODES: u32 = 16;

/// Spinner threads that keep the CPUs other than the case's busy in user mode;
/// at most three, so the case's work stops growing at four CPUs. On more
/// CPUs an idle one may post the leftovers first, which the case accepts.
const BUSY_SPINNERS: usize = 3;

/// Length, in milliseconds, of the window in which no thread of the case makes
/// a syscall: many timer ticks.
const BUSY_WINDOW_MS: u64 = 200;

/// The CPU the case pins its own thread to; the spinners take the next ones.
const BUSY_CASE_CPU: u32 = 0;

// Child stacks of the spinners.
static mut SPIN_STACKS: [ChildStack; BUSY_SPINNERS] = [ChildStack::ZERO; BUSY_SPINNERS];

/// Set to end the spinners' loops.
static SPIN_STOP: AtomicBool = AtomicBool::new(false);

/// Spinners that have started their loops.
static SPIN_READY: AtomicU32 = AtomicU32::new(0);

/// Spin in user mode, with no syscall, until [`SPIN_STOP`] is set, then exit.
extern "C" fn busy_spinner_entry(_arg: u64) -> !
{
    SPIN_READY.fetch_add(1, Ordering::AcqRel);
    while !SPIN_STOP.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    thread_exit()
}

/// Cycle-counter ticks per millisecond on this CPU, measured over a 20 ms
/// sleep against the kernel's elapsed-microseconds clock.
fn cycles_per_ms() -> Result<u64, &'static str>
{
    let elapsed = || system_info(SystemInfoType::ElapsedUs as u64);
    let us0 = elapsed().map_err(|_| "busy_cpu: system_info(ElapsedUs) failed")?;
    let c0 = crate::arch::cycles_now();
    thread_sleep(20).map_err(|_| "busy_cpu: thread_sleep failed")?;
    let c1 = crate::arch::cycles_now();
    let us1 = elapsed().map_err(|_| "busy_cpu: system_info(ElapsedUs) failed")?;
    let us = us1.saturating_sub(us0).max(1);
    u128::from(c1.wrapping_sub(c0))
        .saturating_mul(1000)
        .checked_div(u128::from(us))
        .and_then(|per_ms| u64::try_from(per_ms).ok())
        .filter(|&per_ms| per_ms > 0)
        .ok_or("busy_cpu: the cycle counter did not advance")
}

/// The leftovers of a drain pass reach their queue while every CPU the case
/// occupies runs user code that makes no syscall: the kernel posts them at an
/// interrupt's return to user mode, within a tick. The case binds one pass's
/// worth of bindings to one queue and sixteen more to another, the latter
/// first so that the pass takes the former, keeps the other CPUs busy with
/// spinners, makes the fall to one, and spins with no syscall; its next syscall
/// finds a leftover already posted. Fails if the leftovers wait for a syscall
/// or an idle CPU.
pub fn leftover_posts_reach_a_busy_cpu(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "busy_cpu: system_info(CpuCount) failed")?;
    let spinners = usize::try_from(cpus.saturating_sub(1))
        .unwrap_or(BUSY_SPINNERS)
        .min(BUSY_SPINNERS);
    let first = event_queue_create_observed(ctx.memory_base, FIRST_PASS_NODES, FIRST_PASS_NODES)
        .map_err(|_| "busy_cpu: event_queue_create_observed failed")?;
    let result = event_queue_create_observed(ctx.memory_base, LEFTOVER_NODES, LEFTOVER_NODES)
        .map_err(|_| "busy_cpu: event_queue_create_observed failed")
        .and_then(|rest| {
            let result = thread_set_affinity(ctx.thread_cap, BUSY_CASE_CPU)
                .map_err(|_| "busy_cpu: pin failed")
                .and_then(|()| {
                    let result = busy_window(ctx, first, rest, spinners);
                    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
                        .map_err(|_| "busy_cpu: restore affinity failed");
                    result.and(restore)
                })
                .and_then(|()| pool_restored(ctx, first, u64::from(FIRST_PASS_NODES)))
                .and_then(|()| pool_restored(ctx, rest, u64::from(LEFTOVER_NODES)));
            cap_delete(rest).ok();
            result
        });
    cap_delete(first).ok();
    result
}

/// Body of [`leftover_posts_reach_a_busy_cpu`], with its thread pinned to
/// [`BUSY_CASE_CPU`].
fn busy_window(ctx: &TestContext, first: u64, rest: u64, spinners: usize) -> TestResult
{
    let object = cap_create_notification(ctx.memory_base).map_err(|_| "busy_cpu: create failed")?;
    let mut children: [Option<crate::spawn::SpawnedChild>; BUSY_SPINNERS] =
        core::array::from_fn(|_| None);
    SPIN_STOP.store(false, Ordering::Release);
    SPIN_READY.store(0, Ordering::Release);
    let result = (|| {
        let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "busy_cpu: derive failed")?;
        // The pass takes an object's newest bindings first and its first
        // binding last: the leftover queue's go first.
        for i in 0..u64::from(LEFTOVER_NODES)
        {
            cap_bind_sole_reference(object, rest, CORRELATOR | 0x80 | i)
                .map_err(|_| "busy_cpu: a leftover bind failed")?;
        }
        for i in 0..u64::from(FIRST_PASS_NODES)
        {
            cap_bind_sole_reference(object, first, CORRELATOR | i)
                .map_err(|_| "busy_cpu: a first-pass bind failed")?;
        }
        let per_ms = cycles_per_ms()?;
        start_spinners(ctx, &mut children, spinners)?;
        let ready_wait = per_ms.saturating_mul(post_wait());
        let start = crate::arch::cycles_now();
        while SPIN_READY.load(Ordering::Acquire) < u32::try_from(spinners).unwrap_or(u32::MAX)
        {
            if crate::arch::cycles_now().wrapping_sub(start) > ready_wait
            {
                return Err("busy_cpu: the spinners did not start");
            }
            core::hint::spin_loop();
        }
        // The fall to one; this delete's own drain posts the first pass.
        cap_delete(copy).map_err(|_| "busy_cpu: delete failed")?;
        let window = per_ms.saturating_mul(BUSY_WINDOW_MS);
        let start = crate::arch::cycles_now();
        while crate::arch::cycles_now().wrapping_sub(start) < window
        {
            core::hint::spin_loop();
        }
        // The first syscall since the window: a drain at its return would
        // come too late for this receive.
        let leftover = event_recv_entry(rest, TRY_ONCE);
        SPIN_STOP.store(true, Ordering::Release);
        let leftover = leftover.map_err(|_| "busy_cpu: no leftover posted within the window")?;
        let mut seen_rest = [false; LEFTOVER_NODES as usize];
        mark_post(
            &mut seen_rest,
            leftover.tag ^ (CORRELATOR | 0x80),
            leftover.payload,
        )?;
        for _ in 1..LEFTOVER_NODES
        {
            let entry = event_recv_entry(rest, post_wait())
                .map_err(|_| "busy_cpu: a leftover binding did not post")?;
            mark_post(
                &mut seen_rest,
                entry.tag ^ (CORRELATOR | 0x80),
                entry.payload,
            )?;
        }
        let mut seen_first = [false; FIRST_PASS_NODES as usize];
        for _ in 0..FIRST_PASS_NODES
        {
            let entry = event_recv_entry(first, post_wait())
                .map_err(|_| "busy_cpu: a first-pass binding did not post")?;
            mark_post(&mut seen_first, entry.tag ^ CORRELATOR, entry.payload)?;
        }
        expect_none(rest, "busy_cpu: a leftover binding posted twice")?;
        expect_none(first, "busy_cpu: a first-pass binding posted twice")
    })();
    SPIN_STOP.store(true, Ordering::Release);
    for child in children.iter_mut().flatten()
    {
        crate::spawn::wait_until_exited(child.th, crate::scaled_polls(2000)).ok();
        child.delete_thread().ok();
        child.delete_cspace().ok();
    }
    cap_delete(object).ok();
    result
}

/// Start `spinners` spinner threads, each pinned to its own CPU after
/// [`BUSY_CASE_CPU`], into `children`.
fn start_spinners(
    ctx: &TestContext,
    children: &mut [Option<crate::spawn::SpawnedChild>; BUSY_SPINNERS],
    spinners: usize,
) -> TestResult
{
    for (index, slot) in children.iter_mut().enumerate().take(spinners)
    {
        let child = crate::spawn::new_child(ctx).map_err(|_| "busy_cpu: new_child failed")?;
        let cpu = u32::try_from(index)
            .ok()
            .and_then(|i| i.checked_add(1))
            .and_then(|i| i.checked_add(BUSY_CASE_CPU))
            .ok_or("busy_cpu: spinner CPU out of range")?;
        // SAFETY: SPIN_STACKS is a static array reached only through
        // addr_of!; each spinner runs on its own element, and the case waits
        // for every spinner to exit before the array is used again.
        let stack_top = unsafe { ChildStack::top_at(core::ptr::addr_of!(SPIN_STACKS), index) }?;
        // SAFETY: stack_top's stack is this spinner's alone (above).
        let started = unsafe {
            crate::spawn::configure_and_start_pinned(&child, busy_spinner_entry, stack_top, 0, cpu)
        };
        *slot = Some(child);
        started?;
    }
    Ok(())
}

/// Mark the post at `index` in `seen`, checking its payload and that it
/// is the first.
fn mark_post(seen: &mut [bool], index: u64, payload: u64) -> TestResult
{
    let slot = usize::try_from(index)
        .ok()
        .and_then(|i| seen.get_mut(i))
        .filter(|taken| !**taken)
        .ok_or("busy_cpu: wrong or duplicate post")?;
    if payload != 0
    {
        return Err("busy_cpu: wrong payload");
    }
    *slot = true;
    Ok(())
}

/// A copy moved into another `CSpace`, the move an IPC transfer makes at
/// rendezvous: no post while the copy is in flight, since the destination's
/// reference is taken before the source's goes; one post once the moved copy
/// goes with its `CSpace`. Fails if a move dips the count to one.
pub fn moved_copy_does_not_post(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 1, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "moved_copy: create failed")?;
        let result = moved_copy_on(ctx, eq, object);
        cap_delete(object).ok();
        result
    })
}

/// Body of [`moved_copy_does_not_post`] on `object`.
fn moved_copy_on(ctx: &TestContext, eq: u64, object: u64) -> TestResult
{
    let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "moved_copy: derive failed")?;
    let cs =
        cap_create_cspace(ctx.memory_base, 0, 4).map_err(|_| "moved_copy: create_cspace failed")?;
    cap_bind_sole_reference(object, eq, CORRELATOR).map_err(|_| "moved_copy: bind failed")?;
    let moved = cap_move(copy, cs, 0).map(|_| ());
    let quiet = expect_none(eq, "moved_copy: a post during the move");
    cap_delete(cs).map_err(|_| "moved_copy: delete_cspace failed")?;
    moved.map_err(|_| "moved_copy: move failed")?;
    quiet?;
    expect_post(
        eq,
        CORRELATOR,
        crate::scaled_bound(POST_WAIT_MS),
        "moved_copy: no post once the CSpace holding the copy went",
    )
}

/// Every capability to the queue deleted before the post: the binding keeps
/// the queue alive, and the queue's memory comes back only once the binding
/// has posted. Fails if the binding holds no reference on its queue (a post
/// to freed memory) or leaks it (the queue is never freed).
pub fn queue_outlives_its_capabilities(ctx: &TestContext) -> TestResult
{
    let available = || cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE);
    let baseline = available().map_err(|_| "queue_outlives: cap_info failed")?;
    let object =
        cap_create_notification(ctx.memory_base).map_err(|_| "queue_outlives: create failed")?;
    let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "queue_outlives: derive failed")?;
    let eq = event_queue_create_observed(ctx.memory_base, 4, 1)
        .map_err(|_| "queue_outlives: event_queue_create_observed failed")?;
    let bound = cap_bind_sole_reference(object, eq, CORRELATOR);
    cap_delete(eq).ok();
    let with_queue = available().map_err(|_| "queue_outlives: cap_info failed")?;
    cap_delete(copy).ok();
    cap_delete(object).ok();
    bound.map_err(|_| "queue_outlives: bind failed")?;
    let queue_bytes = syscall_abi::event_queue_retype_bytes(4, 1);
    if baseline.saturating_sub(with_queue) < queue_bytes
    {
        return Err("queue_outlives: the queue was freed with its last capability");
    }
    crate::spawn::wait_memory_baseline(ctx.memory_base, baseline, crate::scaled_polls(2000))
        .map_err(|_| "queue_outlives: the queue was not freed after the post")
}

/// An object that dies with no rest at one reference, its last two going in
/// one `CSpace` teardown: one post, and the nodes return to the pool. Fails
/// if a death skips the binding or leaves its node and queue reference held.
pub fn death_posts_once(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 1, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "death: create failed")?;
        let cs =
            cap_create_cspace(ctx.memory_base, 0, 4).map_err(|_| "death: create_cspace failed");
        let cs = match cs
        {
            Ok(cs) => cs,
            Err(e) =>
            {
                cap_delete(object).ok();
                return Err(e);
            }
        };
        let copies =
            cap_copy(object, cs, RIGHTS_ALL).and_then(|_| cap_copy(object, cs, RIGHTS_ALL));
        let bound = cap_bind_sole_reference(object, eq, CORRELATOR);
        cap_delete(object).ok();
        let quiet = expect_none(eq, "death: a post at two references");
        cap_delete(cs).map_err(|_| "death: delete_cspace failed")?;
        copies.map_err(|_| "death: copy failed")?;
        bound.map_err(|_| "death: bind failed")?;
        quiet?;
        expect_post(
            eq,
            CORRELATOR,
            crate::scaled_bound(POST_WAIT_MS),
            "death: no post at the object's death",
        )?;
        expect_none(eq, "death: a second post")
    })
}

/// A bind with no free node returns `OutOfMemory` and changes nothing.
pub fn exhausted_pool_out_of_memory(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 1, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "exhausted: create failed")?;
        let copy = cap_derive(object, RIGHTS_ALL).map_err(|_| "exhausted: derive failed")?;
        let first = cap_bind_sole_reference(object, eq, CORRELATOR);
        let second = cap_bind_sole_reference(object, eq, CORRELATOR | 1);
        cap_delete(copy).ok();
        let posted = expect_post(
            eq,
            CORRELATOR,
            post_wait(),
            "exhausted: the bound node did not post",
        );
        cap_delete(object).ok();
        first.map_err(|_| "exhausted: bind failed")?;
        if second != Err(SyscallError::OutOfMemory as i64)
        {
            return Err("exhausted: a bind past the pool did not return OutOfMemory");
        }
        posted?;
        expect_none(eq, "exhausted: the refused bind posted")
    })
}

/// A bind's argument errors: a null observed handle and a queue handle that
/// names no queue return `InvalidCapability`, and a queue capability without
/// `POST` returns `InsufficientRights`, each taking no node.
pub fn bind_argument_errors(ctx: &TestContext) -> TestResult
{
    with_queue(ctx, 1, |eq| {
        let object =
            cap_create_notification(ctx.memory_base).map_err(|_| "bind_errors: create failed")?;
        let recv_only = cap_derive(eq, RIGHTS_EQ_RECV);
        let null = cap_bind_sole_reference(0, eq, 0);
        let not_queue = cap_bind_sole_reference(object, object, 0);
        let no_post = recv_only.map(|q| {
            let r = cap_bind_sole_reference(object, q, 0);
            cap_delete(q).ok();
            r
        });
        cap_delete(object).ok();
        if null != Err(SyscallError::InvalidCapability as i64)
            || not_queue != Err(SyscallError::InvalidCapability as i64)
        {
            return Err("bind_errors: a bad handle did not return InvalidCapability");
        }
        if no_post != Ok(Err(SyscallError::InsufficientRights as i64))
        {
            return Err("bind_errors: a queue without POST did not return InsufficientRights");
        }
        expect_none(eq, "bind_errors: a refused bind posted")
    })
}
