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

use syscall::{
    RIGHTS_ALL, RIGHTS_EQ_RECV, cap_bind_sole_reference, cap_copy, cap_create_cspace,
    cap_create_notification, cap_delete, cap_derive, cap_info, cap_move,
    event_queue_create_observed, event_recv_entry, system_info, thread_exit,
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
        let entry = event_recv_entry(eq, TRY_ONCE)
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

/// Bind, then delete the other copy: one post, with the correlator, at the
/// delete's return, and none while two references remain. Fails if the fall
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
            TRY_ONCE,
            "other_copy: no post at the delete's return",
        )?;
        cap_delete(object).map_err(|_| "other_copy: delete of the last copy failed")?;
        expect_none(eq, "other_copy: a second post")
    })
}

/// Bind on the only reference: the bind's own pin release is the fall to one,
/// so the post comes at the bind's return. Fails if the pin release is not
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
            TRY_ONCE,
            "sole_bind: no post at the bind's return",
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
        expect_post(
            eq,
            correlator,
            crate::scaled_bound(POST_WAIT_MS),
            "racing_delete: no post",
        )?;
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
        let first = event_recv_entry(eq, TRY_ONCE).map_err(|_| "two_bindings: no first post")?;
        let second = event_recv_entry(eq, TRY_ONCE).map_err(|_| "two_bindings: no second post")?;
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
            TRY_ONCE,
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
