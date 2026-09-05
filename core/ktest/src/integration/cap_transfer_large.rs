// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/cap_transfer_large.rs

//! Integration: IPC transfer of a capability whose child list exceeds one
//! reparent batch (`MAX_REPARENT_EDITS` in the kernel's capability-internals
//! design doc), so the kernel finishes the move in further batches after the
//! message has committed, and the moved cap keeps its derivation position
//! across the `CSpace` boundary.
//!
//! Two rounds, one child thread each in its own `CSpace`. In the first the
//! server is already blocked in recv when the child calls (the call-direction
//! transfer); in the second the child calls first and the server receives a
//! queued sender (the receive-direction transfer, whose sender is parked
//! while its `CSpace` is held across the batches). The child:
//!   1. Derives `CHILDREN` caps from its notification cap, one of them with
//!      a grandchild, then calls the endpoint passing the parent cap.
//!   2. After the reply, deletes the child that has the grandchild: the
//!      grandchild must re-link under the moved cap in the server's `CSpace`.
//!   3. Signals the server, waits for the server's revoke, then reports
//!      whether every probe and the grandchild became unusable.
//!
//! The server receives the call, replies, waits for the child's signal,
//! revokes the received cap, releases the child, and collects its verdict.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_notification, cap_create_thread,
    cap_delete, cap_derive, cap_revoke, notification_send, notification_wait, thread_configure,
    thread_exit, thread_sleep, thread_start,
};
use syscall_abi::{RIGHTS_EP_SEND_GRANT, RIGHTS_NTF_NOTIFY, RIGHTS_NTF_WAIT};

use crate::spawn::{ArgBlock, child_args};
use crate::{ChildStack, TestContext, TestResult};

/// More children than one reparent batch.
const CHILDREN: usize = 300;
/// Slot pages for the child's `CSpace`: its four caps, the children, and
/// the grandchild.
const CHILD_CSPACE_PAGES: u64 = 8;

/// Child → server: the probe child is deleted; revoke now.
const SIG_PROBE_DELETED: u64 = 0x1;
/// Child → server: every descendant became unusable after the revoke.
const SIG_PASS: u64 = 0xDEAD;
/// Child → server: a step failed.
const SIG_FAIL: u64 = 0xBAD;

static mut CHILD_STACKS: [ChildStack; 2] = [ChildStack::ZERO, ChildStack::ZERO];

#[derive(Clone, Copy)]
struct ChildArgs
{
    ep: u32,
    test_sig: u32,
    sync_sig: u32,
    go_sig: u32,
}

static CHILD_ARGS: ArgBlock<ChildArgs, 2> = ArgBlock::new(ChildArgs {
    ep: 0,
    test_sig: 0,
    sync_sig: 0,
    go_sig: 0,
});

/// Which side reaches the endpoint first, selecting the transfer direction.
#[derive(Clone, Copy)]
enum Order
{
    /// The server blocks in recv before the child calls: call direction.
    ServerRecvFirst,
    /// The child is queued on the endpoint before the server receives:
    /// receive direction.
    SenderQueuedFirst,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    run_round(ctx, 0, Order::ServerRecvFirst)?;
    run_round(ctx, 1, Order::SenderQueuedFirst)
}

fn run_round(ctx: &TestContext, round: usize, order: Order) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::cap_transfer_large: cap_create_endpoint failed")?;
    let test_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::cap_transfer_large: create test_sig failed")?;
    let sync_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::cap_transfer_large: create sync_sig failed")?;
    let go_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::cap_transfer_large: create go_sig failed")?;

    let cs = cap_create_cspace(ctx.memory_base, 0, CHILD_CSPACE_PAGES)
        .map_err(|_| "integration::cap_transfer_large: cap_create_cspace failed")?;
    let child_ep = cap_copy(ep, cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "integration::cap_transfer_large: cap_copy ep failed")?;
    let child_test_sig = cap_copy(test_sig, cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::cap_transfer_large: cap_copy test_sig failed")?;
    let child_sync_sig = cap_copy(sync_sig, cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::cap_transfer_large: cap_copy sync_sig failed")?;
    let child_go_sig = cap_copy(go_sig, cs, RIGHTS_NTF_WAIT)
        .map_err(|_| "integration::cap_transfer_large: cap_copy go_sig failed")?;

    // SAFETY: the child for this round has not been started yet.
    let child_arg = unsafe {
        CHILD_ARGS.publish(
            round,
            ChildArgs {
                ep: child_ep,
                test_sig: child_test_sig,
                sync_sig: child_sync_sig,
                go_sig: child_go_sig,
            },
        )
    };

    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
        .map_err(|_| "integration::cap_transfer_large: cap_create_thread failed")?;
    // SAFETY: one stack per round; the round's child is the only user.
    let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(CHILD_STACKS[round]) });
    thread_configure(th, child_entry as *const () as u64, stack_top, child_arg)
        .map_err(|_| "integration::cap_transfer_large: thread_configure failed")?;
    thread_start(th).map_err(|_| "integration::cap_transfer_large: thread_start failed")?;

    if matches!(order, Order::SenderQueuedFirst)
    {
        // Let the child derive its subtree and enter the call before the
        // server receives, so the transfer runs on the receive path.
        thread_sleep(50).map_err(|_| "integration::cap_transfer_large: thread_sleep failed")?;
    }

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::cap_transfer_large: ipc_recv failed")?;
    let caps = msg.caps();
    if caps.len() != 1
    {
        return Err("integration::cap_transfer_large: expected exactly 1 transferred cap");
    }
    let recv_sig = caps[0];
    notification_send(recv_sig, 0x1)
        .map_err(|_| "integration::cap_transfer_large: transferred cap unusable")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "integration::cap_transfer_large: ipc_reply failed")?;

    let step = notification_wait(sync_sig)
        .map_err(|_| "integration::cap_transfer_large: wait (probe deleted) failed")?;
    if step != SIG_PROBE_DELETED
    {
        return Err("integration::cap_transfer_large: child failed before the revoke");
    }
    // Clears the child's remaining children and the re-linked grandchild
    // across the CSpace boundary.
    cap_revoke(recv_sig).map_err(|_| "integration::cap_transfer_large: cap_revoke failed")?;
    notification_send(go_sig, 0x1)
        .map_err(|_| "integration::cap_transfer_large: notification_send go failed")?;

    let verdict = notification_wait(sync_sig)
        .map_err(|_| "integration::cap_transfer_large: wait (verdict) failed")?;
    if verdict != SIG_PASS
    {
        return Err("integration::cap_transfer_large: a descendant survived the revoke");
    }

    cap_delete(recv_sig).ok();
    cap_delete(th).ok();
    cap_delete(ep).ok();
    cap_delete(test_sig).ok();
    cap_delete(sync_sig).ok();
    cap_delete(go_sig).ok();
    cap_delete(cs).ok();
    Ok(())
}

/// `arg`: address of the child's [`ChildArgs`].
fn child_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run_round` published for this child.
    let ChildArgs {
        ep,
        test_sig,
        sync_sig,
        go_sig,
    } = unsafe { child_args(arg) };

    let fail = || -> ! {
        notification_send(sync_sig, SIG_FAIL).ok();
        thread_exit()
    };

    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        fail();
    }

    let mut head = 0;
    let mut mid = 0;
    let mut tail = 0;
    let mut grandchild = 0;
    for i in 0..CHILDREN
    {
        let Ok(child) = cap_derive(test_sig, RIGHTS_NTF_NOTIFY)
        else
        {
            fail();
        };
        if i == 0
        {
            head = child;
        }
        else if i == CHILDREN / 2
        {
            mid = child;
            let Ok(g) = cap_derive(child, RIGHTS_NTF_NOTIFY)
            else
            {
                fail();
            };
            grandchild = g;
        }
        else if i == CHILDREN - 1
        {
            tail = child;
        }
    }

    let msg = IpcMessage::builder(0).cap(test_sig).build();
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_call(ep, &msg, buf_addr as *mut u64) }.is_err()
    {
        fail();
    }

    // The source slot is null after the transfer; the grandchild's parent
    // is deleted so it re-links under the moved cap in the server's CSpace.
    if notification_send(test_sig, 0x1).is_ok()
        || cap_delete(mid).is_err()
        || notification_send(grandchild, 0x1).is_err()
    {
        fail();
    }
    notification_send(sync_sig, SIG_PROBE_DELETED).ok();
    if notification_wait(go_sig).is_err()
    {
        fail();
    }

    let survived = [head, tail, grandchild]
        .iter()
        .any(|cap| notification_send(*cap, 0x1).is_ok());
    notification_send(sync_sig, if survived { SIG_FAIL } else { SIG_PASS }).ok();
    thread_exit()
}
