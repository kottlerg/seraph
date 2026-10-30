// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/cap_move_into_fresh_cspace_then_ipc.rs

//! Integration: `cap_move` an endpoint into a fresh `CSpace`, then IPC across it.
//!
//! Validates that `cap_move` correctly relocates an IPC-bearing cap into a
//! foreign cspace while preserving IPC routing. The source slot in the
//! parent's cspace becomes null after the move; the child uses its local
//! slot index in the moved cspace to issue `ipc_call`. The parent keeps the
//! original endpoint cap (the moved cap is derived from it) in its own
//! cspace and uses it to `ipc_recv` the child's call.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait,
};
use syscall_abi::RIGHTS_EP_SEND_GRANT;

use crate::{ChildStack, TestContext, TestResult};

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child entry: issue one `ipc_call` via the slot whose index is packed
/// in the low 32 bits of `arg`, then `notification_send` on `done_slot` (high 32 bits) and exit.
// cast_possible_truncation: slot indices are < 2^32.
#[allow(clippy::cast_possible_truncation)]
/// IPC page of the [`caller_entry`] child.
static mut CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

extern "C" fn caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF_FFFF) as u32;
    let done_slot = (arg >> 32) as u32;

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(CALLER_IPC_PAGE));
    // SAFETY: `CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        syscall::notification_send(done_slot, 1).ok();
        syscall::thread_exit();
    }
    let msg = IpcMessage::new(0xABC);
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) };
    syscall::notification_send(done_slot, 1).ok();
    syscall::thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("cap_move_into_fresh_cspace_then_ipc: starting");

    // Mint two caps to the same endpoint object: the parent keeps the original
    // (in its own cspace) and a derived copy (a child of it, per
    // `SYS_CAP_COPY`) is the cap that will be moved into the child cspace.
    let ep_parent = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: cap_create_endpoint (parent) failed")?;
    let ep_donor = cap_copy(ep_parent, ctx.cspace_cap, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: sibling cap_copy (donor) failed")?;

    let done = cap_create_notification(ctx.memory_base).map_err(
        |_| "cap_move_into_fresh_cspace_then_ipc: cap_create_notification (done) failed",
    )?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: spawn::new_child failed")?;

    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: cap_copy (child_done) failed")?;

    // Move (not copy) the derived donor cap into the child's cspace. After
    // this, ep_donor in the parent's cspace becomes null; the cap lives
    // only in the child's cspace.
    let child_ep = syscall::cap_move(ep_donor, child.cs, 0)
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: cap_move failed")?;

    // `cap_info` succeeds on any live cap and fails with `InvalidCapability` on
    // a null slot, so it observes whether the move nulled the source.
    if syscall::cap_info(ep_donor, syscall_abi::CAP_INFO_TAG_RIGHTS).is_ok()
    {
        return Err("cap_move_into_fresh_cspace_then_ipc: source slot still usable after cap_move");
    }

    let arg = u64::from(child_ep) | (u64::from(child_done) << 32);
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, caller_entry, stack_top, arg) }
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: configure_and_start failed")?;

    // Server side: recv the call through the parent's original cap, reply,
    // then verify the call was actually the child's.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep_parent, ctx.ipc_buf) }
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: ipc_recv failed")?;
    if msg.label != 0xABC
    {
        return Err("cap_move_into_fresh_cspace_then_ipc: wrong label on received message");
    }
    let reply = IpcMessage::new(0);
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
        .map_err(|_| "cap_move_into_fresh_cspace_then_ipc: ipc_reply failed")?;

    // Wait for the child to exit cleanly.
    notification_wait(done).ok();

    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(ep_parent).ok();
    cap_delete(done).ok();
    Ok(())
}
