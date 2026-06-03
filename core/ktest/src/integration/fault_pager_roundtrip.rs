// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fault_pager_roundtrip.rs

//! Integration: a userspace pager resolves a page fault and resumes the thread.
//!
//! Exercises the full fault-handler protocol round-trip on the real fault path:
//!
//!   1. A child thread is bound (`SYS_THREAD_SET_FAULT_HANDLER`) to an endpoint
//!      and started; it stores to an unmapped reserved VA, faulting.
//!   2. The harness thread acts as the pager: it `ipc_recv`s the kernel-
//!      synthesized fault message, verifies its shape (`FAULT_LABEL`, badge,
//!      `FAULT_KIND_VM`, faulting VA, write access), maps a frame at the
//!      faulting VA, and replies `FAULT_REPLY_RESUME`.
//!   3. The child re-executes the faulting store against the now-mapped page,
//!      reads the value back to confirm the store landed, and signals success.
//!
//! Contrast with `fault_kills_thread.rs` (no handler bound ⇒ the same fault is
//! terminal). A mis-wired resume path would hang the bounded `notification_wait`
//! rather than completing.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, mem_map, mem_unmap,
    notification_wait, thread_set_fault_handler,
};
use syscall_abi::{
    FAULT_ACCESS_WRITE, FAULT_CLASS_ALL, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_RESUME,
    MAP_WRITABLE, RIGHTS_ALL,
};

use crate::{ChildStack, TestContext, TestResult};

/// Unmapped, canonical user-half VA the child touches; page-aligned so the
/// faulting address equals it exactly. Distinct from other tests' VAs.
const RESERVED_VA: u64 = 0x6100_0000_0000;

/// Caller-chosen badge bound with the handler; the kernel delivers it in the
/// fault message so the pager can correlate the faulting thread.
const FAULT_BADGE: u64 = 0xC0FF_EE01;

/// Sentinel the child stores and reads back to prove the resumed store landed.
const SENTINEL: u64 = 0xF00D_D00D_1234_5678;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "fault_pager_roundtrip: cap_create_endpoint failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fault_pager_roundtrip: cap_create_notification failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "fault_pager_roundtrip: spawn::new_child failed")?;

    // Give the child a notification cap so it can signal success after resume.
    let child_sig = cap_copy(sig, child.cs, RIGHTS_ALL)
        .map_err(|_| "fault_pager_roundtrip: cap_copy(sig) failed")?;

    // Bind the child's fault handler to our endpoint before it runs.
    thread_set_fault_handler(child.th, ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "fault_pager_roundtrip: thread_set_fault_handler failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, fault_child, stack_top, u64::from(child_sig))
        .map_err(|_| "fault_pager_roundtrip: configure_and_start failed")?;

    // Act as the pager: receive the fault, verify its shape, back the page.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fault_pager_roundtrip: ipc_recv failed")?;

    if msg.label != FAULT_LABEL
    {
        return Err("fault_pager_roundtrip: message is not a kernel fault (wrong label)");
    }
    if msg.badge != FAULT_BADGE
    {
        return Err("fault_pager_roundtrip: wrong fault badge");
    }
    if msg.word(0) != FAULT_KIND_VM
    {
        return Err("fault_pager_roundtrip: fault kind is not VM");
    }
    if msg.word(1) != RESERVED_VA
    {
        return Err("fault_pager_roundtrip: wrong faulting address");
    }
    if msg.word(2) & FAULT_ACCESS_WRITE == 0
    {
        return Err("fault_pager_roundtrip: write access flag not set");
    }

    // Back the faulting page from the frame pool, then resume the child.
    let mem = crate::frame_pool::alloc()
        .ok_or("fault_pager_roundtrip: frame_pool::alloc returned None")?;
    mem_map(mem, ctx.aspace_cap, RESERVED_VA, 0, 1, MAP_WRITABLE)
        .map_err(|_| "fault_pager_roundtrip: mem_map failed")?;

    // Reply RESUME, deliberately attaching a (null) cap slot. The kernel must
    // ignore a fault reply's payload and caps — not validate-then-kill the
    // faulter — so a stray cap here must NOT terminate the child. Regression
    // guard for the fault-reply fast path. Slot 0 is the permanent null slot.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe {
        ipc::ipc_reply(
            &IpcMessage::builder(FAULT_REPLY_RESUME).cap(0).build(),
            ctx.ipc_buf,
        )
    }
    .map_err(|_| "fault_pager_roundtrip: ipc_reply(RESUME) failed")?;

    // The child re-executes the store, verifies it, and signals success.
    notification_wait(sig).map_err(|_| "fault_pager_roundtrip: notification_wait failed")?;

    // Cleanup: delete the child first (its Thread dealloc releases the fault
    // binding's reference on the endpoint), then the rest.
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    mem_unmap(ctx.aspace_cap, RESERVED_VA, 1).ok();
    // SAFETY: mem is from the pool and now unmapped.
    unsafe { crate::frame_pool::free(mem) };
    cap_delete(ep).ok();
    cap_delete(sig).ok();
    Ok(())
}

/// Child entry: store to the reserved VA (faults; the pager backs it and
/// resumes), read it back, and signal success. The trailing loop only satisfies
/// the `-> !` signature; the harness reaps the child after the signal.
fn fault_child(child_sig: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: RESERVED_VA is unmapped on first touch; the bound pager maps a
    // frame and replies RESUME, so this store completes on re-execution.
    unsafe {
        p.write_volatile(SENTINEL);
    }
    // SAFETY: same page, now mapped; read back to confirm the store landed.
    let readback = unsafe { p.read_volatile() };
    if readback == SENTINEL
    {
        // cast_possible_truncation: child_sig is a cap slot index passed as u64.
        #[allow(clippy::cast_possible_truncation)]
        syscall::notification_send(child_sig as u32, 1).ok();
    }
    loop
    {
        core::hint::spin_loop();
    }
}
