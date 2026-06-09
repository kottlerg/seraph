// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/cross_cspace_revoke_no_alias.rs

//! Integration: a cross-`CSpace` `cap_revoke` must not let a recipient's stale
//! handle alias a recycled slot (#349).
//!
//! Regression for the cross-`CSpace` stale-slot alias class. A capability
//! derived in one `CSpace` and IPC-moved into another keeps its derivation edge
//! across the boundary, so revoking the source's subtree walks into the foreign
//! `CSpace` and `free_slot`s the slot the recipient still legitimately holds.
//! With bare slot-index handles the freed index was recycled (LIFO) onto an
//! unrelated live object and the recipient's handle silently aliased it (#341
//! was one instance, delivered via an IPC **reply**, which is why this test uses
//! the reply direction). Per-slot generation closes the class: freeing the slot
//! bumps its generation, so the recipient's now-stale handle fails
//! `InvalidCapability` instead of aliasing whatever later occupies the index.
//!
//! Scenario:
//!   1. Parent creates `target` (the derive source), `ep`, `go`/`report` (the
//!      release + verdict handshake), and `decoy` (the unrelated object used to
//!      recycle the freed slot).
//!   2. Child (fresh `CSpace`) `ipc_call`s `ep`; parent `cap_derive`s `c1` from
//!      `target` and returns it in the **reply** — the kernel moves `c1` into
//!      the child's `CSpace` at slot K, preserving the cross-`CSpace` edge.
//!   3. Parent `cap_revoke(target)`: the subtree walk reaches the child and frees
//!      slot K (bumping its generation).
//!   4. Parent recycles slot K by `cap_copy`ing `decoy` into the child's `CSpace`
//!      (LIFO reclaims K) and hands the child the new handle through `go`.
//!   5. Child confirms the recycle landed at K with an advanced generation, then
//!      uses its stale `c1`: it must fail `InvalidCapability` (not alias `decoy`),
//!      while the fresh handle to K still works. The child reports the verdict on
//!      `report`.
//!
//! This asserts the generation-only model: the test depends on the cross-`CSpace`
//! edge being preserved (so the revoke frees the recipient's slot) and on the
//! stale handle then failing closed.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_derive, cap_revoke,
    ipc_buffer_set, notification_send, notification_wait, notification_wait_timeout, thread_exit,
};
use syscall_abi::{SyscallError, cap_handle_gen, cap_handle_index};

use crate::{ChildStack, TestContext, TestResult};

// NOTIFY (bit 7) — send only; WAIT (bit 8) — wait only; SEND|GRANT (bits 4,6).
const RIGHTS_NOTIFY: u64 = 1 << 7;
const RIGHTS_WAIT: u64 = 1 << 8;
const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);

// Verdict codes the child reports on `report`. Distinct single bits so the
// parent can name the exact failure. `0` is reserved for the wait-timeout path.
const REPORT_OK: u64 = 0x01;
const REPORT_NOT_REUSED: u64 = 0x02;
const REPORT_GEN_NOT_ADVANCED: u64 = 0x04;
const REPORT_STALE_ALIASED: u64 = 0x08;
const REPORT_STALE_WRONG_ERROR: u64 = 0x10;
const REPORT_FRESH_BROKEN: u64 = 0x20;

// Bits the child writes through the stale / fresh handles. Non-zero and distinct;
// the parent never reads them (the verdict travels on `report`).
const ALIAS_BITS: u64 = 0xA1;
const FRESH_BITS: u64 = 0xF5;

// Generous bound: the child only needs a few syscalls after the `go` signal.
const REPORT_TIMEOUT_MS: u64 = 1000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("cross_cspace_revoke_no_alias: starting");

    // `target` is the derive source whose subtree the parent revokes. `decoy` is
    // an unrelated notification used to recycle the child's freed slot. `go`
    // releases the child (and carries the recycled handle); `report` returns the
    // child's verdict.
    let target = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_create_notification (target) failed")?;
    let decoy = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_create_notification (decoy) failed")?;
    let go = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_create_notification (go) failed")?;
    let report = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_create_notification (report) failed")?;
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_create_endpoint failed")?;

    // Child CSpace: a SEND|GRANT copy of `ep` (to call), a WAIT copy of `go` (to
    // park on), and a NOTIFY copy of `report` (to answer). `c1` arrives via the
    // reply.
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "cross_cspace_revoke_no_alias: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_copy (child_ep) failed")?;
    let child_go = cap_copy(go, child.cs, RIGHTS_WAIT)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_copy (child_go) failed")?;
    let child_report = cap_copy(report, child.cs, RIGHTS_NOTIFY)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_copy (child_report) failed")?;

    let arg = u64::from(child_ep) | (u64::from(child_go) << 16) | (u64::from(child_report) << 32);
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, child_entry, stack_top, arg)
        .map_err(|_| "cross_cspace_revoke_no_alias: configure_and_start failed")?;

    // Receive the child's call, derive `c1` from `target`, and hand it back in
    // the reply — the kernel moves it into the child's CSpace (cross-CSpace),
    // keeping the derivation edge to `target`.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let _ = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "cross_cspace_revoke_no_alias: ipc_recv failed")?;
    let c1 = cap_derive(target, RIGHTS_NOTIFY)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_derive (c1) failed")?;
    let reply = IpcMessage::builder(0).cap(c1).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
        .map_err(|_| "cross_cspace_revoke_no_alias: ipc_reply failed")?;

    // Revoke `target`'s subtree. The cross-CSpace edge is intact, so this walks
    // into the child and frees the slot holding `c1` (bumping its generation).
    cap_revoke(target).map_err(|_| "cross_cspace_revoke_no_alias: cap_revoke (target) failed")?;

    // Recycle the just-freed child slot: `cap_copy` into `child.cs` pops the LIFO
    // free list, reclaiming `c1`'s old index for an unrelated live notification.
    // The returned handle carries the bumped generation; hand it to the child so
    // it can confirm the recycle aliased `c1`'s slot.
    let recycled = cap_copy(decoy, child.cs, RIGHTS_NOTIFY)
        .map_err(|_| "cross_cspace_revoke_no_alias: cap_copy (recycle) failed")?;
    notification_send(go, u64::from(recycled))
        .map_err(|_| "cross_cspace_revoke_no_alias: notification_send (go) failed")?;

    let verdict = notification_wait_timeout(report, REPORT_TIMEOUT_MS)
        .map_err(|_| "cross_cspace_revoke_no_alias: notification_wait_timeout (report) failed")?;
    let outcome = match verdict
    {
        REPORT_OK => Ok(()),
        REPORT_NOT_REUSED => Err(
            "cross_cspace_revoke_no_alias: freed slot was not recycled at the moved cap's index",
        ),
        REPORT_GEN_NOT_ADVANCED =>
        {
            Err("cross_cspace_revoke_no_alias: generation did not advance on the cross-CSpace free")
        }
        REPORT_STALE_ALIASED =>
        {
            Err("cross_cspace_revoke_no_alias: stale handle aliased the recycled slot after revoke")
        }
        REPORT_STALE_WRONG_ERROR =>
        {
            Err("cross_cspace_revoke_no_alias: stale handle failed with the wrong error")
        }
        REPORT_FRESH_BROKEN =>
        {
            Err("cross_cspace_revoke_no_alias: generation rejected the valid recycled handle")
        }
        0 => Err("cross_cspace_revoke_no_alias: child did not report (timeout)"),
        _ => Err("cross_cspace_revoke_no_alias: unexpected report value"),
    };

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(ep).ok();
    cap_delete(go).ok();
    cap_delete(report).ok();
    cap_delete(decoy).ok();
    cap_delete(target).ok();

    outcome?;
    crate::log("cross_cspace_revoke_no_alias: PASS");
    Ok(())
}

// ── Child thread ──────────────────────────────────────────────────────────────

/// `arg` packs: bits[15:0] = `ep_slot`, bits[31:16] = `go_slot`,
/// bits[47:32] = `report_slot` (all child `CSpace` indices).
fn child_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let go_slot = ((arg >> 16) & 0xFFFF) as u32;
    let report_slot = ((arg >> 32) & 0xFFFF) as u32;

    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if ipc_buffer_set(buf_addr).is_err()
    {
        thread_exit()
    }

    // Call the parent; the reply carries the derived `c1` in cap_slots[0].
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let Ok(reply) = (unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0), buf_addr as *mut u64) })
    else
    {
        thread_exit()
    };
    let caps = reply.caps();
    if caps.is_empty()
    {
        thread_exit()
    }
    let c1 = caps[0];

    // Park until the parent has revoked `target` and recycled the freed slot. The
    // release carries the recycled slot's fresh handle.
    let Ok(recycled_bits) = notification_wait(go_slot)
    else
    {
        thread_exit()
    };
    // The parent zero-extended a u32 handle into the notification word; the low
    // 32 bits are exact.
    let recycled = (recycled_bits & 0xFFFF_FFFF) as u32;

    let _ = notification_send(report_slot, child_verdict(c1, recycled));
    thread_exit()
}

/// Compute the child's verdict: the recycle must have landed on `c1`'s slot with
/// an advanced generation, the stale `c1` handle must fail closed, and the fresh
/// `recycled` handle to that slot must still work.
fn child_verdict(c1: u32, recycled: u32) -> u64
{
    if cap_handle_index(recycled) != cap_handle_index(c1)
    {
        return REPORT_NOT_REUSED;
    }
    if cap_handle_gen(recycled) == cap_handle_gen(c1)
    {
        return REPORT_GEN_NOT_ADVANCED;
    }

    // The stale handle addresses `c1`'s old (index, generation); the slot now
    // holds `decoy` with the bumped generation. It must be rejected, not aliased.
    match notification_send(c1, ALIAS_BITS)
    {
        Err(e) if e == SyscallError::InvalidCapability as i64 =>
        {}
        Ok(()) => return REPORT_STALE_ALIASED,
        Err(_) => return REPORT_STALE_WRONG_ERROR,
    }

    // The fresh handle to the recycled slot must still resolve and send.
    if notification_send(recycled, FRESH_BITS).is_err()
    {
        return REPORT_FRESH_BROKEN;
    }

    REPORT_OK
}
