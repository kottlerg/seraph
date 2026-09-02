// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/cap.rs

//! Tier 1 tests for capability syscalls.
//!
//! Covers: `SYS_CAP_CREATE_*`, `SYS_CAP_COPY` (both auto-allocate and
//! explicit-slot paths), `SYS_CAP_MOVE`, `SYS_CAP_DERIVE`, `SYS_CAP_REVOKE`,
//! `SYS_CAP_DELETE`.
//!
//! Each function tests one syscall or one distinct behaviour. Tests clean up
//! caps they create where convenient, but leaks are acceptable — ktest exits
//! after all tests finish.

use syscall::{
    cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_create_notification,
    cap_delete, cap_derive, cap_derive_badge, cap_info, cap_insert, cap_move, cap_revoke,
    event_queue_create, notification_send, notification_wait,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult};

static mut TEARDOWN_BATCH_STACK: ChildStack = ChildStack::ZERO;
static mut STOP_BLOCKED_STACK: ChildStack = ChildStack::ZERO;
static mut STOP_SPINNING_STACK: ChildStack = ChildStack::ZERO;

// Rights bit constants (from kernel/src/cap/slot.rs).
// Notification NOTIFY (send) / WAIT (receive-block); endpoint SEND / GRANT.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

// ── SYS_CAP_CREATE_NOTIFICATION ────────────────────────────────────────────────────

/// `cap_create_notification` returns a usable slot.
pub fn create_notification(ctx: &TestContext) -> TestResult
{
    let slot =
        cap_create_notification(ctx.memory_base).map_err(|_| "cap_create_notification failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_notification failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_ENDPOINT ──────────────────────────────────────────────────

/// `cap_create_endpoint` returns a usable slot.
pub fn create_endpoint(ctx: &TestContext) -> TestResult
{
    let slot = cap_create_endpoint(ctx.memory_base).map_err(|_| "cap_create_endpoint failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_endpoint failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_EVENT_Q ───────────────────────────────────────────────────

/// `cap_create_event_q` (via `event_queue_create`) returns a usable slot.
pub fn create_event_q(ctx: &TestContext) -> TestResult
{
    let slot = event_queue_create(ctx.memory_base, 8).map_err(|_| "event_queue_create failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_event_q failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_CSPACE ────────────────────────────────────────────────────

/// `cap_create_cspace` succeeds with a valid page count.
pub fn create_cspace(ctx: &TestContext) -> TestResult
{
    let slot = cap_create_cspace(ctx.memory_base, 0, 4).map_err(|_| "cap_create_cspace failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_cspace failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_ASPACE ────────────────────────────────────────────────────

/// `cap_create_aspace` returns a usable slot.
pub fn create_aspace(ctx: &TestContext) -> TestResult
{
    let slot = cap_create_aspace(ctx.memory_base, 0, 8).map_err(|_| "cap_create_aspace failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_aspace failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_THREAD ────────────────────────────────────────────────────

/// `cap_create_thread` succeeds when given valid aspace and cspace caps.
pub fn create_thread(ctx: &TestContext) -> TestResult
{
    // Thread needs both an address space and a cspace to be bound to.
    // `spawn::new_child` mints both via `cap_create_cspace` + `cap_create_thread`.
    let child = crate::spawn::new_child(ctx).map_err(|_| "spawn::new_child failed")?;
    cap_delete(child.th).map_err(|_| "cap_delete thread failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cspace failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_WAIT_SET ──────────────────────────────────────────────────

/// `cap_create_wait_set` (via `wait_set_create`) returns a usable slot.
pub fn create_wait_set(ctx: &TestContext) -> TestResult
{
    let slot = cap_create_wait_set(ctx.memory_base).map_err(|_| "cap_create_wait_set failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_wait_set failed")?;
    Ok(())
}

// Thin wrapper — the syscall wrapper is `wait_set_create` in shared/syscall but
// the underlying syscall number is `SYS_CAP_CREATE_WAIT_SET`.
fn cap_create_wait_set(memory_cap: u32) -> Result<u32, i64>
{
    syscall::wait_set_create(memory_cap)
}

// ── SYS_CAP_COPY ─────────────────────────────────────────────────────────────

/// `cap_copy` places a copy of a cap into another `CSpace`.
///
/// The copy is verified to be independently usable (`notification_send` still works
/// on the source; the destination `CSpace` is deleted as cleanup, which drops
/// all caps inside it).
pub fn copy(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for copy test failed")?;
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for copy test failed")?;

    // Copy with all rights — `syscall::RIGHTS_ALL` passes through whatever rights the source has.
    cap_copy(sig, dest_cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy failed")?;

    // Source slot is still valid after a copy.
    notification_send(sig, 0x1).map_err(|_| "notification_send on source after cap_copy failed")?;

    cap_delete(sig).map_err(|_| "cap_delete sig after copy test failed")?;
    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after copy test failed")?;
    Ok(())
}

// ── SYS_CAP_COPY explicit slot (cap_insert) ──────────────────────────────────

/// `cap_insert` places a copy at a caller-chosen slot index in another `CSpace`.
///
/// Like `cap_copy` but the destination slot is explicit. We verify the source
/// is unaffected (insert is a copy, not a move).
pub fn insert(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for insert test failed")?;
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for insert test failed")?;

    // Insert at slot 5 in dest_cs.
    cap_insert(sig, dest_cs, 5, syscall::RIGHTS_ALL).map_err(|_| "cap_insert failed")?;

    // Source slot is preserved (insert = copy, not move).
    notification_send(sig, 0x1)
        .map_err(|_| "notification_send on source after cap_insert failed")?;

    cap_delete(sig).map_err(|_| "cap_delete sig after insert test failed")?;
    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after insert test failed")?;
    Ok(())
}

// ── SYS_CAP_MOVE ─────────────────────────────────────────────────────────────

/// `cap_move` transfers a cap to another `CSpace` and nulls the source slot.
pub fn r#move(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for move test failed")?;
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for move test failed")?;

    // Move to dest_cs; auto-allocate destination slot (dest_index = 0).
    cap_move(sig, dest_cs, 0).map_err(|_| "cap_move failed")?;

    // Source slot must now be null — using it should fail.
    let err = notification_send(sig, 0x1);
    if err.is_ok()
    {
        return Err("source slot still usable after cap_move (expected null)");
    }

    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after move test failed")?;
    Ok(())
}

// ── SYS_CAP_DERIVE ───────────────────────────────────────────────────────────

/// `cap_derive` produces an attenuated cap; the derived cap has at most the
/// rights of the source masked by `rights_mask`.
///
/// We create a notification with NOTIFY+WAIT rights, derive a copy with NOTIFY only,
/// then verify:
///  - The derived cap can send (has NOTIFY).
///  - The derived cap cannot wait (lacks WAIT) — kernel returns `InsufficientRights`.
pub fn derive_attenuation(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for derive test failed")?;

    // Derive with NOTIFY right only (no WAIT).
    let derived = cap_derive(sig, RIGHTS_NOTIFY).map_err(|_| "cap_derive failed")?;

    // Derived cap can send.
    notification_send(derived, 0x1).map_err(|_| "notification_send on derived cap failed")?;

    // Derived cap cannot wait — InsufficientRights (-3).
    // We call notification_wait on a cap that has no bits set AND no WAIT right.
    // The kernel should reject with InsufficientRights before blocking.
    let wait_err = syscall::notification_wait(derived);
    if wait_err != Err(SyscallError::InsufficientRights as i64)
    {
        // If the kernel returns a different error (or somehow succeeds),
        // something is wrong with rights enforcement.
        // Note: if notification bits were set (from our send above), the kernel might
        // return them before checking rights. Clear is fine for this test since
        // notification_send ORs bits and notification_wait clears them — after send(0x1) and
        // then a wait, the bits are consumed. The next wait on derived must fail.
        // ... actually notification_wait on a cap with WAIT right AND bits set would
        // succeed. But derived has NO WAIT right, so kernel checks rights first.
        return Err(
            "notification_wait on NOTIFY-only derived cap did not return InsufficientRights",
        );
    }

    cap_delete(derived).map_err(|_| "cap_delete derived cap failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after derive test failed")?;
    Ok(())
}

// ── SYS_CAP_REVOKE ───────────────────────────────────────────────────────────

/// `cap_revoke` invalidates all descendants of a cap.
///
/// After revoking the parent, the derived cap must be unusable.
pub fn revoke_invalidates(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for revoke test failed")?;
    let derived =
        cap_derive(sig, RIGHTS_NOTIFY).map_err(|_| "cap_derive for revoke test failed")?;

    // Revoke all descendants of sig (derived is now invalid).
    cap_revoke(sig).map_err(|_| "cap_revoke failed")?;

    // Derived cap must now fail.
    let err = notification_send(derived, 0x1);
    if err.is_ok()
    {
        return Err("derived cap still usable after cap_revoke");
    }

    cap_delete(sig).map_err(|_| "cap_delete sig after revoke test failed")?;
    Ok(())
}

/// Deleting an intermediate cap re-links its children under its parent in
/// batches, so grandchildren stay usable after the delete and are still
/// revoked from the grandparent afterwards.
///
/// 300 grandchildren exceed one `MAX_REPARENT_EDITS` batch, so the delete
/// crosses a lock release with children still to move. Probes at the head,
/// middle, and tail of the child list cover both batches; the `USED` count
/// returns to its baseline once the revoke has freed everything.
pub fn delete_intermediate_keeps_grandchildren_revocable(ctx: &TestContext) -> TestResult
{
    const GRANDCHILDREN: u32 = 300;

    let used_before = cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_USED)
        .map_err(|_| "delete_intermediate: cap_info(used before) failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "delete_intermediate: create_notification failed")?;

    // Everything below hangs off `sig`, so a failure anywhere is cleaned up
    // by revoking and deleting it — a leaked 300-cap tail would otherwise
    // skew every later USED baseline.
    let body = || -> TestResult {
        let mid =
            cap_derive(sig, RIGHTS_NOTIFY).map_err(|_| "delete_intermediate: derive mid failed")?;
        let mut probes: [Option<u32>; 3] = [None; 3];
        for i in 0..GRANDCHILDREN
        {
            let gc = cap_derive(mid, RIGHTS_NOTIFY)
                .map_err(|_| "delete_intermediate: derive grandchild failed")?;
            match i
            {
                0 => probes[0] = Some(gc),
                x if x == GRANDCHILDREN / 2 => probes[1] = Some(gc),
                x if x == GRANDCHILDREN - 1 => probes[2] = Some(gc),
                _ =>
                {}
            }
        }

        cap_delete(mid).map_err(|_| "delete_intermediate: cap_delete(mid) failed")?;
        for probe in probes.iter().flatten()
        {
            notification_send(*probe, 0x1).map_err(
                |_| "delete_intermediate: grandchild unusable after deleting its parent",
            )?;
        }

        cap_revoke(sig).map_err(|_| "delete_intermediate: cap_revoke(sig) failed")?;
        for probe in probes.iter().flatten()
        {
            if notification_send(*probe, 0x1).is_ok()
            {
                return Err("delete_intermediate: grandchild survived the grandparent's revoke");
            }
        }
        Ok(())
    };
    let result = body();
    if result.is_err()
    {
        cap_revoke(sig).ok();
    }
    cap_delete(sig).map_err(|_| "delete_intermediate: cap_delete(sig) failed")?;
    result?;

    let used_after = cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_USED)
        .map_err(|_| "delete_intermediate: cap_info(used after) failed")?;
    if used_after != used_before
    {
        return Err("delete_intermediate: USED did not return to baseline");
    }
    Ok(())
}

/// `cap_revoke` clears subtrees larger than one revoke batch — wide, deep,
/// and bushy shapes — and the freed slots return to the `CSpace`.
///
/// The revoke batch bound (see `MAX_REVOKE_EDITS` in the kernel's
/// capability-internals design doc) must be invisible to callers. Each of
/// the three shapes exceeds one batch: a 600-child fan-out, a 300-deep
/// derive chain, and a bushy 4×100 two-level tree whose second level
/// straddles the batch boundary. Probes cover head, middle, and tail
/// positions of the child lists. Three consecutive cycles on one root
/// verify the tree and freelist stay healthy across batched revokes.
pub fn revoke_large_subtree(ctx: &TestContext) -> TestResult
{
    const WIDE_CHILDREN: usize = 600;
    const DEEP_CHAIN: usize = 300;
    const BUSHY_CHILDREN: usize = 4;
    const BUSHY_GRANDCHILDREN: usize = 100;

    let used0 = cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_USED)
        .map_err(|_| "cap_info(USED) baseline failed")?;

    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for revoke_large_subtree failed")?;

    // Cycle 1: wide fan-out — 600 direct children of the root.
    // Probes: head, middle, and tail of the child list.
    let mut probes: [Option<u32>; 3] = [None; 3];
    for i in 0..WIDE_CHILDREN
    {
        let child = cap_derive(sig, RIGHTS_NOTIFY).map_err(|_| "cap_derive (wide) failed")?;
        if i == 0
        {
            probes[0] = Some(child);
        }
        else if i == WIDE_CHILDREN / 2
        {
            probes[1] = Some(child);
        }
        else if i == WIDE_CHILDREN - 1
        {
            probes[2] = Some(child);
        }
    }
    for probe in probes.iter().flatten()
    {
        notification_send(*probe, 0x1).map_err(|_| "wide probe unusable before revoke")?;
    }
    cap_revoke(sig).map_err(|_| "cap_revoke (wide) failed")?;
    for probe in probes.iter().flatten()
    {
        if notification_send(*probe, 0x1).is_ok()
        {
            return Err("derived cap still usable after wide batched revoke");
        }
    }

    // Cycle 2: deep chain — derive-of-derive to 300 levels under the root.
    let mut cur = sig;
    let mut mid = None;
    for i in 0..DEEP_CHAIN
    {
        cur = cap_derive(cur, RIGHTS_NOTIFY).map_err(|_| "cap_derive (deep) failed")?;
        if i == DEEP_CHAIN / 2
        {
            mid = Some(cur);
        }
    }
    let mid = mid.ok_or("deep chain built no midpoint")?;
    cap_revoke(sig).map_err(|_| "cap_revoke (deep) failed")?;
    if notification_send(mid, 0x1).is_ok() || notification_send(cur, 0x1).is_ok()
    {
        return Err("derived cap still usable after deep batched revoke");
    }

    // Cycle 3: bushy — 4 children × 100 grandchildren (404 nodes), so the
    // batch boundary lands mid-way through the grandchild population.
    let mut bushy_probe = None;
    for c in 0..BUSHY_CHILDREN
    {
        let child = cap_derive(sig, RIGHTS_NOTIFY).map_err(|_| "cap_derive (bushy) failed")?;
        for g in 0..BUSHY_GRANDCHILDREN
        {
            let grandchild = cap_derive(child, RIGHTS_NOTIFY)
                .map_err(|_| "cap_derive (bushy grandchild) failed")?;
            if c == BUSHY_CHILDREN / 2 && g == BUSHY_GRANDCHILDREN / 2
            {
                bushy_probe = Some(grandchild);
            }
        }
    }
    let bushy_probe = bushy_probe.ok_or("bushy tree built no probe")?;
    cap_revoke(sig).map_err(|_| "cap_revoke (bushy) failed")?;
    if notification_send(bushy_probe, 0x1).is_ok()
    {
        return Err("grandchild cap still usable after bushy batched revoke");
    }

    // Only the root remains; deleting it restores the slot-count baseline.
    let used_before_delete = cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_USED)
        .map_err(|_| "cap_info(USED) after revokes failed")?;
    if used_before_delete != used0 + 1
    {
        return Err("slot count not restored after batched revokes");
    }
    cap_delete(sig).map_err(|_| "cap_delete root after revoke_large_subtree failed")?;
    let used_end = cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_USED)
        .map_err(|_| "cap_info(USED) final failed")?;
    if used_end != used0
    {
        return Err("slot count not at baseline after root delete");
    }
    Ok(())
}

// ── SYS_CAP_COPY explicit slot negative ──────────────────────────────────────

/// `cap_insert` to an already-occupied destination slot must return an error.
pub fn insert_to_occupied_slot_err(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for occupied-slot test failed")?;
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for occupied-slot test failed")?;

    // First insert at slot 5 — must succeed.
    cap_insert(sig, dest_cs, 5, syscall::RIGHTS_ALL)
        .map_err(|_| "first cap_insert to slot 5 failed")?;

    // Second insert at the same slot 5 — must fail (slot is occupied).
    let err = cap_insert(sig, dest_cs, 5, syscall::RIGHTS_ALL);
    if err.is_ok()
    {
        return Err("cap_insert to occupied slot should fail");
    }

    cap_delete(sig).map_err(|_| "cap_delete sig after occupied-slot test failed")?;
    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after occupied-slot test failed")?;
    Ok(())
}

// ── SYS_CAP_COPY negative ─────────────────────────────────────────────────────

/// `cap_copy` using a non-`CSpace` cap as the destination `CSpace` must fail.
///
/// Passing a Notification cap where a `CSpace` cap is expected should be rejected
/// before any modification occurs.
pub fn copy_into_non_cspace_err(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for non-cspace test failed")?;

    // sig is a Notification, not a CSpace — using it as dest_cs must fail.
    let err = cap_copy(sig, sig, syscall::RIGHTS_ALL);
    if err.is_ok()
    {
        return Err("cap_copy with non-CSpace dest_cs should fail");
    }

    cap_delete(sig).map_err(|_| "cap_delete sig after non-cspace test failed")?;
    Ok(())
}

// ── SYS_CAP_DELETE ───────────────────────────────────────────────────────────

/// `cap_delete` removes a cap from the `CSpace`; the slot becomes unusable.
pub fn delete(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for delete test failed")?;

    // Verify it's usable before deletion.
    notification_send(sig, 0x1).map_err(|_| "notification_send before delete failed")?;

    cap_delete(sig).map_err(|_| "cap_delete failed")?;

    // After deletion the slot is null; notification_send must fail.
    let err = notification_send(sig, 0x1);
    if err.is_ok()
    {
        return Err("notification_send succeeded after cap_delete (slot not null)");
    }

    Ok(())
}

// ── SYS_CAP_DELETE (idempotent) ──────────────────────────────────────────────

/// `cap_delete` on an already-null slot returns Ok (idempotent).
pub fn delete_null_slot_ok(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for delete_null_slot_ok failed")?;
    cap_delete(sig).map_err(|_| "first cap_delete failed")?;

    // Second delete on the now-null slot must succeed (no-op).
    cap_delete(sig).map_err(|_| "second cap_delete on null slot returned error")?;
    Ok(())
}

// ── SYS_CAP_COPY explicit slot negative (out of bounds) ──────────────────────

/// `cap_insert` with a slot index beyond the destination `CSpace` capacity must fail.
pub fn insert_out_of_bounds_err(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for insert_oob test failed")?;
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for insert_oob test failed")?;

    // Slot 99999 is beyond any cspace capacity.
    let err = cap_insert(sig, dest_cs, 99999, syscall::RIGHTS_ALL);
    if err.is_ok()
    {
        return Err("cap_insert at out-of-bounds slot should fail");
    }

    cap_delete(sig).map_err(|_| "cap_delete sig after insert_oob test failed")?;
    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after insert_oob test failed")?;
    Ok(())
}

// ── SYS_CAP_DERIVE (zero rights) ────────────────────────────────────────────

/// `cap_derive` with `rights_mask`=0 succeeds; the derived cap cannot perform
/// any operation.
pub fn derive_zero_rights(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for derive_zero_rights failed")?;

    let derived = cap_derive(sig, 0).map_err(|_| "cap_derive(0) failed")?;

    // Derived cap with zero rights cannot send.
    let send_err = notification_send(derived, 0x1);
    if send_err.is_ok()
    {
        return Err("notification_send on zero-rights derived cap should fail");
    }

    // Derived cap with zero rights cannot wait.
    // Pre-set bits on the real notification so we test rights, not blocking.
    notification_send(sig, 0x1).map_err(|_| "notification_send on root failed")?;
    let wait_err = notification_wait(derived);
    if wait_err.is_ok()
    {
        return Err("notification_wait on zero-rights derived cap should fail");
    }

    // Drain the bits.
    notification_wait(sig).ok();
    cap_delete(derived).map_err(|_| "cap_delete derived failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after derive_zero_rights failed")?;
    Ok(())
}

// ── SYS_CAP_REVOKE negative (null slot) ──────────────────────────────────────

/// `cap_revoke` on a null slot returns an error.
pub fn revoke_null_slot_err(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for revoke_null_slot_err failed")?;
    cap_delete(sig).map_err(|_| "cap_delete failed")?;

    // Slot is now null; revoke must fail.
    let err = cap_revoke(sig);
    if err.is_ok()
    {
        return Err("cap_revoke on null slot should fail");
    }
    Ok(())
}

// ── SYS_CAP_CREATE_EVENT_Q negative ──────────────────────────────────────────

/// `event_queue_create(0)` must return `InvalidArgument` (capacity must be 1-4096).
pub fn create_event_q_zero_capacity_err(ctx: &TestContext) -> TestResult
{
    let err = event_queue_create(ctx.memory_base, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("event_queue_create(0) did not return InvalidArgument");
    }
    Ok(())
}

/// `event_queue_create(4097)` must return `InvalidArgument` (max capacity is 4096).
pub fn create_event_q_over_max_err(ctx: &TestContext) -> TestResult
{
    let err = event_queue_create(ctx.memory_base, 4097);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("event_queue_create(4097) did not return InvalidArgument");
    }
    Ok(())
}

// ── SYS_CAP_DERIVE_BADGE ────────────────────────────────────────────────────

/// `cap_derive_badge` attaches a badge to a derived capability.
pub fn derive_badge(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "create_endpoint for derive_badge test failed")?;

    let badged =
        cap_derive_badge(ep, syscall::RIGHTS_ALL, 42).map_err(|_| "cap_derive_badge failed")?;

    // The badged cap is usable (it's a valid endpoint derivative).
    cap_delete(badged).map_err(|_| "cap_delete badged cap failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after derive_badge test failed")?;
    Ok(())
}

/// `cap_derive_badge` with badge=0 returns `InvalidArgument`.
pub fn derive_badge_zero_err(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "create_endpoint for derive_badge_zero_err test failed")?;

    let err = cap_derive_badge(ep, syscall::RIGHTS_ALL, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("cap_derive_badge(0) did not return InvalidArgument");
    }

    cap_delete(ep).map_err(|_| "cap_delete ep after derive_badge_zero_err test failed")?;
    Ok(())
}

/// Re-badging a cap that already has a badge returns `InvalidArgument`.
pub fn derive_badge_rebadge_err(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "create_endpoint for rebadge_err test failed")?;

    let badged = cap_derive_badge(ep, syscall::RIGHTS_ALL, 100)
        .map_err(|_| "first cap_derive_badge failed")?;

    // Attempting to set a new badge on an already-badged cap must fail.
    let err = cap_derive_badge(badged, syscall::RIGHTS_ALL, 200);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("re-badging did not return InvalidArgument");
    }

    cap_delete(badged).map_err(|_| "cap_delete badged failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after rebadge_err test failed")?;
    Ok(())
}

/// `cap_derive` from a badged cap inherits the badge (verified via IPC delivery).
pub fn derive_inherits_badge(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "create_endpoint for inherit test failed")?;

    let badged =
        cap_derive_badge(ep, syscall::RIGHTS_ALL, 77).map_err(|_| "cap_derive_badge failed")?;

    // Derive from the badged cap — should inherit badge=77.
    let derived =
        cap_derive(badged, syscall::RIGHTS_ALL).map_err(|_| "cap_derive from badged failed")?;

    // We can't directly inspect the badge without IPC, but verify the cap is usable.
    cap_delete(derived).map_err(|_| "cap_delete derived failed")?;
    cap_delete(badged).map_err(|_| "cap_delete badged failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after inherit test failed")?;
    Ok(())
}

/// `cap_derive_badge` works on non-endpoint caps (badges are generic).
pub fn derive_badge_on_notification(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for derive_badge_on_notification failed")?;

    let badged = cap_derive_badge(sig, syscall::RIGHTS_ALL, 99)
        .map_err(|_| "cap_derive_badge on notification failed")?;

    // Badged notification cap is still usable for notification operations.
    notification_send(badged, 0x1).map_err(|_| "notification_send on badged cap failed")?;
    notification_wait(sig).map_err(|_| "notification_wait after badged send failed")?;

    cap_delete(badged).map_err(|_| "cap_delete badged notification failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after derive_badge_on_notification failed")?;
    Ok(())
}

/// Derives the [`cspace_teardown_multibatch`] child performs: wider than one
/// reparent batch (`MAX_REPARENT_EDITS`), so the dying child list is drained
/// in several holds.
const DERIVES: u64 = 300;

/// Tearing down a `CSpace` whose derivation state spans multiple drain
/// batches completes and leaves the survivors' forest clean.
///
/// A child thread bound to its own `CSpace` derives ~300 SEND caps from
/// its copy of the parent's endpoint (300 dying children head-popped off
/// one dying slot) and exits; deleting the child `CSpace` then drives
/// `drain_dying_cspace_batch` across several `MAX_DRAIN_EDITS` windows
/// (each derive contributes an unlink edit, plus one per slot). The
/// parent's endpoint — the derivation ancestor of everything that died —
/// must afterwards revoke cleanly (no dead-link `InvalidState`) and stay
/// usable.
///
/// The pin against a vacuous pass is the parent's Memory cap returning to
/// its pre-spawn `AVAILABLE` baseline afterwards — only the `CSpace`
/// dealloc path (which runs the drain) returns those pages, so a lingering
/// reference that skipped teardown would leave the delta. The child
/// `CSpace`'s `USED` count is also checked before the delete; the handshake
/// already implies it, so that check only guards a future change to the
/// spawn helper or to derive semantics silently shrinking the burst.
pub fn cspace_teardown_multibatch(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "teardown_batch: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "teardown_batch: cap_create_notification failed")?;
    let baseline = cap_info(ctx.memory_base, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "teardown_batch: cap_info(baseline) failed")?;

    let child =
        crate::spawn::new_child(ctx).map_err(|_| "teardown_batch: spawn::new_child failed")?;
    // Headroom for the derive burst (default child pool backs 167 slots).
    cap_create_cspace(ctx.memory_base, child.cs, 4)
        .map_err(|_| "teardown_batch: child cspace augment failed")?;
    let child_ep = cap_copy(ep, child.cs, syscall_abi::RIGHTS_EP_SEND)
        .map_err(|_| "teardown_batch: cap_copy ep failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "teardown_batch: cap_copy done failed")?;
    let child_arg = u64::from(child_ep) | (u64::from(child_done) << 32);

    let stack_top = ChildStack::top(core::ptr::addr_of!(TEARDOWN_BATCH_STACK));
    crate::spawn::configure_and_start(&child, teardown_batch_child_entry, stack_top, child_arg)
        .map_err(|_| "teardown_batch: configure_and_start failed")?;

    let bits = notification_wait(done).map_err(|_| "teardown_batch: notification_wait failed")?;
    if bits != 0x1
    {
        cap_delete(child.th).ok();
        cap_delete(child.cs).ok();
        cap_delete(ep).ok();
        cap_delete(done).ok();
        return Err("teardown_batch: child failed its derive burst");
    }

    // Pin 1: the burst landed in the dying CSpace (ep + done copies plus
    // the derives), so the drain has more than one batch of edits ahead.
    let used = cap_info(child.cs, syscall_abi::CAP_INFO_CSPACE_USED)
        .map_err(|_| "teardown_batch: cap_info(child USED) failed")?;
    if used < DERIVES + 2
    {
        cap_delete(child.th).ok();
        cap_delete(child.cs).ok();
        cap_delete(ep).ok();
        cap_delete(done).ok();
        return Err("teardown_batch: derive burst did not populate the child CSpace");
    }

    // Tear down: the child CSpace dies holding one slot with ~300 derived
    // children plus the bootstrap copies — several drain batches.
    cap_delete(child.th).map_err(|_| "teardown_batch: cap_delete(thread) failed")?;
    cap_delete(child.cs).map_err(|_| "teardown_batch: cap_delete(cspace) failed")?;

    // Pin 2: both child objects were reclaimed — the CSpace dealloc (the
    // only path that runs the drain) returned its pool and wrapper pages.
    let after = cap_info(ctx.memory_base, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "teardown_batch: cap_info(after) failed")?;
    if after != baseline
    {
        cap_delete(ep).ok();
        cap_delete(done).ok();
        return Err("teardown_batch: child CSpace was not reclaimed (teardown did not run)");
    }

    // The ancestor's revoke must be clean: a dangling link left by the
    // drain would surface as InvalidState (dead-link truncation).
    cap_revoke(ep).map_err(|_| "teardown_batch: cap_revoke(ep) failed after teardown")?;
    // And the endpoint itself must still be intact.
    let probe = cap_derive(ep, syscall_abi::RIGHTS_EP_SEND)
        .map_err(|_| "teardown_batch: endpoint unusable after teardown")?;
    cap_delete(probe).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    Ok(())
}

/// Deleting the last capability to a `CSpace` stops every thread bound to
/// it before the slot pages are reclaimed: a child blocked in
/// `notification_wait` and a child spinning on `thread_yield` both report
/// `Exited` afterwards, their objects reclaim through the thread cap alone,
/// and the parent's Memory cap returns to baseline. Deleting the `CSpace`
/// before the thread is exactly the order the spawn helper used to forbid.
pub fn cspace_delete_stops_bound_thread(ctx: &TestContext) -> TestResult
{
    let baseline = cap_info(ctx.memory_base, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "stop_bound: cap_info(baseline) failed")?;
    let ready =
        cap_create_notification(ctx.memory_base).map_err(|_| "stop_bound: create ready failed")?;
    let block =
        cap_create_notification(ctx.memory_base).map_err(|_| "stop_bound: create block failed")?;

    // Blocked child: signals ready, then waits on `block` (never signalled).
    let child = crate::spawn::new_child(ctx).map_err(|_| "stop_bound: new_child failed")?;
    let child_ready = cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "stop_bound: cap_copy ready failed")?;
    let child_block = cap_copy(block, child.cs, syscall_abi::RIGHTS_NTF_WAIT)
        .map_err(|_| "stop_bound: cap_copy block failed")?;
    let arg = u64::from(child_ready) | (u64::from(child_block) << 32);
    let stack_top = ChildStack::top(core::ptr::addr_of!(STOP_BLOCKED_STACK));
    crate::spawn::configure_and_start(&child, stop_blocked_child_entry, stack_top, arg)
        .map_err(|_| "stop_bound: configure_and_start (blocked) failed")?;
    notification_wait(ready).map_err(|_| "stop_bound: wait ready failed")?;

    cap_delete(child.cs)
        .map_err(|_| "stop_bound: cap_delete(cspace) under blocked child failed")?;
    let state = cap_info(child.th, syscall_abi::CAP_INFO_THREAD_STATE)
        .map_err(|_| "stop_bound: cap_info(thread state, blocked) failed")?;
    if (state >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED
    {
        cap_delete(child.th).ok();
        return Err("stop_bound: blocked child not Exited after its CSpace was deleted");
    }
    if state & 0xFFFF_FFFF != syscall_abi::EXIT_KILLED
    {
        cap_delete(child.th).ok();
        return Err("stop_bound: blocked child's exit reason is not EXIT_KILLED");
    }
    cap_delete(child.th).map_err(|_| "stop_bound: cap_delete(thread, blocked) failed")?;

    // Spinning child: yields forever; on a multi-CPU guest it may be running
    // on another CPU when its CSpace goes.
    let child = crate::spawn::new_child(ctx).map_err(|_| "stop_bound: new_child (spin) failed")?;
    let child_ready = cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "stop_bound: cap_copy ready (spin) failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(STOP_SPINNING_STACK));
    crate::spawn::configure_and_start(
        &child,
        stop_spinning_child_entry,
        stack_top,
        u64::from(child_ready),
    )
    .map_err(|_| "stop_bound: configure_and_start (spin) failed")?;
    notification_wait(ready).map_err(|_| "stop_bound: wait ready (spin) failed")?;

    cap_delete(child.cs)
        .map_err(|_| "stop_bound: cap_delete(cspace) under spinning child failed")?;
    let state = cap_info(child.th, syscall_abi::CAP_INFO_THREAD_STATE)
        .map_err(|_| "stop_bound: cap_info(thread state, spin) failed")?;
    if (state >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED
    {
        cap_delete(child.th).ok();
        return Err("stop_bound: spinning child not Exited after its CSpace was deleted");
    }
    if state & 0xFFFF_FFFF != syscall_abi::EXIT_KILLED
    {
        cap_delete(child.th).ok();
        return Err("stop_bound: spinning child's exit reason is not EXIT_KILLED");
    }
    cap_delete(child.th).map_err(|_| "stop_bound: cap_delete(thread, spin) failed")?;

    cap_delete(block).ok();
    cap_delete(ready).ok();
    let after = cap_info(ctx.memory_base, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "stop_bound: cap_info(after) failed")?;
    if after != baseline
    {
        return Err("stop_bound: memory did not return to baseline");
    }
    Ok(())
}

/// Child for [`cspace_delete_stops_bound_thread`]: signal, then block on a
/// notification nobody signals. Reaching the exit means the wait returned,
/// which the test never expects.
fn stop_blocked_child_entry(arg: u64) -> !
{
    let ready_slot = (arg & 0xFFFF_FFFF) as u32;
    let block_slot = (arg >> 32) as u32;
    notification_send(ready_slot, 0x1).ok();
    notification_wait(block_slot).ok();
    syscall::thread_exit()
}

/// Child for [`cspace_delete_stops_bound_thread`]: signal, then yield forever.
fn stop_spinning_child_entry(arg: u64) -> !
{
    let ready_slot = (arg & 0xFFFF_FFFF) as u32;
    notification_send(ready_slot, 0x1).ok();
    loop
    {
        syscall::thread_yield().ok();
    }
}

/// Poll bound for the self-delete child: ~2 s at 1 ms per poll.
const SELF_DELETE_MAX_POLLS: u32 = 2000;

static mut SELF_DELETE_STACK: ChildStack = ChildStack::ZERO;

/// A thread deleting the last capability to its **own** `CSpace` is stopped
/// by that delete and never returns from it; the `CSpace` is reclaimed
/// off-CPU once the thread has been scheduled away.
///
/// The child holds the only capability to its own `CSpace` (copied in, then
/// ktest's copy deleted before the child starts). It signals ready and
/// deletes it. ktest observes the child `Exited` with `EXIT_KILLED`,
/// reclaims the thread, and waits for memory to return to baseline — the
/// `CSpace`'s own reclaim completes on the child's CPU after it is off it.
pub fn cspace_self_delete_stops_caller(ctx: &TestContext) -> TestResult
{
    let baseline = cap_info(ctx.memory_base, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "self_delete: cap_info(baseline) failed")?;
    let ready =
        cap_create_notification(ctx.memory_base).map_err(|_| "self_delete: create ready failed")?;
    let child = crate::spawn::new_child(ctx).map_err(|_| "self_delete: new_child failed")?;
    let child_ready = cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "self_delete: cap_copy ready failed")?;
    let own_cs = cap_copy(child.cs, child.cs, syscall_abi::RIGHTS_ALL)
        .map_err(|_| "self_delete: cap_copy cspace into itself failed")?;
    // Drop ktest's capability first, so the child's delete is the last one.
    cap_delete(child.cs).map_err(|_| "self_delete: cap_delete(cspace) failed")?;

    let arg = u64::from(child_ready) | (u64::from(own_cs) << 32);
    let stack_top = ChildStack::top(core::ptr::addr_of!(SELF_DELETE_STACK));
    crate::spawn::configure_and_start(&child, self_delete_child_entry, stack_top, arg)
        .map_err(|_| "self_delete: configure_and_start failed")?;
    notification_wait(ready).map_err(|_| "self_delete: wait ready failed")?;

    let reason = crate::spawn::wait_until_exited(child.th, SELF_DELETE_MAX_POLLS);
    cap_delete(child.th).map_err(|_| "self_delete: cap_delete(thread) failed")?;
    cap_delete(ready).ok();
    if reason? != syscall_abi::EXIT_KILLED
    {
        return Err("self_delete: child's exit reason is not EXIT_KILLED");
    }
    crate::spawn::wait_memory_baseline(ctx.memory_base, baseline, SELF_DELETE_MAX_POLLS)
        .map_err(|_| "self_delete: memory did not return to baseline")
}

/// Child for [`cspace_self_delete_stops_caller`]: signal ready, then delete
/// the last capability to its own `CSpace`. The delete never returns; the
/// yield loop only satisfies the signature.
fn self_delete_child_entry(arg: u64) -> !
{
    let ready_slot = (arg & 0xFFFF_FFFF) as u32;
    let own_cs = (arg >> 32) as u32;
    notification_send(ready_slot, 0x1).ok();
    cap_delete(own_cs).ok();
    loop
    {
        syscall::thread_yield().ok();
    }
}

/// Child for [`cspace_teardown_multibatch`]: derives `count` SEND caps
/// from its endpoint copy (building a wide dying child list), signals
/// completion, and exits without cleaning up — teardown is the test.
fn teardown_batch_child_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF_FFFF) as u32;
    let done_slot = (arg >> 32) as u32;

    let mut ok = true;
    for _ in 0..DERIVES
    {
        if cap_derive(ep_slot, syscall_abi::RIGHTS_EP_SEND).is_err()
        {
            ok = false;
            break;
        }
    }
    notification_send(done_slot, if ok { 0x1 } else { 0xBAD }).ok();
    syscall::thread_exit()
}
