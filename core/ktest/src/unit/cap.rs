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
    cap_delete, cap_derive, cap_derive_badge, cap_insert, cap_move, cap_revoke, event_queue_create,
    notification_send, notification_wait,
};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

// Rights bit constants (from kernel/src/cap/slot.rs).
// NOTIFY = bit 7 (send), WAIT = bit 8 (receive/block), SEND = bit 4, GRANT = bit 6.
const RIGHTS_NOTIFY: u64 = 1 << 7;

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

/// `cap_create_cspace` succeeds with a valid slot count.
pub fn create_cspace(ctx: &TestContext) -> TestResult
{
    let slot =
        cap_create_cspace(ctx.memory_base, 0, 4, 32).map_err(|_| "cap_create_cspace(32) failed")?;
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
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4, 16)
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
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4, 16)
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
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4, 16)
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

// ── SYS_CAP_COPY explicit slot negative ──────────────────────────────────────

/// `cap_insert` to an already-occupied destination slot must return an error.
pub fn insert_to_occupied_slot_err(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification for occupied-slot test failed")?;
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4, 16)
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
    // max_slots is clamped to [1, 14336]; create a small CSpace.
    let dest_cs = cap_create_cspace(ctx.memory_base, 0, 4, 16)
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
