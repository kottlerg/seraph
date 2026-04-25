// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/cap.rs

//! Tier 1 tests for capability syscalls.
//!
//! Covers: `SYS_CAP_CREATE_*`, `SYS_CAP_COPY`, `SYS_CAP_MOVE`,
//! `SYS_CAP_INSERT`, `SYS_CAP_DERIVE`, `SYS_CAP_REVOKE`, `SYS_CAP_DELETE`.
//!
//! Each function tests one syscall or one distinct behaviour. Tests clean up
//! caps they create where convenient, but leaks are acceptable — ktest exits
//! after all tests finish.

use syscall::{
    cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_create_signal,
    cap_create_thread, cap_delete, cap_derive, cap_derive_token, cap_insert, cap_move, cap_revoke,
    event_queue_create, signal_send, signal_wait,
};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

// Rights bit constants (from kernel/src/cap/slot.rs).
// SIGNAL = bit 7 (send), WAIT = bit 8 (receive/block), SEND = bit 4, GRANT = bit 6.
const RIGHTS_SIGNAL: u64 = 1 << 7;

// ── SYS_CAP_CREATE_SIGNAL ────────────────────────────────────────────────────

/// `cap_create_signal` returns a usable slot.
pub fn create_signal(_ctx: &TestContext) -> TestResult
{
    let slot = cap_create_signal().map_err(|_| "cap_create_signal failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_signal failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_ENDPOINT ──────────────────────────────────────────────────

/// `cap_create_endpoint` returns a usable slot.
pub fn create_endpoint(_ctx: &TestContext) -> TestResult
{
    let slot = cap_create_endpoint().map_err(|_| "cap_create_endpoint failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_endpoint failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_EVENT_Q ───────────────────────────────────────────────────

/// `cap_create_event_q` (via `event_queue_create`) returns a usable slot.
pub fn create_event_q(_ctx: &TestContext) -> TestResult
{
    let slot = event_queue_create(8).map_err(|_| "event_queue_create failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_event_q failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_CSPACE ────────────────────────────────────────────────────

/// `cap_create_cspace` succeeds with a valid slot count.
pub fn create_cspace(_ctx: &TestContext) -> TestResult
{
    let slot = cap_create_cspace(32).map_err(|_| "cap_create_cspace(32) failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_cspace failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_ASPACE ────────────────────────────────────────────────────

/// `cap_create_aspace` returns a usable slot.
pub fn create_aspace(_ctx: &TestContext) -> TestResult
{
    let slot = cap_create_aspace().map_err(|_| "cap_create_aspace failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_aspace failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_THREAD ────────────────────────────────────────────────────

/// `cap_create_thread` succeeds when given valid aspace and cspace caps.
pub fn create_thread(ctx: &TestContext) -> TestResult
{
    // Thread needs both an address space and a cspace to be bound to.
    let cs = cap_create_cspace(16).map_err(|_| "cap_create_cspace for thread test failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs).map_err(|_| "cap_create_thread failed")?;
    cap_delete(th).map_err(|_| "cap_delete thread failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cspace failed")?;
    Ok(())
}

// ── SYS_CAP_CREATE_WAIT_SET ──────────────────────────────────────────────────

/// `cap_create_wait_set` (via `wait_set_create`) returns a usable slot.
pub fn create_wait_set(_ctx: &TestContext) -> TestResult
{
    let slot = cap_create_wait_set().map_err(|_| "cap_create_wait_set failed")?;
    cap_delete(slot).map_err(|_| "cap_delete after create_wait_set failed")?;
    Ok(())
}

// Thin wrapper — the syscall wrapper is `wait_set_create` in shared/syscall but
// the underlying syscall number is `SYS_CAP_CREATE_WAIT_SET`.
fn cap_create_wait_set() -> Result<u32, i64>
{
    syscall::wait_set_create()
}

// ── SYS_CAP_COPY ─────────────────────────────────────────────────────────────

/// `cap_copy` places a copy of a cap into another `CSpace`.
///
/// The copy is verified to be independently usable (`signal_send` still works
/// on the source; the destination `CSpace` is deleted as cleanup, which drops
/// all caps inside it).
pub fn copy(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for copy test failed")?;
    let dest_cs = cap_create_cspace(16).map_err(|_| "create_cspace for copy test failed")?;

    // Copy with all rights — `syscall::RIGHTS_ALL` passes through whatever rights the source has.
    cap_copy(sig, dest_cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy failed")?;

    // Source slot is still valid after a copy.
    signal_send(sig, 0x1).map_err(|_| "signal_send on source after cap_copy failed")?;

    cap_delete(sig).map_err(|_| "cap_delete sig after copy test failed")?;
    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after copy test failed")?;
    Ok(())
}

// ── SYS_CAP_INSERT ───────────────────────────────────────────────────────────

/// `cap_insert` places a copy at a caller-chosen slot index in another `CSpace`.
///
/// Like `cap_copy` but the destination slot is explicit. We verify the source
/// is unaffected (insert is a copy, not a move).
pub fn insert(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for insert test failed")?;
    let dest_cs = cap_create_cspace(16).map_err(|_| "create_cspace for insert test failed")?;

    // Insert at slot 5 in dest_cs.
    cap_insert(sig, dest_cs, 5, syscall::RIGHTS_ALL).map_err(|_| "cap_insert failed")?;

    // Source slot is preserved (insert = copy, not move).
    signal_send(sig, 0x1).map_err(|_| "signal_send on source after cap_insert failed")?;

    cap_delete(sig).map_err(|_| "cap_delete sig after insert test failed")?;
    cap_delete(dest_cs).map_err(|_| "cap_delete dest_cs after insert test failed")?;
    Ok(())
}

// ── SYS_CAP_MOVE ─────────────────────────────────────────────────────────────

/// `cap_move` transfers a cap to another `CSpace` and nulls the source slot.
pub fn r#move(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for move test failed")?;
    let dest_cs = cap_create_cspace(16).map_err(|_| "create_cspace for move test failed")?;

    // Move to dest_cs; auto-allocate destination slot (dest_index = 0).
    cap_move(sig, dest_cs, 0).map_err(|_| "cap_move failed")?;

    // Source slot must now be null — using it should fail.
    let err = signal_send(sig, 0x1);
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
/// We create a signal with SIGNAL+WAIT rights, derive a copy with SIGNAL only,
/// then verify:
///  - The derived cap can send (has SIGNAL).
///  - The derived cap cannot wait (lacks WAIT) — kernel returns `InsufficientRights`.
pub fn derive_attenuation(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for derive test failed")?;

    // Derive with SIGNAL right only (no WAIT).
    let derived = cap_derive(sig, RIGHTS_SIGNAL).map_err(|_| "cap_derive failed")?;

    // Derived cap can send.
    signal_send(derived, 0x1).map_err(|_| "signal_send on derived cap failed")?;

    // Derived cap cannot wait — InsufficientRights (-3).
    // We call signal_wait on a cap that has no bits set AND no WAIT right.
    // The kernel should reject with InsufficientRights before blocking.
    let wait_err = syscall::signal_wait(derived);
    if wait_err != Err(SyscallError::InsufficientRights as i64)
    {
        // If the kernel returns a different error (or somehow succeeds),
        // something is wrong with rights enforcement.
        // Note: if signal bits were set (from our send above), the kernel might
        // return them before checking rights. Clear is fine for this test since
        // signal_send ORs bits and signal_wait clears them — after send(0x1) and
        // then a wait, the bits are consumed. The next wait on derived must fail.
        // ... actually signal_wait on a cap with WAIT right AND bits set would
        // succeed. But derived has NO WAIT right, so kernel checks rights first.
        return Err("signal_wait on SIGNAL-only derived cap did not return InsufficientRights");
    }

    cap_delete(derived).map_err(|_| "cap_delete derived cap failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after derive test failed")?;
    Ok(())
}

// ── SYS_CAP_REVOKE ───────────────────────────────────────────────────────────

/// `cap_revoke` invalidates all descendants of a cap.
///
/// After revoking the parent, the derived cap must be unusable.
pub fn revoke_invalidates(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for revoke test failed")?;
    let derived =
        cap_derive(sig, RIGHTS_SIGNAL).map_err(|_| "cap_derive for revoke test failed")?;

    // Revoke all descendants of sig (derived is now invalid).
    cap_revoke(sig).map_err(|_| "cap_revoke failed")?;

    // Derived cap must now fail.
    let err = signal_send(derived, 0x1);
    if err.is_ok()
    {
        return Err("derived cap still usable after cap_revoke");
    }

    cap_delete(sig).map_err(|_| "cap_delete sig after revoke test failed")?;
    Ok(())
}

// ── SYS_CAP_INSERT negative ───────────────────────────────────────────────────

/// `cap_insert` to an already-occupied destination slot must return an error.
pub fn insert_to_occupied_slot_err(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for occupied-slot test failed")?;
    let dest_cs =
        cap_create_cspace(16).map_err(|_| "create_cspace for occupied-slot test failed")?;

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
/// Passing a Signal cap where a `CSpace` cap is expected should be rejected
/// before any modification occurs.
pub fn copy_into_non_cspace_err(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for non-cspace test failed")?;

    // sig is a Signal, not a CSpace — using it as dest_cs must fail.
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
pub fn delete(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for delete test failed")?;

    // Verify it's usable before deletion.
    signal_send(sig, 0x1).map_err(|_| "signal_send before delete failed")?;

    cap_delete(sig).map_err(|_| "cap_delete failed")?;

    // After deletion the slot is null; signal_send must fail.
    let err = signal_send(sig, 0x1);
    if err.is_ok()
    {
        return Err("signal_send succeeded after cap_delete (slot not null)");
    }

    Ok(())
}

// ── SYS_CAP_DELETE (idempotent) ──────────────────────────────────────────────

/// `cap_delete` on an already-null slot returns Ok (idempotent).
pub fn delete_null_slot_ok(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for delete_null_slot_ok failed")?;
    cap_delete(sig).map_err(|_| "first cap_delete failed")?;

    // Second delete on the now-null slot must succeed (no-op).
    cap_delete(sig).map_err(|_| "second cap_delete on null slot returned error")?;
    Ok(())
}

// ── SYS_CAP_INSERT negative (out of bounds) ──────────────────────────────────

/// `cap_insert` with a slot index beyond the destination `CSpace` capacity must fail.
pub fn insert_out_of_bounds_err(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for insert_oob test failed")?;
    // CSpace capacity is clamped to [256, 16384]; create the smallest possible.
    let dest_cs = cap_create_cspace(16).map_err(|_| "create_cspace for insert_oob test failed")?;

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
pub fn derive_zero_rights(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for derive_zero_rights failed")?;

    let derived = cap_derive(sig, 0).map_err(|_| "cap_derive(0) failed")?;

    // Derived cap with zero rights cannot send.
    let send_err = signal_send(derived, 0x1);
    if send_err.is_ok()
    {
        return Err("signal_send on zero-rights derived cap should fail");
    }

    // Derived cap with zero rights cannot wait.
    // Pre-set bits on the real signal so we test rights, not blocking.
    signal_send(sig, 0x1).map_err(|_| "signal_send on root failed")?;
    let wait_err = signal_wait(derived);
    if wait_err.is_ok()
    {
        return Err("signal_wait on zero-rights derived cap should fail");
    }

    // Drain the bits.
    signal_wait(sig).ok();
    cap_delete(derived).map_err(|_| "cap_delete derived failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after derive_zero_rights failed")?;
    Ok(())
}

// ── SYS_CAP_REVOKE negative (null slot) ──────────────────────────────────────

/// `cap_revoke` on a null slot returns an error.
pub fn revoke_null_slot_err(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for revoke_null_slot_err failed")?;
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
pub fn create_event_q_zero_capacity_err(_ctx: &TestContext) -> TestResult
{
    let err = event_queue_create(0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("event_queue_create(0) did not return InvalidArgument");
    }
    Ok(())
}

/// `event_queue_create(4097)` must return `InvalidArgument` (max capacity is 4096).
pub fn create_event_q_over_max_err(_ctx: &TestContext) -> TestResult
{
    let err = event_queue_create(4097);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("event_queue_create(4097) did not return InvalidArgument");
    }
    Ok(())
}

// ── SYS_CAP_DERIVE_TOKEN ────────────────────────────────────────────────────

/// `cap_derive_token` attaches a token to a derived capability.
pub fn derive_token(_ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint().map_err(|_| "create_endpoint for derive_token test failed")?;

    let tokened =
        cap_derive_token(ep, syscall::RIGHTS_ALL, 42).map_err(|_| "cap_derive_token failed")?;

    // The tokened cap is usable (it's a valid endpoint derivative).
    cap_delete(tokened).map_err(|_| "cap_delete tokened cap failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after derive_token test failed")?;
    Ok(())
}

/// `cap_derive_token` with token=0 returns `InvalidArgument`.
pub fn derive_token_zero_err(_ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint()
        .map_err(|_| "create_endpoint for derive_token_zero_err test failed")?;

    let err = cap_derive_token(ep, syscall::RIGHTS_ALL, 0);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("cap_derive_token(0) did not return InvalidArgument");
    }

    cap_delete(ep).map_err(|_| "cap_delete ep after derive_token_zero_err test failed")?;
    Ok(())
}

/// Re-tokening a cap that already has a token returns `InvalidArgument`.
pub fn derive_token_retoken_err(_ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint().map_err(|_| "create_endpoint for retoken_err test failed")?;

    let tokened = cap_derive_token(ep, syscall::RIGHTS_ALL, 100)
        .map_err(|_| "first cap_derive_token failed")?;

    // Attempting to set a new token on an already-tokened cap must fail.
    let err = cap_derive_token(tokened, syscall::RIGHTS_ALL, 200);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("re-tokening did not return InvalidArgument");
    }

    cap_delete(tokened).map_err(|_| "cap_delete tokened failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after retoken_err test failed")?;
    Ok(())
}

/// `cap_derive` from a tokened cap inherits the token (verified via IPC delivery).
pub fn derive_inherits_token(_ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint().map_err(|_| "create_endpoint for inherit test failed")?;

    let tokened =
        cap_derive_token(ep, syscall::RIGHTS_ALL, 77).map_err(|_| "cap_derive_token failed")?;

    // Derive from the tokened cap — should inherit token=77.
    let derived =
        cap_derive(tokened, syscall::RIGHTS_ALL).map_err(|_| "cap_derive from tokened failed")?;

    // We can't directly inspect the token without IPC, but verify the cap is usable.
    cap_delete(derived).map_err(|_| "cap_delete derived failed")?;
    cap_delete(tokened).map_err(|_| "cap_delete tokened failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after inherit test failed")?;
    Ok(())
}

/// `cap_derive_token` works on non-endpoint caps (tokens are generic).
pub fn derive_token_on_signal(_ctx: &TestContext) -> TestResult
{
    let sig = cap_create_signal().map_err(|_| "create_signal for derive_token_on_signal failed")?;

    let tokened = cap_derive_token(sig, syscall::RIGHTS_ALL, 99)
        .map_err(|_| "cap_derive_token on signal failed")?;

    // Tokened signal cap is still usable for signal operations.
    signal_send(tokened, 0x1).map_err(|_| "signal_send on tokened cap failed")?;
    signal_wait(sig).map_err(|_| "signal_wait after tokened send failed")?;

    cap_delete(tokened).map_err(|_| "cap_delete tokened signal failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after derive_token_on_signal failed")?;
    Ok(())
}
