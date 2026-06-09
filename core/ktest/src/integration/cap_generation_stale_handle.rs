// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/cap_generation_stale_handle.rs

//! Integration: a same-`CSpace` stale cap handle fails closed (#349).
//!
//! Per-slot generation is the mechanism that closes the stale-slot alias class.
//! This is the same-`CSpace` counterpart to `cross_cspace_revoke_no_alias`: a
//! handle reused within one `CSpace` after its slot is freed and recycled.
//! Create a notification, delete it (freeing and generation-bumping the slot),
//! create another notification that reclaims the same slot index (LIFO free
//! list), then replay the original handle. The original must fail with
//! `InvalidCapability` (its generation no longer matches the slot) rather than
//! aliasing the new occupant, while the new handle works.

use syscall::{cap_create_notification, cap_delete, notification_send, notification_wait};
use syscall_abi::{SyscallError, cap_handle_gen, cap_handle_index};

use crate::{TestContext, TestResult};

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("cap_generation_stale_handle: starting");

    // First notification — capture its handle, then delete it (free + bump gen).
    let stale = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_generation_stale_handle: cap_create_notification (first) failed")?;
    cap_delete(stale).map_err(|_| "cap_generation_stale_handle: cap_delete (first) failed")?;

    // Second notification — LIFO reclaims the freed slot at the same index, with
    // the bumped generation.
    let fresh = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_generation_stale_handle: cap_create_notification (second) failed")?;

    // The two handles must address the same slot index but differ in generation;
    // otherwise the slot was not recycled and the test would not exercise the
    // alias window.
    if cap_handle_index(stale) != cap_handle_index(fresh)
    {
        // Slot not reused (e.g. cspace grew); not a failure of the fix, but the
        // scenario was not exercised. Clean up and report so the gap is visible.
        cap_delete(fresh).ok();
        return Err("cap_generation_stale_handle: freed slot was not recycled (index differs)");
    }
    if cap_handle_gen(stale) == cap_handle_gen(fresh)
    {
        cap_delete(fresh).ok();
        return Err("cap_generation_stale_handle: generation did not advance on recycle");
    }

    // The stale handle must be rejected (generation mismatch), not aliased onto
    // the new occupant.
    match notification_send(stale, 0x1)
    {
        Err(e) if e == SyscallError::InvalidCapability as i64 =>
        {}
        Ok(()) =>
        {
            cap_delete(fresh).ok();
            return Err(
                "cap_generation_stale_handle: stale handle still usable (aliased the new cap)",
            );
        }
        Err(_) =>
        {
            cap_delete(fresh).ok();
            return Err("cap_generation_stale_handle: stale handle failed with the wrong error");
        }
    }

    // The fresh handle must still work end-to-end.
    notification_send(fresh, 0x2)
        .map_err(|_| "cap_generation_stale_handle: fresh handle send failed")?;
    let bits = notification_wait(fresh)
        .map_err(|_| "cap_generation_stale_handle: fresh handle wait failed")?;
    if bits != 0x2
    {
        cap_delete(fresh).ok();
        return Err("cap_generation_stale_handle: fresh handle delivered wrong bits");
    }

    cap_delete(fresh).ok();
    crate::log("cap_generation_stale_handle: PASS");
    Ok(())
}
