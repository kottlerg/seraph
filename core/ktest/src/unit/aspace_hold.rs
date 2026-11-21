// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/aspace_hold.rs

//! Tier 1 — `SYS_ASPACE_HOLD` and `SYS_ASPACE_RELEASE` in isolation, on spaces
//! that hold no thread (the stops, deferrals and resumes are Tier 2's
//! `integration::aspace_hold`; spec: core/kernel/docs/syscalls.md
//! § `SYS_ASPACE_HOLD` and § `SYS_ASPACE_RELEASE`).
//!
//! - A cap that is no address space, a null handle and a stale one are refused
//!   with `InvalidCapability`; a kernel that checks the object type after the
//!   rights, or not at all, fails the first.
//! - A cap without `RIGHTS_AS_CONTROL` is refused with `InsufficientRights` by
//!   both calls; a kernel that checks `Map` or `Read` instead fails it.
//! - The hold state machine: release of a space not held and hold of a held one
//!   are `InvalidState`, and the pair repeats; a kernel that leaves the flag set
//!   by a refused call, or clears it wrongly, fails a step.
//! - Deleting the last cap of a held space succeeds and returns its memory.

use syscall::{
    aspace_hold, aspace_release, cap_create_aspace, cap_create_notification, cap_delete,
    cap_derive, cap_info,
};
use syscall_abi::{CAP_INFO_MEMORY_AVAILABLE, RIGHTS_AS_MAP, RIGHTS_AS_READ, SyscallError};

use crate::{TestContext, TestResult};

const INVALID_CAPABILITY: Result<(), i64> = Err(SyscallError::InvalidCapability as i64);
const INSUFFICIENT_RIGHTS: Result<(), i64> = Err(SyscallError::InsufficientRights as i64);
const INVALID_STATE: Result<(), i64> = Err(SyscallError::InvalidState as i64);

/// Poll bound for the memory return of the last test: about 2 s at 1 ms per
/// poll, applied through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// A cap the test holds, deleted on drop; 0 holds none.
struct Cap(u64);

impl Drop for Cap
{
    fn drop(&mut self)
    {
        if self.0 != 0
        {
            cap_delete(self.0).ok();
        }
    }
}

/// A fresh, empty address space.
fn fresh(ctx: &TestContext) -> Result<Cap, &'static str>
{
    cap_create_aspace(ctx.memory_base, 0, 8)
        .map(Cap)
        .map_err(|_| "aspace_hold: cap_create_aspace failed")
}

/// Both calls refuse a non-address-space cap, the null handle and a stale
/// handle with `InvalidCapability`.
pub fn invalid_capability(ctx: &TestContext) -> TestResult
{
    let notification = cap_create_notification(ctx.memory_base)
        .map_err(|_| "aspace_hold: cap_create_notification failed")?;
    let wrong_type = Cap(notification);
    // The deleted cap's handle names no cap: its generation is stale.
    let stale = cap_create_notification(ctx.memory_base)
        .map_err(|_| "aspace_hold: cap_create_notification failed")?;
    cap_delete(stale).map_err(|_| "aspace_hold: cap_delete failed")?;
    for (handle, what) in [
        (wrong_type.0, "a non-address-space cap"),
        (0, "the null handle"),
        (stale, "a stale handle"),
    ]
    {
        if aspace_hold(handle) != INVALID_CAPABILITY
        {
            crate::log(what);
            return Err("aspace_hold: hold did not refuse the handle with InvalidCapability");
        }
        if aspace_release(handle) != INVALID_CAPABILITY
        {
            crate::log(what);
            return Err("aspace_hold: release did not refuse the handle with InvalidCapability");
        }
    }
    Ok(())
}

/// A cap with `Map` and `Read` but not `Control` is refused by both calls.
pub fn insufficient_rights(ctx: &TestContext) -> TestResult
{
    let space = fresh(ctx)?;
    let weak = Cap(cap_derive(space.0, RIGHTS_AS_MAP | RIGHTS_AS_READ)
        .map_err(|_| "aspace_hold: cap_derive failed")?);
    if aspace_hold(weak.0) != INSUFFICIENT_RIGHTS
    {
        return Err("aspace_hold: hold without Control was not InsufficientRights");
    }
    if aspace_release(weak.0) != INSUFFICIENT_RIGHTS
    {
        return Err("aspace_hold: release without Control was not InsufficientRights");
    }
    // The refused hold left the space unheld: the full cap still reads it so.
    if aspace_release(space.0) != INVALID_STATE
    {
        return Err("aspace_hold: a refused hold changed the space's state");
    }
    Ok(())
}

/// Release of an unheld space, and hold of a held one, are `InvalidState`; the
/// hold and release pair repeats.
pub fn state_machine(ctx: &TestContext) -> TestResult
{
    let space = fresh(ctx)?;
    if aspace_release(space.0) != INVALID_STATE
    {
        return Err("aspace_hold: release of an unheld space was not InvalidState");
    }
    aspace_hold(space.0).map_err(|_| "aspace_hold: first hold failed")?;
    if aspace_hold(space.0) != INVALID_STATE
    {
        return Err("aspace_hold: hold of a held space was not InvalidState");
    }
    aspace_release(space.0).map_err(|_| "aspace_hold: first release failed")?;
    if aspace_release(space.0) != INVALID_STATE
    {
        return Err("aspace_hold: second release was not InvalidState");
    }
    aspace_hold(space.0).map_err(|_| "aspace_hold: second hold failed")?;
    aspace_release(space.0).map_err(|_| "aspace_hold: third release failed")
}

/// Deleting the only cap of a held, empty space succeeds and the space's
/// memory returns.
pub fn delete_held_space(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "aspace_hold: cap_info(baseline) failed")?;
    let mut space = fresh(ctx)?;
    aspace_hold(space.0).map_err(|_| "aspace_hold: hold failed")?;
    let held = core::mem::take(&mut space.0);
    cap_delete(held).map_err(|_| "aspace_hold: cap_delete of a held space failed")?;
    crate::spawn::wait_memory_baseline(memory, baseline, crate::scaled_polls(MAX_POLLS))
        .map_err(|_| "aspace_hold: memory did not return to baseline")
}
