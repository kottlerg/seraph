// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/cap_generation_wide.rs

//! Integration: the full width of a cap handle is validated (#637).
//!
//! Exercises `docs/capability-model.md` § Capability Handle Format with
//! generations past one byte and handle bits past 32:
//!
//! 1. A slot recycled 256 times keeps its index while its generation moves
//!    past 255, and the handle from 256 recycles earlier stays stale. A
//!    generation stored or carried in 8 bits wraps back to that handle's
//!    value there, and the stale handle would name the new occupant.
//! 2. A live handle with only its high half altered (bit 63 set, the
//!    generation off by one, the generation cleared) is refused, so the
//!    kernel decodes the whole register and truncates nothing.
//! 3. A call that transfers the stale handle is refused before it blocks: the
//!    IPC buffer's cap block carries the full handle, generation included.
//! 4. A cap-bearing call with no IPC buffer registered is refused with
//!    `InvalidArgument`, since the cap handles travel in that page.

use ipc::IpcMessage;
use syscall::{
    cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set, notification_send,
    raw_ipc_call,
};
use syscall_abi::{
    CAP_GEN_MASK, SyscallError, cap_handle_encode, cap_handle_gen, cap_handle_index,
};

use crate::{TestContext, TestResult};

/// Recycles of one slot between the stale handle and the live one: the
/// period of an 8-bit generation.
const RECYCLES: u32 = 256;

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("cap_generation_wide: starting");

    let (stale, live) = recycle_past_one_byte(ctx)?;
    let result = check_live_and_stale(ctx, stale, live);
    cap_delete(live).ok();
    result?;

    crate::log("cap_generation_wide: PASS");
    Ok(())
}

/// Create a notification, then delete and recreate it `RECYCLES` times on the
/// same slot (the free list is LIFO). Returns `(stale, live)`: the first
/// handle and the last occupant's.
fn recycle_past_one_byte(ctx: &TestContext) -> Result<(u64, u64), &'static str>
{
    let stale = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_generation_wide: cap_create_notification (first) failed")?;
    let mut live = stale;
    for _ in 0..RECYCLES
    {
        cap_delete(live)
            .map_err(|_| "cap_generation_wide: cap_delete in the recycle loop failed")?;
        live = cap_create_notification(ctx.memory_base)
            .map_err(|_| "cap_generation_wide: cap_create_notification in the loop failed")?;
        if cap_handle_index(live) != cap_handle_index(stale)
        {
            cap_delete(live).ok();
            return Err("cap_generation_wide: freed slot was not recycled (index differs)");
        }
    }
    if cap_handle_gen(live) != cap_handle_gen(stale) + RECYCLES
    {
        cap_delete(live).ok();
        return Err("cap_generation_wide: generation did not advance once per recycle");
    }
    Ok((stale, live))
}

fn check_live_and_stale(ctx: &TestContext, stale: u64, live: u64) -> TestResult
{
    // The live handle works.
    notification_send(live, 0x1).map_err(|_| "cap_generation_wide: live handle send failed")?;

    // (1) The handle from 256 recycles earlier is stale, not an alias.
    expect_invalid_cap(
        notification_send(stale, 0x1),
        "cap_generation_wide: handle 256 recycles stale still names the slot",
    )?;

    // (2) Altering only the bits above the index is refused.
    let index = cap_handle_index(live);
    let generation = cap_handle_gen(live);
    let altered = [
        live | (1u64 << 63),
        cap_handle_encode(index, generation.wrapping_add(1) & CAP_GEN_MASK),
        u64::from(index),
    ];
    for handle in altered
    {
        expect_invalid_cap(
            notification_send(handle, 0x1),
            "cap_generation_wide: handle with an altered high half accepted",
        )?;
    }

    // (3) and (4) need an endpoint to call; nothing receives on it, so a call
    // that passed its checks would block, and each call below must fail first.
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_generation_wide: cap_create_endpoint failed")?;
    let result = check_call_paths(ctx, ep, stale);
    cap_delete(ep).ok();
    result
}

fn check_call_paths(ctx: &TestContext, ep: u64, stale: u64) -> TestResult
{
    // (3) The cap block carries the stale handle in full.
    let msg = IpcMessage::builder(1).cap(stale).build();
    // SAFETY: ctx.ipc_buf is ktest's registered IPC buffer page.
    match unsafe { ipc::ipc_call(ep, &msg, ctx.ipc_buf) }
    {
        Err(e) if e == SyscallError::InvalidCapability as i64 =>
        {}
        Ok(_) => return Err("cap_generation_wide: call transferring a stale handle succeeded"),
        Err(_) => return Err("cap_generation_wide: stale-handle call failed with the wrong error"),
    }

    // (4) With no IPC buffer registered, a cap-bearing call cannot name its
    // caps. Deregister, call, and re-register the page before any check can
    // return, so later tests keep their buffer.
    // SAFETY: deregistering (0) dedicates no page.
    unsafe { ipc_buffer_set(0) }.map_err(|_| "cap_generation_wide: ipc_buffer_set(0) failed")?;
    let unbuffered = raw_ipc_call(ep, 1, 0, 1);
    // SAFETY: ctx.ipc_buf is the page ktest registered at startup, dedicated
    // to the kernel's IPC access under the contract it was first registered
    // with; re-registering it restores that state.
    unsafe { ipc_buffer_set(ctx.ipc_buf as u64) }
        .map_err(|_| "cap_generation_wide: re-registering the IPC buffer failed")?;
    match unbuffered
    {
        Err(e) if e == SyscallError::InvalidArgument as i64 => Ok(()),
        Ok(_) => Err("cap_generation_wide: cap-bearing call with no IPC buffer succeeded"),
        Err(_) =>
        {
            Err("cap_generation_wide: unbuffered cap-bearing call failed with the wrong error")
        }
    }
}

fn expect_invalid_cap(result: Result<(), i64>, msg: &'static str) -> TestResult
{
    match result
    {
        Err(e) if e == SyscallError::InvalidCapability as i64 => Ok(()),
        _ => Err(msg),
    }
}
