// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/ioport_syscalls.rs

//! Tier 1 (x86-64): `SYS_IOPORT_BIND` and `SYS_IOPORT_SPLIT` on the `IoPort`
//! caps of the initial capability set.

use syscall::{cap_create_cspace, cap_create_thread, cap_derive};
use syscall_abi::{RIGHTS_ALL, SyscallError};

use crate::{TestContext, TestResult};

/// `ioport_bind` binds an I/O port range to a thread: binds ktest's wide `IoPort`
/// cap ([`super::io_port_cap`]) to a test thread. If ktest holds no `IoPort`
/// cap, the test is skipped.
pub fn bind(ctx: &TestContext) -> TestResult
{
    // Create a thread to receive the port range and scan for a cap.
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for ioport_bind test failed")?;
    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
        .map_err(|_| "cap_create_thread for ioport_bind test failed")?;

    let result = match bind_wide(th)
    {
        Ok(Some(_)) => Ok(()),
        Ok(None) =>
        {
            crate::log("ktest: hw::ioport_bind SKIP (no IoPort cap)");
            Ok(())
        }
        Err(e) => Err(e),
    };
    syscall::cap_delete(th).ok();
    syscall::cap_delete(cs).ok();
    result
}

/// Bind ktest's wide `IoPort` cap ([`super::io_port_cap`]) to `th`; returns
/// its handle, or `None` when ktest holds none. A bind leaves the cap in place,
/// so it moves no later carve. `OutOfMemory`, the table's three pages missing
/// from `th`'s `CSpace` pool, and any other refusal fail the test.
fn bind_wide(th: u64) -> Result<Option<u64>, &'static str>
{
    let Some(cap) = super::io_port_cap()
    else
    {
        return Ok(None);
    };
    match syscall::ioport_bind(th, cap)
    {
        Ok(()) => Ok(Some(cap)),
        Err(e) if e == SyscallError::OutOfMemory as i64 =>
        {
            Err("hw::ioport_bind: the binding table could not be funded")
        }
        Err(_) => Err("hw::ioport_bind: the bind of the wide IoPort cap was refused"),
    }
}

/// A thread's port-binding table comes from its own `CSpace`'s pool, and that
/// `CSpace`'s teardown returns it when the `CSpace` dies before the thread
/// ([core/kernel/docs/capability-internals.md § `IoPort`
/// Bindings](../../../../kernel/docs/capability-internals.md#ioport-bindings)):
/// after the `CSpace`, then the thread, are deleted, `memory_base` has every
/// byte back. A bind of the thread its `CSpace`'s death left `Exited` is
/// refused with `InvalidCapability`.
pub fn bind_table_outlives_no_pool(ctx: &TestContext) -> TestResult
{
    let available =
        || syscall::cap_info(ctx.memory_base, syscall_abi::CAP_INFO_MEMORY_AVAILABLE).unwrap_or(0);
    let before = available();
    // Three pool pages, exactly the table's.
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "hw::ioport_bind_teardown: cap_create_cspace failed")?;
    let Ok(th) = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
    else
    {
        syscall::cap_delete(cs).ok();
        return Err("hw::ioport_bind_teardown: cap_create_thread failed");
    };
    let bound = bind_wide(th);
    // The CSpace goes first: its teardown stops the thread and frees its table.
    let deleted = syscall::cap_delete(cs);
    let rebind = match bound
    {
        Ok(Some(slot)) => Some(syscall::ioport_bind(th, slot)),
        _ => None,
    };
    syscall::cap_delete(th).ok();
    let after = available();
    match bound
    {
        Err(e) => return Err(e),
        Ok(None) =>
        {
            crate::log("ktest: hw::ioport_bind_teardown SKIP (no IoPort cap)");
            return Ok(());
        }
        Ok(Some(_)) =>
        {}
    }
    if deleted.is_err()
    {
        return Err("hw::ioport_bind_teardown: cap_delete(cs) failed");
    }
    if rebind != Some(Err(SyscallError::InvalidCapability as i64))
    {
        return Err("hw::ioport_bind_teardown: a bind of an Exited thread was not refused");
    }
    if after != before
    {
        return Err("hw::ioport_bind_teardown: the CSpace's pages did not all come back");
    }
    Ok(())
}

/// `ioport_split` divides an `IoPort` cap into two non-overlapping children.
///
/// Splits a derived copy of ktest's wide `IoPort` cap ([`super::ioport::wide`])
/// one port in. The copy has an object of its own, so the split consumes the
/// copy alone and the wide cap, and every cap carved from it, stays whole.
/// Validates: both child handles are non-zero and distinct; re-splitting the
/// consumed copy fails; an out-of-range split of a child fails with
/// `InvalidArgument`. If ktest holds no wide cap of at least two ports, the
/// test is skipped.
pub fn split(_ctx: &TestContext) -> TestResult
{
    let Some((wide, base, _)) =
        super::ioport::wide().filter(|&(_, base, end)| end.saturating_sub(base) >= 2)
    else
    {
        crate::log("ktest: hw::ioport_split SKIP (no IoPort cap of two ports)");
        return Ok(());
    };
    // `base + 1 < end <= 0x10000`, so the split point fits a `u16`.
    let at = u16::try_from(base.saturating_add(1))
        .map_err(|_| "hw::ioport_split: split point out of range")?;
    let copy = cap_derive(wide, RIGHTS_ALL).map_err(|_| "hw::ioport_split: cap_derive failed")?;
    let Ok((lo, hi)) = syscall::ioport_split(copy, at)
    else
    {
        syscall::cap_delete(copy).ok();
        return Err("hw::ioport_split: the split of the copy failed");
    };
    let result = (|| -> TestResult {
        if lo == 0 || hi == 0 || lo == hi
        {
            return Err("ioport_split returned bad slot ids");
        }
        // The copy is consumed; re-split must fail.
        if syscall::ioport_split(copy, at).is_ok()
        {
            return Err("re-split of consumed parent succeeded");
        }
        // Out-of-range split on a child must fail with InvalidArgument. 0 is
        // always invalid (it would yield an empty lower half).
        let oob = syscall::ioport_split(lo, 0);
        if !matches!(oob, Err(e) if e == SyscallError::InvalidArgument as i64)
        {
            return Err("split with split_at=0 should fail with InvalidArgument");
        }
        Ok(())
    })();
    syscall::cap_delete(lo).ok();
    syscall::cap_delete(hi).ok();
    result
}
