// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/ioport_syscalls.rs

//! Tier 1 (x86-64): `SYS_IOPORT_BIND` and `SYS_IOPORT_SPLIT` on the `IoPort`
//! caps of the initial capability set.

use syscall::{cap_create_cspace, cap_create_thread};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// `ioport_bind` binds an I/O port range to a thread: scans for the first
/// `IoPort` cap and binds it to a test thread. If no `IoPort` cap is found, the test is skipped.
///
/// The scan bound is the cspace's backed capacity (queried at runtime via
/// `cap_info`) so the test stays robust against changes to cap mint
/// order or post-init carve products landing at slot indices above
/// `aspace_cap`.
pub fn bind(ctx: &TestContext) -> TestResult
{
    // Create a thread to receive the port range and scan for a cap.
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "create_cspace for ioport_bind test failed")?;
    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
        .map_err(|_| "cap_create_thread for ioport_bind test failed")?;

    let result = match bind_first_ioport(ctx, th)
    {
        Ok(Some(_)) => Ok(()),
        Ok(None) =>
        {
            crate::log("ktest: hw::ioport_bind SKIP (no IoPort caps in initial cap set)");
            Ok(())
        }
        Err(e) => Err(e),
    };
    syscall::cap_delete(th).ok();
    syscall::cap_delete(cs).ok();
    result
}

/// Bind the first `IoPort` cap of ktest's `CSpace` to `th`; returns its slot,
/// or `None` when there is none. A slot of another type refuses the bind and
/// is skipped; `OutOfMemory`, the table's three pages missing from `th`'s
/// `CSpace` pool, fails the test instead of passing for a missing cap.
fn bind_first_ioport(ctx: &TestContext, th: u64) -> Result<Option<u64>, &'static str>
{
    let bound = crate::unit::hw::scan_bound(ctx);
    for slot in 1..=u64::from(bound)
    {
        match syscall::ioport_bind(th, slot)
        {
            Ok(()) => return Ok(Some(slot)),
            Err(e) if e == SyscallError::OutOfMemory as i64 =>
            {
                return Err("hw::ioport_bind: the binding table could not be funded");
            }
            // Any other error (a slot of another type, most often) leaves
            // the cap intact; keep scanning.
            Err(_) =>
            {}
        }
    }
    Ok(None)
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
    let bound = bind_first_ioport(ctx, th);
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
            crate::log("ktest: hw::ioport_bind_teardown SKIP (no IoPort caps in initial cap set)");
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
/// Scans the cspace for the first `IoPort` cap whose
/// range covers port 0x80 and splits it there. Slots whose cap is the
/// wrong type or an `IoPort` not covering 0x80 are skipped
/// non-destructively. Validates: both child slots are non-zero and
/// distinct; re-splitting the now-consumed parent slot fails;
/// out-of-range splits fail with `InvalidArgument`. If no such
/// `IoPort` is found, the test is skipped.
///
/// The original cap is consumed by the split; this is the documented
/// semantics. No later test depends on the same slot.
pub fn split(ctx: &TestContext) -> TestResult
{
    // Find an IoPort cap covering 0x80 by probing with
    // `ioport_split`. `ioport_split` returns `InvalidCapability` for
    // wrong cap types and `InvalidArgument` for an `IoPort` whose
    // range doesn't cover the split point. Either result lets us
    // identify the slot's type non-destructively, since neither
    // consumes the cap.
    //
    // The scan bound is the cspace's backed capacity (queried at runtime
    // via `cap_info`) so carve products from `ioport::bind_port_range`
    // (which splits the wide cap `ioport::init` records) — which land at
    // slot indices above `aspace_cap` — are always reachable, regardless of
    // how the cspace has grown.
    let bound = crate::unit::hw::scan_bound(ctx);
    for slot in 1..=u64::from(bound)
    {
        // Try splitting at 0x80. If the slot is not an IoPort we
        // get InvalidCapability and keep scanning. If it is an
        // IoPort that doesn't cover 0x80 (e.g. a narrow
        // sub-range carved by `ioport::bind_port_range`) we also keep
        // scanning — another slot may hold a wider IoPort that
        // does cover the probe point.
        match syscall::ioport_split(slot, 0x80)
        {
            Err(e) if e == SyscallError::InvalidCapability as i64 =>
            {
                // Wrong cap type — keep scanning.
            }
            Err(e) if e == SyscallError::InvalidArgument as i64 =>
            {
                // IoPort whose range doesn't cover 0x80; cap is
                // intact. Keep scanning for another candidate.
            }
            Err(_) =>
            {
                return Err("ioport_split returned unexpected error");
            }
            Ok((slot1, slot2)) =>
            {
                if slot1 == 0 || slot2 == 0 || slot1 == slot2
                {
                    return Err("ioport_split returned bad slot ids");
                }
                // Parent slot is consumed; re-split must fail.
                if syscall::ioport_split(slot, 0x80).is_ok()
                {
                    return Err("re-split of consumed parent succeeded");
                }
                // Out-of-range split on a child must fail with
                // InvalidArgument. 0 is always invalid (would yield
                // an empty lower half).
                let oob = syscall::ioport_split(slot1, 0);
                if !matches!(oob, Err(e) if e == SyscallError::InvalidArgument as i64)
                {
                    return Err("split with split_at=0 should fail with InvalidArgument");
                }
                // Clean up children.
                syscall::cap_delete(slot1).ok();
                syscall::cap_delete(slot2).ok();
                return Ok(());
            }
        }
    }

    crate::log("ktest: hw::ioport_split SKIP (no IoPort covering 0x80 in initial cap set)");
    Ok(())
}
