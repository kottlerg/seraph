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

    let bound = crate::unit::hw::scan_bound(ctx);
    for slot in 1u32..=bound
    {
        // Any error (a slot of another type, most often) leaves the cap
        // intact; keep scanning.
        if syscall::ioport_bind(th, slot).is_ok()
        {
            syscall::cap_delete(th).ok();
            syscall::cap_delete(cs).ok();
            return Ok(());
        }
    }

    crate::log("ktest: hw::ioport_bind SKIP (no IoPort caps in initial cap set)");
    syscall::cap_delete(th).ok();
    syscall::cap_delete(cs).ok();
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
    for slot in 1u32..=bound
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
