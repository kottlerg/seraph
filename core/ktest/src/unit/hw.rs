// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/hw.rs

//! Tier 1 tests for hardware access syscalls.
//!
//! Covers: `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER`,
//! `SYS_IRQ_ACK`, `SYS_IRQ_SPLIT`. The per-architecture `SYS_IOPORT_BIND`,
//! `SYS_IOPORT_SPLIT`, and `SYS_SBI_CALL` tests live behind `crate::arch`.
//!
//! Tests that require specific hardware capability types (`Mmio`, Interrupt,
//! `IoPort`) scan the initial capability set for a matching cap. If none is
//! found in the current boot configuration, the test is skipped and reports Ok.
//! Skips are logged to serial so they are visible in the test run output.

use syscall::{
    aspace_query, cap_create_notification, irq_ack, irq_register, irq_split, mem_unmap, mmio_split,
};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// Test virtual address for MMIO mapping: 5.25 GiB, in the gap between the
/// byte-heap zone and the reservation arena, below every `process_layout`
/// window (ktest's PIE image loads in `IMAGE_WINDOW`).
const MMIO_TEST_VA: u64 = 0x1_5000_0000;

/// Upper bound for a slot scan over the test's own `CSpace`: its backed
/// capacity, which the kernel clamps below 2^24 so the narrowing cannot fail;
/// the address-space cap's index if the query fails, which still covers every
/// boot-minted cap.
pub fn scan_bound(ctx: &TestContext) -> u32
{
    syscall::cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_CAPACITY)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(ctx.aspace_cap)
}

// ── SYS_MMIO_MAP ──────────────────────────────────────────────────────────────

/// `mmio_map` maps a hardware MMIO region into the address space.
///
/// Maps only a single carved page, not the whole aperture:
/// `sys_mmio_map` draws intermediate PT pages from the *target* AS's own pool,
/// and the first `Mmio` in the boot config can span hundreds of MiB
/// (hundreds of PT pages) — mapping it whole would drain `ctx.aspace_cap`'s
/// pool, which the `mem_map` integration and bench tests share. One page
/// suffices to exercise the map + `aspace_query` path. The region is split so
/// its large remainder stays a valid `Mmio` for [`mmio_split_carves`].
/// Skipped if no `Mmio` of at least two pages exists in this boot config.
pub fn mmio_map(ctx: &TestContext) -> TestResult
{
    // Probe each slot with a one-page split. `InvalidCapability` ⇒ wrong tag;
    // `InvalidArgument` ⇒ an `Mmio` smaller than two pages. Both leave
    // the cap intact, so the scan is non-destructive until a split succeeds.
    // The scan bound is the cspace's backed capacity (queried at runtime)
    // so the test stays robust against cap mint order.
    let bound = scan_bound(ctx);
    for slot in 1..=bound
    {
        let Ok((lo, _hi)) = mmio_split(slot, 0x1000)
        else
        {
            continue;
        };
        // `lo` covers one page; map and verify it. The remainder child (`_hi`)
        // stays in the CSpace as a valid `Mmio` for the split test that
        // runs next.
        let result = (|| -> TestResult {
            syscall::mmio_map(ctx.aspace_cap, lo, MMIO_TEST_VA, 0)
                .map_err(|_| "mmio_map of carved page failed")?;
            let phys = aspace_query(ctx.aspace_cap, MMIO_TEST_VA)
                .map_err(|_| "aspace_query after mmio_map failed")?;
            if phys == 0 || phys & 0xFFF != 0
            {
                return Err("aspace_query returned invalid phys after mmio_map");
            }
            Ok(())
        })();
        let _ = mem_unmap(ctx.aspace_cap, MMIO_TEST_VA, 1);
        syscall::cap_delete(lo).ok();
        return result;
    }

    crate::log("ktest: hw::mmio_map SKIP (no Mmio >= 2 pages in initial cap set)");
    Ok(())
}

// ── SYS_IRQ_REGISTER / SYS_IRQ_ACK ───────────────────────────────────────────

/// `irq_register` binds a notification to an interrupt; `irq_ack` re-enables delivery.
///
/// Scans for the first Interrupt capability. Creates a notification for delivery.
/// After registration, ACKs to re-enable the interrupt line. If no Interrupt
/// cap is found, the test is skipped.
pub fn irq_register_ack(ctx: &TestContext) -> TestResult
{
    let irq_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for IRQ test failed")?;

    // The scan bound is the cspace's backed capacity (queried at runtime)
    // so the test stays robust against cap mint order.
    let bound = scan_bound(ctx);
    for slot in 1..=bound
    {
        // Any error (a slot of another type, most often) leaves the cap
        // intact; keep scanning.
        if irq_register(slot, irq_sig).is_ok()
        {
            irq_ack(slot).map_err(|_| "irq_ack failed")?;
            syscall::cap_delete(irq_sig).map_err(|_| "cap_delete irq_sig after irq test failed")?;
            return Ok(());
        }
    }

    crate::log("ktest: hw::irq_register_ack SKIP (no Interrupt caps in initial cap set)");
    syscall::cap_delete(irq_sig).ok();
    Ok(())
}

// ── SYS_MMIO_SPLIT ────────────────────────────────────────────────────────────

/// `mmio_split` on the first `Mmio` ≥ 8 KiB returns two valid children
/// with disjoint base/size. Skipped if no suitable cap exists.
pub fn mmio_split_carves(ctx: &TestContext) -> TestResult
{
    let bound = scan_bound(ctx);

    for slot in 1u32..=bound
    {
        // Probe: split at PAGE_SIZE. InvalidCapability ⇒ wrong tag.
        // InvalidArgument ⇒ Mmio exists but too small.
        match mmio_split(slot, 0x1000)
        {
            Err(e) if e == SyscallError::InvalidCapability as i64 =>
            {}
            Err(e) if e == SyscallError::InvalidArgument as i64 =>
            {}
            Err(_) => return Err("hw::mmio_split_carves: unexpected error from mmio_split"),
            Ok((slot1, slot2)) =>
            {
                if slot1 == 0 || slot2 == 0 || slot1 == slot2
                {
                    return Err("hw::mmio_split_carves: split returned bad slot ids");
                }
                syscall::cap_delete(slot1).ok();
                syscall::cap_delete(slot2).ok();
                return Ok(());
            }
        }
    }

    crate::log("ktest: hw::mmio_split_carves SKIP (no Mmio caps in initial cap set)");
    Ok(())
}

/// `mmio_split` on a Memory cap (wrong tag) must return `InvalidCapability`.
pub fn mmio_split_wrong_tag_err(ctx: &TestContext) -> TestResult
{
    let err = mmio_split(ctx.memory_base, 0x1000);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::mmio_split_wrong_tag_err: did not return InvalidCapability");
    }
    Ok(())
}

/// An Interrupt cap naming an id outside the routable range
/// (`MIN_IRQ_ID..=MAX_IRQ_ID`) is refused by `irq_register` with
/// `InvalidArgument`, and deleting it leaves the kernel's routing table alone.
///
/// Only riscv64 can name such an id: its root Interrupt cap spans the PLIC's
/// 1024-id space while the kernel routes sources 1..=127. The test splits id
/// 1023 off the first cap whose range contains it, which leaves the low part
/// `[start, 1023)` in place for the split tests that follow. Skipped where no
/// cap contains id 1023 (x86-64, whose root cap is the routable range).
pub fn irq_register_unroutable_id_err(ctx: &TestContext) -> TestResult
{
    const UNROUTABLE_ID: u32 = 1023;

    let irq_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "hw::irq_register_unroutable_id_err: cap_create_notification failed")?;

    let bound = scan_bound(ctx);
    for slot in 1u32..=bound
    {
        // Wrong-tag and out-of-range responses leave the cap intact.
        let Ok((_lo, hi)) = irq_split(slot, UNROUTABLE_ID)
        else
        {
            continue;
        };
        // `hi` is the single id 1023 (no cap extends past the 1024-id space).
        let err = irq_register(hi, irq_sig);
        // Deleting the cap must not touch the routing table for an id it cannot
        // index (the kernel panicked here before the teardown guard).
        let deleted = syscall::cap_delete(hi);
        syscall::cap_delete(irq_sig).ok();
        if err != Err(SyscallError::InvalidArgument as i64)
        {
            return Err("hw::irq_register_unroutable_id_err: id 1023 not refused");
        }
        deleted.map_err(|_| "hw::irq_register_unroutable_id_err: cap_delete of id 1023 failed")?;
        return Ok(());
    }

    crate::log("ktest: hw::irq_register_unroutable_id_err SKIP (no cap contains id 1023)");
    syscall::cap_delete(irq_sig).ok();
    Ok(())
}

// ── SYS_IRQ_SPLIT ─────────────────────────────────────────────────────────────

/// `irq_split` at IRQ id 1 on the first Interrupt-range cap whose range
/// strictly contains it (start 0, `count > 1`) returns two disjoint
/// children. Skipped if no such cap exists.
pub fn irq_split_carves(ctx: &TestContext) -> TestResult
{
    let bound = scan_bound(ctx);

    for slot in 1u32..=bound
    {
        // Probe: split at IRQ id 1 (`split_at` is absolute), which only a cap
        // starting at IRQ 0 with count > 1 accepts. Wrong-tag and out-of-range
        // responses both leave the cap intact.
        match irq_split(slot, 1)
        {
            Err(_) =>
            {} // Wrong tag or non-splittable; keep scanning.
            Ok((slot1, slot2)) =>
            {
                if slot1 == 0 || slot2 == 0 || slot1 == slot2
                {
                    return Err("hw::irq_split_carves: split returned bad slot ids");
                }
                syscall::cap_delete(slot1).ok();
                syscall::cap_delete(slot2).ok();
                return Ok(());
            }
        }
    }

    crate::log("ktest: hw::irq_split_carves SKIP (no Interrupt range caps with count>1)");
    Ok(())
}

/// `irq_split` on a Memory cap (wrong tag) must return `InvalidCapability`.
pub fn irq_split_wrong_tag_err(ctx: &TestContext) -> TestResult
{
    let err = irq_split(ctx.memory_base, 0);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::irq_split_wrong_tag_err: did not return InvalidCapability");
    }
    Ok(())
}
