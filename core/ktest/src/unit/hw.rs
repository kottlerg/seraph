// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/hw.rs

//! Tier 1 tests for hardware access syscalls.
//!
//! Covers: `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER`,
//! `SYS_IRQ_ACK`, `SYS_IRQ_SPLIT`, `SYS_IOPORT_BIND`, `SYS_IOPORT_SPLIT`.
//! The per-architecture `SYS_SBI_CALL` tests live behind `crate::arch`.
//!
//! Tests that require specific hardware capability types (`Mmio`, Interrupt,
//! `IoPort`) scan the initial capability set for a matching cap. If none is
//! found in the current boot configuration, the test is skipped and reports Ok.
//! Skips are logged to serial so they are visible in the test run output.

use syscall::{
    aspace_query, cap_create_notification, irq_ack, irq_register, irq_split, mem_unmap, mmio_split,
};
#[cfg(target_arch = "x86_64")]
use syscall::{cap_create_cspace, cap_create_thread};
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
fn scan_bound(ctx: &TestContext) -> u32
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

// ── SYS_IOPORT_BIND ───────────────────────────────────────────────────────────

/// `ioport_bind` binds an I/O port range to a thread.
///
/// On RISC-V this syscall is not supported and must return `NotSupported`.
/// On `x86_64`, scans for the first `IoPort` cap and binds it to a test
/// thread. If no `IoPort` cap is found, the test is skipped.
///
/// The scan bound is the cspace's backed capacity (queried at runtime via
/// `cap_info`) so the test stays robust against changes to cap mint
/// order or post-init carve products landing at slot indices above
/// `aspace_cap`.
// needless_return: cfg-gated early return is required to terminate the riscv64
// path; the x86_64 path follows in the same function body.
#[allow(clippy::needless_return)]
pub fn ioport_bind(ctx: &TestContext) -> TestResult
{
    // RISC-V: verify NotSupported is returned regardless of arguments.
    #[cfg(target_arch = "riscv64")]
    {
        let _ = ctx;
        let err = syscall::ioport_bind(0, 0);
        if err != Err(SyscallError::NotSupported as i64)
        {
            return Err("ioport_bind on RISC-V did not return NotSupported");
        }
        return Ok(());
    }

    // x86_64: create a thread to receive the port range and scan for a cap.
    #[cfg(target_arch = "x86_64")]
    {
        let cs = cap_create_cspace(ctx.memory_base, 0, 4)
            .map_err(|_| "create_cspace for ioport_bind test failed")?;
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
            .map_err(|_| "cap_create_thread for ioport_bind test failed")?;

        let bound = scan_bound(ctx);
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
}

// ── SYS_IOPORT_SPLIT ──────────────────────────────────────────────────────────

/// `ioport_split` divides an `IoPort` cap into two non-overlapping children.
///
/// On RISC-V this syscall is not supported and must return `NotSupported`.
/// On `x86_64`, scans the cspace for the first `IoPort` cap whose
/// range covers port 0x80 and splits it there. Slots whose cap is the
/// wrong type or an `IoPort` not covering 0x80 are skipped
/// non-destructively. Validates: both child slots are non-zero and
/// distinct; re-splitting the now-consumed parent slot fails;
/// out-of-range splits fail with `InvalidArgument`. If no such
/// `IoPort` is found, the test is skipped.
///
/// The original cap is consumed by the split; this is the documented
/// semantics. No later test depends on the same slot.
// needless_return: cfg-gated early return is required to terminate the riscv64
// path; the x86_64 path follows in the same function body.
#[allow(clippy::needless_return)]
pub fn ioport_split(ctx: &TestContext) -> TestResult
{
    // RISC-V: verify NotSupported is returned regardless of arguments.
    #[cfg(target_arch = "riscv64")]
    {
        let _ = ctx;
        let err = syscall::ioport_split(0, 1);
        if err != Err(SyscallError::NotSupported as i64)
        {
            return Err("ioport_split on RISC-V did not return NotSupported");
        }
        return Ok(());
    }

    // x86_64: find an IoPort cap covering 0x80 by probing with
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
    #[cfg(target_arch = "x86_64")]
    {
        let bound = scan_bound(ctx);
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
