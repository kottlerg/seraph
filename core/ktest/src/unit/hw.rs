// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/hw.rs

//! Tier 1 tests for hardware access syscalls.
//!
//! Covers: `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER`,
//! `SYS_IRQ_ACK`, `SYS_IRQ_SPLIT`, `SYS_IOPORT_BIND`, `SYS_IOPORT_SPLIT`,
//! `SYS_SBI_CALL`.
//!
//! Tests that require specific hardware capability types (`MmioRegion`, Interrupt,
//! `IoPortRange`) scan the initial capability set for a matching cap. If none is
//! found in the current boot configuration, the test is skipped and reports Ok.
//! Skips are logged to serial so they are visible in the test run output.

use syscall::{aspace_query, cap_create_signal, irq_ack, irq_register, irq_split, mmio_split};
#[cfg(target_arch = "x86_64")]
use syscall::{cap_create_cspace, cap_create_thread};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// Test virtual address for MMIO mapping. 1.25 GiB — above ktest's load address.
const MMIO_TEST_VA: u64 = 0x5000_0000;

/// Kernel pin: every `CSpace` is clamped to at most `L1_SIZE * L2_SIZE`
/// (256 * 56 = 14336) slots. Used as a fallback if `cap_info` ever
/// returns a value larger than `u32::MAX`, which the kernel's own
/// invariants forbid today.
#[cfg(target_arch = "x86_64")]
const ROOT_CSPACE_MAX_SLOTS: u32 = 14336;

// ── SYS_MMIO_MAP ──────────────────────────────────────────────────────────────

/// `mmio_map` maps a hardware MMIO region into the address space.
///
/// Scans the initial capability set for the first `MmioRegion` cap. On a
/// successful map, verifies the VA is now mapped via `aspace_query`. If no
/// `MmioRegion` cap exists in this boot configuration, the test is skipped.
pub fn mmio_map(ctx: &TestContext) -> TestResult
{
    // Hardware caps live in slots 1..aspace_cap. Scan for the first MmioRegion.
    // A non-MmioRegion slot returns InvalidCapability; an MmioRegion succeeds.
    for slot in 1..ctx.aspace_cap
    {
        match syscall::mmio_map(ctx.aspace_cap, slot, MMIO_TEST_VA, 0)
        {
            Err(e) if e == SyscallError::InvalidCapability as i64 =>
            {}
            Err(_) =>
            {} // Wrong type or other error — keep scanning.
            Ok(()) =>
            {
                let phys = aspace_query(ctx.aspace_cap, MMIO_TEST_VA)
                    .map_err(|_| "aspace_query after mmio_map failed")?;
                if phys == 0 || phys & 0xFFF != 0
                {
                    return Err("aspace_query returned invalid phys after mmio_map");
                }
                return Ok(());
            }
        }
    }

    crate::log("ktest: hw::mmio_map SKIP (no MmioRegion caps in initial cap set)");
    Ok(())
}

// ── SYS_IRQ_REGISTER / SYS_IRQ_ACK ───────────────────────────────────────────

/// `irq_register` binds a signal to an interrupt; `irq_ack` re-enables delivery.
///
/// Scans for the first Interrupt capability. Creates a signal for delivery.
/// After registration, ACKs to re-enable the interrupt line. If no Interrupt
/// cap is found, the test is skipped.
pub fn irq_register_ack(ctx: &TestContext) -> TestResult
{
    let irq_sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for IRQ test failed")?;

    for slot in 1..ctx.aspace_cap
    {
        match irq_register(slot, irq_sig)
        {
            Err(e) if e == SyscallError::InvalidCapability as i64 =>
            {}
            Err(_) =>
            {}
            Ok(()) =>
            {
                irq_ack(slot).map_err(|_| "irq_ack failed")?;
                syscall::cap_delete(irq_sig)
                    .map_err(|_| "cap_delete irq_sig after irq test failed")?;
                return Ok(());
            }
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
/// On `x86_64`, scans for the first `IoPortRange` cap and binds it to a test
/// thread. If no `IoPortRange` cap is found, the test is skipped.
///
/// The scan bound is the cspace's `max_slots` (queried at runtime via
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
        let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 8)
            .map_err(|_| "create_cspace for ioport_bind test failed")?;
        let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
            .map_err(|_| "cap_create_thread for ioport_bind test failed")?;

        let max_slots = if let Ok(n) =
            syscall::cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_CAPACITY)
        {
            u32::try_from(n).unwrap_or(ROOT_CSPACE_MAX_SLOTS)
        }
        else
        {
            syscall::cap_delete(th).ok();
            syscall::cap_delete(cs).ok();
            return Err("cap_info(CAP_INFO_CSPACE_CAPACITY) failed");
        };
        for slot in 1u32..max_slots
        {
            match syscall::ioport_bind(th, slot)
            {
                Err(e) if e == SyscallError::InvalidCapability as i64 =>
                {}
                Err(_) =>
                {}
                Ok(()) =>
                {
                    syscall::cap_delete(th).ok();
                    syscall::cap_delete(cs).ok();
                    return Ok(());
                }
            }
        }

        crate::log("ktest: hw::ioport_bind SKIP (no IoPortRange caps in initial cap set)");
        syscall::cap_delete(th).ok();
        syscall::cap_delete(cs).ok();
        Ok(())
    }
}

// ── SYS_IOPORT_SPLIT ──────────────────────────────────────────────────────────

/// `ioport_split` divides an `IoPortRange` cap into two non-overlapping children.
///
/// On RISC-V this syscall is not supported and must return `NotSupported`.
/// On `x86_64`, scans the cspace for the first `IoPortRange` cap whose
/// range covers port 0x80 and splits it there. Slots whose cap is the
/// wrong type or an `IoPortRange` not covering 0x80 are skipped
/// non-destructively. Validates: both child slots are non-zero and
/// distinct; re-splitting the now-consumed parent slot fails;
/// out-of-range splits fail with `InvalidArgument`. If no such
/// `IoPortRange` is found, the test is skipped.
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

    // x86_64: find an IoPortRange cap covering 0x80 by probing with
    // `ioport_split`. `ioport_split` returns `InvalidCapability` for
    // wrong cap types and `InvalidArgument` for an `IoPortRange` whose
    // range doesn't cover the split point. Either result lets us
    // identify the slot's type non-destructively, since neither
    // consumes the cap.
    //
    // The scan bound is the cspace's `max_slots` (queried at runtime
    // via `cap_info`) so post-init carve products from `ioport::init`
    // — which land at slot indices above `aspace_cap` — are always
    // reachable, regardless of how the cspace has grown.
    #[cfg(target_arch = "x86_64")]
    {
        let max_slots =
            match syscall::cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_CAPACITY)
            {
                Ok(n) => u32::try_from(n).unwrap_or(ROOT_CSPACE_MAX_SLOTS),
                Err(_) => return Err("cap_info(CAP_INFO_CSPACE_CAPACITY) failed"),
            };
        for slot in 1u32..max_slots
        {
            // Try splitting at 0x80. If the slot is not an IoPortRange we
            // get InvalidCapability and keep scanning. If it is an
            // IoPortRange that doesn't cover 0x80 (e.g. a narrow
            // sub-range carved by `ioport::bind_port_range`) we also keep
            // scanning — another slot may hold a wider IoPortRange that
            // does cover the probe point.
            match syscall::ioport_split(slot, 0x80)
            {
                Err(e) if e == SyscallError::InvalidCapability as i64 =>
                {
                    // Wrong cap type — keep scanning.
                }
                Err(e) if e == SyscallError::InvalidArgument as i64 =>
                {
                    // IoPortRange whose range doesn't cover 0x80; cap is
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

        crate::log(
            "ktest: hw::ioport_split SKIP (no IoPortRange covering 0x80 in initial cap set)",
        );
        Ok(())
    }
}

// ── SYS_MMIO_SPLIT ────────────────────────────────────────────────────────────

/// `mmio_split` on the first `MmioRegion` ≥ 8 KiB returns two valid children
/// with disjoint base/size. Skipped if no suitable cap exists.
pub fn mmio_split_carves(ctx: &TestContext) -> TestResult
{
    let max_slots = syscall::cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_CAPACITY)
        .map_or(ctx.aspace_cap, |n| u32::try_from(n).unwrap_or(u32::MAX));

    for slot in 1u32..max_slots
    {
        // Probe: split at PAGE_SIZE. InvalidCapability ⇒ wrong tag.
        // InvalidArgument ⇒ MmioRegion exists but too small.
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

    crate::log("ktest: hw::mmio_split_carves SKIP (no MmioRegion caps in initial cap set)");
    Ok(())
}

/// `mmio_split` on a Frame cap (wrong tag) must return `InvalidCapability`.
pub fn mmio_split_wrong_tag_err(ctx: &TestContext) -> TestResult
{
    let err = mmio_split(ctx.memory_frame_base, 0x1000);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::mmio_split_wrong_tag_err: did not return InvalidCapability");
    }
    Ok(())
}

// ── SYS_IRQ_SPLIT ─────────────────────────────────────────────────────────────

/// `irq_split` on the first Interrupt-range cap with `count > 1` returns two
/// disjoint children. Skipped if no suitable cap exists.
pub fn irq_split_carves(ctx: &TestContext) -> TestResult
{
    let max_slots = syscall::cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_CAPACITY)
        .map_or(ctx.aspace_cap, |n| u32::try_from(n).unwrap_or(u32::MAX));

    for slot in 1u32..max_slots
    {
        // Probe: split at base+1. Wrong-tag and unsplittable-range responses
        // both leave the cap intact.
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

/// `irq_split` on a Frame cap (wrong tag) must return `InvalidCapability`.
pub fn irq_split_wrong_tag_err(ctx: &TestContext) -> TestResult
{
    let err = irq_split(ctx.memory_frame_base, 0);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::irq_split_wrong_tag_err: did not return InvalidCapability");
    }
    Ok(())
}

// ── SYS_SBI_CALL ──────────────────────────────────────────────────────────────

/// On RISC-V, `sbi_call(sbi_control_cap, EID=0x10, FID=0, …)` reads the SBI
/// spec version. Verifies the call path: the kernel forwards to SBI and
/// returns a plausible version (major in `0..=3`).
#[cfg(target_arch = "riscv64")]
pub fn sbi_call_get_spec_version(ctx: &TestContext) -> TestResult
{
    // EID_BASE = 0x10, FID_GET_SPEC_VERSION = 0 per the SBI base extension.
    let version = syscall::sbi_call(ctx.sbi_control_cap, 0x10, 0, 0, 0, 0)
        .map_err(|_| "hw::sbi_call_get_spec_version: sbi_call returned error")?;
    let major = version >> 24;
    if major > 3
    {
        return Err("hw::sbi_call_get_spec_version: implausible SBI major version");
    }
    Ok(())
}

/// On `x86_64`, `sbi_call` is unconditionally `NotSupported` regardless of
/// arguments (the syscall is a RISC-V-only forwarder).
#[cfg(target_arch = "x86_64")]
pub fn sbi_call_not_supported_x86_64(_ctx: &TestContext) -> TestResult
{
    let err = syscall::sbi_call(0, 0, 0, 0, 0, 0);
    if err != Err(SyscallError::NotSupported as i64)
    {
        return Err("hw::sbi_call_not_supported_x86_64: did not return NotSupported");
    }
    Ok(())
}
