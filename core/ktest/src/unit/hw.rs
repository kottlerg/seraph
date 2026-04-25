// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/hw.rs

//! Tier 1 tests for hardware access syscalls.
//!
//! Covers: `SYS_DMA_GRANT`, `SYS_MMIO_MAP`, `SYS_IRQ_REGISTER`,
//! `SYS_IRQ_ACK`, `SYS_IOPORT_BIND`.
//!
//! Tests that require specific hardware capability types (`MmioRegion`, Interrupt,
//! `IoPortRange`) scan the initial capability set for a matching cap. If none is
//! found in the current boot configuration, the test is skipped and reports Ok.
//! Skips are logged to serial so they are visible in the test run output.

use syscall::{aspace_query, cap_create_signal, dma_grant, irq_ack, irq_register};
#[cfg(target_arch = "x86_64")]
use syscall::{cap_create_cspace, cap_create_thread};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// Test virtual address for MMIO mapping. 1.25 GiB — above ktest's load address.
const MMIO_TEST_VA: u64 = 0x5000_0000;

// ── SYS_DMA_GRANT ─────────────────────────────────────────────────────────────

/// `dma_grant` without `FLAG_DMA_UNSAFE` must return `DmaUnsafe`.
///
/// Uses the TEXT frame cap (`aspace_cap + 1`) as the frame source.
pub fn dma_grant_unsafe_flag_required(ctx: &TestContext) -> TestResult
{
    let text_frame = ctx.aspace_cap + 1;

    let err = dma_grant(text_frame, 0, 0);
    if err != Err(SyscallError::DmaUnsafe as i64)
    {
        return Err("dma_grant without FLAG_DMA_UNSAFE did not return DmaUnsafe");
    }
    Ok(())
}

/// `dma_grant` with `FLAG_DMA_UNSAFE` returns a non-zero, page-aligned physical address.
pub fn dma_grant_with_flag(ctx: &TestContext) -> TestResult
{
    let text_frame = ctx.aspace_cap + 1;

    let phys = dma_grant(text_frame, 0, syscall_abi::FLAG_DMA_UNSAFE)
        .map_err(|_| "dma_grant with FLAG_DMA_UNSAFE failed")?;

    if phys == 0
    {
        return Err("dma_grant returned zero physical address");
    }
    if phys & 0xFFF != 0
    {
        return Err("dma_grant returned non-page-aligned physical address");
    }
    Ok(())
}

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
    let irq_sig = cap_create_signal().map_err(|_| "cap_create_signal for IRQ test failed")?;

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
        let cs = cap_create_cspace(8).map_err(|_| "create_cspace for ioport_bind test failed")?;
        let th = cap_create_thread(ctx.aspace_cap, cs)
            .map_err(|_| "cap_create_thread for ioport_bind test failed")?;

        for slot in 1..ctx.aspace_cap
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
