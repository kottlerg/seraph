// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/sysinfo.rs

//! Tier 1 tests for system info syscalls.
//!
//! Covers: `SYS_SYSTEM_INFO` (all `SystemInfoType` variants and unknown
//! discriminant).

use syscall::{MAP_WRITABLE, mem_map, mem_unmap, system_info};
use syscall_abi::{KERNEL_VERSION, PAGE_SIZE, SyscallError, SystemInfoType};

use crate::{TestContext, TestResult};

// ── SYS_SYSTEM_INFO ───────────────────────────────────────────────────────────

/// `system_info(KernelVersion)` returns the expected version constant.
///
/// The kernel version tracks the Seraph project version. See `KERNEL_VERSION`
/// in `abi/syscall/src/lib.rs` for the encoding and source.
pub fn kernel_version(_ctx: &TestContext) -> TestResult
{
    let ver = system_info(SystemInfoType::KernelVersion as u64)
        .map_err(|_| "system_info(KernelVersion) failed")?;
    if ver != KERNEL_VERSION
    {
        return Err("system_info(KernelVersion) returned unexpected value");
    }
    // Log the version in "vMAJOR.MINOR.PATCH" format for visibility.
    crate::log_version("ktest: kernel version ", ver);
    Ok(())
}

/// `system_info(CpuCount)` returns a value ≥ 1.
///
/// The count is the number of CPUs the boot reported, each brought online in
/// Phase 8 (see `core/kernel/docs/initialization.md` § Phase 8: Scheduler and
/// SMP Bringup), so it tracks the QEMU `-smp` setting.
pub fn cpu_count(_ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus == 0
    {
        return Err("system_info(CpuCount) returned 0 (expected at least 1)");
    }
    crate::log_u64("ktest: CpuCount=", cpus);
    Ok(())
}

/// `system_info(PageSize)` must return 4096.
pub fn page_size(_ctx: &TestContext) -> TestResult
{
    let sz =
        system_info(SystemInfoType::PageSize as u64).map_err(|_| "system_info(PageSize) failed")?;
    if sz != 4096
    {
        return Err("system_info(PageSize) did not return 4096");
    }
    Ok(())
}

/// `system_info(BootProtocolVersion)` must return the protocol version the
/// running kernel was compiled against ([`boot_protocol::BOOT_PROTOCOL_VERSION`]
/// — ktest builds from the same tree, so the shared constant is the oracle).
pub fn boot_protocol_version(_ctx: &TestContext) -> TestResult
{
    let bpv = system_info(SystemInfoType::BootProtocolVersion as u64)
        .map_err(|_| "system_info(BootProtocolVersion) failed")?;
    if bpv != u64::from(boot_protocol::BOOT_PROTOCOL_VERSION)
    {
        return Err("system_info(BootProtocolVersion) mismatches BOOT_PROTOCOL_VERSION");
    }
    Ok(())
}

/// `system_info` with an unknown discriminant returns `InvalidArgument`.
pub fn unknown_kind_err(_ctx: &TestContext) -> TestResult
{
    let err = system_info(0xFFFF_FFFF);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("system_info(unknown kind) did not return InvalidArgument");
    }
    Ok(())
}

/// `system_info(ElapsedUs)` returns a positive, monotonically increasing value.
pub fn elapsed_us(_ctx: &TestContext) -> TestResult
{
    let t0 = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "system_info(ElapsedUs) first call failed")?;
    if t0 == 0
    {
        return Err("system_info(ElapsedUs) returned 0 (expected > 0)");
    }

    // Second call must be >= first (monotonic).
    let t1 = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "system_info(ElapsedUs) second call failed")?;
    if t1 < t0
    {
        return Err("system_info(ElapsedUs) not monotonic (second < first)");
    }
    Ok(())
}

/// `system_info(CurrentCpu)` returns a CPU index < `CpuCount`.
///
/// The return value MUST be a valid CPU id. Used by affinity / migration
/// tests to observe which CPU a thread runs on; this test exercises the
/// query itself.
pub fn current_cpu(_ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    let cpu = system_info(SystemInfoType::CurrentCpu as u64)
        .map_err(|_| "system_info(CurrentCpu) failed")?;
    if cpu >= cpus
    {
        return Err("system_info(CurrentCpu) returned an out-of-range CPU id");
    }
    crate::log_u64("ktest: CurrentCpu=", cpu);
    Ok(())
}

/// `system_info(CpuCount)` returns ≥ 2 when the kernel was booted with SMP.
///
/// Requires QEMU `-smp N` with N ≥ 2. Skips with a log message rather than
/// failing if only one CPU is online, so single-CPU runs stay green.
pub fn cpu_count_smp(_ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: sysinfo::cpu_count_smp SKIP (boot with -smp N for SMP test)");
        return Ok(());
    }
    crate::log_u64("ktest: SMP CpuCount=", cpus);
    Ok(())
}

/// `system_info(UserVaTop)` returns one of the supported modes' user tops,
/// and it is the address `mem_map` refuses from: a map at it fails with
/// `InvalidAddress`, a map of the page below it does not.
///
/// ruststd sizes a process's heap and reservation-arena zones from this
/// value (`process_layout::growth_zones`), so a value above the real
/// gate would put those zones where every map fails.
pub fn user_va_top(ctx: &TestContext) -> TestResult
{
    let top = system_info(SystemInfoType::UserVaTop as u64)
        .map_err(|_| "system_info(UserVaTop) failed")?;
    // Sv39, x86-64 4-level (top page unmappable), Sv48, x86-64 5-level
    // (top page unmappable), Sv57.
    if ![
        1 << 38,
        (1 << 47) - PAGE_SIZE,
        1 << 47,
        (1 << 56) - PAGE_SIZE,
        1 << 56,
    ]
    .contains(&top)
    {
        return Err("system_info(UserVaTop) is no supported mode's user top");
    }
    crate::log_u64("ktest: UserVaTop=", top);

    let memory_cap =
        crate::frame_pool::alloc().ok_or("sysinfo::user_va_top: frame pool exhausted")?;
    // SAFETY: `top` is at the user-half gate, which the kernel refuses (the
    // test's premise), so the call maps nothing.
    let at_top = unsafe { mem_map(memory_cap, ctx.aspace_cap, top, 0, 1, MAP_WRITABLE) };
    let below = top - PAGE_SIZE;
    // SAFETY: `below` is a ktest scratch page (the top page of the user half,
    // or on x86-64 one of its top two; see the crate's § Scratch VAs): tests
    // run one at a time and none leaves a scratch page mapped, so nothing
    // lives there, and no reference into it is formed.
    let under_top = unsafe { mem_map(memory_cap, ctx.aspace_cap, below, 0, 1, MAP_WRITABLE) };
    if under_top.is_ok()
    {
        // SAFETY: the page was mapped just above and nothing references it.
        let _ = unsafe { mem_unmap(ctx.aspace_cap, below, 1) };
    }
    // SAFETY: memory_cap came from the pool and no mapping of it remains.
    unsafe { crate::frame_pool::free(memory_cap) };

    if at_top != Err(SyscallError::InvalidAddress as i64)
    {
        return Err("mem_map at UserVaTop did not fail with InvalidAddress");
    }
    // The page below the gate may still fail for want of page-table budget,
    // but never on the address.
    if under_top == Err(SyscallError::InvalidAddress as i64)
    {
        return Err("mem_map of the page below UserVaTop failed with InvalidAddress");
    }
    Ok(())
}
