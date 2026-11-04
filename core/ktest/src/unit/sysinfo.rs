// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/sysinfo.rs

//! Tier 1 tests for system info syscalls.
//!
//! Covers: `SYS_SYSTEM_INFO` (all `SystemInfoType` variants and unknown
//! discriminant).

use syscall::{
    MAP_WRITABLE, cap_create_cspace, cap_create_thread, cap_delete, cap_info, mem_map, mem_unmap,
    memory_merge, memory_split, system_info,
};
use syscall_abi::{
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_SIZE, KERNEL_VERSION, PAGE_SIZE, SyscallError,
    SystemInfoType,
};

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

/// `system_info(StackHighWater)` answers each stack class with a depth inside
/// that class's stack, and refuses an unknown class with `InvalidArgument`.
///
/// Tier 1 runs on a fresh boot, so every depth is a partial one; the Tier S
/// `stress::stack_depth` cell reports them after the stress tier.
pub fn stack_high_water_classes(_ctx: &TestContext) -> TestResult
{
    use syscall::stack_high_water;
    use syscall_abi::{STACK_CLASS_HANDOFF, STACK_CLASS_IDLE, STACK_CLASS_THREAD};

    let kernel_stack = crate::KERNEL_STACK_BYTES;
    // The calling thread's own stack is in use, so the thread class reads
    // above zero; an idle stack has at least run its idle loop.
    let thread = stack_high_water(STACK_CLASS_THREAD)
        .map_err(|_| "sysinfo::stack_high_water: thread class failed")?;
    if thread == 0 || thread >= kernel_stack
    {
        return Err("sysinfo::stack_high_water: thread depth outside (0, stack size)");
    }
    let idle = stack_high_water(STACK_CLASS_IDLE)
        .map_err(|_| "sysinfo::stack_high_water: idle class failed")?;
    if idle == 0 || idle >= kernel_stack
    {
        return Err("sysinfo::stack_high_water: idle depth outside (0, stack size)");
    }
    let handoff = stack_high_water(STACK_CLASS_HANDOFF)
        .map_err(|_| "sysinfo::stack_high_water: handoff class failed")?;
    if handoff == 0 || handoff >= boot_protocol::layout::HANDOFF_STACK_BYTES as u64
    {
        return Err("sysinfo::stack_high_water: handoff depth outside (0, stack size)");
    }
    if stack_high_water(3) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("sysinfo::stack_high_water: unknown class not refused");
    }
    Ok(())
}

/// `system_info(ThreadRetypeBytes)` is what one thread creation consumes: a
/// Memory cap of exactly that many bytes funds one `cap_create_thread` and is
/// left with nothing, and a cap one page short is refused.
///
/// procmgr, init and ruststd size every Thread slab from this value, and the
/// kernel sizes the slot from the boot CPU's extended-state area, so a
/// selector that disagreed with the slot would fail or overrun every spawn.
pub fn thread_retype_bytes_funds_one_thread(ctx: &TestContext) -> TestResult
{
    let bytes = system_info(SystemInfoType::ThreadRetypeBytes as u64)
        .map_err(|_| "system_info(ThreadRetypeBytes) failed")?;
    // The guard page below the kernel stack, the kernel stack (four pages),
    // the wrapper and TCB page, and a save area of at least one page, all
    // whole pages: a slot without its guard reads six.
    if bytes % PAGE_SIZE != 0 || bytes < 7 * PAGE_SIZE
    {
        return Err("system_info(ThreadRetypeBytes) is not a slot of seven or more whole pages");
    }
    crate::log_u64("ktest: ThreadRetypeBytes=", bytes);
    let pages = bytes / PAGE_SIZE;

    let short = split_top(ctx, pages - 1)?;
    let refused = cap_create_thread(short, ctx.aspace_cap, ctx.cspace_cap, 0, 0);
    if let Ok(thread) = refused
    {
        let _ = cap_delete(thread);
    }
    memory_merge(ctx.memory_base, short)
        .map_err(|_| "sysinfo::thread_retype_bytes: memory_merge of the short grant failed")?;
    if refused.is_ok()
    {
        return Err("cap_create_thread succeeded from a grant one page short of ThreadRetypeBytes");
    }

    let exact = split_top(ctx, pages)?;
    let made = cap_create_thread(exact, ctx.aspace_cap, ctx.cspace_cap, 0, 0);
    let left = cap_info(exact, CAP_INFO_MEMORY_AVAILABLE);
    if let Ok(thread) = made
    {
        let _ = cap_delete(thread);
    }
    memory_merge(ctx.memory_base, exact)
        .map_err(|_| "sysinfo::thread_retype_bytes: memory_merge of the exact grant failed")?;
    if made.is_err()
    {
        return Err("cap_create_thread failed from a grant of exactly ThreadRetypeBytes");
    }
    if left != Ok(0)
    {
        return Err("a thread left bytes in a grant of exactly ThreadRetypeBytes");
    }
    Ok(())
}

/// `system_info(LiveCSpaceCount)` counts `CSpace` ids in use: at least the
/// root's, one more while a created `CSpace` lives, and back once it is
/// deleted.
///
/// Defect caught: a `CSpace` teardown that does not return its id to the
/// registry (the count stays raised after the delete), or a selector that
/// does not follow creation.
pub fn live_cspace_count(ctx: &TestContext) -> TestResult
{
    let count = || {
        system_info(SystemInfoType::LiveCSpaceCount as u64)
            .map_err(|_| "system_info(LiveCSpaceCount) failed")
    };
    let before = count()?;
    if before == 0
    {
        return Err("system_info(LiveCSpaceCount) does not count ktest's own CSpace");
    }
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "sysinfo::live_cspace_count: cap_create_cspace failed")?;
    let during = count();
    cap_delete(cs).map_err(|_| "sysinfo::live_cspace_count: cap_delete failed")?;
    let after = count()?;
    if during? != before + 1
    {
        return Err("system_info(LiveCSpaceCount) did not count a created CSpace");
    }
    if after != before
    {
        return Err("a CSpace teardown did not return its id (LiveCSpaceCount stayed raised)");
    }
    Ok(())
}

/// Split a virgin grant of `pages` pages off the top of `ctx.memory_base`,
/// for the caller to merge back.
fn split_top(ctx: &TestContext, pages: u64) -> Result<u32, &'static str>
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "sysinfo::thread_retype_bytes: cap_info(memory_base) failed")?;
    let at = size
        .checked_sub(pages * PAGE_SIZE)
        .ok_or("sysinfo::thread_retype_bytes: memory_base too small")?;
    memory_split(ctx.memory_base, at)
        .map_err(|_| "sysinfo::thread_retype_bytes: memory_split(memory_base) failed")
}
