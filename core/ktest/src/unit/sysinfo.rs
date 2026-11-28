// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/sysinfo.rs

//! Tier 1 tests for system info syscalls.
//!
//! Covers: `SYS_SYSTEM_INFO` (every `SystemInfoType` variant, and an unknown
//! discriminant). `EndpointRetypeBytes` and `ThreadRetypeBytes` are each
//! checked against the creation they fund. `SpeculationControls` is read here
//! for its views and their refusals; x86-64's `integration::speculation_controls` checks the words
//! against each other on every CPU. `InstructionCacheSyncs` is read here for the boot's sync of
//! ktest's own image; its rise across each runtime call site is checked by
//! `integration::thread_memory` and `unit::retype`'s code stub. `SmtSibling` is
//! read here for its range; `integration::smt_siblings` checks each ring against
//! the core each CPU reports. `IdleHalts` is read here across a sleep of a
//! thread pinned to CPU 0, and for its per-thread, per-CPU mark: a new
//! thread's first call and a moved thread's call; the benchmark harnesses read
//! it around their timed samples (shared/bench/README.md § Idle halts).
//! `SchedStages` is read here for the answer each build of the kernel gives;
//! `bench::thread`'s `context_switch_pair` reports its stage means.

use syscall::{
    MAP_WRITABLE, cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_notification,
    cap_create_thread, cap_delete, cap_info, idle_halts, mem_map, mem_unmap, memory_merge,
    memory_split, notification_send, notification_wait, sched_stages, smt_sibling,
    speculation_controls, system_info, thread_exit, thread_set_affinity, thread_sleep,
    thread_yield,
};
use syscall_abi::{
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_SIZE, KERNEL_VERSION, PAGE_SIZE, RIGHTS_NTF_NOTIFY,
    SCHED_STAGE_LOCK, SCHED_STAGES_ARM, SCHED_STAGES_RESUMES, SCHED_STAGES_SWITCHES,
    SPECULATION_VIEW_IN_EFFECT, SPECULATION_VIEW_INPUTS, SPECULATION_VIEW_SELECTED, SyscallError,
    SystemInfoType,
};

use crate::{ChildStack, TestContext, TestResult};

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

/// `system_info(SchedStages)` answers as the kernel's build decides: a
/// kernel without its `sched-stages` feature refuses every word, the arm
/// included, with `InvalidArgument`; one with it answers the arm with 0 and
/// every stage and count word after it, never more register switches closed
/// than switches committed, and refuses the words past the arm
/// (core/kernel/docs/scheduler.md § Stage Breakdown).
pub fn sched_stages_words(_ctx: &TestContext) -> TestResult
{
    let invalid = Err(SyscallError::InvalidArgument as i64);
    match sched_stages(SCHED_STAGES_ARM)
    {
        Ok(0) =>
        {}
        Ok(_) => return Err("sysinfo::sched_stages: the arm returned a non-zero value"),
        Err(e) if e == SyscallError::InvalidArgument as i64 =>
        {
            if sched_stages(SCHED_STAGE_LOCK) != invalid
            {
                return Err("sysinfo::sched_stages: a word answered where the arm was refused");
            }
            return Ok(());
        }
        Err(_) => return Err("sysinfo::sched_stages: the arm failed other than InvalidArgument"),
    }
    for word in SCHED_STAGE_LOCK..SCHED_STAGES_ARM
    {
        if sched_stages(word).is_err()
        {
            return Err("sysinfo::sched_stages: a stage or count word was refused after the arm");
        }
    }
    let resumes =
        sched_stages(SCHED_STAGES_RESUMES).map_err(|_| "sysinfo::sched_stages: resumes refused")?;
    let switches = sched_stages(SCHED_STAGES_SWITCHES)
        .map_err(|_| "sysinfo::sched_stages: switches refused")?;
    if resumes > switches
    {
        return Err("sysinfo::sched_stages: more register switches closed than committed");
    }
    if sched_stages(SCHED_STAGES_ARM + 1) != invalid || sched_stages(u64::MAX) != invalid
    {
        return Err("sysinfo::sched_stages: a word past the arm was not refused");
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
    let below = top
        .checked_sub(PAGE_SIZE)
        .ok_or("sysinfo::user_va_top: UserVaTop is below one page")?;
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
    // whole pages: the bound catches a slot without its guard when the save
    // area is one page.
    if bytes % PAGE_SIZE != 0 || bytes < 7 * PAGE_SIZE
    {
        return Err("system_info(ThreadRetypeBytes) is not a slot of seven or more whole pages");
    }
    crate::log_u64("ktest: ThreadRetypeBytes=", bytes);
    let pages = bytes / PAGE_SIZE;

    let short = split_top(
        ctx,
        pages
            .checked_sub(1)
            .ok_or("sysinfo::thread_retype_bytes: no pages in a slot")?,
    )?;
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

/// `system_info(EndpointRetypeBytes)` is what one endpoint creation consumes:
/// the 72 bytes of the object wrapper and the endpoint's state, and a hint
/// byte for every four CPUs of the boot. A Memory cap of whole pages funds as
/// many endpoints as the debit's size class fits in it, is left with nothing,
/// and refuses one more.
///
/// ruststd sizes every endpoint's slab request from this value, and the
/// kernel sizes the endpoint's slot hints from the boot's CPU count, so a
/// selector that disagreed with the slot would fail every endpoint creation
/// or let the hints of one endpoint overrun the next.
pub fn endpoint_retype_bytes_funds_one_endpoint(ctx: &TestContext) -> TestResult
{
    let bytes = system_info(SystemInfoType::EndpointRetypeBytes as u64)
        .map_err(|_| "system_info(EndpointRetypeBytes) failed")?;
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "sysinfo::endpoint_retype_bytes: system_info(CpuCount) failed")?;
    if Some(bytes) != cpus.div_ceil(4).checked_add(72)
    {
        return Err("system_info(EndpointRetypeBytes) is not 72 bytes and two bits per CPU");
    }
    crate::log_u64("ktest: EndpointRetypeBytes=", bytes);
    // The kernel's size classes: the 128- and 512-byte bins, whole pages
    // above.
    let class = syscall_abi::retype_class_bytes(bytes);
    let pages = class.div_ceil(PAGE_SIZE);
    let fits = pages
        .saturating_mul(PAGE_SIZE)
        .checked_div(class)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0);

    let grant = split_top(ctx, pages)?;
    let mut made = [0u64; (PAGE_SIZE / 128) as usize];
    let mut count: usize = 0;
    for slot in made.iter_mut().take(fits)
    {
        let Ok(ep) = cap_create_endpoint(grant)
        else
        {
            break;
        };
        *slot = ep;
        count = count.saturating_add(1);
    }
    let left = cap_info(grant, CAP_INFO_MEMORY_AVAILABLE);
    let refused = cap_create_endpoint(grant);
    if let Ok(ep) = refused
    {
        let _ = cap_delete(ep);
    }
    for &ep in made.iter().take(count)
    {
        let _ = cap_delete(ep);
    }
    memory_merge(ctx.memory_base, grant)
        .map_err(|_| "sysinfo::endpoint_retype_bytes: memory_merge of the grant failed")?;
    if count != fits
    {
        return Err("a grant of whole pages funded fewer endpoints than EndpointRetypeBytes sets");
    }
    if refused.is_ok()
    {
        return Err("cap_create_endpoint succeeded from a grant EndpointRetypeBytes says is spent");
    }
    if left != Ok(0)
    {
        return Err("endpoints left bytes in a grant EndpointRetypeBytes says they fill");
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
    if Some(during?) != before.checked_add(1)
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
fn split_top(ctx: &TestContext, pages: u64) -> Result<u64, &'static str>
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "sysinfo::split_top: cap_info(memory_base) failed")?;
    let at = pages
        .checked_mul(PAGE_SIZE)
        .and_then(|bytes| size.checked_sub(bytes))
        .ok_or("sysinfo::split_top: memory_base too small")?;
    memory_split(ctx.memory_base, at)
        .map_err(|_| "sysinfo::split_top: memory_split(memory_base) failed")
}

/// `system_info(SpeculationControls)` answers each view where the kernel
/// reports mitigation state (x86-64) and returns `NotSupported` for each where
/// it does not (riscv64); a view past the last returns `InvalidArgument` on
/// both. Where it answers, a selected control is a known
/// `SPECULATION_CONTROL_*` bit and the inputs a known `SPECULATION_INPUT_*`
/// bit.
pub fn speculation_controls_views(_ctx: &TestContext) -> TestResult
{
    let views = [
        SPECULATION_VIEW_INPUTS,
        SPECULATION_VIEW_SELECTED,
        SPECULATION_VIEW_IN_EFFECT,
    ];
    if crate::arch::HAS_SPECULATION_CONTROLS
    {
        let inputs = speculation_controls(SPECULATION_VIEW_INPUTS)
            .map_err(|_| "system_info(SpeculationControls) inputs view failed")?;
        let selected = speculation_controls(SPECULATION_VIEW_SELECTED)
            .map_err(|_| "system_info(SpeculationControls) selected view failed")?;
        speculation_controls(SPECULATION_VIEW_IN_EFFECT)
            .map_err(|_| "system_info(SpeculationControls) in-effect view failed")?;
        if inputs & !syscall_abi::SPECULATION_INPUT_ALL != 0
        {
            return Err("system_info(SpeculationControls) inputs carry an undefined bit");
        }
        if selected & !syscall_abi::SPECULATION_CONTROL_ALL != 0
        {
            return Err("system_info(SpeculationControls) selection carries an undefined bit");
        }
    }
    else
    {
        for view in views
        {
            if speculation_controls(view) != Err(SyscallError::NotSupported as i64)
            {
                return Err("system_info(SpeculationControls) did not return NotSupported");
            }
        }
    }
    if speculation_controls(SPECULATION_VIEW_IN_EFFECT + 1)
        != Err(SyscallError::InvalidArgument as i64)
    {
        return Err(
            "system_info(SpeculationControls, unknown view) did not return InvalidArgument",
        );
    }
    Ok(())
}

/// `system_info(SmtSibling)` names a CPU below `CpuCount` for each CPU, and
/// returns `InvalidArgument` for an index at or past it; that each ring is
/// its core's CPUs is `integration::smt_siblings`'s.
pub fn smt_sibling_range(_ctx: &TestContext) -> TestResult
{
    let cpus =
        system_info(SystemInfoType::CpuCount as u64).map_err(|_| "system_info(CpuCount) failed")?;
    for cpu in 0..cpus
    {
        let next = smt_sibling(cpu).map_err(|_| "system_info(SmtSibling) failed")?;
        if next >= cpus
        {
            return Err("system_info(SmtSibling) returned an out-of-range CPU id");
        }
    }
    for past in [cpus, u64::MAX]
    {
        if smt_sibling(past) != Err(SyscallError::InvalidArgument as i64)
        {
            return Err("system_info(SmtSibling, past CpuCount) did not return InvalidArgument");
        }
    }
    Ok(())
}

/// Yields that let the scheduler move a pinned thread to its CPU, as the
/// bench harness's pin bounds them.
const MAX_YIELDS: u32 = 1000;
/// The affinity argument that clears a thread's hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Pin `thread`, the calling thread, to `cpu` and yield until it runs there;
/// `false` when it never did.
fn run_on(thread: u64, cpu: u32) -> Result<bool, &'static str>
{
    thread_set_affinity(thread, cpu).map_err(|_| "sysinfo::idle_halts: pin failed")?;
    let on_cpu = || system_info(SystemInfoType::CurrentCpu as u64) == Ok(u64::from(cpu));
    for _ in 0..MAX_YIELDS
    {
        if on_cpu()
        {
            return Ok(true);
        }
        let _ = thread_yield();
    }
    Ok(on_cpu())
}

/// `system_info(IdleHalts)` counts the halts of the calling CPU's idle
/// thread since the caller's previous call on that CPU: a thread pinned to
/// CPU 0 that calls and then sleeps leaves the CPU nothing to run, so its
/// next call returns a count above zero.
///
/// Defect caught: a halt the idle loop does not count, or a query that reads
/// another CPU's count, either of which lets a benchmark's timed window idle
/// with no sign of it in the window's result line.
pub fn idle_halts_rise_across_a_sleep(ctx: &TestContext) -> TestResult
{
    /// The sleep: one tick or more, so the CPU halts at least once.
    const SLEEP_MS: u64 = 2;

    let outcome = if run_on(ctx.thread_cap, 0)?
    {
        // Pinned to CPU 0 and running there, the thread marks CPU 0; the
        // call's value (`InvalidState` when the thread has not called on CPU
        // 0 before) is not read.
        let _ = idle_halts();
        let slept = thread_sleep(SLEEP_MS);
        match (slept, idle_halts())
        {
            (Ok(()), Ok(halts)) if halts > 0 => Ok(()),
            (Ok(()), Ok(_)) => Err("system_info(IdleHalts) counted no halt across a sleep"),
            _ => Err("sysinfo::idle_halts: the sleep, or the read after it, failed"),
        }
    }
    else
    {
        Err("sysinfo::idle_halts: the thread never ran on CPU 0")
    };
    let _ = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    outcome
}

/// Bit the `idle_halts_mark_per_thread_and_cpu` child always sends, so that
/// its notification is never empty.
const MARK_CHILD_RAN: u64 = 1 << 0;
/// Bit the child sends when its first call returned `InvalidState`.
const MARK_CHILD_FIRST_UNMARKED: u64 = 1 << 1;
/// Bit the child sends when its second call returned a count.
const MARK_CHILD_SECOND_ANSWERED: u64 = 1 << 2;

/// The child's stack; one child runs on it at a time, and it has exited when
/// the test returns.
static mut STACK_IDLE_HALTS_MARK: ChildStack = ChildStack::ZERO;

/// `idle_halts_mark_per_thread_and_cpu`'s child, pinned to CPU 0: calls
/// `IdleHalts` twice and reports both outcomes on `sig`.
extern "C" fn idle_halts_mark_child(sig: u64) -> !
{
    let first = idle_halts();
    let second = idle_halts();
    let mut bits = MARK_CHILD_RAN;
    if first == Err(SyscallError::InvalidState as i64)
    {
        bits |= MARK_CHILD_FIRST_UNMARKED;
    }
    if second.is_ok()
    {
        bits |= MARK_CHILD_SECOND_ANSWERED;
    }
    notification_send(sig, bits).ok();
    thread_exit()
}

/// `system_info(IdleHalts)` answers only across two calls of one thread on
/// one CPU: a new thread's first call, and a call after the thread's previous
/// call ran on another CPU, return `InvalidState` and mark the CPU, and the
/// next call there returns a count.
///
/// Defect caught: a Thread retype that leaves a mark naming CPU 0, as zeroed
/// memory or a dead thread's TCB would (the new thread would read a
/// difference from a count it never took), or a mark not tied to its CPU (a
/// moved thread would read the difference of two CPUs' counts).
pub fn idle_halts_mark_per_thread_and_cpu(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "sysinfo::idle_halts_mark: create_notification failed")?;
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "sysinfo::idle_halts_mark: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "sysinfo::idle_halts_mark: cap_copy of the notification failed")?;
    // SAFETY: `STACK_IDLE_HALTS_MARK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_IDLE_HALTS_MARK)) };
    // SAFETY: the stack is `STACK_IDLE_HALTS_MARK`, this test's own
    // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start_pinned(
            &child,
            idle_halts_mark_child,
            stack_top,
            child_sig,
            0,
        )
    }
    .map_err(|_| "sysinfo::idle_halts_mark: configure_and_start_pinned failed")?;
    let bits = notification_wait(sig);
    child
        .delete_thread()
        .map_err(|_| "sysinfo::idle_halts_mark: cap_delete of the child failed")?;
    cap_delete(sig)
        .map_err(|_| "sysinfo::idle_halts_mark: cap_delete of the notification failed")?;
    child
        .delete_cspace()
        .map_err(|_| "sysinfo::idle_halts_mark: cap_delete of the child's CSpace failed")?;
    let bits = bits.map_err(|_| "sysinfo::idle_halts_mark: notification_wait failed")?;
    if bits & MARK_CHILD_FIRST_UNMARKED == 0
    {
        return Err("a new thread's first IdleHalts call did not return InvalidState");
    }
    if bits & MARK_CHILD_SECOND_ANSWERED == 0
    {
        return Err("a new thread's second IdleHalts call on one CPU returned no count");
    }

    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "sysinfo::idle_halts_mark: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log(
            "ktest: sysinfo::idle_halts_mark_per_thread_and_cpu SKIP (the moved-thread half needs 2 CPUs)",
        );
        return Ok(());
    }
    let outcome = idle_halts_mark_moves(ctx.thread_cap);
    let _ = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    outcome
}

/// The moved-thread half of `idle_halts_mark_per_thread_and_cpu`, on
/// `thread`, the calling thread: a count on CPU 0, `InvalidState` on the
/// first call after the move to CPU 1, and a count on the call after it.
fn idle_halts_mark_moves(thread: u64) -> TestResult
{
    if !run_on(thread, 0)?
    {
        return Err("sysinfo::idle_halts_mark: the thread never ran on CPU 0");
    }
    let _ = idle_halts();
    if idle_halts().is_err()
    {
        return Err("a second IdleHalts call on one CPU returned no count");
    }
    if !run_on(thread, 1)?
    {
        return Err("sysinfo::idle_halts_mark: the thread never ran on CPU 1");
    }
    if idle_halts() != Err(SyscallError::InvalidState as i64)
    {
        return Err("an IdleHalts call after a move to another CPU did not return InvalidState");
    }
    if idle_halts().is_err()
    {
        return Err("the IdleHalts call after the moved one returned no count");
    }
    Ok(())
}

/// The kernel synchronised instruction fetch for ktest's own image before
/// ktest ran (Phase 9 maps init's segments, which the bootloader and the PIE
/// rebase wrote through data stores; docs/memory-model.md § Instruction-Fetch
/// Coherence). ktest's entry reads the count before it maps anything, so a
/// boot that skips the Phase-9 sync reads zero; under QEMU the missing sync
/// would not otherwise fail. A failed read at the entry is reported as such,
/// not as a boot without the sync.
pub fn boot_image_synchronised(_ctx: &TestContext) -> TestResult
{
    match crate::BOOT_ICACHE_SYNCS.load(core::sync::atomic::Ordering::Relaxed)
    {
        crate::BOOT_ICACHE_SYNCS_UNREAD =>
        {
            Err("sysinfo::boot_image_synchronised: system_info failed at ktest's entry")
        }
        0 => Err("sysinfo::boot_image_synchronised: no instruction-fetch sync before ktest ran"),
        _ => Ok(()),
    }
}
