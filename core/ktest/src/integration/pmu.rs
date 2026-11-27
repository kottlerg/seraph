// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/pmu.rs

//! Integration: the PMU syscalls (`SYS_PMU_INFO`, `SYS_PMU_CONFIGURE`, `SYS_PMU_BIND`) program a
//! CPU's counters and grant a thread their direct reads (docs/capability-model.md
//! § `PmuControl`).
//!
//! Where the CPU has counters, the case checks, in order: the refusals that
//! hold on any CPU (an unpinned caller, more than eight events, an unknown or
//! repeated event, a mode word that names no mode, a capability without the
//! right or of another type, and a bind flag other than 0 and 1); that each
//! event the info mask names configures and each it does not is refused as
//! unsupported; that a child never bound faults on its first counter read
//! (`#GP(0)` on x86-64, an illegal instruction on riscv64) at the read; that
//! this thread, bound, reads both counters of a `Cycles`, `Instructions` configuration
//! and each advances across a counted loop; and, from two CPUs, that unbinding a
//! child that reads in a loop on another CPU makes its next read fault. A
//! CPU with no counters (x86-64 under TCG) skips the case after the info call.
//!
//! **No fault dump.** The handler resumes each faulted child at [`exit_entry`], so it
//! exits voluntarily and the kernel prints no kill dump.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use pmu::client::Pmu;
use pmu::{Info, PmuEvent, PmuMode};
use syscall::{
    cap_create_endpoint, cap_delete, cap_derive, pmu_configure, pmu_info, thread_read_regs,
    thread_set_affinity, thread_sleep, thread_write_regs, thread_yield,
};
use syscall_abi::{
    EXIT_VOLUNTARY, FAULT_KIND_EXCEPTION, FAULT_LABEL, FAULT_REPLY_RESUME, PMU_EVENT_COUNT,
    SYS_PMU_BIND, SyscallError, SystemInfoType,
};

use crate::spawn::SpawnedChild;
use crate::{ChildStack, TestContext, TestResult};

/// Badge bound with the handler and delivered in each fault message.
const FAULT_BADGE: u64 = 0x0C47_0002;

/// Register-file buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Poll bound for a child's progress and exit: ~2 s at ~1 ms per poll, through
/// [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Wait bound in milliseconds for a fault message, through
/// [`crate::scaled_bound`].
const FAULT_WAIT_MS: u64 = 2000;

/// Iterations of the counted loop.
const LOOP_N: u64 = 100_000;

/// Reads the revoke child completes before the unbind: the child is bound and
/// running when the count passes it.
const PROGRESS_MIN: u64 = 8;

/// The CPU the case measures on.
const CPU_A: u32 = 0;

/// The CPU the revoke case runs its child on.
const CPU_B: u32 = 1;

/// The affinity that names no CPU.
const AFFINITY_ANY: u32 = u32::MAX;

/// The fault class (`syscall_abi::FAULT_EXC_*`) an unbound counter read raises.
#[cfg(target_arch = "x86_64")]
const READ_FAULT: u64 = syscall_abi::FAULT_EXC_PROTECTION;
/// The fault class an unbound counter read raises.
#[cfg(target_arch = "riscv64")]
const READ_FAULT: u64 = syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION;

/// The error code of that fault, where the architecture fixes one.
#[cfg(target_arch = "x86_64")]
const READ_FAULT_CODE: Option<u64> = Some(0);
/// The error code of that fault, where the architecture fixes one.
#[cfg(target_arch = "riscv64")]
const READ_FAULT_CODE: Option<u64> = None;

/// Address of the counter read the unbound child is about to execute.
static UNBOUND_IP: AtomicU64 = AtomicU64::new(0);

/// Address of the counter read the revoke child last began.
static REVOKE_IP: AtomicU64 = AtomicU64::new(0);

/// Reads the revoke child has completed.
static PROGRESS: AtomicU64 = AtomicU64::new(0);

static mut UNBOUND_STACK: ChildStack = ChildStack::ZERO;
static mut REVOKE_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    if ctx.pmu_control_cap == 0
    {
        return Err("integration::pmu: no PmuControl capability in the initial cap set");
    }
    let pmu = Pmu::new(ctx.pmu_control_cap);
    let info = match pmu.info()
    {
        Ok(info) => info,
        Err(code) if code == SyscallError::NotSupported as i64 =>
        {
            if cfg!(target_arch = "x86_64")
            {
                crate::log("ktest: integration::pmu SKIP (no PMU on this CPU)");
                return Ok(());
            }
            return Err("integration::pmu: SYS_PMU_INFO reports no counters on riscv64");
        }
        Err(_) => return Err("integration::pmu: SYS_PMU_INFO failed"),
    };
    if !info.present()
        || info.counters < 2
        || info.width == 0
        || !info.supports(PmuEvent::Cycles)
        || !info.supports(PmuEvent::Instructions)
    {
        return Err("integration::pmu: info lacks two counters, a width, Cycles or Instructions");
    }
    refusals(ctx)?;

    pin(ctx, CPU_A)?;
    let result = measure(ctx, pmu, info);
    // Teardown on every path: this thread's own grant, CPU A's counters, the
    // affinity.
    let back = pin(ctx, CPU_A);
    pmu.unbind(ctx.thread_cap).ok();
    let released = pmu.release();
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    result?;
    back?;
    released.map_err(|_| "integration::pmu: release of CPU A's counters failed")?;
    restored.map_err(|_| "integration::pmu: restoring this thread's affinity failed")?;
    crate::log("ktest: integration::pmu PASS");
    Ok(())
}

/// Pin this thread to `cpu` and yield once, so that it runs there.
fn pin(ctx: &TestContext, cpu: u32) -> TestResult
{
    thread_set_affinity(ctx.thread_cap, cpu)
        .map_err(|_| "integration::pmu: thread_set_affinity failed")?;
    thread_yield().map_err(|_| "integration::pmu: thread_yield failed")
}

/// The result `got` is the error `want`, else `msg`.
fn expect_err<T>(got: Result<T, i64>, want: SyscallError, msg: &'static str) -> TestResult
{
    if got.err() == Some(want as i64)
    {
        Ok(())
    }
    else
    {
        Err(msg)
    }
}

/// The refusals that need no counters and no pinning, except the first.
fn refusals(ctx: &TestContext) -> TestResult
{
    let cap = ctx.pmu_control_cap;
    let user = PmuMode::User.raw();
    expect_err(
        pmu_configure(cap, 0, 1, user),
        SyscallError::InvalidState,
        "integration::pmu: configure with no affinity set was not refused InvalidState",
    )?;
    expect_err(
        pmu_configure(cap, 0, 9, user),
        SyscallError::InvalidArgument,
        "integration::pmu: configure of nine events was not refused InvalidArgument",
    )?;
    expect_err(
        pmu_configure(cap, u64::from(PMU_EVENT_COUNT), 1, user),
        SyscallError::InvalidArgument,
        "integration::pmu: configure of an unknown event was not refused InvalidArgument",
    )?;
    expect_err(
        pmu_configure(cap, 0, 2, user),
        SyscallError::InvalidArgument,
        "integration::pmu: configure of a repeated event was not refused InvalidArgument",
    )?;
    // Neither 0 nor 4 names a mode.
    for mode in [0, 4]
    {
        if PmuMode::from_raw(mode).is_some()
        {
            return Err("integration::pmu: a test mode word names a mode");
        }
        expect_err(
            pmu_configure(cap, 0, 1, mode),
            SyscallError::InvalidArgument,
            "integration::pmu: configure with a bad mode word was not refused InvalidArgument",
        )?;
    }
    let weak = cap_derive(cap, 0).map_err(|_| "integration::pmu: cap_derive failed")?;
    let weak_result = expect_err(
        pmu_info(weak),
        SyscallError::InsufficientRights,
        "integration::pmu: info without Configure was not refused InsufficientRights",
    );
    cap_delete(weak).map_err(|_| "integration::pmu: deleting the derived cap failed")?;
    weak_result?;
    expect_err(
        pmu_info(ctx.thread_cap),
        SyscallError::InvalidCapability,
        "integration::pmu: info on a Thread cap was not refused InvalidCapability",
    )?;
    // SAFETY: SYS_PMU_BIND takes capability handles and a flag; the call
    // changes no mapping, IPC page or thread entry state, as raw_syscall3's
    // contract requires.
    let raw = unsafe { syscall::raw_syscall3(SYS_PMU_BIND, cap, ctx.thread_cap, 2) };
    if raw != SyscallError::InvalidArgument as i64
    {
        return Err("integration::pmu: bind with the flag 2 was not refused InvalidArgument");
    }
    Ok(())
}

/// The pinned part: every event, the unbound read, the bound reads, and the
/// revoke. Runs with this thread pinned to [`CPU_A`].
fn measure(ctx: &TestContext, pmu: Pmu, info: Info) -> TestResult
{
    for event in PmuEvent::ALL
    {
        let configured = pmu.configure(&[event], PmuMode::User);
        if info.supports(event)
        {
            if configured.is_err()
            {
                return Err("integration::pmu: a supported event did not configure");
            }
        }
        else
        {
            expect_err(
                configured,
                SyscallError::NotSupported,
                "integration::pmu: an unsupported event was not refused NotSupported",
            )?;
        }
    }
    let counters = pmu
        .configure(&[PmuEvent::Cycles, PmuEvent::Instructions], PmuMode::User)
        .map_err(|_| "integration::pmu: configure of Cycles and Instructions failed")?;
    let first = counters
        .handles()
        .first()
        .copied()
        .ok_or("integration::pmu: configure returned no handle")?;

    unbound_read_faults(ctx, first)?;

    counters
        .bind(ctx.thread_cap)
        .map_err(|_| "integration::pmu: bind of this thread failed")?;
    let mut start = [0u64; 2];
    counters.read(&mut start);
    core::hint::black_box(counted_loop(LOOP_N));
    let mut end = [0u64; 2];
    counters.read(&mut end);
    let [c0, i0] = start;
    let [c1, i1] = end;
    let cycles = counters.delta(c0, c1);
    let instructions = counters.delta(i0, i1);
    crate::log_args(format_args!(
        "ktest: integration::pmu cycles={cycles} instructions={instructions}"
    ));
    if cycles == 0 || instructions == 0 || c1 < c0 || i1 < i0
    {
        return Err("integration::pmu: a counter did not advance across the loop");
    }
    if cfg!(target_arch = "x86_64") && instructions < LOOP_N
    {
        return Err("integration::pmu: fewer instructions counted than loop iterations");
    }
    pmu.unbind(ctx.thread_cap)
        .map_err(|_| "integration::pmu: unbind of this thread failed")?;

    revoke(ctx, pmu)
}

/// A counted loop of `n` iterations.
#[inline(never)]
fn counted_loop(n: u64) -> u64
{
    let mut acc = 0u64;
    for i in 0..n
    {
        acc = core::hint::black_box(acc.wrapping_add(i));
    }
    acc
}

/// A child never bound, pinned to [`CPU_A`], faults at its first counter read.
fn unbound_read_faults(ctx: &TestContext, handle: u8) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::pmu: cap_create_endpoint failed")?;
    let result = (|| {
        let mut child = crate::spawn::new_child(ctx)
            .map_err(|_| "integration::pmu: spawn::new_child failed")?;
        crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
            .map_err(|_| "integration::pmu: thread_set_fault_handler failed")?;
        UNBOUND_IP.store(0, Ordering::Release);
        // SAFETY: `UNBOUND_STACK` is a static stack, reached only through `addr_of!`.
        let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(UNBOUND_STACK)) };
        // SAFETY: the stack is `UNBOUND_STACK`, this case's own `ChildStack`, on which no
        // other live thread runs: the one child runs here and is reaped below.
        unsafe {
            crate::spawn::configure_and_start_pinned(
                &child,
                unbound_reader,
                stack_top,
                u64::from(handle),
                CPU_A,
            )
        }
        .map_err(|_| "integration::pmu: configure_and_start_pinned failed")?;
        expect_fault(
            ctx,
            ep,
            &child,
            &UNBOUND_IP,
            "integration::pmu: an unbound counter read did not fault",
        )?;
        reap(&mut child)
    })();
    cap_delete(ep).ok();
    result
}

/// Revoke on another CPU: a bound child reading in a loop on [`CPU_B`] faults at
/// its next read once unbound. Skipped below two CPUs.
fn revoke(ctx: &TestContext, pmu: Pmu) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::pmu: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: integration::pmu revoke SKIP (needs 2 CPUs)");
        return Ok(());
    }
    let result = revoke_on_b(ctx, &pmu);
    // Release CPU B's counters from B, and return to A, on every path.
    let released = pin(ctx, CPU_B).and_then(|()| {
        pmu.release()
            .map_err(|_| "integration::pmu: release of CPU B's counters failed")
    });
    let back = pin(ctx, CPU_A);
    result?;
    released?;
    back
}

/// The body of [`revoke`].
fn revoke_on_b(ctx: &TestContext, pmu: &Pmu) -> TestResult
{
    pin(ctx, CPU_B)?;
    let counters = pmu
        .configure(&[PmuEvent::Cycles], PmuMode::User)
        .map_err(|_| "integration::pmu: configure on CPU B failed")?;
    let handle = counters
        .handles()
        .first()
        .copied()
        .ok_or("integration::pmu: configure on CPU B returned no handle")?;
    pin(ctx, CPU_A)?;

    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::pmu: cap_create_endpoint failed")?;
    let result = (|| {
        let mut child = crate::spawn::new_child(ctx)
            .map_err(|_| "integration::pmu: spawn::new_child failed")?;
        crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
            .map_err(|_| "integration::pmu: thread_set_fault_handler failed")?;
        pmu.bind(child.th)
            .map_err(|_| "integration::pmu: bind of the child failed")?;
        REVOKE_IP.store(0, Ordering::Release);
        PROGRESS.store(0, Ordering::Release);
        // SAFETY: `REVOKE_STACK` is a static stack, reached only through `addr_of!`.
        let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(REVOKE_STACK)) };
        // SAFETY: the stack is `REVOKE_STACK`, this case's own `ChildStack`, on which no
        // other live thread runs: the one child runs here and is reaped below.
        unsafe {
            crate::spawn::configure_and_start_pinned(
                &child,
                revoke_reader,
                stack_top,
                u64::from(handle),
                CPU_B,
            )
        }
        .map_err(|_| "integration::pmu: configure_and_start_pinned failed")?;

        let mut polls = 0u32;
        while PROGRESS.load(Ordering::Acquire) < PROGRESS_MIN
        {
            polls = polls.saturating_add(1);
            if polls >= crate::scaled_polls(MAX_POLLS)
            {
                return Err("integration::pmu: the bound child did not read without faulting");
            }
            thread_sleep(1).ok();
        }
        pmu.unbind(child.th)
            .map_err(|_| "integration::pmu: unbind of the child failed")?;
        expect_fault(
            ctx,
            ep,
            &child,
            &REVOKE_IP,
            "integration::pmu: revoke did not reach the running thread",
        )?;
        reap(&mut child)
    })();
    cap_delete(ep).ok();
    result
}

/// Wait for a child resumed at [`exit_entry`] to exit voluntarily, and delete its caps.
fn reap(child: &mut SpawnedChild) -> TestResult
{
    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason != EXIT_VOLUNTARY
    {
        return Err("integration::pmu: resumed child did not exit voluntarily");
    }
    Ok(())
}

/// Receive the child's fault on `ep`, check it is [`READ_FAULT`] at the address the child
/// recorded in `ip_slot`, and resume the child at [`exit_entry`]. `missing` is the
/// failure when no fault arrives in time.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each), the `Result` temporaries \
              of its `ipc_recv_timeout(..)?` and the `regs` buffer (512 B); on init's 16 KiB stack"
)]
fn expect_fault(
    ctx: &TestContext,
    ep: u64,
    child: &SpawnedChild,
    ip_slot: &AtomicU64,
    missing: &'static str,
) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv_timeout(ep, ctx.ipc_buf, crate::scaled_bound(FAULT_WAIT_MS)) }
        .map_err(|_| missing)?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE || msg.word(0) != FAULT_KIND_EXCEPTION
    {
        return Err("integration::pmu: unexpected fault message");
    }
    let read_ip = ip_slot.load(Ordering::Acquire);
    if read_ip == 0 || msg.word(3) != read_ip
    {
        return Err("integration::pmu: the fault is not at the counter read");
    }
    if msg.word(1) != READ_FAULT || READ_FAULT_CODE.is_some_and(|code| msg.word(2) != code)
    {
        return Err("integration::pmu: the counter read raised another exception");
    }

    let mut regs = [0u8; BUF];
    thread_read_regs(child.th, &mut regs[..])
        .map_err(|_| "integration::pmu: thread_read_regs failed")?;
    crate::spawn::redirect_to_entry(&mut regs[..], exit_entry as *const () as u64)?;
    // SAFETY: the frame was read from this fault-blocked child, so its stack
    // pointer lies on the child's own `ChildStack`; `redirect_to_entry` pointed it
    // at `exit_entry`, an `extern "C"` entry that never returns and needs nothing
    // of the abandoned frame, with the stack pointer moved down to the entry
    // ABI's alignment on that same stack.
    unsafe { thread_write_regs(child.th, &regs[..]) }
        .map_err(|_| "integration::pmu: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::pmu: ipc_reply(RESUME) failed")?;
    Ok(())
}

/// Child entry: read counter `handle`, never bound, so the read faults.
extern "C" fn unbound_reader(handle: u64) -> !
{
    core::hint::black_box(read_recording(handle_byte(handle), &UNBOUND_IP));
    syscall::thread_exit()
}

/// Child entry: read counter `handle` in a loop, bound at first, counting each
/// read in [`PROGRESS`]; faults at the first read after the unbind.
extern "C" fn revoke_reader(handle: u64) -> !
{
    loop
    {
        core::hint::black_box(read_recording(handle_byte(handle), &REVOKE_IP));
        PROGRESS.fetch_add(1, Ordering::Release);
    }
}

/// Recovery entry the handler resumes a faulted child at: exit voluntarily.
extern "C" fn exit_entry(_arg: u64) -> !
{
    syscall::thread_exit()
}

/// The read handle a child's argument carries.
fn handle_byte(arg: u64) -> u8
{
    u8::try_from(arg).unwrap_or(0)
}

/// Store the address of the read of counter `handle` into `slot`, then execute
/// it, as [`read_counter`] does.
#[cfg(target_arch = "x86_64")]
fn read_recording(handle: u8, slot: &AtomicU64) -> u64
{
    let slot = slot.as_ptr();
    let lo: u32;
    let hi: u32;
    // SAFETY: `lea` and the store use the scratch register `t` and write only the
    // `AtomicU64` behind `slot`; `rdpmc` reads counter ECX into EDX:EAX and touches no
    // flag; unbound it raises #GP and writes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            "rdpmc",
            t = out(reg) _,
            slot = in(reg) slot,
            in("ecx") u32::from(handle),
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Store the address of the read of counter `handle` (the CSR offset from `cycle`,
/// 3 to 31) into `slot`, then execute it, as [`read_counter`] does; 0 for a handle no
/// counter CSR has.
#[cfg(target_arch = "riscv64")]
fn read_recording(handle: u8, slot: &AtomicU64) -> u64
{
    let slot = slot.as_ptr();
    macro_rules! csrr {
        ($($n:literal),*) => {
            match handle
            {
                $($n => {
                    let v: u64;
                    // SAFETY: `lla` and the store use the scratch register `t` and
                    // write only the `AtomicU64` behind `slot`; the `csrr` writes only
                    // `v`, and an unbound one raises an illegal-instruction exception and
                    // writes nothing. RISC-V has no flags register.
                    unsafe {
                        core::arch::asm!(
                            "lla {t}, 2f",
                            "sd {t}, 0({slot})",
                            "2:",
                            concat!("csrr {v}, hpmcounter", $n),
                            t = out(reg) _,
                            v = out(reg) v,
                            slot = in(reg) slot,
                            options(nostack),
                        );
                    }
                    v
                })*
                _ => 0,
            }
        };
    }
    csrr!(
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31
    )
}
