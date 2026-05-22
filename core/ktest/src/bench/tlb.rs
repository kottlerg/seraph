// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! TLB-shootdown latency benchmark.
//!
//! Pre-spawns one pinned thread per available CPU (besides ktest's own
//! CPU 0), all sharing ktest's address space — so the aspace is
//! `current` on every CPU. The benchmark loop then `mem_map`s + `mem_unmap`s
//! a single page; per-iteration bracketing isolates the `mem_unmap` call
//! (which triggers an IPI shootdown on every CPU with the aspace `current`).
//!
//! Logs `cpus=N` alongside the result so SMP and UP runs aren't conflated.

use syscall::{cap_create_signal, cap_delete, signal_send, signal_wait, system_info, thread_yield};
use syscall_abi::SystemInfoType;

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

const MAX_PINNED: usize = 7; // CPU 0 is ktest's own; pin children to 1..=7.
static mut SHOOTDOWN_STACKS: [ChildStack; MAX_PINNED] = [const { ChildStack::ZERO }; MAX_PINNED];

/// Child entry: signal "ready", then loop on `thread_yield` until
/// `cap_delete` of the thread cap tears it down.
///
/// `thread_yield` is the preemption point: the kernel's
/// thread-cap-delete path marks the thread Exited under the scheduler
/// lock; on the next reschedule (which a yield triggers immediately)
/// the kernel observes Exited and reaps the TCB without having to
/// race the timer tick. A pure-userspace `spin_loop` body — the
/// previous shape — has no kernel entry point, so a CPU pinned to a
/// single yield-free spinner can only be preempted on a timer
/// boundary, which under release-mode CI is too unreliable: the
/// follow-on `cap_delete` in the bench teardown hangs the harness.
///
/// We still keep ktest's aspace `current` on the pinned CPU between
/// yields (each yield returns to the same spinner because no other
/// thread is ready on that CPU), so the bench's premise — the parent's
/// `mem_unmap` issues a TLB-shootdown IPI to every CPU with the aspace
/// live — still holds.
// cast_possible_truncation: ready_slot is a kernel cap slot index < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn shootdown_spinner_entry(ready_slot: u64) -> !
{
    signal_send(ready_slot as u32, 0x1).ok();
    loop
    {
        let _ = thread_yield();
    }
}

#[allow(clippy::too_many_lines)] // spinner spawn + measure loop + cleanup.
pub(super) fn bench_tlb_shootdown(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x6200_0000;

    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    // cast_possible_truncation: cpus is < 256 on every supported platform.
    #[allow(clippy::cast_possible_truncation)]
    let pin_count = (cpus.saturating_sub(1) as usize).min(MAX_PINNED);

    let Ok(ready) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };

    let mut threads = [0u32; MAX_PINNED];
    let mut cspaces = [0u32; MAX_PINNED];
    let mut spawned: usize = 0;

    // Spawn one pinned spinner per non-ktest CPU.
    for i in 0..pin_count
    {
        let Ok(child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_ready) = syscall::cap_copy(ready, child.cs, 1 << 7)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };
        // SAFETY: bench tier runs sequentially; this is the only use of
        // SHOOTDOWN_STACKS[i].
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(SHOOTDOWN_STACKS[i]) });
        // i runs 0..pin_count ≤ MAX_PINNED ≤ 7; fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        let cpu = (i + 1) as u32;
        if spawn::configure_and_start_pinned(
            &child,
            shootdown_spinner_entry,
            stack_top,
            u64::from(child_ready),
            cpu,
        )
        .is_err()
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        }
        threads[i] = child.th;
        cspaces[i] = child.cs;
        spawned += 1;
    }

    // Wait for each spawned child to confirm it's running (ensures the
    // aspace is loaded on each pinned CPU before we measure shootdowns).
    for _ in 0..spawned
    {
        let _ = signal_wait(ready);
    }

    let Some(frame) = crate::frame_pool::alloc()
    else
    {
        // Tear down children before returning.
        for i in 0..spawned
        {
            cap_delete(threads[i]).ok();
            cap_delete(cspaces[i]).ok();
        }
        cap_delete(ready).ok();
        return;
    };

    let n = u64::from(iters);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        if syscall::mem_map(frame, ctx.aspace_cap, BENCH_VA, 0, 1, syscall::MAP_WRITABLE).is_err()
        {
            break;
        }
        // Measure the unmap — that's the path that issues the shootdown IPI.
        let t0 = cycles_now();
        let _ = syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1);
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    // SAFETY: frame is from pool and now unmapped.
    unsafe { crate::frame_pool::free(frame) };

    // Tear down spinners. Deleting the Thread cap kicks the spinner off the
    // CPU (kernel waits for the running thread to context-switch out, then
    // frees the TCB).
    for i in 0..spawned
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(ready).ok();

    log_bench_header("tlb_shootdown_unmap", iters);
    crate::log_u64("ktest: bench  cpus=", cpus);
    crate::log_u64("ktest: bench  pinned_workers=", spawned as u64);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
