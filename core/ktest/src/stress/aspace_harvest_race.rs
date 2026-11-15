// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/aspace_harvest_race.rs

//! Stress: `SYS_ASPACE_HARVEST` races stores and loads of the pages it reads
//! and clears.
//!
//! [`WORKERS`] worker threads, a fixed four whatever the CPU count, each own
//! four of sixteen scratch pages and loop storing a round counter as a `u64`
//! at offset 0 of each owned page and reading it back, until [`STOP`] is set.
//! Worker `w` is pinned to CPU `w % cpus`, so on fewer than four CPUs the
//! workers share the ones there are. The harness, with no worker bound to a
//! fault handler, makes [`HARVESTS`] harvests of the sixteen pages, then sets
//! [`STOP`] and waits, blocking, for every worker's report. A worker may make
//! no progress while the harness harvests on its CPU (children run at the
//! lowest priority); this is accepted.
//!
//! ## Pass criterion
//!
//! Every worker reports done with no mismatch (a fault kills a worker, so its
//! done bit never arrives and the bounded wait fails), every harvest's count
//! equals the popcount of its bitmap, and the OR of the bitmaps has all sixteen
//! bits set, since the first harvest sees the A bit every leaf the kernel
//! installs starts with.

use core::sync::atomic::{AtomicBool, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_exit,
};
use syscall_abi::{PAGE_SIZE, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Scratch VA (crate docs § Scratch VAs) of the cell's pages, distinct from
/// every other test's VA.
const VA: u64 = 0x1_9200_0000;

/// Worker threads, fixed.
const WORKERS: usize = 4;

/// Pages each worker owns.
const PAGES_PER_WORKER: usize = 4;

/// Pages the cell maps from [`VA`].
const PAGES: usize = WORKERS * PAGES_PER_WORKER;

/// Harvest calls the harness makes before it stops the workers.
const HARVESTS: u32 = 500;

/// Set by the harness (or the cell's drop) to end the workers' loops.
static STOP: AtomicBool = AtomicBool::new(false);

/// A worker's done bit is `1 << index`; this bit above them all marks a
/// worker that read back a value other than the one it stored.
const MISMATCH_BIT: u64 = 1 << 32;

/// Bound on the whole harvesting loop, in milliseconds, through
/// [`crate::scaled_bound`].
const LOOP_MS: u64 = 20_000;

/// Per-worker arguments, handed to `worker_entry` by address.
#[derive(Clone, Copy)]
struct WorkerArgs
{
    done: u64,
    /// The worker's first page.
    first_va: u64,
    done_bit: u64,
}

static WORKER_ARGS: spawn::ArgBlock<WorkerArgs, WORKERS> = spawn::ArgBlock::new(WorkerArgs {
    done: 0,
    first_va: 0,
    done_bit: 0,
});

/// The address of page `i`; `i` is below [`PAGES`], so the sum stays in the
/// low scratch band.
fn page_va(i: usize) -> u64
{
    (i as u64).wrapping_mul(PAGE_SIZE).wrapping_add(VA)
}

/// What the cell holds, released on drop: the workers first (no thread then
/// reaches a page), then the frames, then the notification.
struct Cell
{
    done: u64,
    children: [spawn::SpawnedChild; WORKERS],
    frames: [Option<crate::frame_pool::FrameGuard>; PAGES],
}

impl Drop for Cell
{
    fn drop(&mut self)
    {
        STOP.store(true, Ordering::Release);
        for child in &mut self.children
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
        }
        for frame in &mut self.frames
        {
            drop(frame.take());
        }
        if self.done != 0
        {
            cap_delete(self.done).ok();
        }
    }
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::aspace_harvest_race: system_info(CpuCount) failed")?
        .max(1);
    STOP.store(false, Ordering::Release);
    let mut cell = Cell {
        done: 0,
        children: [const { spawn::SpawnedChild::EMPTY }; WORKERS],
        frames: Default::default(),
    };
    for (i, slot) in cell.frames.iter_mut().enumerate()
    {
        let mut frame = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
            .ok_or("stress::aspace_harvest_race: frame pool exhausted")?;
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs), off
        // every Rust object and IPC page of ktest.
        unsafe { frame.map(page_va(i)) }
            .map_err(|_| "stress::aspace_harvest_race: mem_map failed")?;
        *slot = Some(frame);
    }
    cell.done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::aspace_harvest_race: cap_create_notification failed")?;
    let done = cell.done;

    for (w, child_slot) in cell.children.iter_mut().enumerate()
    {
        *child_slot = spawn::new_child(ctx)
            .map_err(|_| "stress::aspace_harvest_race: spawn::new_child failed")?;
        let child = &*child_slot;
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "stress::aspace_harvest_race: cap_copy(done) failed")?;
        // SAFETY: worker `w` has not been started; the block is reused only
        // after every worker has been deleted.
        let arg = unsafe {
            WORKER_ARGS.publish(
                w,
                WorkerArgs {
                    done: child_done,
                    first_va: page_va(w.wrapping_mul(PAGES_PER_WORKER)),
                    done_bit: 1u64 << w,
                },
            )
        };
        // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let stack_top =
            unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), w) }?;
        let cpu = (w as u64)
            .checked_rem(cpus)
            .and_then(|slot| u32::try_from(slot).ok())
            .unwrap_or(0);
        // SAFETY: the stack is `super::STRESS_STACKS[w]`, this test's own
        // `ChildStack`, on which no other live thread runs (`ChildStack`'s
        // rule).
        unsafe { spawn::configure_and_start_pinned(child, worker_entry, stack_top, arg, cpu) }
            .map_err(|_| "stress::aspace_harvest_race: configure_and_start_pinned failed")?;
    }

    harvest_then_collect(ctx, done)
}

/// Harvest the pages [`HARVESTS`] times, checking each harvest's count against
/// its bitmap; then stop the workers and collect every done bit, blocking so a
/// starved worker gets its CPU. The accumulated bitmaps must cover every page.
fn harvest_then_collect(ctx: &TestContext, done: u64) -> TestResult
{
    let all_done = (1u64 << WORKERS) - 1;
    let mut seen = [0u8; PAGES / 8];
    for _ in 0..HARVESTS
    {
        let mut bitmap = [0u8; PAGES / 8];
        let count = syscall::aspace_harvest(ctx.aspace_cap, VA, PAGES as u64, &mut bitmap)
            .map_err(|_| "stress::aspace_harvest_race: aspace_harvest failed")?;
        let popcount: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
        if count != u64::from(popcount)
        {
            return Err("stress::aspace_harvest_race: a harvest's count differs from its bitmap");
        }
        for (acc, byte) in seen.iter_mut().zip(bitmap)
        {
            *acc |= byte;
        }
    }
    STOP.store(true, Ordering::Release);

    let deadline_us = crate::scaled_bound(LOOP_MS).saturating_mul(1000);
    let start_us = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "stress::aspace_harvest_race: system_info(ElapsedUs) failed")?;
    let mut done_bits = 0u64;
    let mut mismatch = false;
    while done_bits & all_done != all_done
    {
        let now_us = system_info(SystemInfoType::ElapsedUs as u64)
            .map_err(|_| "stress::aspace_harvest_race: system_info(ElapsedUs) failed")?;
        let remaining_ms = deadline_us
            .saturating_sub(now_us.saturating_sub(start_us))
            .checked_div(1000)
            .unwrap_or(0);
        if remaining_ms == 0
        {
            return Err("stress::aspace_harvest_race: workers did not all report done in time");
        }
        let bits = notification_wait_timeout(done, remaining_ms)
            .map_err(|_| "stress::aspace_harvest_race: notification_wait failed")?;
        done_bits |= bits & all_done;
        mismatch |= bits & MISMATCH_BIT != 0;
    }
    if mismatch
    {
        return Err("stress::aspace_harvest_race: a worker read back a value it did not store");
    }
    if seen != [0xFF; PAGES / 8]
    {
        return Err("stress::aspace_harvest_race: the harvests did not report every page");
    }
    Ok(())
}

/// A worker: store the round counter into each owned page and read it back
/// until [`STOP`] is set, then report.
extern "C" fn worker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the `WORKER_ARGS` entry `run` published.
    let a: WorkerArgs = unsafe { spawn::child_args(arg) };
    let pages: [u64; PAGES_PER_WORKER] =
        core::array::from_fn(|i| a.first_va.wrapping_add((i as u64).wrapping_mul(PAGE_SIZE)));
    let mut mismatch = false;
    let mut round = 0u64;
    while !STOP.load(Ordering::Acquire)
    {
        round = round.wrapping_add(1);
        for &va in &pages
        {
            let ptr = va as *mut u64;
            // SAFETY: the page is mapped writable by `run`, owned by this
            // worker alone, holds no Rust object, and `va` is page-aligned.
            unsafe { ptr.write_volatile(round) };
            // SAFETY: as for the write.
            let seen = unsafe { ptr.read_volatile() };
            mismatch |= seen != round;
        }
    }
    let bits = if mismatch
    {
        a.done_bit | MISMATCH_BIT
    }
    else
    {
        a.done_bit
    };
    notification_send(a.done, bits).ok();
    thread_exit()
}
