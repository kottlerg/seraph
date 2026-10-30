// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/concurrent_map_unmap.rs

//! Stress test: concurrent memory map/unmap from multiple threads.
//!
//! `NUM_CHILDREN` threads each map and unmap a distinct VA range
//! `MAP_ITERATIONS` times (fewer past 16 CPUs, see
//! [`super::scaled_attempts`]), sharing the same address space. Exercises
//! page table lock contention and TLB shootdown under load.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, mem_map, mem_unmap, notification_send,
    notification_wait, system_info, thread_exit,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CHILDREN: usize = 16;
const MAP_ITERATIONS: u32 = 1000;

/// Fewest iterations per child at any width: every unmap broadcasts a
/// shootdown to the CPUs running the address space, so a few dozen still
/// contend the page-table lock and the shootdown from every child.
const MIN_MAP_ITERATIONS: u32 = 64;

/// A child's `done` bit is `1 << index`; [`ERROR_BIT`] above them all marks
/// a child that failed.
const ERROR_BIT: u64 = 1 << 32;

// Every child's done bit must lie below the error bit.
const _: () = assert!(NUM_CHILDREN <= 32);

/// Per-child arguments, handed to `mapper_entry` by address.
#[derive(Clone, Copy)]
struct MapperArgs
{
    done: u32,
    memory: u32,
    aspace: u32,
    done_bit: u64,
    /// Map/unmap iterations to run.
    iterations: u32,
}

static MAPPER_ARGS: spawn::ArgBlock<MapperArgs, NUM_CHILDREN> = spawn::ArgBlock::new(MapperArgs {
    done: 0,
    memory: 0,
    aspace: 0,
    done_bit: 0,
    iterations: 0,
});

/// Base VA for stress mappings, well above normal test VAs.
const STRESS_MAP_BASE: u64 = 0x1_5000_0000;
/// Spacing between each child's VA (16-page stride).
const VA_STRIDE: u64 = 0x1_0000;

/// The pool frames and children the cell holds: the first `allocated`
/// frames and the first `spawned` children are live.
struct Mappers
{
    frames: [u32; NUM_CHILDREN],
    allocated: usize,
    children: [spawn::SpawnedChild; NUM_CHILDREN],
    spawned: usize,
}

/// Child `index`'s stress VA.
fn child_va(index: usize) -> u64
{
    STRESS_MAP_BASE + (index as u64) * VA_STRIDE
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "concurrent_map_unmap: system_info(CpuCount) failed")?;
    // Each unmap's shootdown reaches more CPUs, and costs more, with the
    // width; the count shrinks with it.
    let iterations = super::scaled_attempts(MAP_ITERATIONS, MIN_MAP_ITERATIONS, cpus);
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "concurrent_map_unmap: create done failed")?;

    let mut mappers = Mappers {
        frames: [0; NUM_CHILDREN],
        allocated: 0,
        children: [const { spawn::SpawnedChild::EMPTY }; NUM_CHILDREN],
        spawned: 0,
    };
    let result =
        start_mappers(ctx, done, iterations, &mut mappers).and_then(|()| await_mappers(done));
    let released = release(ctx, &mut mappers);
    cap_delete(done).ok();
    result?;
    released
}

/// Allocate one pool frame per child, then start each child on its own
/// frame and VA, recording each frame and child in `mappers` as soon as it
/// exists.
fn start_mappers(ctx: &TestContext, done: u32, iterations: u32, mappers: &mut Mappers)
-> TestResult
{
    for i in 0..NUM_CHILDREN
    {
        mappers.frames[i] =
            crate::frame_pool::alloc().ok_or("concurrent_map_unmap: frame pool exhausted")?;
        mappers.allocated = i + 1;
    }

    // Each child gets copies of its Memory cap and the aspace cap in its own
    // CSpace.
    for (i, va_slot) in VA_PER_CHILD.iter().enumerate()
    {
        mappers.children[i] =
            spawn::new_child(ctx).map_err(|_| "concurrent_map_unmap: spawn::new_child failed")?;
        mappers.spawned = i + 1;
        let child = &mappers.children[i];
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "concurrent_map_unmap: cap_copy done failed")?;
        // Copy memory and aspace caps into child's CSpace with full rights.
        let child_memory = cap_copy(mappers.frames[i], child.cs, syscall::RIGHTS_ALL)
            .map_err(|_| "concurrent_map_unmap: cap_copy memory failed")?;
        let child_aspace = cap_copy(ctx.aspace_cap, child.cs, syscall::RIGHTS_ALL)
            .map_err(|_| "concurrent_map_unmap: cap_copy aspace failed")?;

        // SAFETY: child `i` has not been started yet; the block is reused
        // only after every child has been reaped.
        let arg = unsafe {
            MAPPER_ARGS.publish(
                i,
                MapperArgs {
                    done: child_done,
                    memory: child_memory,
                    aspace: child_aspace,
                    done_bit: 1u64 << i,
                    iterations,
                },
            )
        };

        // Publish this child's VA in its VA_PER_CHILD slot; the child recovers `i`
        // from its done_bit (`trailing_zeros`).
        va_slot.store(child_va(i), core::sync::atomic::Ordering::Release);

        // SAFETY: Each child uses a distinct stack index.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        // SAFETY: the stack is `super::STRESS_STACKS[i]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start(child, mapper_entry, stack_top, arg) }
            .map_err(|_| "concurrent_map_unmap: configure_and_start failed")?;
    }
    Ok(())
}

/// Wait for every child's done bit; fail if any child reported failure.
fn await_mappers(done: u32) -> TestResult
{
    let all_done = (1u64 << NUM_CHILDREN) - 1;
    let mut done_bits: u64 = 0;
    let mut child_failed = false;
    while done_bits & all_done != all_done
    {
        let bits = notification_wait(done)
            .map_err(|_| "concurrent_map_unmap: notification_wait failed")?;
        done_bits |= bits;
        if bits & ERROR_BIT != 0
        {
            child_failed = true;
        }
    }
    if child_failed
    {
        return Err("concurrent_map_unmap: child reported failure");
    }
    Ok(())
}

/// Delete every child started, then return each frame to the pool once its
/// VA is unmapped: a child that failed may have left its frame mapped, and
/// a frame still mapped stays out of the pool rather than being handed out
/// again.
fn release(ctx: &TestContext, mappers: &mut Mappers) -> TestResult
{
    for child in &mut mappers.children[..mappers.spawned]
    {
        child.delete_thread().ok();
        child.delete_cspace().ok();
    }
    let mut result = Ok(());
    for i in 0..mappers.allocated
    {
        let va = child_va(i);
        // A VA its child left unmapped refuses the unmap; either way the
        // query below decides.
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        let _ = unsafe { mem_unmap(ctx.aspace_cap, va, 1) };
        if syscall::aspace_query(ctx.aspace_cap, va).is_ok()
        {
            result = Err("concurrent_map_unmap: a child's VA stayed mapped");
            continue;
        }
        // SAFETY: the frame came from the pool, every child that could map
        // it was deleted above, and its only VA is unmapped (the query just
        // failed), so `frame_pool::free`'s unmapped precondition holds.
        unsafe { crate::frame_pool::free(mappers.frames[i]) };
    }
    result
}

/// Per-child VA, set by parent before starting each child.
static VA_PER_CHILD: [core::sync::atomic::AtomicU64; NUM_CHILDREN] = {
    // AtomicU64 is not Copy, so the repeat expression needs an inline const block.
    [const { core::sync::atomic::AtomicU64::new(0) }; NUM_CHILDREN]
};

extern "C" fn mapper_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this child.
    let MapperArgs {
        done: done_slot,
        memory: memory_cap,
        aspace,
        done_bit,
        iterations,
    } = unsafe { spawn::child_args(arg) };

    // Determine our child index from done_bit (1<<i → i).
    let child_idx = done_bit.trailing_zeros() as usize;
    let va = VA_PER_CHILD[child_idx].load(core::sync::atomic::Ordering::Acquire);

    for _ in 0..iterations
    {
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { mem_map(memory_cap, aspace, va, 0, 1, syscall::MAP_WRITABLE) }.is_err()
        {
            // Report the failure with the done bit.
            notification_send(done_slot, done_bit | ERROR_BIT).ok();
            thread_exit();
        }

        // Verify the mapping exists via aspace_query (non-destructive). The
        // test exercises page-table map/unmap only and never touches the
        // frame's contents; pool frames are carved from a RAM cap, not from
        // ktest's image (core/ktest/src/frame_pool.rs).
        if syscall::aspace_query(aspace, va).is_err()
        {
            notification_send(done_slot, done_bit | ERROR_BIT).ok();
            thread_exit();
        }

        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { mem_unmap(aspace, va, 1) }.is_err()
        {
            notification_send(done_slot, done_bit | ERROR_BIT).ok();
            thread_exit();
        }
    }

    notification_send(done_slot, done_bit).ok();
    thread_exit()
}
