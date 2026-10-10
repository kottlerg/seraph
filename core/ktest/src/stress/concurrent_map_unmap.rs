// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/concurrent_map_unmap.rs

//! Stress test: concurrent memory map/unmap from multiple threads.
//!
//! `NUM_CHILDREN` threads each map and unmap a distinct VA range
//! repeatedly, sharing the same address space. Exercises page table
//! lock contention and TLB shootdown under load.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, mem_map, mem_unmap, notification_send,
    notification_wait, thread_exit,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CHILDREN: usize = 16;
const MAP_ITERATIONS: usize = 1000;

// Each child owns one bit of the `done` word below bit 32 (bit 32 is the
// error indicator), so the encoding holds for NUM_CHILDREN <= 32; this
// assert admits up to 64.
const _: () = assert!(NUM_CHILDREN <= 64);

/// Per-child arguments, handed to `mapper_entry` by address.
#[derive(Clone, Copy)]
struct MapperArgs
{
    done: u32,
    memory: u32,
    aspace: u32,
    done_bit: u64,
}

static MAPPER_ARGS: spawn::ArgBlock<MapperArgs, NUM_CHILDREN> = spawn::ArgBlock::new(MapperArgs {
    done: 0,
    memory: 0,
    aspace: 0,
    done_bit: 0,
});

/// Base VA for stress mappings, well above normal test VAs.
const STRESS_MAP_BASE: u64 = 0x1_5000_0000;
/// Spacing between each child's VA (16-page stride).
const VA_STRIDE: u64 = 0x1_0000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "concurrent_map_unmap: create done failed")?;

    // Allocate frames from pool for each child. Every `?` early return
    // below skips the cleanup at the end of `run`: it leaks the pool frames
    // already allocated and, past the first spawn, leaves the children
    // already started running with their threads and CSpaces (#444).
    let mut memory_caps = [0u32; NUM_CHILDREN];
    for memory_cap in &mut memory_caps
    {
        *memory_cap =
            crate::frame_pool::alloc().ok_or("concurrent_map_unmap: frame pool exhausted")?;
    }

    // Spawn children. Each child gets copies of its Memory cap and the aspace
    // cap in its own CSpace.
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];
    for i in 0..NUM_CHILDREN
    {
        let child =
            spawn::new_child(ctx).map_err(|_| "concurrent_map_unmap: spawn::new_child failed")?;
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "concurrent_map_unmap: cap_copy done failed")?;
        // Copy memory and aspace caps into child's CSpace with full rights.
        let child_memory = cap_copy(memory_caps[i], child.cs, syscall::RIGHTS_ALL)
            .map_err(|_| "concurrent_map_unmap: cap_copy memory failed")?;
        let child_aspace = cap_copy(ctx.aspace_cap, child.cs, syscall::RIGHTS_ALL)
            .map_err(|_| "concurrent_map_unmap: cap_copy aspace failed")?;

        let done_bit = 1u64 << i;
        let va = STRESS_MAP_BASE + (i as u64) * VA_STRIDE;
        // SAFETY: child `i` has not been started yet; the block is reused
        // only after every child has been reaped.
        let arg = unsafe {
            MAPPER_ARGS.publish(
                i,
                MapperArgs {
                    done: child_done,
                    memory: child_memory,
                    aspace: child_aspace,
                    done_bit,
                },
            )
        };

        // Publish this child's VA in VA_PER_CHILD[i]; the child recovers `i`
        // from its done_bit (`trailing_zeros`).
        VA_PER_CHILD[i].store(va, core::sync::atomic::Ordering::Release);

        // SAFETY: Each child uses a distinct stack index.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, mapper_entry, stack_top, arg)
            .map_err(|_| "concurrent_map_unmap: configure_and_start failed")?;

        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Wait for all children. Each child sends a unique bit (1<<i).
    let all_done = (1u64 << NUM_CHILDREN) - 1;
    let mut done_bits: u64 = 0;
    let mut child_failed = false;
    while done_bits & all_done != all_done
    {
        let bits = notification_wait(done)
            .map_err(|_| "concurrent_map_unmap: notification_wait failed")?;
        done_bits |= bits;
        // Bit 32 is the error indicator (well clear of done_bit range for
        // NUM_CHILDREN up to 32).
        if bits & (1 << 32) != 0
        {
            child_failed = true;
        }
    }

    // Clean up.
    for i in 0..NUM_CHILDREN
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
        // SAFETY: `memory_caps` are from the pool. A child that reports
        // success has unmapped its VA, so `frame_pool::free`'s unmapped
        // precondition holds for its frame. A child that exits on a failed
        // `aspace_query` or `mem_unmap` leaves its frame mapped at its stress
        // VA, and nothing here unmaps it: on that path this free breaks the
        // precondition and a later `alloc` can hand out a frame that is still
        // mapped (#444). The test still fails via `child_failed`.
        unsafe { crate::frame_pool::free(memory_caps[i]) };
    }
    cap_delete(done).ok();

    if child_failed
    {
        return Err("concurrent_map_unmap: child reported failure");
    }
    Ok(())
}

/// Per-child VA, set by parent before starting each child.
static VA_PER_CHILD: [core::sync::atomic::AtomicU64; NUM_CHILDREN] = {
    // AtomicU64 is not Copy, so the repeat expression needs an inline const block.
    [const { core::sync::atomic::AtomicU64::new(0) }; NUM_CHILDREN]
};

fn mapper_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this child.
    let MapperArgs {
        done: done_slot,
        memory: memory_cap,
        aspace,
        done_bit,
    } = unsafe { spawn::child_args(arg) };

    // Determine our child index from done_bit (1<<i → i).
    let child_idx = done_bit.trailing_zeros() as usize;
    let va = VA_PER_CHILD[child_idx].load(core::sync::atomic::Ordering::Acquire);

    for _ in 0..MAP_ITERATIONS
    {
        if mem_map(memory_cap, aspace, va, 0, 1, syscall::MAP_WRITABLE).is_err()
        {
            // Send done_bit | error indicator (bit 32).
            notification_send(done_slot, done_bit | (1 << 32)).ok();
            thread_exit();
        }

        // Verify the mapping exists via aspace_query (non-destructive). The
        // test exercises page-table map/unmap only and never touches the
        // frame's contents; pool frames are carved from a RAM cap, not from
        // ktest's image (core/ktest/src/frame_pool.rs).
        if syscall::aspace_query(aspace, va).is_err()
        {
            notification_send(done_slot, done_bit | (1 << 32)).ok();
            thread_exit();
        }

        if mem_unmap(aspace, va, 1).is_err()
        {
            notification_send(done_slot, done_bit | (1 << 32)).ok();
            thread_exit();
        }
    }

    notification_send(done_slot, done_bit).ok();
    thread_exit()
}
