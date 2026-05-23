// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: concurrent memory map/unmap from multiple threads.
//!
//! `NUM_CHILDREN` threads each map and unmap a distinct VA range
//! repeatedly, sharing the same address space. Exercises page table
//! lock contention and TLB shootdown under load.

use syscall::{
    cap_copy, cap_create_signal, cap_delete, mem_map, mem_unmap, signal_send, signal_wait,
    thread_exit,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CHILDREN: usize = 16;
const MAP_ITERATIONS: usize = 1000;

// done_bit is packed at bits 48..63 of the spawn arg (16-bit lane), so
// `1u64 << i` must fit in 16 bits — bounding NUM_CHILDREN at 16. Raising
// past 16 requires widening the lane or switching to bit-index packing
// (see concurrent_signal.rs for the larger-lane idiom).
const _: () = assert!(NUM_CHILDREN <= 16);

/// Base VA for stress mappings, well above normal test VAs.
const STRESS_MAP_BASE: u64 = 0x5000_0000;
/// Spacing between each child's VA (16-page stride).
const VA_STRIDE: u64 = 0x1_0000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "concurrent_map_unmap: create done failed")?;

    // Allocate frames from pool for each child.
    let mut frames = [0u32; NUM_CHILDREN];
    for frame in &mut frames
    {
        *frame = crate::frame_pool::alloc().ok_or("concurrent_map_unmap: frame pool exhausted")?;
    }

    // Spawn children. Each child gets copies of its frame cap and the aspace
    // cap in its own CSpace.
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];
    for i in 0..NUM_CHILDREN
    {
        let child =
            spawn::new_child(ctx).map_err(|_| "concurrent_map_unmap: spawn::new_child failed")?;
        let child_done = cap_copy(done, child.cs, 1 << 7)
            .map_err(|_| "concurrent_map_unmap: cap_copy done failed")?;
        // Copy frame and aspace caps into child's CSpace with full rights.
        let child_frame = cap_copy(frames[i], child.cs, syscall::RIGHTS_ALL)
            .map_err(|_| "concurrent_map_unmap: cap_copy frame failed")?;
        let child_aspace = cap_copy(ctx.aspace_cap, child.cs, syscall::RIGHTS_ALL)
            .map_err(|_| "concurrent_map_unmap: cap_copy aspace failed")?;

        let done_bit = 1u64 << i;
        let va = STRESS_MAP_BASE + (i as u64) * VA_STRIDE;
        // Pack: done_slot[15:0], child_frame[31:16], child_aspace[47:32], done_bit[63:48]
        let arg = u64::from(child_done)
            | (u64::from(child_frame) << 16)
            | (u64::from(child_aspace) << 32)
            | (done_bit << 48);

        // Set the VA for this child via a static. Children read it from
        // a shared array indexed by child_frame slot (deterministic mapping).
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
        let bits = signal_wait(done).map_err(|_| "concurrent_map_unmap: signal_wait failed")?;
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
        // SAFETY: frames are from pool and unmapped by children.
        unsafe { crate::frame_pool::free(frames[i]) };
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
    // const-fn loop is unstable in stable Rust; use a const block + manual
    // population via array-init-by-fn idiom.
    [const { core::sync::atomic::AtomicU64::new(0) }; NUM_CHILDREN]
};

// cast_possible_truncation: slot indices are kernel cap slots < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn mapper_entry(arg: u64) -> !
{
    let done_slot = (arg & 0xFFFF) as u32;
    let frame_cap = ((arg >> 16) & 0xFFFF) as u32;
    let aspace = ((arg >> 32) & 0xFFFF) as u32;
    // done_bit is `1u64 << i` for i in 0..NUM_CHILDREN; at NUM=16 it spans
    // bits 0..15, so the mask is 16-bit not 8-bit.
    let done_bit = (arg >> 48) & 0xFFFF;

    // Determine our child index from done_bit (1<<i → i).
    let child_idx = done_bit.trailing_zeros() as usize;
    let va = VA_PER_CHILD[child_idx].load(core::sync::atomic::Ordering::Acquire);

    for _ in 0..MAP_ITERATIONS
    {
        if mem_map(frame_cap, aspace, va, 0, 1, syscall::MAP_WRITABLE).is_err()
        {
            // Send done_bit | error indicator (bit 32).
            signal_send(done_slot, done_bit | (1 << 32)).ok();
            thread_exit();
        }

        // Verify the mapping exists via aspace_query (non-destructive).
        // We do NOT write through the new VA because pool frames are
        // backed by ktest's BSS segment — the physical page is already
        // mapped in BSS, so writing via the stress VA would corrupt
        // ktest's own statics.
        if syscall::aspace_query(aspace, va).is_err()
        {
            signal_send(done_slot, done_bit | (1 << 32)).ok();
            thread_exit();
        }

        if mem_unmap(aspace, va, 1).is_err()
        {
            signal_send(done_slot, done_bit | (1 << 32)).ok();
            thread_exit();
        }
    }

    signal_send(done_slot, done_bit).ok();
    thread_exit()
}
