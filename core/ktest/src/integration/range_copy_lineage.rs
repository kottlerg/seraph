// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/range_copy_lineage.rs

//! Integration: copies of a range-capability lineage, the `CSpace` arena that
//! funds them, and a funded copy that outlives its funder.
//!
//! Takes a fresh lineage root (`crate::arch::fresh_range_root`: an `IoPort`
//! split on x86-64, an `Mmio` split on riscv64) and checks, in order:
//!
//! 1. [`COPIES`] copies, twice the former fixed per-lineage limit and one
//!    more, derive from the root or from a copy; deleting the root while they
//!    live keeps the lineage usable.
//! 2. A copy is funded by the `CSpace` that receives it
//!    ([core/kernel/docs/capability-internals.md § Body
//!    Arena](../../../kernel/docs/capability-internals.md#body-arena)): into a
//!    `CSpace` whose one pool page its body takes, the slot cannot be backed
//!    and the copy fails with `OutOfMemory`; after an augment it succeeds.
//! 3. A copy moved out of its funding `CSpace` outlives it: the dead `CSpace`
//!    keeps its donations (the augment frame stays retyped) while the moved
//!    copy lives and can still be derived from, and returns them (the frame's
//!    bytes are available again) once that copy is deleted.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_cspace, cap_create_notification, cap_create_thread, cap_delete,
    cap_derive, cap_info, notification_wait,
};
use syscall_abi::{CAP_INFO_MEMORY_AVAILABLE, RIGHTS_ALL, SyscallError};

use crate::{ChildStack, TestContext, TestResult};

/// Copies made in step 1: past twice the former limit of 64.
const COPIES: usize = 129;

const PAGE: u64 = 4096;

static mut MOVER_STACK: ChildStack = ChildStack::ZERO;

/// The mover's handles, all in the funding `CSpace`: the copy to move, ktest's
/// `CSpace`, and the notification it signals when done.
static MOVER_COPY: AtomicU32 = AtomicU32::new(0);
static MOVER_DEST: AtomicU32 = AtomicU32::new(0);
static MOVER_DONE: AtomicU32 = AtomicU32::new(0);

/// The mover's result: the moved copy's handle in ktest's `CSpace`, with bit
/// 63 set once the move succeeded.
static MOVED: AtomicU64 = AtomicU64::new(0);

const MOVED_OK: u64 = 1 << 63;

/// Mover entry, bound to the funding `CSpace`: move the copy into ktest's
/// `CSpace`, report the new handle, and signal done.
extern "C" fn mover_entry(_arg: u64) -> !
{
    let copy = MOVER_COPY.load(Ordering::Acquire);
    let dest = MOVER_DEST.load(Ordering::Acquire);
    if let Ok(h) = syscall::cap_move(copy, dest, 0)
    {
        MOVED.store(MOVED_OK | u64::from(h), Ordering::Release);
    }
    syscall::notification_send(MOVER_DONE.load(Ordering::Acquire), 1).ok();
    syscall::thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let Some(root) = crate::arch::fresh_range_root(ctx)
    else
    {
        crate::log("ktest: integration::range_copy_lineage SKIP (no fresh range root)");
        return Ok(());
    };

    let mut copies = [0u32; COPIES];
    let mut made = 0;
    let mut result = many_copies(root, &mut copies, &mut made);
    if result.is_ok()
    {
        result = funded_by_destination(ctx, copies[1]);
    }
    for &c in &copies[..made]
    {
        cap_delete(c).ok();
    }
    cap_delete(root).ok();
    result
}

fn many_copies(root: u32, copies: &mut [u32; COPIES], made: &mut usize) -> TestResult
{
    while *made < COPIES
    {
        let src = if made.is_multiple_of(2)
        {
            root
        }
        else
        {
            copies[0]
        };
        copies[*made] = cap_derive(src, RIGHTS_ALL)
            .map_err(|_| "integration::range_copy_lineage: a copy was refused")?;
        *made += 1;
    }
    // The root goes; its copies keep the lineage.
    cap_delete(root).map_err(|_| "integration::range_copy_lineage: cap_delete(root) failed")?;
    let late = cap_derive(copies[1], RIGHTS_ALL)
        .map_err(|_| "integration::range_copy_lineage: a copy after the root's delete failed")?;
    cap_delete(late).map_err(|_| "integration::range_copy_lineage: cap_delete(late) failed")?;
    Ok(())
}

fn funded_by_destination(ctx: &TestContext, source: u32) -> TestResult
{
    // One pool page: the copy's body takes it, and its slot has none.
    let cs = cap_create_cspace(ctx.memory_base, 0, 2)
        .map_err(|_| "integration::range_copy_lineage: cap_create_cspace failed")?;
    let frame = crate::frame_pool::FrameGuard::new(ctx.aspace_cap);
    let result = match frame
    {
        Some(ref f) => outlives_funder(ctx, source, cs, f.cap()),
        None => Err("integration::range_copy_lineage: frame pool exhausted"),
    };
    cap_delete(cs).ok();
    result
}

fn outlives_funder(ctx: &TestContext, source: u32, cs: u32, frame: u32) -> TestResult
{
    if cap_copy(source, cs, RIGHTS_ALL) != Err(SyscallError::OutOfMemory as i64)
    {
        return Err("integration::range_copy_lineage: an unfunded copy was not refused");
    }
    cap_create_cspace(frame, cs, 1)
        .map_err(|_| "integration::range_copy_lineage: augment of the funding CSpace failed")?;
    let copy = cap_copy(source, cs, RIGHTS_ALL)
        .map_err(|_| "integration::range_copy_lineage: a funded copy was refused")?;
    let moved = move_out(ctx, cs, copy)?;

    // The funder is gone (the caller deletes `cs` on every path; here first).
    cap_delete(cs).map_err(|_| "integration::range_copy_lineage: cap_delete(cs) failed")?;
    let pinned = cap_info(frame, CAP_INFO_MEMORY_AVAILABLE).unwrap_or(u64::MAX);
    let derived = cap_derive(moved, RIGHTS_ALL);
    if let Ok(d) = derived
    {
        cap_delete(d).ok();
    }
    cap_delete(moved).map_err(|_| "integration::range_copy_lineage: cap_delete(moved) failed")?;
    let returned = cap_info(frame, CAP_INFO_MEMORY_AVAILABLE).unwrap_or(0);
    if pinned != 0
    {
        return Err("integration::range_copy_lineage: a dead funder returned its donations early");
    }
    if derived.is_err()
    {
        return Err("integration::range_copy_lineage: a copy outliving its funder is unusable");
    }
    if returned != PAGE
    {
        return Err("integration::range_copy_lineage: the funder's donations were not returned");
    }
    Ok(())
}

/// Move `copy` (a handle in `cs`) into ktest's own `CSpace` from a thread
/// bound to `cs`; returns its new handle.
fn move_out(ctx: &TestContext, cs: u32, copy: u32) -> Result<u32, &'static str>
{
    let parent_cs = cap_copy(ctx.cspace_cap, cs, RIGHTS_ALL)
        .map_err(|_| "integration::range_copy_lineage: cap_copy(cspace) failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::range_copy_lineage: cap_create_notification failed")?;
    let result = (|| {
        let child_done = cap_copy(done, cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "integration::range_copy_lineage: cap_copy(done) failed")?;
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
            .map_err(|_| "integration::range_copy_lineage: cap_create_thread failed")?;
        let mut guard = crate::spawn::SpawnedChild { th, cs: 0 };
        MOVED.store(0, Ordering::Relaxed);
        MOVER_COPY.store(copy, Ordering::Relaxed);
        MOVER_DEST.store(parent_cs, Ordering::Relaxed);
        MOVER_DONE.store(child_done, Ordering::Release);
        let stack_top = ChildStack::top(core::ptr::addr_of!(MOVER_STACK));
        // SAFETY: the stack is `MOVER_STACK`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { crate::spawn::configure_and_start(&guard, mover_entry, stack_top, 0) }
            .map_err(|_| "integration::range_copy_lineage: configure_and_start failed")?;
        notification_wait(done).ok();
        guard.delete_thread().ok();
        let moved = MOVED.load(Ordering::Acquire);
        if moved & MOVED_OK == 0
        {
            return Err("integration::range_copy_lineage: the move out of the funder failed");
        }
        u32::try_from(moved & !MOVED_OK)
            .map_err(|_| "integration::range_copy_lineage: the moved handle is not a handle")
    })();
    cap_delete(done).ok();
    result
}
