// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/arena_reclaim.rs

//! Integration: a dead `CSpace` returns the donations its own arena's bodies
//! depend on.
//!
//! A Memory tail split by a thread bound to `CSpace` A has its body in A's
//! arena ([core/kernel/docs/capability-internals.md § Body
//! Arena](../../../kernel/docs/capability-internals.md#body-arena)). Donated to
//! a `CSpace`'s pool, the tail is held by that donation. Two cases:
//!
//! 1. Self-funding: the tail T is donated to A itself. When A dies, its
//!    donations, T's included, go back at once, though T's body still lives in
//!    one of A's arena pages; the page goes back when T does.
//! 2. Mutual funding: A's tail is donated to B and B's tail to A, then both
//!    die. Each returns the other's tail, and nothing is held once both tails
//!    go.
//! 3. Budget floor: a `CSpace` whose free slots are all on pages already in
//!    use and whose growth budget is spent refuses an `Mmio` copy, whose body
//!    needs a fresh arena page, with `OutOfMemory` however many slots are free;
//!    the top-up `syscall_abi::cspace_topup_pages` computes for one slot
//!    restores a page of budget, and the copy then succeeds.
//!
//! A RAM tail cannot be deleted in ktest (its destruction would free into the
//! sealed buddy), so each tail is moved out to ktest's own `CSpace` before its
//! funder dies and is merged back into the Memory capability it came from at
//! the end; the donation's hold on the tail, the dependency the teardown must
//! break, is the same as for a deleted tail. Each case checks that the
//! donations came back (`CAP_INFO_MEMORY_AVAILABLE` of each tail) while the
//! tails' bodies live, and that every page, the arena pages included, is back
//! in `memory_base` at the end.

use core::sync::atomic::{AtomicU32, Ordering};

use init_protocol::{CapType, InitInfo};
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_notification, cap_create_thread,
    cap_delete, cap_info, cap_move, memory_merge, memory_split, notification_wait,
};
use syscall_abi::{
    CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_CAPACITY, CAP_INFO_CSPACE_USED,
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_SIZE, CSPACE_IPC_RECV_RESERVE, RIGHTS_ALL,
    SyscallError,
};

use crate::{ChildStack, TestContext, TestResult};

const PAGE: u64 = 4096;

static mut SPLITTER_STACK: ChildStack = ChildStack::ZERO;

/// The splitter's inputs, handles in its `CSpace`: the two-page Memory cap to
/// split, ktest's `CSpace`, and the notification it signals when done.
static SPLIT_SRC: AtomicU32 = AtomicU32::new(0);
static SPLIT_DEST: AtomicU32 = AtomicU32::new(0);
static SPLIT_DONE: AtomicU32 = AtomicU32::new(0);
/// The splitter's results, handles in ktest's `CSpace` (0 on failure): the
/// one-page head and the tail whose body its `CSpace` funded.
static SPLIT_HEAD: AtomicU32 = AtomicU32::new(0);
static SPLIT_TAIL: AtomicU32 = AtomicU32::new(0);

/// Splitter entry, bound to the funding `CSpace`: split the two-page cap at
/// one page, so the tail's body is a chunk of this `CSpace`'s arena, then
/// move both halves into ktest's `CSpace` and signal done.
extern "C" fn splitter_entry(_arg: u64) -> !
{
    let src = SPLIT_SRC.load(Ordering::Acquire);
    let dest = SPLIT_DEST.load(Ordering::Acquire);
    if let Ok(tail) = memory_split(src, PAGE)
        && let (Ok(t), Ok(h)) = (cap_move(tail, dest, 0), cap_move(src, dest, 0))
    {
        SPLIT_TAIL.store(t, Ordering::Release);
        SPLIT_HEAD.store(h, Ordering::Release);
    }
    syscall::notification_send(SPLIT_DONE.load(Ordering::Acquire), 1).ok();
    syscall::thread_exit();
}

/// A two-page piece of `memory_base` and a tail of one page split from it by
/// a thread bound to `cs`, so the tail's body is in `cs`'s arena.
struct Funded
{
    head: u32,
    tail: u32,
}

/// Split two pages off the top of `memory_base`, move them into `cs`, and have
/// a thread bound to `cs` split them; returns the head and the tail, both back
/// in ktest's `CSpace`.
fn split_in(ctx: &TestContext, cs: u32) -> Result<Funded, &'static str>
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "integration::arena_reclaim: cap_info(memory_base) failed")?;
    let piece = memory_split(ctx.memory_base, size - 2 * PAGE)
        .map_err(|_| "integration::arena_reclaim: memory_split(memory_base) failed")?;
    let in_cs =
        cap_move(piece, cs, 0).map_err(|_| "integration::arena_reclaim: cap_move(piece) failed")?;
    let dest = cap_copy(ctx.cspace_cap, cs, RIGHTS_ALL)
        .map_err(|_| "integration::arena_reclaim: cap_copy(cspace) failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::arena_reclaim: cap_create_notification failed")?;
    let result = (|| {
        let child_done = cap_copy(done, cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "integration::arena_reclaim: cap_copy(done) failed")?;
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
            .map_err(|_| "integration::arena_reclaim: cap_create_thread failed")?;
        let mut guard = crate::spawn::SpawnedChild { th, cs: 0 };
        SPLIT_HEAD.store(0, Ordering::Relaxed);
        SPLIT_TAIL.store(0, Ordering::Relaxed);
        SPLIT_SRC.store(in_cs, Ordering::Relaxed);
        SPLIT_DEST.store(dest, Ordering::Relaxed);
        SPLIT_DONE.store(child_done, Ordering::Release);
        let stack_top = ChildStack::top(core::ptr::addr_of!(SPLITTER_STACK));
        // SAFETY: the stack is `SPLITTER_STACK`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule): the two
        // splitters run one after the other.
        unsafe { crate::spawn::configure_and_start(&guard, splitter_entry, stack_top, 0) }
            .map_err(|_| "integration::arena_reclaim: configure_and_start failed")?;
        notification_wait(done).ok();
        guard.delete_thread().ok();
        let (head, tail) = (
            SPLIT_HEAD.load(Ordering::Acquire),
            SPLIT_TAIL.load(Ordering::Acquire),
        );
        if head == 0 || tail == 0
        {
            return Err("integration::arena_reclaim: the split in the funding CSpace failed");
        }
        Ok(Funded { head, tail })
    })();
    cap_delete(done).ok();
    result
}

/// Merge a funded piece back into `memory_base`: the tail into its head, then
/// the head into `memory_base`.
fn merge_back(ctx: &TestContext, f: &Funded) -> TestResult
{
    memory_merge(f.head, f.tail)
        .map_err(|_| "integration::arena_reclaim: memory_merge(head, tail) failed")?;
    memory_merge(ctx.memory_base, f.head)
        .map_err(|_| "integration::arena_reclaim: memory_merge(memory_base, head) failed")
}

fn available(cap: u32) -> u64
{
    cap_info(cap, CAP_INFO_MEMORY_AVAILABLE).unwrap_or(u64::MAX)
}

pub fn run(ctx: &TestContext) -> TestResult
{
    self_funded(ctx)?;
    mutually_funded(ctx)?;
    budget_floor(ctx)
}

/// Case 3: slot headroom alone does not fund a body; the budget floor does.
fn budget_floor(ctx: &TestContext) -> TestResult
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let Some(probe) = crate::init_info::descriptors(info)
        .iter()
        .find(|d| d.cap_type == CapType::Mmio && d.aux0 == crate::arch::MMIO_PROBE_PHYS)
        .map(|d| d.slot)
    else
    {
        crate::log("ktest: integration::arena_reclaim budget_floor SKIP (no probe Mmio cap)");
        return Ok(());
    };
    // One pool page, which the first slot takes: free slots remain on it, and
    // the budget is spent.
    let cs = cap_create_cspace(ctx.memory_base, 0, 2)
        .map_err(|_| "integration::arena_reclaim: cap_create_cspace failed")?;
    let result = (|| {
        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::arena_reclaim: cap_create_endpoint failed")?;
        let copied = cap_copy(ep, cs, RIGHTS_ALL);
        cap_delete(ep).ok();
        copied.map_err(|_| "integration::arena_reclaim: cap_copy(endpoint) failed")?;
        let headroom = || {
            let capacity = cap_info(cs, CAP_INFO_CSPACE_CAPACITY).unwrap_or(0);
            let used = cap_info(cs, CAP_INFO_CSPACE_USED).unwrap_or(capacity);
            capacity
                .saturating_sub(used)
                .saturating_sub(CSPACE_IPC_RECV_RESERVE)
        };
        let budget = cap_info(cs, CAP_INFO_CSPACE_BUDGET).unwrap_or(u64::MAX);
        let free = headroom();
        if budget != 0 || free == 0
        {
            return Err("integration::arena_reclaim: the fixture's CSpace is not shaped as meant");
        }
        if cap_copy(probe, cs, RIGHTS_ALL) != Err(SyscallError::OutOfMemory as i64)
        {
            return Err("integration::arena_reclaim: a body was funded with no budget");
        }
        let pages = syscall_abi::cspace_topup_pages(free, budget, 1);
        if pages == 0
        {
            return Err("integration::arena_reclaim: the top-up ignored the spent budget");
        }
        cap_create_cspace(ctx.memory_base, cs, pages)
            .map_err(|_| "integration::arena_reclaim: the top-up's augment failed")?;
        cap_copy(probe, cs, RIGHTS_ALL)
            .map_err(|_| "integration::arena_reclaim: a body was refused after the top-up")?;
        Ok(())
    })();
    cap_delete(cs).ok();
    result
}

/// Case 1: A's tail is donated to A.
fn self_funded(ctx: &TestContext) -> TestResult
{
    let base_before = available(ctx.memory_base);
    let a = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "integration::arena_reclaim: cap_create_cspace(A) failed")?;
    let funded = match split_in(ctx, a)
    {
        Ok(f) => f,
        Err(e) =>
        {
            cap_delete(a).ok();
            return Err(e);
        }
    };
    let donated = cap_create_cspace(funded.tail, a, 1).is_ok();
    let held = available(funded.tail);
    cap_delete(a).map_err(|_| "integration::arena_reclaim: cap_delete(A) failed")?;
    let returned = available(funded.tail);
    merge_back(ctx, &funded)?;
    let base_after = available(ctx.memory_base);
    if !donated || held != 0
    {
        return Err("integration::arena_reclaim: the tail's donation to its funder failed");
    }
    if returned != PAGE
    {
        return Err("integration::arena_reclaim: a dead CSpace held the donation its body needs");
    }
    if base_after != base_before
    {
        return Err("integration::arena_reclaim: a page of the dead CSpace never came back");
    }
    Ok(())
}

/// Case 2: A's tail is donated to B, and B's to A.
fn mutually_funded(ctx: &TestContext) -> TestResult
{
    let base_before = available(ctx.memory_base);
    let a = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "integration::arena_reclaim: cap_create_cspace(A) failed")?;
    let Ok(b) = cap_create_cspace(ctx.memory_base, 0, 4)
    else
    {
        cap_delete(a).ok();
        return Err("integration::arena_reclaim: cap_create_cspace(B) failed");
    };
    let pieces = split_in(ctx, a).and_then(|fa| split_in(ctx, b).map(|fb| (fa, fb)));
    let Ok((fa, fb)) = pieces
    else
    {
        cap_delete(a).ok();
        cap_delete(b).ok();
        return Err("integration::arena_reclaim: a split in a funding CSpace failed");
    };
    let donated =
        cap_create_cspace(fa.tail, b, 1).is_ok() && cap_create_cspace(fb.tail, a, 1).is_ok();
    cap_delete(a).map_err(|_| "integration::arena_reclaim: cap_delete(A) failed")?;
    cap_delete(b).map_err(|_| "integration::arena_reclaim: cap_delete(B) failed")?;
    let returned = (available(fa.tail), available(fb.tail));
    merge_back(ctx, &fb)?;
    merge_back(ctx, &fa)?;
    let base_after = available(ctx.memory_base);
    if !donated
    {
        return Err("integration::arena_reclaim: a cross donation failed");
    }
    if returned != (PAGE, PAGE)
    {
        return Err("integration::arena_reclaim: mutually funded CSpaces held each other's tail");
    }
    if base_after != base_before
    {
        return Err("integration::arena_reclaim: a page of the dead CSpaces never came back");
    }
    Ok(())
}
