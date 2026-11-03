// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/arena_reclaim.rs

//! Integration: a dead `CSpace` returns the donations its own arena's bodies
//! depend on.
//!
//! A Memory tail split by a thread bound to `CSpace` A has its body in A's
//! arena ([core/kernel/docs/capability-internals.md § Body
//! Arena](../../../kernel/docs/capability-internals.md#body-arena)). Donated to
//! a `CSpace`'s pool, the tail is held by that donation. Five cases:
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
//! 4. Kept pages in a spilled record: a `CSpace` takes 16 donations, which
//!    fill its inline records, then a 16-page donation from its own Memory
//!    piece P, recorded on a record page. A thread bound to it derives
//!    `MANY` `Mmio` capabilities, three arena pages of bodies, and moves each
//!    out to ktest's `CSpace`. When the `CSpace` dies, P comes back but for
//!    the arena pages the moved bodies sit on, at least two, so P's span is
//!    cut into several runs; P is whole again once the moved capabilities go.
//! 5. Kept pages on freed table pages (x86-64): a `CSpace` made from one
//!    8-page piece binds an `IoPort` to a thread of its own and deletes the
//!    thread, whose port-binding table's pages go back to the top of its pool
//!    with their record cell; two of the three arena pages of case 4's bodies
//!    are carved from them (a slot page takes the third), and the piece comes
//!    back cut around the kept pages as in case 4.
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
    cap_delete, cap_derive, cap_info, cap_move, memory_merge, memory_split, notification_wait,
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

/// Bodies case 4 places: three arena pages' worth at 31 bodies a page.
const MANY: usize = 70;
/// Pages of case 4's Memory piece P, donated in one augment.
const P_PAGES: u64 = 16;
/// Pages of case 5's Memory piece, the funding `CSpace`'s whole slab.
#[cfg(target_arch = "x86_64")]
const T_PAGES: u64 = 8;
/// The copier's inputs, handles in its `CSpace`: the `Mmio` capability to
/// derive from, ktest's `CSpace`, and the notification it signals when done.
static COPY_SRC: AtomicU32 = AtomicU32::new(0);
static COPY_DEST: AtomicU32 = AtomicU32::new(0);
static COPY_DONE: AtomicU32 = AtomicU32::new(0);
/// The copier's results, handles in ktest's `CSpace` (0 where it stopped).
static COPIES: [AtomicU32; MANY] = [const { AtomicU32::new(0) }; MANY];

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

/// Copier entry, bound to the funding `CSpace`: derive `MANY` `Mmio`
/// capabilities from the one it is given, each a fresh object in this
/// `CSpace`'s arena, and move each into ktest's `CSpace`; then signal done.
extern "C" fn copier_entry(_arg: u64) -> !
{
    let src = COPY_SRC.load(Ordering::Acquire);
    let dest = COPY_DEST.load(Ordering::Acquire);
    for out in &COPIES
    {
        let Ok(derived) = cap_derive(src, RIGHTS_ALL)
        else
        {
            break;
        };
        let Ok(moved) = cap_move(derived, dest, 0)
        else
        {
            cap_delete(derived).ok();
            break;
        };
        out.store(moved, Ordering::Release);
    }
    syscall::notification_send(COPY_DONE.load(Ordering::Acquire), 1).ok();
    syscall::thread_exit();
}

/// Run `entry` on a thread bound to `cs` and wait on `done`, which the
/// entry signals through its copy in `cs`; the caller has set the entry's
/// inputs.
fn run_bound(ctx: &TestContext, cs: u32, done: u32, entry: extern "C" fn(u64) -> !) -> TestResult
{
    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
        .map_err(|_| "integration::arena_reclaim: cap_create_thread failed")?;
    let mut guard = crate::spawn::SpawnedChild { th, cs: 0 };
    let stack_top = ChildStack::top(core::ptr::addr_of!(SPLITTER_STACK));
    // SAFETY: the stack is `SPLITTER_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule): the bound
    // threads run one after the other, each waited for here.
    unsafe { crate::spawn::configure_and_start(&guard, entry, stack_top, 0) }
        .map_err(|_| "integration::arena_reclaim: configure_and_start failed")?;
    notification_wait(done).ok();
    guard.delete_thread().ok();
    Ok(())
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
        SPLIT_HEAD.store(0, Ordering::Relaxed);
        SPLIT_TAIL.store(0, Ordering::Relaxed);
        SPLIT_SRC.store(in_cs, Ordering::Relaxed);
        SPLIT_DEST.store(dest, Ordering::Relaxed);
        SPLIT_DONE.store(child_done, Ordering::Release);
        run_bound(ctx, cs, done, splitter_entry)?;
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
    budget_floor(ctx)?;
    kept_in_spilled_record(ctx)?;
    #[cfg(target_arch = "x86_64")]
    kept_on_freed_table_pages(ctx)?;
    Ok(())
}

/// The probe `Mmio` capability init hands ktest, if the platform has one.
fn probe_mmio(ctx: &TestContext) -> Option<u32>
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    crate::init_info::descriptors(info)
        .iter()
        .find(|d| d.cap_type == CapType::Mmio && d.aux0 == crate::arch::MMIO_PROBE_PHYS)
        .map(|d| d.slot)
}

/// Case 3: slot headroom alone does not fund a body; the budget floor does.
fn budget_floor(ctx: &TestContext) -> TestResult
{
    let Some(probe) = probe_mmio(ctx)
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

/// Case 4: several kept pages in one donation recorded on a record page.
fn kept_in_spilled_record(ctx: &TestContext) -> TestResult
{
    let Some(probe) = probe_mmio(ctx)
    else
    {
        crate::log(
            "ktest: integration::arena_reclaim kept_in_spilled_record SKIP (no probe Mmio cap)",
        );
        return Ok(());
    };
    let base_before = available(ctx.memory_base);
    let piece = split_piece(ctx, P_PAGES)?;
    let Ok(a) = cap_create_cspace(ctx.memory_base, 0, 4)
    else
    {
        memory_merge(ctx.memory_base, piece).ok();
        return Err("integration::arena_reclaim: cap_create_cspace(A) failed");
    };
    let placed = (|| {
        // The create-time slab and 15 augments fill the 16 inline records; P's
        // donation goes on a record page, taken from P itself.
        for _ in 0..15
        {
            cap_create_cspace(ctx.memory_base, a, 1)
                .map_err(|_| "integration::arena_reclaim: an inline augment failed")?;
        }
        cap_create_cspace(piece, a, P_PAGES)
            .map_err(|_| "integration::arena_reclaim: the spilled augment failed")?;
        place_moved_bodies(ctx, a, probe)
    })();
    finish_kept(ctx, a, piece, P_PAGES, base_before, placed)
}

/// Case 5 (x86-64): kept pages, two of them carved from pool pages a
/// port-binding table gave back, which carry their donation record's cell
/// from the table.
#[cfg(target_arch = "x86_64")]
fn kept_on_freed_table_pages(ctx: &TestContext) -> TestResult
{
    let Some(probe) = probe_mmio(ctx)
    else
    {
        crate::log(
            "ktest: integration::arena_reclaim kept_on_freed_table_pages SKIP (no probe Mmio cap)",
        );
        return Ok(());
    };
    let base_before = available(ctx.memory_base);
    let piece = split_piece(ctx, T_PAGES)?;
    // Every page of A is the piece's: its create-time slab, its only donation.
    let Ok(a) = cap_create_cspace(piece, 0, T_PAGES)
    else
    {
        memory_merge(ctx.memory_base, piece).ok();
        return Err("integration::arena_reclaim: cap_create_cspace(A from the piece) failed");
    };
    let mut bound = false;
    let placed = (|| {
        // A bound thread's first bind takes its table's three pages from A's
        // pool; deleting the thread returns them to the top of the pool, each
        // with its record's cell, where the arena carves two of its pages
        // and a slot page takes the third.
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, a, 0, 0)
            .map_err(|_| "integration::arena_reclaim: cap_create_thread failed")?;
        bound = (1..=crate::unit::hw::scan_bound(ctx))
            .any(|slot| syscall::ioport_bind(th, slot).is_ok());
        cap_delete(th).ok();
        if !bound
        {
            return Ok(());
        }
        place_moved_bodies(ctx, a, probe)
    })();
    if placed.is_ok() && !bound
    {
        cap_delete(a).ok();
        memory_merge(ctx.memory_base, piece).ok();
        crate::log("ktest: integration::arena_reclaim kept_on_freed_table_pages SKIP (no IoPort)");
        return Ok(());
    }
    finish_kept(ctx, a, piece, T_PAGES, base_before, placed)
}

/// Split a piece of `pages` pages off the top of `memory_base`.
fn split_piece(ctx: &TestContext, pages: u64) -> Result<u32, &'static str>
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "integration::arena_reclaim: cap_info(memory_base) failed")?;
    memory_split(ctx.memory_base, size - pages * PAGE)
        .map_err(|_| "integration::arena_reclaim: memory_split(memory_base) failed")
}

/// Have a thread bound to `a` derive `MANY` `Mmio` capabilities from a copy of
/// `probe` in `a`, each a body in `a`'s arena, and move each into `COPIES`.
fn place_moved_bodies(ctx: &TestContext, a: u32, probe: u32) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::arena_reclaim: cap_create_notification failed")?;
    let result = (|| {
        let src = cap_copy(probe, a, RIGHTS_ALL)
            .map_err(|_| "integration::arena_reclaim: cap_copy(probe) failed")?;
        let dest = cap_copy(ctx.cspace_cap, a, RIGHTS_ALL)
            .map_err(|_| "integration::arena_reclaim: cap_copy(cspace) failed")?;
        let child_done = cap_copy(done, a, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "integration::arena_reclaim: cap_copy(done) failed")?;
        for out in &COPIES
        {
            out.store(0, Ordering::Relaxed);
        }
        COPY_SRC.store(src, Ordering::Relaxed);
        COPY_DEST.store(dest, Ordering::Relaxed);
        COPY_DONE.store(child_done, Ordering::Release);
        run_bound(ctx, a, done, copier_entry)
    })();
    cap_delete(done).ok();
    result
}

/// Delete `a`, which `piece` (`pages` pages) funded and whose arena holds the
/// bodies of `COPIES`, then the copies, and merge `piece` back. `placed` is the
/// fixture's outcome. Checks that `piece` came back but for at least two kept
/// pages while the copies lived, so its span was cut into several runs, and is
/// whole once they go.
fn finish_kept(
    ctx: &TestContext,
    a: u32,
    piece: u32,
    pages: u64,
    base_before: u64,
    placed: TestResult,
) -> TestResult
{
    let moved = COPIES
        .iter()
        .filter(|c| c.load(Ordering::Acquire) != 0)
        .count();
    let deleted = cap_delete(a).is_ok();
    let held = available(piece);
    for out in &COPIES
    {
        let c = out.swap(0, Ordering::AcqRel);
        if c != 0
        {
            cap_delete(c).ok();
        }
    }
    let whole = available(piece);
    memory_merge(ctx.memory_base, piece)
        .map_err(|_| "integration::arena_reclaim: memory_merge(memory_base, piece) failed")?;
    let base_after = available(ctx.memory_base);
    placed?;
    if moved != MANY || !deleted
    {
        return Err("integration::arena_reclaim: the bodies were not placed and moved out");
    }
    if held > (pages - 2) * PAGE
    {
        return Err(
            "integration::arena_reclaim: fewer than two of the piece's arena pages were kept",
        );
    }
    if whole != pages * PAGE
    {
        return Err("integration::arena_reclaim: the piece's kept pages never came back");
    }
    if base_after != base_before
    {
        return Err("integration::arena_reclaim: a page of the dead CSpace never came back");
    }
    Ok(())
}
