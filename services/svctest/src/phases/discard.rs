// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/discard.rs

//! Giving memmgr back the frames of a demand region: `DISCARD_RANGE` and
//! `SHRINK_REGION` (services/memmgr/docs/ipc-interface.md § Label 20 and
//! § Label 13), and the std heap's trims and discards of its committed growth
//! (docs/userspace-memory-model.md § Byte Heap).
//!
//! The phase first drives the labels on regions of its own. On a committed
//! region memmgr refuses each discard that breaks the chunk rule and unmaps
//! nothing for it ([`discard_refusals`]); a discard of touched chunks returns
//! their frames to the pool and promises them again, keeps the charge, and a
//! repeat of it succeeds; the discarded pages then read zero and the rest keep
//! what was written; and a shrink returns the frames it cuts
//! ([`committed_region_window`]). On an uncommitted region a discard
//! uncharges its pages and their refault reads zero ([`uncommitted_region`]).
//!
//! It then runs two children of `/tests/svctest`: a `discard-hog`
//! ([`discard_hog_main`]), which shows that a later touch of a discarded
//! committed page cannot fail with all that memmgr can promise taken, and a
//! `heap-release` child ([`heap_release_main`]), whose heap discards a large
//! freed block and trims its top. Each child's charge leaves svctest's budget
//! subtree before the phase goes on, memmgr's free and promised totals then
//! return to their levels, and the all-RAM-accounted identity holds.

use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use std::process::exit;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::PAGE_SIZE;

use crate::bootstrap::Caps;
use crate::phases::heap_commit::{
    CHUNK_PAGES, HOG_BALLAST_BYTES, HOG_BALLAST_FAILED, HOG_MARGIN_PAGES, HOG_MAX_ROUNDS,
    HOG_NOT_COMMITTED, HOG_STATUS_FAILED, POOL_POLLS, POOL_WINDOWS, children_charge,
    children_reclaimed, commit_to_margin, expect_region_reply, memmgr_label, own_usage,
    pool_totals, settled_totals, totals_settle_to, touch_committed,
};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_discard_range",
        run: discard_range_phase,
    }]
}

/// Child-mode dispatch for the argv tokens this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == DISCARD_HOG_ROLE
    {
        discard_hog_main();
    }
    if role == HEAP_RELEASE_ROLE
    {
        heap_release_main();
    }
}

/// argv[1] of the child that refaults a discarded committed region with all
/// that memmgr can promise taken.
const DISCARD_HOG_ROLE: &str = "discard-hog";
/// argv[1] of the child whose heap gives its committed growth back.
const HEAP_RELEASE_ROLE: &str = "heap-release";

/// Pages of the regions the phase registers: four chunks.
const REGION_PAGES: u64 = 4 * CHUNK_PAGES;
/// Bytes of one chunk.
const CHUNK_LEN: u64 = CHUNK_PAGES * PAGE_SIZE;
/// Pages a discard of two chunks returns.
const TWO_CHUNKS: u64 = 2 * CHUNK_PAGES;

/// Exit code of the discard hog: its region's registration failed.
const HOG_REGION_FAILED: i32 = 10;
/// Exit code of the discard hog: memmgr refused the discard of its region.
const HOG_DISCARD_FAILED: i32 = 11;
/// Exit code of the discard hog: a refaulted page of its region read other
/// than zero.
const HOG_NOT_ZERO: i32 = 12;

/// Bytes of each of the heap-release child's two blocks: 64 chunks, so that
/// a free of either reaches the heap's discard and trim sizes.
const RELEASE_BLOCK_BYTES: usize = 4 << 20;
/// Pages the free of the lower block must return to the pool and promise
/// again: 48 of its 64 chunks, the others left for the block's node, its
/// edges and the pages other processes take meanwhile.
const RELEASE_DISCARD_PAGES: u64 = 48 * CHUNK_PAGES;
/// Pages the free of the upper block, which trims the heap's top, must
/// uncharge: 96 of the two blocks' 128 chunks.
const RELEASE_TRIM_PAGES: u64 = 96 * CHUNK_PAGES;
/// Exit code of the heap-release child: an allocation of a block failed.
const RELEASE_ALLOC_FAILED: i32 = 10;
/// Exit code of the heap-release child: the upper block did not lie above
/// the lower one.
const RELEASE_NOT_STACKED: i32 = 11;
/// Exit code of the heap-release child: the free of the heap's top did not
/// uncharge [`RELEASE_TRIM_PAGES`].
const RELEASE_NOT_TRIMMED: i32 = 12;
/// Exit code of the heap-release child: the free of the lower block did not
/// return [`RELEASE_DISCARD_PAGES`] in any of [`POOL_WINDOWS`] windows.
const RELEASE_NOT_DISCARDED: i32 = 13;

/// The phase: the labels on regions of svctest's own, then the two children
/// in windows until memmgr's totals return to their levels around them, then
/// the identity.
fn discard_range_phase(caps: &Caps)
{
    discard_refusals();
    let returned = (0..POOL_WINDOWS).any(|_| committed_region_window());
    assert!(
        returned,
        "a DISCARD_RANGE or SHRINK_REGION of touched committed chunks did not return their \
         frames to the pool in any of {POOL_WINDOWS} windows"
    );
    uncommitted_region();
    let settled = (0..POOL_WINDOWS).any(|_| {
        let children = children_charge();
        let before = settled_totals();
        run_child(
            DISCARD_HOG_ROLE,
            "the discard hog",
            &format!(
                "{HOG_STATUS_FAILED}=QUERY_POOL_STATUS failed, {HOG_NOT_COMMITTED}=it did not \
                 commit down to its margin, {HOG_BALLAST_FAILED}=its ballast's allocation failed, \
                 {HOG_REGION_FAILED}=its region's registration failed, {HOG_DISCARD_FAILED}=its \
                 discard was refused, {HOG_NOT_ZERO}=a refaulted page read other than zero, a \
                 fault=the refault of a discarded committed page was declined"
            ),
        );
        children_reclaimed(children, "the discard hog");
        run_child(
            HEAP_RELEASE_ROLE,
            "the heap-release child",
            &format!(
                "{HOG_STATUS_FAILED}=a memmgr query failed, {HOG_BALLAST_FAILED}=its ballast's \
                 allocation failed, {RELEASE_ALLOC_FAILED}=a block's allocation failed, \
                 {RELEASE_NOT_STACKED}=its blocks lay out of order, {RELEASE_NOT_TRIMMED}=the \
                 free of the heap's top uncharged too little, {RELEASE_NOT_DISCARDED}=the free of \
                 a large interior block returned too little"
            ),
        );
        children_reclaimed(children, "the heap-release child");
        totals_settle_to(before)
    });
    assert!(
        settled,
        "memmgr's free and promised totals did not return to their levels after the discard \
         children in any of {POOL_WINDOWS} windows"
    );
    crate::phases::memmgr::ram_accounted_identity_phase(caps);
    std::os::seraph::log!("memmgr_discard_range phase passed");
}

/// Reserve `pages` pages and register them as a committed region; panics
/// when either fails.
fn register_committed(pages: u64) -> ReservedRange
{
    let range = reserve_pages(pages).expect("reserving a committed region's range failed");
    let register = IpcMessage::builder(memmgr_labels::REGISTER_REGION)
        .word(0, range.va_start())
        .word(1, bytes(pages))
        .word(2, syscall::MAP_WRITABLE)
        .word(3, memmgr_labels::REGION_COMMIT)
        .build();
    let got = memmgr_label(&register, "REGISTER_REGION with REGION_COMMIT");
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "REGISTER_REGION with REGION_COMMIT: {got:#x}"
    );
    range
}

/// Unregister the committed region `range` holds, of `pages` pages, and
/// give its range back.
fn unregister_committed(range: ReservedRange, pages: u64)
{
    expect_region_reply(
        memmgr_labels::UNREGISTER_REGION,
        range.va_start(),
        bytes(pages),
        memmgr_errors::SUCCESS,
        "UNREGISTER_REGION of a committed region",
    );
    unreserve_pages(range);
}

/// Bytes of `pages` pages.
fn bytes(pages: u64) -> u64
{
    pages.saturating_mul(PAGE_SIZE)
}

/// The address of page `index` of the region at `base`.
fn page_va(base: u64, index: u64) -> u64
{
    base.saturating_add(bytes(index))
}

/// The word the phase writes at the start of page `index` of a region:
/// nonzero, and different on each page.
fn marker(index: u64) -> u64
{
    0x5eed_0000_0000 | index.saturating_add(1)
}

/// Write [`marker`] at the start of each of the `pages` pages from `base`.
fn write_markers(base: u64, pages: u64)
{
    for i in 0..pages
    {
        // SAFETY: the page is in a demand region this phase registered
        // writable, in a reservation of its own that no Rust object occupies;
        // the write is volatile so that it is made, and faults, here.
        unsafe { std::ptr::write_volatile(page_va(base, i) as *mut u64, marker(i)) };
    }
}

/// Assert each of the `pages` pages from `base` starts with its
/// [`marker`] when `index` lies outside `zeroed`, and reads zero in it.
fn check_pages(base: u64, pages: u64, zeroed: std::ops::Range<u64>, what: &str)
{
    for i in 0..pages
    {
        // SAFETY: as in [`write_markers`]; a read of a discarded page faults
        // in a zero-filled one.
        let got = unsafe { std::ptr::read_volatile(page_va(base, i) as *const u64) };
        let want = if zeroed.contains(&i) { 0 } else { marker(i) };
        assert_eq!(got, want, "{what}: page {i} of the region read {got:#x}");
    }
}

/// Whether memmgr's free total rises `free` pages above `before`, and its
/// promised total `promised` pages when given, within [`POOL_POLLS`] polls,
/// each after a recheck of memmgr's deferred list, on which a run the kernel
/// still held at the unmap waits.
fn totals_rise(before: (u64, u64, u64), free: u64, promised: Option<u64>) -> bool
{
    for _ in 0..POOL_POLLS
    {
        crate::phases::memmgr::recheck_deferred();
        let Some((f, p, _)) = pool_totals()
        else
        {
            return false;
        };
        let promised_rose = promised.is_none_or(|n| p >= before.1.saturating_add(n));
        if f >= before.0.saturating_add(free) && promised_rose
        {
            return true;
        }
        std::thread::yield_now();
    }
    false
}

/// memmgr's refusals, with `INVALID_ARGUMENT`, of discards on a committed
/// region of [`REGION_PAGES`] pages that break the chunk rule or leave the
/// region; none of them unmaps a page.
fn discard_refusals()
{
    use memmgr_labels::DISCARD_RANGE;

    let range = register_committed(REGION_PAGES);
    let base = range.va_start();
    write_markers(base, REGION_PAGES);
    let invalid = memmgr_errors::INVALID_ARGUMENT;
    let end = page_va(base, REGION_PAGES);
    for (va, len, what) in [
        (
            page_va(base, 1),
            CHUNK_LEN,
            "DISCARD_RANGE off a chunk boundary",
        ),
        (base, 0, "DISCARD_RANGE of no bytes"),
        (
            base,
            PAGE_SIZE,
            "DISCARD_RANGE of part of a chunk short of the end",
        ),
        (
            page_va(base, 3 * CHUNK_PAGES),
            2 * CHUNK_LEN,
            "DISCARD_RANGE past the region's end",
        ),
        (end, CHUNK_LEN, "DISCARD_RANGE where no region lies"),
    ]
    {
        expect_region_reply(DISCARD_RANGE, va, len, invalid, what);
    }
    check_pages(base, REGION_PAGES, 0..0, "after the refused discards");
    unregister_committed(range, REGION_PAGES);
}

/// One window on a committed region of [`REGION_PAGES`] touched pages: a
/// discard of its middle two chunks returns their frames and promises them
/// again while the charge stays, a repeat of it succeeds, the discarded pages
/// read zero and the rest keep their markers, and a shrink to one chunk
/// returns the frames of the three it cuts. Returns whether memmgr's totals
/// showed both returns; other processes move them inside a window.
fn committed_region_window() -> bool
{
    use memmgr_labels::{DISCARD_RANGE, SHRINK_REGION};

    let range = register_committed(REGION_PAGES);
    let base = range.va_start();
    write_markers(base, REGION_PAGES);
    let own = own_usage();
    let before = pool_totals().expect("QUERY_POOL_STATUS failed");
    let success = memmgr_errors::SUCCESS;
    let middle = page_va(base, CHUNK_PAGES);
    expect_region_reply(
        DISCARD_RANGE,
        middle,
        2 * CHUNK_LEN,
        success,
        "DISCARD_RANGE of two touched chunks of a committed region",
    );
    let discarded = totals_rise(before, TWO_CHUNKS, Some(TWO_CHUNKS));
    expect_region_reply(
        DISCARD_RANGE,
        middle,
        2 * CHUNK_LEN,
        success,
        "DISCARD_RANGE repeated",
    );
    assert_eq!(
        own_usage(),
        own,
        "a discard in a committed region changed the charge, which its commitment keeps"
    );
    let zeroed = CHUNK_PAGES..3 * CHUNK_PAGES;
    check_pages(base, REGION_PAGES, zeroed, "after the committed discard");
    let before = pool_totals().expect("QUERY_POOL_STATUS failed");
    expect_region_reply(
        SHRINK_REGION,
        base,
        CHUNK_LEN,
        success,
        "SHRINK_REGION of a touched committed region to one chunk",
    );
    let shrunk = totals_rise(before, 3 * CHUNK_PAGES, None);
    unregister_committed(range, CHUNK_PAGES);
    discarded && shrunk
}

/// A discard of two touched chunks of an uncommitted region of
/// [`REGION_PAGES`] pages uncharges their pages, as their runs rejoin the
/// pool, and the discarded pages then read zero while the rest keep their
/// markers.
fn uncommitted_region()
{
    let range = std::os::seraph::register_demand_paged(REGION_PAGES)
        .expect("registering an uncommitted region failed");
    let base = range.va_start();
    write_markers(base, REGION_PAGES);
    let own = own_usage();
    expect_region_reply(
        memmgr_labels::DISCARD_RANGE,
        base,
        2 * CHUNK_LEN,
        memmgr_errors::SUCCESS,
        "DISCARD_RANGE of two touched chunks of an uncommitted region",
    );
    let uncharged = (0..POOL_POLLS).any(|_| {
        crate::phases::memmgr::recheck_deferred();
        let low = own_usage().saturating_add(TWO_CHUNKS) <= own;
        if !low
        {
            std::thread::yield_now();
        }
        low
    });
    assert!(
        uncharged,
        "the discard of {TWO_CHUNKS} touched pages of an uncommitted region left svctest charged \
         {} pages, from {own}",
        own_usage()
    );
    check_pages(
        base,
        REGION_PAGES,
        0..TWO_CHUNKS,
        "after the uncommitted discard",
    );
    // SAFETY: `range` is the region registered above, which no Rust object
    // occupies.
    unsafe { std::os::seraph::unregister_demand_paged(range) }
        .expect("unregistering the uncommitted region failed");
}

/// Run `/tests/svctest <role>` (`what`, for the messages) to its exit and
/// check it exited 0; `codes` reads its other exit codes.
fn run_child(role: &str, what: &str, codes: &str)
{
    let status = std::process::Command::new("/tests/svctest")
        .arg(role)
        .status()
        .unwrap_or_else(|e| panic!("spawning {what} failed: {e}"));
    assert!(status.success(), "{what} exited {status:?}: {codes}");
}

// ── The children ─────────────────────────────────────────────────────────────

/// Fill what the heap's floor has free with a ballast written whole, so the
/// blocks allocated after it lie in the committed growth; exits with
/// [`HOG_BALLAST_FAILED`] when its allocation fails. The floor is an
/// uncommitted region whose untouched pages memmgr backs only while it has
/// pages to spare (docs/userspace-memory-model.md § Byte Heap).
fn ballast() -> Vec<u8>
{
    let mut ballast: Vec<u8> = Vec::new();
    if ballast.try_reserve_exact(HOG_BALLAST_BYTES).is_err()
    {
        exit(HOG_BALLAST_FAILED);
    }
    ballast.resize(HOG_BALLAST_BYTES, 1);
    ballast
}

/// Child role: register and touch a committed region of more pages than
/// [`HOG_MARGIN_PAGES`] and memmgr's reserve together, commit through the
/// heap all but the margin of what memmgr can still promise and touch it,
/// discard the whole region, commit down to the margin again and touch that,
/// then read every page of the region, each refaulting, and exit 0. A
/// discard that let its pages' promise go would leave the second commitment
/// room to take them, and memmgr would decline the refault, killing the
/// child; a refaulted page that read other than zero exits
/// [`HOG_NOT_ZERO`].
fn discard_hog_main() -> !
{
    let _ballast = ballast();
    let mut held: Vec<Vec<u8>> = Vec::with_capacity(HOG_MAX_ROUNDS);
    let Some((_, _, reserve)) = pool_totals()
    else
    {
        exit(HOG_STATUS_FAILED)
    };
    let pages = HOG_MARGIN_PAGES
        .saturating_add(reserve)
        .saturating_mul(2)
        .next_multiple_of(CHUNK_PAGES);
    let Ok(range) = reserve_pages(pages)
    else
    {
        exit(HOG_REGION_FAILED)
    };
    let base = range.va_start();
    let register = IpcMessage::builder(memmgr_labels::REGISTER_REGION)
        .word(0, base)
        .word(1, bytes(pages))
        .word(2, syscall::MAP_WRITABLE)
        .word(3, memmgr_labels::REGION_COMMIT)
        .build();
    if memmgr_label(&register, "REGISTER_REGION") != memmgr_errors::SUCCESS
    {
        exit(HOG_REGION_FAILED);
    }
    write_markers(base, pages);
    let mut rounds = HOG_MAX_ROUNDS;
    let _ = commit_to_margin(&mut held, &mut rounds);
    touch_committed(&mut held);
    let discard = IpcMessage::builder(memmgr_labels::DISCARD_RANGE)
        .word(0, base)
        .word(1, bytes(pages))
        .build();
    if memmgr_label(&discard, "DISCARD_RANGE") != memmgr_errors::SUCCESS
    {
        exit(HOG_DISCARD_FAILED);
    }
    let first = held.len();
    let _ = commit_to_margin(&mut held, &mut rounds);
    touch_committed(held.get_mut(first..).unwrap_or_default());
    for i in 0..pages
    {
        // SAFETY: as in [`write_markers`]; the read refaults the discarded
        // page.
        let got = unsafe { std::ptr::read_volatile(page_va(base, i) as *const u64) };
        if got != 0
        {
            exit(HOG_NOT_ZERO);
        }
    }
    exit(0);
}

/// Child role: past a [`ballast`] that fills the heap's floor, allocate two
/// blocks of [`RELEASE_BLOCK_BYTES`], the upper above the lower, and touch
/// the lower. The free of the lower block, inside the heap, makes the heap
/// discard its chunks, which return to memmgr's pool and are promised again;
/// the free of the upper one, the heap's top, makes the heap trim its
/// committed growth, which uncharges the pages cut. Repeats in up to
/// [`POOL_WINDOWS`] windows until memmgr's totals show the discard, since
/// other processes move them inside one, and exits 0.
fn heap_release_main() -> !
{
    let _ballast = ballast();
    for _ in 0..POOL_WINDOWS
    {
        let mut lower: Vec<u8> = Vec::new();
        let mut upper: Vec<u8> = Vec::new();
        if lower.try_reserve_exact(RELEASE_BLOCK_BYTES).is_err()
            || upper.try_reserve_exact(RELEASE_BLOCK_BYTES).is_err()
        {
            exit(RELEASE_ALLOC_FAILED);
        }
        if (upper.as_ptr() as usize) < (lower.as_ptr() as usize).saturating_add(RELEASE_BLOCK_BYTES)
        {
            exit(RELEASE_NOT_STACKED);
        }
        touch_committed(std::slice::from_mut(&mut lower));
        let Some(((own, _, _), before)) = crate::phases::budget::memory_usage().zip(pool_totals())
        else
        {
            exit(HOG_STATUS_FAILED)
        };
        drop(lower);
        let discarded = totals_rise(before, RELEASE_DISCARD_PAGES, Some(RELEASE_DISCARD_PAGES));
        drop(upper);
        let Some((trimmed, _, _)) = crate::phases::budget::memory_usage()
        else
        {
            exit(HOG_STATUS_FAILED)
        };
        if trimmed.saturating_add(RELEASE_TRIM_PAGES) > own
        {
            exit(RELEASE_NOT_TRIMMED);
        }
        if discarded
        {
            exit(0);
        }
    }
    exit(RELEASE_NOT_DISCARDED);
}
