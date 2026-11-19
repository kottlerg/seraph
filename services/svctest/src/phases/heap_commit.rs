// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/heap_commit.rs

//! Committed regions (`memmgr_labels::REGION_COMMIT`;
//! services/memmgr/docs/memory-pool.md § Commit), through their labels and
//! through the std heap, whose growth above its floor is one committed region
//! (docs/userspace-memory-model.md § Byte Heap).
//!
//! The phase first drives the labels on a region of its own
//! ([`region_resize`]). It then runs two children of `/tests/svctest`: a
//! `heap-commit-limited` child under a max of [`LIMITED_MAX_PAGES`]
//! ([`limited_child_main`]), whose `try_reserve` past the max returns `Err`
//! and which keeps running, and a `heap-commit-hog` ([`hog_main`]), which
//! commits all but [`HOG_MARGIN_PAGES`] of what memmgr can still promise,
//! sees a grant past that refused although free pages exist, and touches every
//! page it committed with no fault declined. Each child's charge leaves
//! svctest's budget subtree before the phase goes on, memmgr's free total net
//! of eviction and its promised total then return to their levels
//! ([`PoolLevels`]), and the all-RAM-accounted identity holds.

use std::os::seraph::startup_info;
use std::process::exit;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::PAGE_SIZE;

use crate::bootstrap::Caps;
use crate::phases::budget;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_heap_commit",
        run: heap_commit_phase,
    }]
}

/// Child-mode dispatch for the argv tokens this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == LIMITED_ROLE
    {
        limited_child_main();
    }
    if role == HOG_ROLE
    {
        hog_main();
    }
}

/// argv[1] of the child the phase creates with a max.
const LIMITED_ROLE: &str = "heap-commit-limited";
/// argv[1] of the child that commits what memmgr can still promise.
const HOG_ROLE: &str = "heap-commit-hog";

/// The max in pages of the limited child: room for its image, its stacks, its
/// heap floor and [`LIMITED_KEEP_BYTES`] of growth.
const LIMITED_MAX_PAGES: u64 = 4096;
/// Pages the limited child's first reservation asks: past its max even with
/// the whole heap floor free to hold part of it.
const PAST_MAX_PAGES: u64 = 2 * LIMITED_MAX_PAGES;
/// Bytes the limited child allocates and writes after its refused
/// reservation: more than its heap floor holds, so its heap grows.
const LIMITED_KEEP_BYTES: usize = 4 << 20;
/// Exit code: `try_reserve` of [`PAST_MAX_PAGES`] pages succeeded.
const LIMITED_PAST_MAX_GRANTED: i32 = 2;
/// Exit code: the allocation of [`LIMITED_KEEP_BYTES`] failed.
const LIMITED_KEEP_FAILED: i32 = 3;
/// Exit code: a page of the kept allocation read back other than written.
const LIMITED_KEEP_CORRUPT: i32 = 4;

/// Pages the hog leaves uncommitted, for the other processes of the boot to
/// allocate while it runs; its commitment ends when it has at most this many
/// left to commit.
pub(crate) const HOG_MARGIN_PAGES: u64 = 1024;
/// Reservations the hog may attempt before it gives up, over all its
/// commitments down to the margin: each failure halves the next attempt, and
/// each success commits at least half of what is left above the margin.
pub(crate) const HOG_MAX_ROUNDS: usize = 256;
/// Grants past what is left the hog may ask before it gives up: each one
/// memmgr admits means another process freed pages after the hog read what
/// was left, and the hog gives it back before it asks again.
const HOG_REFUSAL_ATTEMPTS: usize = 8;
/// Bytes of the hog's ballast: the size of the heap's floor, so the ballast
/// holds at least what the floor has free.
pub(crate) const HOG_BALLAST_BYTES: usize = 2 << 20;
/// Exit code: a `QUERY_POOL_STATUS` call to memmgr failed or was refused.
pub(crate) const HOG_STATUS_FAILED: i32 = 2;
/// Exit code: the hog did not commit down to [`HOG_MARGIN_PAGES`] in
/// [`HOG_MAX_ROUNDS`] attempts.
pub(crate) const HOG_NOT_COMMITTED: i32 = 3;
/// Exit code: a grant of one page past what is left was admitted in each of
/// [`HOG_REFUSAL_ATTEMPTS`] attempts, or refused other than with
/// `OUT_OF_MEMORY_BEST_EFFORT`.
const HOG_GRANT_NOT_REFUSED: i32 = 4;
/// Exit code: the refusal reported no free pages past the grant asked, so it
/// did not show a refusal of pages the pool holds.
const HOG_NO_FREE_PAGES: i32 = 5;
/// Exit code: the allocation of the ballast failed.
pub(crate) const HOG_BALLAST_FAILED: i32 = 6;
/// Exit code: memmgr refused the release of a grant it admitted past what
/// was left, or its grant reply had no valid layout.
const HOG_RELEASE_FAILED: i32 = 7;

/// Pages of one memmgr demand chunk, the unit `SHRINK_REGION` and
/// `DISCARD_RANGE` take.
pub(crate) const CHUNK_PAGES: u64 = memmgr_labels::DEMAND_CHUNK_BYTES / PAGE_SIZE;
/// Pages the phase's own committed region is registered with: two chunks.
const REGION_PAGES: u64 = 2 * CHUNK_PAGES;

/// Sample windows the phase retries: memmgr's totals are system-wide, and
/// other processes can move them inside one.
pub(crate) const POOL_WINDOWS: u32 = 8;
/// Status queries per window after the children's destroy. A test wait bound.
pub(crate) const POOL_POLLS: u32 = 256;
/// How long the phase waits for memmgr to reclaim a child that has exited. A
/// test wait bound: procmgr's teardown of the hog and memmgr's reclaim of
/// what it committed, most of RAM.
const RECLAIM_TIMEOUT: Duration = Duration::from_secs(120);

/// The phase: the labels on a region of svctest's own, then the two children
/// in windows until memmgr's levels return around them ([`windows_settle`]), then
/// the identity. Each child's exit is followed by memmgr's reclaim of it
/// ([`children_reclaimed`]), so no window starts, and no child is created,
/// while an earlier child's charge and commitment are still held.
fn heap_commit_phase(caps: &Caps)
{
    region_resize();
    windows_settle("the heap-commit children", |children| {
        run_limited_child();
        children_reclaimed(children, "the heap-commit limited child");
        run_hog();
        children_reclaimed(children, "the heap-commit hog");
    });
    crate::phases::memmgr::ram_accounted_identity_phase(caps);
    std::os::seraph::log!("memmgr_heap_commit phase passed");
}

/// memmgr's `QUERY_POOL_STATUS` free total, promised total and growth floor
/// (`data[3]`, `data[8]` and `data[11]`), in pages; `None` when the call
/// fails or is refused. Allocates nothing.
pub(crate) fn pool_totals() -> Option<(u64, u64, u64)>
{
    let reply = pool_status()?;
    Some((
        reply.word(3) / PAGE_SIZE,
        reply.word(8) / PAGE_SIZE,
        reply.word(11) / PAGE_SIZE,
    ))
}

/// memmgr's `QUERY_POOL_STATUS` totals a window compares, in pages: the free
/// total (`data[3]`), the promised total (`data[8]`), and the store and
/// swapped totals (`data[9]` and `data[10]`) that net eviction out of the
/// free total ([`Self::net_free`]).
#[derive(Clone, Copy)]
struct PoolLevels
{
    free: u64,
    promised: u64,
    store: u64,
    swapped: u64,
}

impl PoolLevels
{
    /// Read the totals; panics when the call fails or is refused. Allocates
    /// nothing.
    fn read() -> Self
    {
        let req = IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS);
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
        let reply = unsafe {
            ipc::ipc_call(
                startup_info().memmgr_endpoint,
                &req,
                std::os::seraph::current_ipc_buf(),
            )
        }
        .expect("QUERY_POOL_STATUS failed");
        assert_eq!(
            reply.label,
            memmgr_errors::SUCCESS,
            "QUERY_POOL_STATUS refused"
        );
        Self {
            free: reply.word(3) / PAGE_SIZE,
            promised: reply.word(8) / PAGE_SIZE,
            store: reply.word(9) / PAGE_SIZE,
            swapped: reply.word(10) / PAGE_SIZE,
        }
    }

    /// The free total net of eviction: the free pages there would be with
    /// every evicted chunk restored and its store runs freed, `free + store -
    /// swapped`. memmgr evicts other processes' cold chunks in the background
    /// while the hog holds the pool `LOW`, and restores one on its next fault
    /// (services/memmgr/docs/memory-pool.md § Eviction), so the free total
    /// alone can read differently after a window although every page the
    /// window took came back. An eviction of a chunk of `b` backed pages into
    /// `s` store pages raises `free` by `b - s`, `store` by `s` and
    /// `swapped` by `b`; a restore reverses it, and a write of the chunk to
    /// the disk tier moves its `s` store pages to `free`. None of them moves
    /// this sum, which an allocation or a free moves page for page.
    fn net_free(&self) -> i128
    {
        i128::from(self.free)
            .wrapping_add(i128::from(self.store))
            .wrapping_sub(i128::from(self.swapped))
    }

    /// What a window compares: the free total net of eviction and the
    /// promised total.
    fn level(&self) -> (i128, u64)
    {
        (self.net_free(), self.promised)
    }
}

impl std::fmt::Display for PoolLevels
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(
            f,
            "{} free net of eviction ({} free, {} in the store, {} swapped) and {} promised",
            self.net_free(),
            self.free,
            self.store,
            self.swapped,
            self.promised
        )
    }
}

/// memmgr's levels once its deferred list has settled
/// ([`budget::settled_pool_free`]).
fn settled_levels() -> PoolLevels
{
    let _ = budget::settled_pool_free();
    PoolLevels::read()
}

/// Wait until memmgr's levels read `before`'s ([`PoolLevels::level`]),
/// within [`POOL_POLLS`] polls, each after a recheck of memmgr's deferred
/// list. `Err` carries the totals the last poll read.
fn levels_settle_to(before: PoolLevels) -> Result<(), PoolLevels>
{
    let mut last = before;
    for _ in 0..POOL_POLLS
    {
        crate::phases::memmgr::recheck_deferred();
        last = PoolLevels::read();
        if last.level() == before.level()
        {
            return Ok(());
        }
        std::thread::yield_now();
    }
    Err(last)
}

/// Run `window` in up to [`POOL_WINDOWS`] windows, until memmgr's free
/// total net of eviction and its promised total return after one to the
/// levels they read before it ([`PoolLevels`], [`settled_levels`],
/// [`levels_settle_to`]). `window` takes what memmgr charged svctest's
/// descendants before it ([`children_charge`]). Panics, naming `what`,
/// when no window settles, stating the last window's levels and the totals it
/// read last, so the failure shows which total missed and by how many pages.
pub(crate) fn windows_settle(what: &str, mut window: impl FnMut(u64))
{
    let mut missed = None;
    for _ in 0..POOL_WINDOWS
    {
        let children = children_charge();
        let before = settled_levels();
        window(children);
        match levels_settle_to(before)
        {
            Ok(()) => return,
            Err(last) => missed = Some((before, last)),
        }
    }
    if let Some((before, last)) = missed
    {
        panic!(
            "memmgr's levels did not return after {what} in any of {POOL_WINDOWS} windows: \
             the last window's levels were {before}, and it read last {last}, {:+} free net of \
             eviction and {:+} promised",
            last.net_free().wrapping_sub(before.net_free()),
            i128::from(last.promised).wrapping_sub(i128::from(before.promised))
        );
    }
}

/// What memmgr charges svctest's descendants, in pages: the subtree count of
/// svctest's budget node less its own (`QUERY_MEMORY_USAGE`).
pub(crate) fn children_charge() -> u64
{
    let (own, _, subtree) = budget::memory_usage().expect("QUERY_MEMORY_USAGE failed");
    subtree.saturating_sub(own)
}

/// Wait until what memmgr charges svctest's descendants reads at most
/// `level`, the charge before `what` was created, each poll after a recheck
/// of memmgr's deferred list, on which runs the kernel still held at the
/// child's teardown wait charged. Neither the child's exit as std's
/// `status()` sees it nor procmgr's `DESTROY_PROCESS` reply waits for
/// memmgr's `PROCESS_DIED`, which frees the child's budget node, its regions
/// and its commitment. Panics when the charge is still held after
/// [`RECLAIM_TIMEOUT`].
pub(crate) fn children_reclaimed(level: u64, what: &str)
{
    let start = Instant::now();
    loop
    {
        crate::phases::memmgr::recheck_deferred();
        let charge = children_charge();
        if charge <= level
        {
            return;
        }
        assert!(
            start.elapsed() < RECLAIM_TIMEOUT,
            "memmgr still charged svctest's descendants {charge} pages, from {level} before \
             {what}, {RECLAIM_TIMEOUT:?} after its exit"
        );
        std::thread::yield_now();
    }
}

/// memmgr's reply label to `msg`.
pub(crate) fn memmgr_label(msg: &IpcMessage, what: &str) -> u64
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            msg,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"))
    .label
}

/// Send `label` with `[va, len]` to memmgr and assert it replies `want`.
pub(crate) fn expect_region_reply(label: u64, va: u64, len: u64, want: u64, what: &str)
{
    let msg = IpcMessage::builder(label).word(0, va).word(1, len).build();
    let got = memmgr_label(&msg, what);
    assert_eq!(got, want, "{what}: memmgr replied {got:#x}");
}

/// svctest's own usage (`QUERY_MEMORY_USAGE` `data[0]`), in pages.
pub(crate) fn own_usage() -> u64
{
    budget::memory_usage().expect("QUERY_MEMORY_USAGE failed").0
}

/// `REGISTER_REGION` with `REGION_COMMIT`, `EXTEND_REGION` and
/// `SHRINK_REGION` on a region of svctest's own:
///
/// 1. The registration charges the region's pages to svctest's node and
///    counts them in `promised`.
/// 2. memmgr refuses with `INVALID_ARGUMENT` an extension below the length,
///    a cut to a length that is no chunk multiple or above the length, an
///    extension at an address no committed region is based at, and an
///    extension of an uncommitted region ([`region_refusals`]).
/// 3. An extension to twice the length charges the added pages; a touch of
///    every page then charges nothing more ([`grow_and_touch`]).
/// 4. A cut to one chunk uncharges the pages cut, a repeat of it changes
///    nothing, and the unregistration of the one-chunk region the cut left
///    uncharges the rest ([`cut_and_unregister`]).
fn region_resize()
{
    use memmgr_labels::{REGION_COMMIT, REGISTER_REGION};

    let range = std::os::seraph::reserve_pages(GROWN_PAGES)
        .expect("reserving the committed region's range failed");
    let base = range.va_start();

    let own0 = own_usage();
    let register = IpcMessage::builder(REGISTER_REGION)
        .word(0, base)
        .word(1, REGION_PAGES * PAGE_SIZE)
        .word(2, syscall::MAP_WRITABLE)
        .word(3, REGION_COMMIT)
        .build();
    let got = memmgr_label(&register, "REGISTER_REGION with REGION_COMMIT");
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "REGISTER_REGION with REGION_COMMIT: {got:#x}"
    );
    let own1 = own_usage();
    assert!(
        own1.saturating_sub(own0) >= REGION_PAGES,
        "the committed registration charged {} pages, below its {REGION_PAGES}",
        own1.saturating_sub(own0)
    );
    let (_, promised, _) = pool_totals().expect("QUERY_POOL_STATUS failed");
    assert!(
        promised >= REGION_PAGES,
        "promised reads {promised} pages with {REGION_PAGES} committed and untouched"
    );

    region_refusals(base);
    let own3 = grow_and_touch(base, own1);
    cut_and_unregister(base, own0, own3);
    std::os::seraph::unreserve_pages(range);
}

/// Pages of the phase's committed region once extended: twice its
/// registered length.
const GROWN_PAGES: u64 = 2 * REGION_PAGES;

/// memmgr's refusals, with `INVALID_ARGUMENT`, of resizes of the committed
/// region at `base`, of [`REGION_PAGES`] pages, that cannot apply.
fn region_refusals(base: u64)
{
    use memmgr_labels::{EXTEND_REGION, SHRINK_REGION};

    let invalid = memmgr_errors::INVALID_ARGUMENT;
    expect_region_reply(
        EXTEND_REGION,
        base,
        (REGION_PAGES - 1) * PAGE_SIZE,
        invalid,
        "EXTEND_REGION below the length",
    );
    expect_region_reply(
        SHRINK_REGION,
        base,
        (CHUNK_PAGES + 1) * PAGE_SIZE,
        invalid,
        "SHRINK_REGION to a length that is no chunk multiple",
    );
    expect_region_reply(
        SHRINK_REGION,
        base,
        GROWN_PAGES * PAGE_SIZE,
        invalid,
        "SHRINK_REGION above the length",
    );
    expect_region_reply(
        EXTEND_REGION,
        base.saturating_add(PAGE_SIZE),
        GROWN_PAGES * PAGE_SIZE,
        invalid,
        "EXTEND_REGION at an address no committed region is based at",
    );
    let plain = std::os::seraph::register_demand_paged(1)
        .expect("registering an uncommitted region failed");
    expect_region_reply(
        EXTEND_REGION,
        plain.va_start(),
        2 * PAGE_SIZE,
        invalid,
        "EXTEND_REGION of an uncommitted region",
    );
    // SAFETY: `plain` is the region registered above, which nothing touched.
    unsafe { std::os::seraph::unregister_demand_paged(plain) }
        .expect("unregistering the uncommitted region failed");
}

/// Extend the committed region at `base` to [`GROWN_PAGES`] pages, check
/// the extension charged its pages to svctest's node, charged `own1` pages
/// before it, then write every page of the region and check the writes
/// charged nothing. Returns the charge after the writes.
fn grow_and_touch(base: u64, own1: u64) -> u64
{
    expect_region_reply(
        memmgr_labels::EXTEND_REGION,
        base,
        GROWN_PAGES * PAGE_SIZE,
        memmgr_errors::SUCCESS,
        "EXTEND_REGION to twice the length",
    );
    let own2 = own_usage();
    assert!(
        own2.saturating_sub(own1) >= GROWN_PAGES - REGION_PAGES,
        "the extension charged {} pages, below its {}",
        own2.saturating_sub(own1),
        GROWN_PAGES - REGION_PAGES
    );
    let mut va = base;
    for _ in 0..GROWN_PAGES
    {
        // SAFETY: `va` is a page of the committed region registered and
        // extended above, in a reservation of this phase that no Rust object
        // occupies; the write is volatile so that it is made, and faults, here.
        unsafe { std::ptr::write_volatile(va as *mut u8, 1) };
        va = va.saturating_add(PAGE_SIZE);
    }
    let own3 = own_usage();
    assert_eq!(
        own3, own2,
        "touching committed pages changed the charge: their pages and page tables were charged \
         at the commitment"
    );
    own3
}

/// Cut the committed region at `base`, of [`GROWN_PAGES`] touched pages
/// with svctest's node charged `own3`, to one chunk, repeat the cut, and
/// unregister the rest, checking the charge each step leaves against `own3`
/// and `own0`, the charge before the registration.
fn cut_and_unregister(base: u64, own0: u64, own3: u64)
{
    let success = memmgr_errors::SUCCESS;
    let chunk_len = CHUNK_PAGES * PAGE_SIZE;
    expect_region_reply(
        memmgr_labels::SHRINK_REGION,
        base,
        chunk_len,
        success,
        "SHRINK_REGION to one chunk",
    );
    let own4 = own_usage();
    assert!(
        own3.saturating_sub(own4) >= GROWN_PAGES - CHUNK_PAGES,
        "the cut uncharged {} pages, below the {} cut",
        own3.saturating_sub(own4),
        GROWN_PAGES - CHUNK_PAGES
    );
    expect_region_reply(
        memmgr_labels::SHRINK_REGION,
        base,
        chunk_len,
        success,
        "SHRINK_REGION repeated",
    );
    assert_eq!(own_usage(), own4, "the repeated cut changed the charge");
    expect_region_reply(
        memmgr_labels::UNREGISTER_REGION,
        base,
        chunk_len,
        success,
        "UNREGISTER_REGION of the cut region",
    );
    let own5 = own_usage();
    assert!(
        own4.saturating_sub(own5) >= CHUNK_PAGES && own5 >= own0,
        "the unregistration left {own5} pages charged, from {own4}, against {own0} before the \
         registration"
    );
}

/// Create the limited child under a max of [`LIMITED_MAX_PAGES`], run it to
/// its exit, destroy it, and check its exit code.
fn run_limited_child()
{
    let what = "the heap-commit limited child";
    let (handle, thread) = budget::create_with_max(LIMITED_ROLE, LIMITED_MAX_PAGES, what);
    let reason = budget::run_to_exit(handle, what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
    assert_eq!(
        reason, 0,
        "{what} exit reason {reason:#x}: {LIMITED_PAST_MAX_GRANTED}=a reservation past its max \
         succeeded, {LIMITED_KEEP_FAILED}=an allocation under its max failed, \
         {LIMITED_KEEP_CORRUPT}=its allocation read back wrong, a fault reason=it was killed"
    );
}

/// Run the hog to its exit and check its exit code.
fn run_hog()
{
    let status = std::process::Command::new("/tests/svctest")
        .arg(HOG_ROLE)
        .status()
        .expect("spawning the heap-commit hog failed");
    assert!(
        status.success(),
        "the heap-commit hog exited {status:?}: {HOG_STATUS_FAILED}=QUERY_POOL_STATUS failed, \
         {HOG_NOT_COMMITTED}=it did not commit down to its margin, {HOG_GRANT_NOT_REFUSED}=a grant \
         past what is left was admitted in every attempt, {HOG_NO_FREE_PAGES}=the refusal showed no free \
         pages, {HOG_BALLAST_FAILED}=its ballast's allocation failed, \
         {HOG_RELEASE_FAILED}=the release of a grant admitted past what was left failed, a fault=a fault on a committed page was declined"
    );
}

// ── The children ─────────────────────────────────────────────────────────────

/// Bytes of `pages` pages, as a reservation length.
pub(crate) fn page_bytes(pages: u64) -> usize
{
    usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(usize::MAX)
}

/// Child role: under a max of [`LIMITED_MAX_PAGES`], a `try_reserve` of
/// [`PAST_MAX_PAGES`] returns `Err` (memmgr refuses the heap's commitment with
/// `LIMIT`), and the child then allocates, writes and reads back
/// [`LIMITED_KEEP_BYTES`], which its heap grows to hold, and exits 0.
fn limited_child_main() -> !
{
    let mut past: Vec<u8> = Vec::new();
    if past.try_reserve_exact(page_bytes(PAST_MAX_PAGES)).is_ok()
    {
        exit(LIMITED_PAST_MAX_GRANTED);
    }
    let mut keep: Vec<u8> = Vec::new();
    if keep.try_reserve_exact(LIMITED_KEEP_BYTES).is_err()
    {
        exit(LIMITED_KEEP_FAILED);
    }
    keep.resize(LIMITED_KEEP_BYTES, 1);
    let page = page_bytes(1);
    if keep.iter().step_by(page).any(|&b| b != 1)
    {
        exit(LIMITED_KEEP_CORRUPT);
    }
    exit(0);
}

/// What memmgr can still promise a node outside the reserve, in pages: its
/// free pages and its overcommit allowance less `promised` and the growth
/// floor (services/memmgr/docs/memory-pool.md § Commit, Overcommit).
pub(crate) fn uncommitted_available() -> u64
{
    promise_room().unwrap_or_else(|| exit(HOG_STATUS_FAILED))
}

/// memmgr's room for a commitment, in pages: `free + A - promised - floor`
/// from one `QUERY_POOL_STATUS`, `A` being the overcommit allowance its
/// swap slots give ([`allowance_pages`]); `None` when the call fails or is
/// refused. Allocates nothing.
pub(crate) fn promise_room() -> Option<u64>
{
    let reply = pool_status()?;
    let free = reply.word(3) / PAGE_SIZE;
    let promised = reply.word(8) / PAGE_SIZE;
    let floor = reply.word(11) / PAGE_SIZE;
    Some(
        free.saturating_add(allowance_pages(&reply))
            .saturating_sub(promised)
            .saturating_sub(floor),
    )
}

/// The overcommit allowance a `QUERY_POOL_STATUS` reply shows, in pages:
/// [`CHUNK_PAGES`] pages a free swap slot (`data[13]`), less the pages
/// compression freed from the evicted chunks not on disk, their pages
/// (`data[10]` less `data[12]`) less the store pages they hold (`data[9]`);
/// 0 while no swap service is registered (services/memmgr/docs/memory-pool.md
/// § Commit, Overcommit).
pub(crate) fn allowance_pages(reply: &IpcMessage) -> u64
{
    let freed = reply
        .word(10)
        .saturating_sub(reply.word(12))
        .saturating_sub(reply.word(9))
        / PAGE_SIZE;
    reply
        .word(13)
        .saturating_mul(CHUNK_PAGES)
        .saturating_sub(freed)
}

/// memmgr's `QUERY_POOL_STATUS` reply; `None` when the call fails or is
/// refused. Allocates nothing.
pub(crate) fn pool_status() -> Option<IpcMessage>
{
    let req = IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            &req,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .ok()?;
    (reply.label == memmgr_errors::SUCCESS).then_some(reply)
}

/// Child role: commit, through `try_reserve` on the heap, all but at most
/// [`HOG_MARGIN_PAGES`] of what memmgr can still promise, halving an attempt
/// it refuses. A best-effort grant of one page more than is then left is
/// refused with `OUT_OF_MEMORY_BEST_EFFORT`, and its reply counts more free
/// pages than the grant asked: the pool holds them, promised to the hog. The
/// hog then writes every page it committed, and exits 0; a fault memmgr
/// declined would kill it instead.
///
/// Other processes free pages while the hog runs (a file system gives back
/// its cache when the hog's commitment raises memmgr's pressure level), so
/// what is left can grow between the hog's read of it and its grant. memmgr
/// then admits the grant; the hog gives it back, commits down to its margin
/// again and asks again, up to [`HOG_REFUSAL_ATTEMPTS`] times. A memmgr that
/// admits past what is left, by any number of pages, admits every attempt,
/// since each gives its grant back before the next read.
///
/// The heap's floor is an uncommitted demand region below the committed one
/// (docs/userspace-memory-model.md § Byte Heap), whose untouched pages memmgr
/// backs only while it has pages to spare. So the hog first fills what its
/// floor has free with a ballast it writes whole while the pool is roomy
/// ([`HOG_BALLAST_BYTES`]), and every block it commits after lies above it.
fn hog_main() -> !
{
    let mut held: Vec<Vec<u8>> = Vec::with_capacity(HOG_MAX_ROUNDS);
    let mut ballast: Vec<u8> = Vec::new();
    if ballast.try_reserve_exact(HOG_BALLAST_BYTES).is_err()
    {
        exit(HOG_BALLAST_FAILED);
    }
    ballast.resize(HOG_BALLAST_BYTES, 1);
    let mut rounds = HOG_MAX_ROUNDS;
    for _ in 0..HOG_REFUSAL_ATTEMPTS
    {
        let left = commit_to_margin(&mut held, &mut rounds);
        if past_grant_refused(left)
        {
            touch_committed(&mut held);
            exit(0);
        }
    }
    exit(HOG_GRANT_NOT_REFUSED);
}

/// Commit blocks into `held` until what memmgr can still promise is at most
/// [`HOG_MARGIN_PAGES`], spending reservation attempts from `rounds`, and
/// return what is then left; exit with [`HOG_NOT_COMMITTED`] when `rounds`
/// runs out first.
pub(crate) fn commit_to_margin(held: &mut Vec<Vec<u8>>, rounds: &mut usize) -> u64
{
    let mut ask = u64::MAX;
    while *rounds > 0
    {
        let available = uncommitted_available();
        if available <= HOG_MARGIN_PAGES
        {
            return available;
        }
        *rounds = rounds.saturating_sub(1);
        ask = ask.min(available.saturating_sub(HOG_MARGIN_PAGES / 2));
        let mut block: Vec<u8> = Vec::new();
        if block.try_reserve_exact(page_bytes(ask)).is_ok()
        {
            held.push(block);
        }
        else
        {
            ask /= 2;
        }
    }
    exit(HOG_NOT_COMMITTED)
}

/// Ask memmgr for a best-effort grant of one page more than `left`. Returns
/// `true` when memmgr refuses it with `OUT_OF_MEMORY_BEST_EFFORT` and counts
/// more free pages than the grant asked, and `false` when it grants it, once
/// the grant is given back ([`give_back`]). Exits with [`HOG_NO_FREE_PAGES`] on a refusal that
/// counts no more free pages than asked, and with [`HOG_GRANT_NOT_REFUSED`] on
/// any other reply.
fn past_grant_refused(left: u64) -> bool
{
    let past = left.saturating_add(1);
    let grant = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, past)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            &grant,
            std::os::seraph::current_ipc_buf(),
        )
    };
    match reply
    {
        Ok(r) if r.label == memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT =>
        {
            if r.word(0) <= past
            {
                exit(HOG_NO_FREE_PAGES);
            }
            true
        }
        Ok(r) if r.label == memmgr_errors::SUCCESS =>
        {
            give_back(&r);
            false
        }
        _ => exit(HOG_GRANT_NOT_REFUSED),
    }
}

/// Give back every run of the grant `reply` transferred: delete its caps,
/// so memmgr pools the runs at once, then release the runs by region id,
/// `reply`'s `data[0]` being their count.
/// Exits with [`HOG_RELEASE_FAILED`] when the reply has no valid grant layout
/// or memmgr refuses the release.
fn give_back(reply: &IpcMessage)
{
    let Some((_, ids)) = ipc::memmgr_grant_layout(reply)
    else
    {
        exit(HOG_RELEASE_FAILED)
    };
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    let release = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, reply.word(0))
        .words(1, ids)
        .build();
    if memmgr_label_or_exit(&release) != memmgr_errors::SUCCESS
    {
        exit(HOG_RELEASE_FAILED);
    }
}

/// memmgr's reply label to `msg`; exits with [`HOG_RELEASE_FAILED`] when
/// the call fails.
fn memmgr_label_or_exit(msg: &IpcMessage) -> u64
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            msg,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .map_or(None, |r| Some(r.label))
    .unwrap_or_else(|| exit(HOG_RELEASE_FAILED))
}

/// Write one byte of every page of the blocks in `held`, each a committed
/// reservation the hog has not touched.
pub(crate) fn touch_committed(held: &mut [Vec<u8>])
{
    let page = page_bytes(1);
    for block in held
    {
        for byte in block.spare_capacity_mut().iter_mut().step_by(page)
        {
            // SAFETY: `byte` is a byte of the block's reserved capacity, which
            // this process owns; the write is volatile so that it is made, and
            // faults, here.
            unsafe { std::ptr::write_volatile(byte.as_mut_ptr(), 1) };
        }
    }
}
