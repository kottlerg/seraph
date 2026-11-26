// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/memory_objects.rs

//! Memory objects (`memmgr_labels::SEAL_OBJECT`, `ATTACH_OBJECT` and
//! `OBJECT_RELEASE`; services/memmgr/docs/memory-pool.md § Memory objects).
//!
//! The phase seals two grants of svctest's, filled with a pattern, into a
//! three-page object ([`seal`]), refuses the requests the labels' contracts
//! refuse ([`refusals`]), and attaches the object shared and private in
//! svctest and in `memory-object-child` children ([`attach_and_share`]): each
//! attacher reads the pattern and is charged what it maps, a private write is
//! seen by no other attacher, and a write to a shared attachment kills its
//! writer. It then releases the object, which lives on while svctest attaches
//! it and frees its frames with the last attachment ([`release`]). Last it
//! attaches the zero object ([`zero_object`]): a read takes no page, a write
//! takes its own pages and leaves the zero frame zero, and a shared
//! attachment larger than the free pages is admitted, since it takes none.
//!
//! A phase of its own, early in the run ([`early`]), seals one grant
//! spanning more leaf page tables than one map's page-table funding covers
//! into an object ([`large_object`]), reads every page back from memmgr's
//! own view of it, and releases it. It runs before the later phases leave
//! the pool's free memory in runs too short for a grant that large at the
//! default memory size.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_SIZE};

use crate::bootstrap::Caps;
use crate::phases::heap_commit::{CHUNK_PAGES, expect_region_reply, own_usage, pool_totals};
use crate::phases::memmgr::{recheck_deferred, release_grant, try_request_contiguous};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_memory_objects",
        run: memory_objects_phase,
    }]
}

/// The phase that seals one large grant ([`large_object`]), registered
/// right after memmgr's own phases (`phases::all`, ordering constraint 17).
pub fn early() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_large_object",
        run: large_object_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == OBJECT_CHILD_ROLE
    {
        object_child_main();
    }
    if role == LIMITED_ROLE
    {
        limited_child_main();
    }
}

/// argv[1] of the child that attaches svctest's object; argv[2] is
/// [`WRITER_ARG`] for the child that writes its shared attachment.
const OBJECT_CHILD_ROLE: &str = "memory-object-child";
/// argv[2] of the `memory-object-child` that writes its shared attachment.
const WRITER_ARG: &str = "write";
/// argv[1] of the child the phase creates with a max of [`LIMITED_MAX_PAGES`].
const LIMITED_ROLE: &str = "memory-object-limited";
/// The max in pages of the `memory-object-limited` child.
const LIMITED_MAX_PAGES: u64 = 4096;
/// Pages of the zero-object attachments the limited child asks: twice its max.
const PAST_MAX_PAGES: u64 = 2 * LIMITED_MAX_PAGES;
/// Exit code: the limited child's reservation of [`PAST_MAX_PAGES`] failed.
const LIMITED_RESERVE_FAILED: i32 = 2;
/// Exit code: a private attachment past the limited child's max was not
/// refused with `LIMIT`.
const LIMITED_PRIVATE_ADMITTED: i32 = 3;
/// Exit code: a shared attachment past the limited child's max was not
/// refused with `LIMIT`.
const LIMITED_SHARED_ADMITTED: i32 = 4;

/// Pages of the object: a two-page grant, then a one-page grant.
pub(super) const OBJECT_PAGES: u64 = 3;
/// `u64` words in a page.
const PAGE_WORDS: u64 = PAGE_SIZE / 8;
/// The value a private write puts in the first word of a page.
const WRITTEN: u64 = 0x7772_6974_7465_6E21;

/// Label of the call a `memory-object-child` makes on its namespace cap, which
/// carries SEND only, to fetch a copy of the object handle.
pub(super) const FETCH_LABEL: u64 = 0x6D6F_6266;
/// Badge of the SEND that stops [`serve_handle`].
pub(super) const STOP_BADGE: u64 = 0x5710;

/// Exit code: the fetch of the handle failed.
const CHILD_FETCH_FAILED: i32 = 2;
/// Exit code: memmgr refused the child's shared attachment.
const CHILD_SHARED_REFUSED: i32 = 3;
/// Exit code: the shared attachment read other than the pattern.
const CHILD_SHARED_CORRUPT: i32 = 4;
/// Exit code: memmgr refused the child's private attachment.
const CHILD_PRIVATE_REFUSED: i32 = 5;
/// Exit code: the private attachment read other than the pattern before the
/// child wrote it, or other than what it wrote after.
const CHILD_PRIVATE_CORRUPT: i32 = 6;
/// Exit code: an attachment did not charge the child its pages.
const CHILD_NOT_CHARGED: i32 = 7;
/// Exit code: the writer's write to its shared attachment completed.
const CHILD_SHARED_WRITTEN: i32 = 8;

/// Pages of the zero-object attachment: 16 chunks.
const ZERO_PAGES: u64 = 16 * CHUNK_PAGES;
/// How long the phase waits for the object's frames to leave svctest's
/// charge once its last attachment goes. A test wait bound: a frame a dead
/// child's mapping still reached waits on memmgr's deferred list until
/// procmgr's teardown of the child ends.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(60);

/// Pages one leaf page table maps: 2 MiB of 4 KiB pages under every paging
/// mode of both architectures.
const LEAF_TABLE_PAGES: u32 = 512;
/// Pages of the object [`large_object`] seals, one grant of 64 leaf tables
/// (128 MiB). memmgr's own view of it needs a page table for each, more than
/// the `PT_FUND_ROUNDS` top-ups of one map (16 pages at most) and what
/// memmgr's page-table pool holds this early in the run fund together, so
/// memmgr maps the view only because that bound holds per leaf-table window
/// of the map, not per map (services/memmgr/docs/memory-pool.md § Metadata
/// Arena).
const LARGE_PAGES: u32 = 64 * LEAF_TABLE_PAGES;

/// The last `u64` word of a page.
pub(super) const LAST_WORD: u64 = PAGE_WORDS - 1;
/// Half the pages of the zero-object attachment, the half [`zero_object`]
/// writes.
const ZERO_HALF: u64 = ZERO_PAGES / 2;

/// A quarter of the pages of the zero-object attachment: the least its
/// written half takes from the promised total.
const ZERO_QUARTER: u64 = ZERO_PAGES / 4;

/// The value the pattern holds in word `word` of object page `page`.
pub(super) const fn pattern(page: u64, word: u64) -> u64
{
    0x5EA1_0B1E_0000_0000 ^ page.wrapping_shl(16) ^ word
}

/// The address of page `page` from `base`.
const fn page_at(base: u64, page: u64) -> u64
{
    base.wrapping_add(page.wrapping_mul(PAGE_SIZE))
}

/// Write the pattern of object pages `first_page..first_page + pages` at `va`.
fn fill(va: u64, first_page: u64, pages: u64)
{
    for p in 0..pages
    {
        for w in 0..PAGE_WORDS
        {
            let at = page_at(va, p).wrapping_add(w.wrapping_mul(8));
            // SAFETY: the caller maps `pages` writable pages at `va`, which no
            // Rust reference points into.
            unsafe {
                std::ptr::write_volatile(at as *mut u64, pattern(first_page.wrapping_add(p), w));
            }
        }
    }
}

/// Word `word` of the page at `va`.
fn read_word(va: u64, word: u64) -> u64
{
    // SAFETY: the caller attaches or maps the page at `va` readable; no Rust
    // reference points into it, and a read of an unmapped attached page
    // faults to memmgr, which maps it.
    unsafe { std::ptr::read_volatile(va.wrapping_add(word.wrapping_mul(8)) as *const u64) }
}

/// Whether the `pages` pages at `va` hold the pattern of object pages
/// `first_page` on, in their first and last words.
fn holds_pattern(va: u64, first_page: u64, pages: u64) -> bool
{
    (0..pages).all(|p| {
        let page = page_at(va, p);
        let object_page = first_page.wrapping_add(p);
        read_word(page, 0) == pattern(object_page, 0)
            && read_word(page, LAST_WORD) == pattern(object_page, LAST_WORD)
    })
}

/// Write [`WRITTEN`] to the first word of the page at `va`.
fn write_first(va: u64)
{
    // SAFETY: the caller attaches the page at `va` writable and private; no
    // Rust reference points into it.
    unsafe { std::ptr::write_volatile(va as *mut u64, WRITTEN) };
}

/// memmgr's reply to `msg` over `target`.
pub(super) fn call(target: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(target, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"))
}

/// The `ATTACH_OBJECT` request for `pages` pages at `va` from object page
/// `first_page` on, `handle` its cap (none for the zero object).
fn attach_msg(
    va: u64,
    pages: u64,
    prot: u64,
    first_page: u64,
    flags: u64,
    handle: Option<u64>,
) -> IpcMessage
{
    let b = IpcMessage::builder(memmgr_labels::ATTACH_OBJECT)
        .word(0, va)
        .word(1, page_at(0, pages))
        .word(2, prot)
        .word(3, first_page)
        .word(4, flags);
    match handle
    {
        Some(cap) => b.cap(cap).build(),
        None => b.build(),
    }
}

/// `ATTACH_OBJECT` over svctest's own memmgr cap, carrying a copy of
/// `handle` (memmgr deletes it); memmgr's reply label.
pub(super) fn attach(
    va: u64,
    pages: u64,
    prot: u64,
    first_page: u64,
    flags: u64,
    handle: Option<u64>,
) -> u64
{
    let copy = handle.map(handle_copy);
    let msg = attach_msg(va, pages, prot, first_page, flags, copy);
    call(startup_info().memmgr_endpoint, &msg, "ATTACH_OBJECT").label
}

/// A copy of the object handle `handle`, carrying its badge.
pub(super) fn handle_copy(handle: u64) -> u64
{
    syscall::cap_copy(handle, startup_info().self_cspace, syscall::RIGHTS_EP_SEND)
        .expect("memory_objects: copying the object handle")
}

/// A fresh reservation of `pages` pages.
pub(super) fn reserve(pages: u64) -> std::os::seraph::ReservedRange
{
    std::os::seraph::reserve_pages(pages).expect("memory_objects: reserving a range failed")
}

/// Unregister the attachment of `pages` pages at `range` and give back its
/// range.
fn detach(range: std::os::seraph::ReservedRange, pages: u64, what: &str)
{
    expect_region_reply(
        memmgr_labels::UNREGISTER_REGION,
        range.va_start(),
        page_at(0, pages),
        memmgr_errors::SUCCESS,
        what,
    );
    std::os::seraph::unreserve_pages(range);
}

/// The phase; see the module documentation.
fn memory_objects_phase(_: &Caps)
{
    let (handle, sealed) = seal();
    refusals(handle);
    let attached = attach_and_share(handle);
    release(handle, sealed, attached);
    zero_object();
    run_limited_child();
    std::os::seraph::log!("memmgr_memory_objects phase passed");
}

fn large_object_phase(_: &Caps)
{
    large_object();
    std::os::seraph::log!("memmgr_large_object phase passed");
}

/// Fill a two-page and a one-page grant with the pattern of object pages 0
/// to 2 and seal them. A seal naming a grant svctest still maps and holds a
/// cap to is refused whole and leaves both grants svctest's; once both are
/// unmapped the seal succeeds, carrying the caps back, replies the three
/// pages and an object handle, and leaves svctest's usage where it was: the
/// frames stay charged to the sealer. Returns the handle and the sealed
/// pages.
pub(super) fn seal() -> (u64, u64)
{
    let aspace = startup_info().self_aspace;
    let (first, first_id) = try_request_contiguous(2)
        .unwrap_or_else(|l| panic!("memory_objects: two-page grant status {l:#x}"));
    let (second, second_id) = try_request_contiguous(1)
        .unwrap_or_else(|l| panic!("memory_objects: one-page grant status {l:#x}"));
    let range = reserve(OBJECT_PAGES);
    let va = range.va_start();
    for (cap, at, pages) in [(first, va, 2), (second, page_at(va, 2), 1)]
    {
        // SAFETY: `range` is a fresh reservation owned here, VA no Rust
        // object occupies.
        unsafe {
            std::os::seraph::mem_map_funded(cap, aspace, at, 0, pages, MAP_READ | MAP_WRITABLE)
        }
        .expect("memory_objects: mapping a grant failed");
    }
    fill(va, 0, OBJECT_PAGES);
    // SAFETY: the page is the second grant's, mapped above; no reference
    // points into it.
    unsafe { syscall::mem_unmap(aspace, page_at(va, 2), 1) }
        .expect("memory_objects: unmapping the one-page grant failed");

    let seal_msg = |caps: &[u64]| {
        let mut b = IpcMessage::builder(memmgr_labels::SEAL_OBJECT)
            .word(0, 2)
            .word(1, first_id)
            .word(2, second_id);
        for &cap in caps
        {
            b = b.cap(cap);
        }
        b.build()
    };
    let memmgr = startup_info().memmgr_endpoint;
    let refused = call(memmgr, &seal_msg(&[]), "SEAL_OBJECT of a mapped grant").label;
    assert_eq!(
        refused,
        memmgr_errors::INVALID_ARGUMENT,
        "memory_objects: SEAL_OBJECT of a grant svctest maps replied {refused:#x}"
    );

    // SAFETY: as for the unmap above, for the first grant's two pages.
    unsafe { syscall::mem_unmap(aspace, va, 2) }
        .expect("memory_objects: unmapping the two-page grant failed");
    std::os::seraph::unreserve_pages(range);
    let before = own_usage();
    let reply = call(memmgr, &seal_msg(&[first, second]), "SEAL_OBJECT");
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "memory_objects: SEAL_OBJECT of two unmapped grants replied {:#x}",
        reply.label
    );
    assert_eq!(
        reply.word(0),
        OBJECT_PAGES,
        "memory_objects: SEAL_OBJECT replied {} pages",
        reply.word(0)
    );
    let handle = *reply
        .caps()
        .first()
        .expect("memory_objects: SEAL_OBJECT replied no handle");
    let after = own_usage();
    assert_eq!(
        after, before,
        "memory_objects: the seal moved svctest's usage from {before} to {after} pages"
    );
    (handle, OBJECT_PAGES)
}

/// The refusals of the labels' contracts: a writable executable attachment,
/// a writable shared one, one past the object's end, a zero-object one off
/// page 0 or executable ([`attach_refusals`]), `OBJECT_RELEASE` over a process badge,
/// `SEAL_OBJECT` and `ATTACH_OBJECT` over an object handle
/// ([`class_refusals`]), and a resize or a discard of an attachment
/// ([`resize_refusals`]).
fn refusals(handle: u64)
{
    let range = reserve(OBJECT_PAGES);
    let va = range.va_start();
    attach_refusals(handle, va);
    class_refusals(handle, va);
    resize_refusals(handle, va);
    std::os::seraph::unreserve_pages(range);
}

/// The `ATTACH_OBJECT` requests at `va` that memmgr refuses with
/// `INVALID_ARGUMENT` whatever svctest's state.
fn attach_refusals(handle: u64, va: u64)
{
    use memmgr_labels::ATTACH_PRIVATE;

    let invalid = memmgr_errors::INVALID_ARGUMENT;
    for (pages, prot, first_page, flags, object, what) in [
        (
            1,
            MAP_READ | MAP_WRITABLE | MAP_EXECUTABLE,
            0,
            ATTACH_PRIVATE,
            Some(handle),
            "a writable executable attachment",
        ),
        (
            1,
            MAP_READ | MAP_WRITABLE,
            0,
            0,
            Some(handle),
            "a writable shared attachment",
        ),
        (
            2,
            MAP_READ,
            2,
            ATTACH_PRIVATE,
            Some(handle),
            "an attachment past the object",
        ),
        (
            1,
            MAP_READ,
            1,
            0,
            None,
            "a zero-object attachment off page 0",
        ),
        (
            1,
            MAP_READ | MAP_EXECUTABLE,
            0,
            0,
            None,
            "an executable zero-object attachment",
        ),
    ]
    {
        let got = attach(va, pages, prot, first_page, flags, object);
        assert_eq!(got, invalid, "memory_objects: {what} replied {got:#x}");
    }
}

/// The labels memmgr refuses with `UNAUTHORIZED` for the badge's class:
/// `OBJECT_RELEASE` over svctest's own badge, and `SEAL_OBJECT` and
/// `ATTACH_OBJECT` at `va` over an object handle.
fn class_refusals(handle: u64, va: u64)
{
    let memmgr = startup_info().memmgr_endpoint;
    let unauthorized = memmgr_errors::UNAUTHORIZED;
    let got = call(
        memmgr,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE over svctest's badge",
    )
    .label;
    assert_eq!(
        got, unauthorized,
        "memory_objects: OBJECT_RELEASE over a process badge replied {got:#x}"
    );
    let seal = IpcMessage::builder(memmgr_labels::SEAL_OBJECT)
        .word(0, 1)
        .word(1, 0)
        .build();
    let got = call(handle, &seal, "SEAL_OBJECT over the handle").label;
    assert_eq!(
        got, unauthorized,
        "memory_objects: SEAL_OBJECT over an object handle replied {got:#x}"
    );
    let got = call(
        handle,
        &attach_msg(va, 1, MAP_READ, 0, 0, None),
        "ATTACH_OBJECT over the handle",
    )
    .label;
    assert_eq!(
        got, unauthorized,
        "memory_objects: ATTACH_OBJECT over an object handle replied {got:#x}"
    );
}

/// A private attachment at `va` that memmgr admits, then refuses to extend,
/// shrink or discard, since its pages are its object's, and unregisters.
fn resize_refusals(handle: u64, va: u64)
{
    use memmgr_labels::{ATTACH_PRIVATE, DISCARD_RANGE, EXTEND_REGION, SHRINK_REGION};

    let invalid = memmgr_errors::INVALID_ARGUMENT;
    let got = attach(va, OBJECT_PAGES, MAP_READ, 0, ATTACH_PRIVATE, Some(handle));
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: a private attachment replied {got:#x}"
    );
    for (label, at_len, what) in [
        (
            EXTEND_REGION,
            page_at(0, 2 * OBJECT_PAGES),
            "EXTEND_REGION of an attachment",
        ),
        (SHRINK_REGION, 0, "SHRINK_REGION of an attachment"),
        (DISCARD_RANGE, PAGE_SIZE, "DISCARD_RANGE of an attachment"),
    ]
    {
        expect_region_reply(label, va, at_len, invalid, what);
    }
    expect_region_reply(
        memmgr_labels::UNREGISTER_REGION,
        va,
        page_at(0, OBJECT_PAGES),
        memmgr_errors::SUCCESS,
        "UNREGISTER_REGION of an attachment",
    );
}

/// What the attachments of [`attach_and_share`] that [`release`] detaches
/// hold: the ranges and what each charged svctest.
struct Attached
{
    shared: std::os::seraph::ReservedRange,
    private: std::os::seraph::ReservedRange,
    charged: u64,
}

/// svctest attaches the whole object shared and pages 1 and 2 private, each
/// charged to it as a committed region of its length, the shared one no
/// less than the private one; both read the pattern. A private write is seen
/// in the private attachment only. A `memory-object-child` then attaches the
/// object both ways, reads the pattern in each, so svctest's write reached
/// none of its pages, and writes its private one, and svctest's attachments
/// still read the pattern; a writer child's write to its shared attachment
/// kills it, and svctest's shared attachment reads the pattern after it.
fn attach_and_share(handle: u64) -> Attached
{
    use memmgr_labels::ATTACH_PRIVATE;

    let shared = reserve(OBJECT_PAGES);
    let private = reserve(2);
    let (sva, pva) = (shared.va_start(), private.va_start());
    let own0 = own_usage();
    let got = attach(sva, OBJECT_PAGES, MAP_READ, 0, 0, Some(handle));
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: the shared attachment replied {got:#x}"
    );
    let own1 = own_usage();
    let got = attach(
        pva,
        2,
        MAP_READ | MAP_WRITABLE,
        1,
        ATTACH_PRIVATE,
        Some(handle),
    );
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: the private attachment replied {got:#x}"
    );
    let own2 = own_usage();
    let (shared_charge, private_charge) = (own1.saturating_sub(own0), own2.saturating_sub(own1));
    assert!(
        shared_charge >= OBJECT_PAGES && private_charge >= 2 && shared_charge >= private_charge,
        "memory_objects: the shared attachment of {OBJECT_PAGES} pages charged          {shared_charge} pages and the private one of 2 pages {private_charge}"
    );
    assert!(
        holds_pattern(sva, 0, OBJECT_PAGES) && holds_pattern(pva, 1, 2),
        "memory_objects: an attachment read other than the object"
    );

    write_first(pva);
    assert_eq!(
        read_word(pva, 0),
        WRITTEN,
        "memory_objects: a private write did not read back"
    );
    assert!(
        holds_pattern(page_at(pva, 1), 2, 1) && read_word(pva, 1) == pattern(1, 1),
        "memory_objects: the private copy lost the object's other words or pages"
    );
    assert!(
        holds_pattern(sva, 0, OBJECT_PAGES),
        "memory_objects: svctest's private write reached its shared attachment"
    );

    let status = run_child(handle, None);
    assert!(
        status.success(),
        "memory_objects: memory-object-child exited {status} (2 = fetch, 3 = shared refused, \
         4 = shared corrupt, 5 = private refused, 6 = private corrupt, 7 = not charged)"
    );
    assert!(
        holds_pattern(sva, 0, OBJECT_PAGES) && holds_pattern(page_at(pva, 1), 2, 1),
        "memory_objects: the child's private write reached svctest's attachments"
    );

    let status = run_child(handle, Some(WRITER_ARG));
    let code = status.code().and_then(|c| u64::try_from(c).ok());
    assert!(
        code.is_some_and(|c| (syscall::EXIT_FAULT_BASE..syscall::EXIT_KILLED).contains(&c)),
        "memory_objects: the shared-attachment writer exited {status}, not by a fault \
         (8 = its write completed)"
    );
    assert!(
        holds_pattern(sva, 0, OBJECT_PAGES),
        "memory_objects: a write to a shared attachment reached the object"
    );
    Attached {
        shared,
        private,
        charged: shared_charge.saturating_add(private_charge),
    }
}

/// Release the object over its handle. A second release, over a copy, and
/// an attachment through a copy are refused, since the handle state is gone,
/// while svctest's shared attachment still reads the object. Detaching
/// svctest's two attachments, the object's last, frees the object, so
/// svctest's usage falls by their charge and the sealed pages.
fn release(handle: u64, sealed: u64, attached: Attached)
{
    let copy = handle_copy(handle);
    let got = call(
        handle,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE",
    )
    .label;
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: OBJECT_RELEASE replied {got:#x}"
    );
    let got = call(
        copy,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE again",
    )
    .label;
    assert_eq!(
        got,
        memmgr_errors::INVALID_ARGUMENT,
        "memory_objects: a second OBJECT_RELEASE replied {got:#x}"
    );
    let range = reserve(1);
    let got = attach(range.va_start(), 1, MAP_READ, 0, 0, Some(copy));
    std::os::seraph::unreserve_pages(range);
    assert_eq!(
        got,
        memmgr_errors::INVALID_ARGUMENT,
        "memory_objects: an attachment of a released object replied {got:#x}"
    );
    let _ = syscall::cap_delete(copy);
    let _ = syscall::cap_delete(handle);
    assert!(
        holds_pattern(attached.shared.va_start(), 0, OBJECT_PAGES),
        "memory_objects: a released object's attachment read other than the object"
    );

    let before = own_usage();
    let want = before
        .saturating_sub(attached.charged)
        .saturating_sub(sealed);
    detach(
        attached.shared,
        OBJECT_PAGES,
        "UNREGISTER_REGION of the shared attachment",
    );
    detach(
        attached.private,
        2,
        "UNREGISTER_REGION of the private attachment",
    );
    let start = Instant::now();
    loop
    {
        recheck_deferred();
        let own = own_usage();
        if own <= want
        {
            break;
        }
        assert!(
            start.elapsed() < RELEASE_TIMEOUT,
            "memory_objects: svctest's usage is {own} pages {RELEASE_TIMEOUT:?} after its last \
             attachment went, from {before}; the object's frames and the attachments' charge \
             should have left {want}"
        );
        std::thread::yield_now();
    }
}

/// Run a `memory-object-child` with `arg` as its argv[2], if any, serving it a copy
/// of `handle`, and return its exit status.
fn run_child(handle: u64, arg: Option<&str>) -> std::process::ExitStatus
{
    use std::os::seraph::process::CommandExt;

    let ep = std::os::seraph::create_endpoint()
        .expect("memory_objects: server endpoint creation failed");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND).expect("memory_objects: root SEND");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, STOP_BADGE)
        .expect("memory_objects: stop SEND");
    let copy = handle_copy(handle);
    let server = std::thread::Builder::new()
        .name("memory_objects_server".into())
        .spawn(move || serve_handle(ep, copy))
        .expect("memory_objects: server thread spawn failed");
    let mut cmd = std::process::Command::new("/tests/svctest");
    cmd.arg(OBJECT_CHILD_ROLE).namespace_cap(root);
    if let Some(arg) = arg
    {
        cmd.arg(arg);
    }
    let status = cmd
        .status()
        .expect("memory_objects: running memory-object-child failed");
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(stop, &IpcMessage::new(0), current_ipc_buf()) };
    server
        .join()
        .expect("memory_objects: server thread panicked");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);
    status
}

/// Serve `ep` for one `memory-object-child` until the stop badge arrives,
/// which the spawner sends once the child has exited: answer the first fetch
/// with `handle`, and refuse any other call, deleting its caps. `handle` is
/// deleted when no fetch took it.
pub(super) fn serve_handle(ep: u64, handle: u64)
{
    let ipc_buf = current_ipc_buf();
    let mut held = Some(handle);
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("memory_objects server: ipc_recv");
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let stop = msg.badge == STOP_BADGE;
        let reply = match held
        {
            Some(cap) if !stop && msg.label == FETCH_LABEL =>
            {
                held = None;
                IpcMessage::builder(0).cap(cap).build()
            }
            _ if stop => IpcMessage::new(0),
            _ => IpcMessage::new(u64::MAX),
        };
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if stop
        {
            if let Some(cap) = held
            {
                let _ = syscall::cap_delete(cap);
            }
            return;
        }
    }
}

/// A `memory-object-child`: fetch the object handle from the spawner (whose
/// endpoint arrives as this process's namespace cap), attach the object
/// shared and read the pattern, then, as the writer, write the shared
/// attachment, which kills it; otherwise attach it private, read the pattern
/// and write and read back each page. Each attachment must charge the child
/// at least its pages. Exit codes as the `CHILD_` constants say.
fn object_child_main() -> !
{
    use memmgr_labels::ATTACH_PRIVATE;
    use std::process::exit;

    let writer = std::env::args().nth(2).as_deref() == Some(WRITER_ARG);
    let fetch = IpcMessage::new(FETCH_LABEL);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let fetched =
        unsafe { ipc::ipc_call(std::os::seraph::root_dir_cap(), &fetch, current_ipc_buf()) };
    let Some(&[handle]) = fetched.as_ref().ok().map(IpcMessage::caps)
    else
    {
        exit(CHILD_FETCH_FAILED)
    };
    let memmgr = startup_info().memmgr_endpoint;
    let attach_child = |va: u64, prot: u64, flags: u64| {
        let copy =
            syscall::cap_copy(handle, startup_info().self_cspace, syscall::RIGHTS_EP_SEND).ok()?;
        let msg = attach_msg(va, OBJECT_PAGES, prot, 0, flags, Some(copy));
        // SAFETY: as above.
        let reply = unsafe { ipc::ipc_call(memmgr, &msg, current_ipc_buf()) }.ok()?;
        (reply.label == memmgr_errors::SUCCESS).then_some(())
    };
    let usage = || crate::phases::budget::memory_usage().map_or(0, |u| u.0);

    let shared =
        std::os::seraph::reserve_pages(OBJECT_PAGES).unwrap_or_else(|_| exit(CHILD_SHARED_REFUSED));
    let sva = shared.va_start();
    let own0 = usage();
    if attach_child(sva, MAP_READ, 0).is_none()
    {
        exit(CHILD_SHARED_REFUSED);
    }
    if usage() < own0.saturating_add(OBJECT_PAGES)
    {
        exit(CHILD_NOT_CHARGED);
    }
    if !holds_pattern(sva, 0, OBJECT_PAGES)
    {
        exit(CHILD_SHARED_CORRUPT);
    }
    if writer
    {
        // SAFETY: the page is the shared attachment's first; no reference
        // points into it. The write faults, and memmgr declines the fault.
        unsafe { std::ptr::write_volatile(sva as *mut u64, WRITTEN) };
        exit(CHILD_SHARED_WRITTEN);
    }

    let private = std::os::seraph::reserve_pages(OBJECT_PAGES)
        .unwrap_or_else(|_| exit(CHILD_PRIVATE_REFUSED));
    let pva = private.va_start();
    let own1 = usage();
    if attach_child(pva, MAP_READ | MAP_WRITABLE, ATTACH_PRIVATE).is_none()
    {
        exit(CHILD_PRIVATE_REFUSED);
    }
    if usage() < own1.saturating_add(OBJECT_PAGES)
    {
        exit(CHILD_NOT_CHARGED);
    }
    if !holds_pattern(pva, 0, OBJECT_PAGES)
    {
        exit(CHILD_PRIVATE_CORRUPT);
    }
    for p in 0..OBJECT_PAGES
    {
        write_first(page_at(pva, p));
    }
    let written = (0..OBJECT_PAGES).all(|p| {
        let page = page_at(pva, p);
        read_word(page, 0) == WRITTEN && read_word(page, 1) == pattern(p, 1)
    });
    if !written || !holds_pattern(sva, 0, OBJECT_PAGES)
    {
        exit(CHILD_PRIVATE_CORRUPT);
    }
    exit(0)
}

/// memmgr's free total and overcommit allowance (`QUERY_POOL_STATUS`
/// `data[3]` and `data[15]`), in pages: no commitment of more pages than
/// their sum can be admitted, since `promised` may exceed the free total by
/// the allowance alone.
fn free_and_allowance() -> (u64, u64)
{
    let reply = call(
        startup_info().memmgr_endpoint,
        &IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS),
        "QUERY_POOL_STATUS",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "memory_objects: QUERY_POOL_STATUS replied {:#x}",
        reply.label
    );
    (reply.word(3) / PAGE_SIZE, reply.word(15) / PAGE_SIZE)
}

/// The `memory-object-limited` child: a private and a shared zero-object
/// attachment of [`PAST_MAX_PAGES`], past its max, are each refused with
/// `LIMIT`, since both charge the attacher their pages. Exit codes as the
/// `LIMITED_` constants say.
fn limited_child_main() -> !
{
    use memmgr_labels::ATTACH_PRIVATE;
    use std::process::exit;

    let range = std::os::seraph::reserve_pages(PAST_MAX_PAGES)
        .unwrap_or_else(|_| exit(LIMITED_RESERVE_FAILED));
    let memmgr = startup_info().memmgr_endpoint;
    let refused = |prot: u64, flags: u64| {
        let msg = attach_msg(range.va_start(), PAST_MAX_PAGES, prot, 0, flags, None);
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
        unsafe { ipc::ipc_call(memmgr, &msg, current_ipc_buf()) }
            .is_ok_and(|r| r.label == memmgr_errors::LIMIT)
    };
    if !refused(MAP_READ | MAP_WRITABLE, ATTACH_PRIVATE)
    {
        exit(LIMITED_PRIVATE_ADMITTED);
    }
    if !refused(MAP_READ, 0)
    {
        exit(LIMITED_SHARED_ADMITTED);
    }
    exit(0)
}

/// Run the `memory-object-limited` child to its exit and check its exit code.
fn run_limited_child()
{
    use crate::phases::budget;

    let what = "the memory-object limited child";
    let (handle, thread) = budget::create_with_max(LIMITED_ROLE, LIMITED_MAX_PAGES, what);
    let reason = budget::run_to_exit(handle, what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
    assert_eq!(
        reason, 0,
        "{what} exit reason {reason:#x}: {LIMITED_RESERVE_FAILED}=its reservation failed, \
         {LIMITED_PRIVATE_ADMITTED}=a private attachment past its max was not refused, \
         {LIMITED_SHARED_ADMITTED}=a shared one was not, a fault reason=it was killed"
    );
}

/// The zero object. A private attachment of [`ZERO_PAGES`] pages reads zero
/// at every page while memmgr's free and promised totals fall by less than
/// half its pages, its reads taking no page but page tables; writes to its
/// first half read back and lower the promised total by at least a quarter
/// of its pages, and its second half, whose zero-frame leaves were mapped
/// before those writes, still reads zero. A private attachment of more pages
/// than memmgr holds free and may overcommit is refused with `OUT_OF_MEMORY_BEST_EFFORT`, since
/// memmgr could not back its writes, while a shared one of as many is
/// admitted, since it takes no page, and reads zero. Past a max, both are
/// refused ([`run_limited_child`]).
fn zero_object()
{
    use memmgr_labels::ATTACH_PRIVATE;

    let range = reserve(ZERO_PAGES);
    let va = range.va_start();
    let got = attach(
        va,
        ZERO_PAGES,
        MAP_READ | MAP_WRITABLE,
        0,
        ATTACH_PRIVATE,
        None,
    );
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: a private zero-object attachment replied {got:#x}"
    );
    let totals = || pool_totals().expect("memory_objects: QUERY_POOL_STATUS failed");
    let (free0, promised0, _) = totals();
    let zeros = |from: u64, to: u64| {
        (from..to)
            .all(|p| read_word(page_at(va, p), 0) == 0 && read_word(page_at(va, p), LAST_WORD) == 0)
    };
    assert!(
        zeros(0, ZERO_PAGES),
        "memory_objects: the zero object read other than zero"
    );
    let (free1, promised1, _) = totals();
    assert!(
        free0.saturating_sub(free1) < ZERO_HALF && promised0.saturating_sub(promised1) < ZERO_HALF,
        "memory_objects: reading {ZERO_PAGES} zero-object pages took free {free0} -> {free1} \
         and promised {promised0} -> {promised1}"
    );
    for p in 0..ZERO_HALF
    {
        write_first(page_at(va, p));
    }
    assert!(
        (0..ZERO_HALF)
            .all(|p| read_word(page_at(va, p), 0) == WRITTEN && read_word(page_at(va, p), 1) == 0),
        "memory_objects: a write to the zero object did not read back over zeros"
    );
    let (_, promised2, _) = totals();
    assert!(
        promised1.saturating_sub(promised2) >= ZERO_QUARTER,
        "memory_objects: writing {ZERO_HALF} zero-object pages took promised {promised1} -> \
         {promised2}"
    );
    assert!(
        zeros(ZERO_HALF, ZERO_PAGES),
        "memory_objects: a write to the zero object reached the zero frame"
    );
    detach(
        range,
        ZERO_PAGES,
        "UNREGISTER_REGION of the zero-object attachment",
    );

    let (free, allowance) = free_and_allowance();
    let pages = free.saturating_add(allowance).saturating_add(CHUNK_PAGES);
    let range = reserve(pages);
    let got = attach(
        range.va_start(),
        pages,
        MAP_READ | MAP_WRITABLE,
        0,
        ATTACH_PRIVATE,
        None,
    );
    assert_eq!(
        got,
        memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT,
        "memory_objects: a private zero-object attachment of {pages} pages, past the {free} \
         free and the {allowance} overcommit allowance, replied {got:#x}"
    );
    let got = attach(range.va_start(), pages, MAP_READ, 0, 0, None);
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: a shared zero-object attachment of {pages} pages, past the {free} \
         free and the {allowance} overcommit allowance, replied {got:#x}"
    );
    let last = page_at(range.va_start(), pages.saturating_sub(1));
    assert_eq!(
        read_word(last, 0),
        0,
        "memory_objects: a large shared zero-object attachment read other than zero"
    );
    detach(
        range,
        pages,
        "UNREGISTER_REGION of the large zero-object attachment",
    );
}

/// Write the pattern of object pages `0..pages` at `va` in the first and the
/// last word of each page, the words [`holds_pattern`] reads.
fn mark(va: u64, pages: u64)
{
    for p in 0..pages
    {
        for w in [0, LAST_WORD]
        {
            let at = page_at(va, p).wrapping_add(w.wrapping_mul(8));
            // SAFETY: the caller maps `pages` writable pages at `va`, which no
            // Rust reference points into.
            unsafe { std::ptr::write_volatile(at as *mut u64, pattern(p, w)) };
        }
    }
}

/// Request one contiguous grant of `pages` pages: `(grant cap, region id)`.
/// A refusal panics with memmgr's error label and the pool's free total,
/// free-run count and largest free run the reply carries, in pages.
fn request_large(pages: u32) -> (u64, u64)
{
    let want = u64::from(pages) | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, want)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &req, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("memory_objects: REQUEST_MEMORY_CAPS ipc_call failed: {e:?}"));
    assert!(
        reply.label == memmgr_errors::SUCCESS,
        "memory_objects: {pages}-page grant status {:#x} (free {}, runs {}, largest run {})",
        reply.label,
        reply.word(0),
        reply.word(1),
        reply.word(2),
    );
    let grant = *reply
        .caps()
        .first()
        .expect("memory_objects: REQUEST_MEMORY_CAPS returned no cap");
    // One cap: data[1] is its page count, data[2] its region id.
    (grant, reply.word(2))
}

/// Seal one contiguous grant of [`LARGE_PAGES`], marked with the pattern,
/// into an object: memmgr takes a span of its object zone 64 leaf tables long
/// for its own view of the grant, most of them new this early in the run,
/// and maps the view one leaf-table window at a time, funding each window's
/// page tables. Every page
/// of the object then reads back through `OBJECT_READ`, which copies from
/// that view ([`read_back`]), and once the object is released its frames
/// leave svctest's charge.
fn large_object()
{
    let pages = u64::from(LARGE_PAGES);
    let (grant, id) = request_large(LARGE_PAGES);
    let aspace = startup_info().self_aspace;
    let range = reserve(pages);
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation owned here, VA no Rust object
    // occupies.
    unsafe {
        std::os::seraph::mem_map_funded(grant, aspace, va, 0, pages, MAP_READ | MAP_WRITABLE)
    }
    .expect("memory_objects: mapping the large grant failed");
    mark(va, pages);
    // SAFETY: the grant's pages, mapped above; no reference points into them.
    unsafe { syscall::mem_unmap(aspace, va, pages) }
        .expect("memory_objects: unmapping the large grant failed");
    std::os::seraph::unreserve_pages(range);

    let before = own_usage();
    let seal = IpcMessage::builder(memmgr_labels::SEAL_OBJECT)
        .word(0, 1)
        .word(1, id)
        .cap(grant)
        .build();
    let reply = call(
        startup_info().memmgr_endpoint,
        &seal,
        "SEAL_OBJECT of the large grant",
    );
    assert_eq!(
        (reply.label, reply.word(0)),
        (memmgr_errors::SUCCESS, pages),
        "memory_objects: SEAL_OBJECT of a {pages}-page grant replied {:#x}, {} pages",
        reply.label,
        reply.word(0)
    );
    let handle = *reply
        .caps()
        .first()
        .expect("memory_objects: SEAL_OBJECT of the large grant replied no handle");
    read_back(handle, pages);

    let got = call(
        handle,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE of the large object",
    )
    .label;
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_objects: OBJECT_RELEASE of the large object replied {got:#x}"
    );
    let _ = syscall::cap_delete(handle);
    let want = before.saturating_sub(pages);
    let start = Instant::now();
    loop
    {
        recheck_deferred();
        let own = own_usage();
        if own <= want
        {
            break;
        }
        assert!(
            start.elapsed() < RELEASE_TIMEOUT,
            "memory_objects: svctest's usage is {own} pages {RELEASE_TIMEOUT:?} after the large \
             object's release, from {before}; its frames should have left {want}"
        );
        std::thread::yield_now();
    }
}

/// Read each of the `pages` pages of the object `handle` names through
/// `OBJECT_READ`, `OBJECT_READ_PAGES` at a time, into a grant svctest maps,
/// and check that each holds the pattern [`mark`] wrote.
fn read_back(handle: u64, pages: u64)
{
    let step = memmgr_labels::OBJECT_READ_PAGES;
    let step_u32 = u32::try_from(step).expect("memory_objects: OBJECT_READ_PAGES fits a u32");
    let (dst, id) = try_request_contiguous(step_u32)
        .unwrap_or_else(|l| panic!("memory_objects: {step}-page grant status {l:#x}"));
    let aspace = startup_info().self_aspace;
    let range = reserve(step);
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation owned here, VA no Rust object
    // occupies.
    unsafe { std::os::seraph::mem_map_funded(dst, aspace, va, 0, step, MAP_READ) }
        .expect("memory_objects: mapping the read-back grant failed");
    let stride = usize::try_from(step).expect("memory_objects: OBJECT_READ_PAGES fits a usize");
    for first in (0..pages).step_by(stride)
    {
        let copy = syscall::cap_derive(dst, syscall::RIGHTS_MEM_MAP_RW)
            .expect("memory_objects: copying the read-back grant");
        let msg = IpcMessage::builder(memmgr_labels::OBJECT_READ)
            .word(0, first)
            .word(1, 0)
            .word(2, step)
            .cap(handle_copy(handle))
            .cap(copy)
            .build();
        let reply = call(
            startup_info().memmgr_endpoint,
            &msg,
            "OBJECT_READ of the large object",
        );
        assert_eq!(
            (reply.label, reply.word(0)),
            (memmgr_errors::SUCCESS, step),
            "memory_objects: OBJECT_READ of large-object pages from {first} replied {:#x}, {} \
             pages copied",
            reply.label,
            reply.word(0)
        );
        // `OBJECT_READ` wrote page `p` of the grant from object page
        // `first + p`.
        let wrong = (0..step).find(|&p| {
            let page = page_at(va, p);
            let object_page = first.wrapping_add(p);
            read_word(page, 0) != pattern(object_page, 0)
                || read_word(page, LAST_WORD) != pattern(object_page, LAST_WORD)
        });
        assert!(
            wrong.is_none(),
            "memory_objects: large-object page {} read back other than the pattern",
            first.wrapping_add(wrong.unwrap_or(0))
        );
    }
    // SAFETY: the grant's pages, mapped above; no reference points into them.
    unsafe { syscall::mem_unmap(aspace, va, step) }
        .expect("memory_objects: unmapping the read-back grant failed");
    std::os::seraph::unreserve_pages(range);
    release_grant(dst, id);
}
