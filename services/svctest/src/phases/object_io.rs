// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/object_io.rs

//! The memory-object labels a checkpoint and its restore use
//! (`memmgr_labels::OBJECT_READ`, `FILL_REGION` and `MARK_CHECKPOINT`;
//! services/memmgr/docs/ipc-interface.md § Labels 35 to 37).
//!
//! The phase seals the three-page pattern object of `memmgr_memory_objects`
//! ([`seal`]) and requires:
//!
//! - `OBJECT_READ` on svctest's own memmgr cap with the handle alone replies
//!   the object's pages and no checkpoint mark; with the handle and a
//!   two-page grant it copies object pages 1 and 2 into it; it is refused
//!   `INVALID_ARGUMENT` from a page past the object's end, with a grant and
//!   no page count for it, without a handle, and with a SEND on an endpoint
//!   of svctest's own in the handle's place, which memmgr cannot read; and
//!   `UNAUTHORIZED` sent on the object handle itself ([`object_read`]);
//! - `FILL_REGION` into a two-chunk demand region of svctest's backs the
//!   pages the masks name, three, with object pages 0 to 2 in mask order,
//!   grows svctest's usage by at least those pages, and leaves a page no mask
//!   names zero; a repeat backs nothing; it is refused `INVALID_ARGUMENT`
//!   without a handle, with no chunk, with chunks out of order, a base off a chunk, masks
//!   past the object's end or a chunk of an attachment of the object, and
//!   `UNAUTHORIZED` over the object handle, each refusal backing nothing
//!   ([`fill_region`]);
//! - `MARK_CHECKPOINT` from svctest is refused `UNAUTHORIZED` and leaves the
//!   object unmarked ([`mark_refused`]).
//!
//! The `procmgr_checkpoint` phase requires the mark on a checkpoint's object,
//! and `procmgr_snapshot` none on a `SNAPSHOT`'s ([`object_flags`]).

use std::os::seraph::{ReservedRange, startup_info, unreserve_pages};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::{MAP_READ, MAP_WRITABLE, PAGE_SIZE};

use crate::bootstrap::Caps;
use crate::phases::heap_commit::{CHUNK_PAGES, expect_region_reply, memmgr_label, own_usage};
use crate::phases::memmgr::{release_grant, try_request_contiguous};
use crate::phases::memory_objects::{
    LAST_WORD, OBJECT_PAGES, attach, call, handle_copy, pattern, reserve, seal,
};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_object_io",
        run: object_io_phase,
    }]
}

const PHASE: &str = "memmgr_object_io";

/// Bytes of a demand chunk.
const CHUNK_BYTES: u64 = CHUNK_PAGES * PAGE_SIZE;

/// The phase; see the module documentation.
fn object_io_phase(_: &Caps)
{
    let (handle, _) = seal();
    object_read(handle);
    fill_region(handle);
    mark_refused(handle);
    let released = call(
        handle,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE",
    )
    .label;
    assert_eq!(
        released,
        memmgr_errors::SUCCESS,
        "{PHASE}: OBJECT_RELEASE replied {released:#x}"
    );
    syscall::cap_delete(handle).expect("object_io: deleting the object handle");
    std::os::seraph::log!("memmgr_object_io phase passed");
}

/// The `OBJECT_READ` flags and pages of the object `handle` names, read
/// with the handle alone; panics, naming `phase`, on any reply but
/// `SUCCESS` or one that reports a page copied.
pub(super) fn object_flags(handle: u64, phase: &str) -> (u64, u64)
{
    let reply = call(
        startup_info().memmgr_endpoint,
        &IpcMessage::builder(memmgr_labels::OBJECT_READ)
            .cap(handle_copy(handle))
            .build(),
        "OBJECT_READ",
    );
    assert_eq!(
        (reply.label, reply.word(0)),
        (memmgr_errors::SUCCESS, 0),
        "{phase}: OBJECT_READ with the handle alone replied {:#x}, {} pages copied",
        reply.label,
        reply.word(0)
    );
    (reply.word(1), reply.word(2))
}

/// A copy of the Memory cap `cap` with the map and write rights.
fn memory_copy(cap: u64) -> u64
{
    syscall::cap_derive(cap, syscall::RIGHTS_MEM_MAP_RW).expect("object_io: copying a grant")
}

/// Word `word` of the page at `va`.
fn read_word(va: u64, word: u64) -> u64
{
    // SAFETY: the caller maps the page at `va` readable, or registered it in
    // a demand region whose fault memmgr serves; no Rust reference points
    // into it.
    unsafe { std::ptr::read_volatile(va.wrapping_add(word.wrapping_mul(8)) as *const u64) }
}

/// Whether the page at `va` holds the pattern of object page `page` in its
/// first and last words.
fn holds(va: u64, page: u64) -> bool
{
    read_word(va, 0) == pattern(page, 0) && read_word(va, LAST_WORD) == pattern(page, LAST_WORD)
}

/// An endpoint of svctest's own, whose SEND stands in for an object handle
/// a forger hands over: a cap memmgr cannot read the badge of. The endpoint
/// is deleted on drop.
pub(super) struct Foreign(u64);

impl Foreign
{
    /// A new endpoint; panics, naming `phase`, when none can be made.
    pub(super) fn new(phase: &str) -> Self
    {
        let endpoint =
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })
            .unwrap_or_else(|| panic!("{phase}: an endpoint of svctest's own"));
        Self(endpoint)
    }

    /// A SEND on the endpoint, for the receiver to delete.
    pub(super) fn send(&self) -> u64
    {
        syscall::cap_derive(self.0, syscall::RIGHTS_EP_SEND).expect("object_io: a SEND copy")
    }
}

impl Drop for Foreign
{
    fn drop(&mut self)
    {
        let _ = syscall::cap_delete(self.0);
    }
}

/// `OBJECT_READ` sent on `target` with the words `words` and the caps
/// `caps`, which memmgr deletes: the reply's label and its first three
/// words.
fn read_on(target: u64, words: &[u64], caps: &[u64]) -> (u64, u64, u64, u64)
{
    let mut b = IpcMessage::builder(memmgr_labels::OBJECT_READ).words(0, words);
    for &cap in caps
    {
        b = b.cap(cap);
    }
    let reply = call(target, &b.build(), "OBJECT_READ");
    (reply.label, reply.word(0), reply.word(1), reply.word(2))
}

/// `OBJECT_READ` on svctest's own memmgr cap with the words `words`, a copy
/// of `handle` and, when given, the destination cap `cap`.
fn read(handle: u64, words: &[u64], cap: Option<u64>) -> (u64, u64, u64, u64)
{
    let own = startup_info().memmgr_endpoint;
    match cap
    {
        Some(cap) => read_on(own, words, &[handle_copy(handle), cap]),
        None => read_on(own, words, &[handle_copy(handle)]),
    }
}

/// `OBJECT_READ`'s reply and copy, and its refusals.
fn object_read(handle: u64)
{
    assert_eq!(
        object_flags(handle, PHASE),
        (0, OBJECT_PAGES),
        "{PHASE}: OBJECT_READ of a sealed object"
    );
    let past = read(handle, &[OBJECT_PAGES.saturating_add(1)], None);
    assert_eq!(
        past.0,
        memmgr_errors::INVALID_ARGUMENT,
        "{PHASE}: OBJECT_READ from a page past the object's end"
    );
    let own = startup_info().memmgr_endpoint;
    let unnamed = read_on(own, &[], &[]);
    assert_eq!(
        unnamed.0,
        memmgr_errors::INVALID_ARGUMENT,
        "{PHASE}: OBJECT_READ without a handle"
    );
    let foreign = Foreign::new(PHASE);
    let forged = read_on(own, &[], &[foreign.send()]);
    assert_eq!(
        forged.0,
        memmgr_errors::INVALID_ARGUMENT,
        "{PHASE}: OBJECT_READ with a SEND on svctest's own endpoint as the handle"
    );
    let unauthorized = read_on(handle, &[], &[]);
    assert_eq!(
        unauthorized.0,
        memmgr_errors::UNAUTHORIZED,
        "{PHASE}: OBJECT_READ sent on the object handle"
    );

    let (grant, id) = try_request_contiguous(2)
        .unwrap_or_else(|l| panic!("{PHASE}: two-page grant status {l:#x}"));
    let uncounted = read(handle, &[1, 0], Some(memory_copy(grant)));
    assert_eq!(
        uncounted.0,
        memmgr_errors::INVALID_ARGUMENT,
        "{PHASE}: OBJECT_READ with a cap and no page count for it"
    );
    let copied = read(handle, &[1, 0, 2], Some(memory_copy(grant)));
    assert_eq!(
        copied,
        (memmgr_errors::SUCCESS, 2, 0, OBJECT_PAGES),
        "{PHASE}: OBJECT_READ of object pages 1 and 2 into a two-page grant"
    );
    let range = reserve(2);
    let va = range.va_start();
    let aspace = startup_info().self_aspace;
    // SAFETY: `range` is a fresh reservation owned here, VA no Rust object
    // occupies.
    unsafe { std::os::seraph::mem_map_funded(grant, aspace, va, 0, 2, MAP_READ | MAP_WRITABLE) }
        .expect("object_io: mapping the grant failed");
    assert!(
        holds(va, 1) && holds(va.wrapping_add(PAGE_SIZE), 2),
        "{PHASE}: the grant OBJECT_READ wrote does not hold object pages 1 and 2"
    );
    // SAFETY: the two pages mapped above; no reference points into them.
    unsafe { syscall::mem_unmap(aspace, va, 2) }.expect("object_io: unmapping the grant failed");
    unreserve_pages(range);
    release_grant(grant, id);
}

/// `FILL_REGION` over `target` from object page `first` over the chunks
/// `chunks`, each its base and its mask, carrying `cap` when given: the
/// reply's label and its first word.
fn fill_on(target: u64, first: u64, chunks: &[(u64, u64)], cap: Option<u64>) -> (u64, u64)
{
    let mut b = IpcMessage::builder(memmgr_labels::FILL_REGION)
        .word(0, first)
        .word(1, chunks.len() as u64);
    for (i, &(va, mask)) in chunks.iter().enumerate()
    {
        b = b
            .word(2usize.saturating_add(i.saturating_mul(2)), va)
            .word(3usize.saturating_add(i.saturating_mul(2)), mask);
    }
    let msg = match cap
    {
        Some(cap) => b.cap(cap).build(),
        None => b.build(),
    };
    let reply = call(target, &msg, "FILL_REGION");
    (reply.label, reply.word(0))
}

/// `FILL_REGION` over svctest's own memmgr cap with a copy of `handle`.
fn fill(first: u64, chunks: &[(u64, u64)], handle: u64) -> (u64, u64)
{
    fill_on(
        startup_info().memmgr_endpoint,
        first,
        chunks,
        Some(handle_copy(handle)),
    )
}

/// A fresh demand region of `pages` pages, writable, registered with
/// memmgr.
fn demand_region(pages: u64) -> ReservedRange
{
    let range = reserve(pages);
    let register = IpcMessage::builder(memmgr_labels::REGISTER_REGION)
        .word(0, range.va_start())
        .word(1, pages.saturating_mul(PAGE_SIZE))
        .word(2, MAP_WRITABLE)
        .word(3, 0)
        .build();
    let got = memmgr_label(&register, "REGISTER_REGION");
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "{PHASE}: REGISTER_REGION replied {got:#x}"
    );
    range
}

/// Unregister the region of `pages` pages at `range` and give back its range.
fn unregister(range: ReservedRange, pages: u64, what: &str)
{
    expect_region_reply(
        memmgr_labels::UNREGISTER_REGION,
        range.va_start(),
        pages.saturating_mul(PAGE_SIZE),
        memmgr_errors::SUCCESS,
        what,
    );
    unreserve_pages(range);
}

/// `FILL_REGION`'s backing, its repeat and its refusals.
fn fill_region(handle: u64)
{
    let pages = 2 * CHUNK_PAGES;
    let range = demand_region(pages);
    let va = range.va_start();
    let next = va.wrapping_add(CHUNK_BYTES);
    let before = own_usage();
    fill_refusals(handle, va, next);
    let refused = own_usage();
    assert_eq!(
        refused, before,
        "{PHASE}: the refused FILL_REGION requests moved svctest's usage from {before} to {refused}"
    );

    assert_eq!(
        fill(0, &[(va, 0b101), (next, 0b1)], handle),
        (memmgr_errors::SUCCESS, 3),
        "{PHASE}: FILL_REGION of three pages"
    );
    let filled = own_usage();
    assert!(
        filled >= before.saturating_add(3),
        "{PHASE}: FILL_REGION of three pages moved svctest's usage from {before} to {filled}"
    );
    assert_eq!(
        fill(0, &[(va, 0b101), (next, 0b1)], handle),
        (memmgr_errors::SUCCESS, 0),
        "{PHASE}: a repeated FILL_REGION"
    );
    assert_eq!(
        own_usage(),
        filled,
        "{PHASE}: a repeated FILL_REGION moved the usage"
    );
    // A request that names filled pages beside an empty one, as a repeat after
    // a failure part way does, backs the empty one alone, with the object
    // page it takes in mask order, and leaves the filled ones as they are.
    assert_eq!(
        fill(0, &[(va, 0b111)], handle),
        (memmgr_errors::SUCCESS, 1),
        "{PHASE}: FILL_REGION over two filled pages and an empty one"
    );
    let partial = own_usage();
    assert!(
        partial > filled,
        "{PHASE}: FILL_REGION of one more page moved svctest's usage from {filled} to {partial}"
    );
    assert!(
        holds(va, 0)
            && holds(va.wrapping_add(PAGE_SIZE), 1)
            && holds(va.wrapping_add(2 * PAGE_SIZE), 1)
            && holds(next, 2),
        "{PHASE}: the filled pages do not hold their object pages in mask order"
    );
    let unnamed = va.wrapping_add(3 * PAGE_SIZE);
    assert!(
        read_word(unnamed, 0) == 0 && read_word(unnamed, LAST_WORD) == 0,
        "{PHASE}: a page no mask names is not zero"
    );
    unregister(range, pages, "UNREGISTER_REGION of the filled region");
}

/// The `FILL_REGION` refusals, in the demand region whose two chunks start
/// at `va` and `next` and in an attachment of the object `handle` names.
fn fill_refusals(handle: u64, va: u64, next: u64)
{
    let invalid = memmgr_errors::INVALID_ARGUMENT;
    let memmgr = startup_info().memmgr_endpoint;
    assert_eq!(
        fill_on(memmgr, 0, &[(va, 1)], None).0,
        invalid,
        "{PHASE}: FILL_REGION without a handle"
    );
    assert_eq!(
        fill(0, &[], handle).0,
        invalid,
        "{PHASE}: FILL_REGION of no chunk"
    );
    assert_eq!(
        fill(0, &[(next, 1), (va, 1)], handle).0,
        invalid,
        "{PHASE}: FILL_REGION with chunks out of order"
    );
    assert_eq!(
        fill(0, &[(va.wrapping_add(PAGE_SIZE), 1)], handle).0,
        invalid,
        "{PHASE}: FILL_REGION with a base off a chunk"
    );
    assert_eq!(
        fill(2, &[(va, 0b11)], handle).0,
        invalid,
        "{PHASE}: FILL_REGION past the object's end"
    );
    assert_eq!(
        fill_on(handle, 0, &[(va, 1)], None).0,
        memmgr_errors::UNAUTHORIZED,
        "{PHASE}: FILL_REGION over the object handle"
    );
    let attached = reserve(OBJECT_PAGES);
    let attached_va = attached.va_start();
    let label = attach(attached_va, OBJECT_PAGES, MAP_READ, 0, 0, Some(handle));
    assert_eq!(
        label,
        memmgr_errors::SUCCESS,
        "{PHASE}: ATTACH_OBJECT replied {label:#x}"
    );
    assert_eq!(
        fill(0, &[(attached_va, 1)], handle).0,
        invalid,
        "{PHASE}: FILL_REGION into an attachment of the object"
    );
    unregister(
        attached,
        OBJECT_PAGES,
        "UNREGISTER_REGION of the attachment",
    );
}

/// `MARK_CHECKPOINT` from svctest, which is not procmgr.
fn mark_refused(handle: u64)
{
    let account = syscall::cap_derive(startup_info().memmgr_endpoint, syscall::RIGHTS_EP_SEND)
        .expect("object_io: copying svctest's memmgr cap");
    let msg = IpcMessage::builder(memmgr_labels::MARK_CHECKPOINT)
        .cap(handle_copy(handle))
        .cap(account)
        .build();
    let got = memmgr_label(&msg, "MARK_CHECKPOINT");
    assert_eq!(
        got,
        memmgr_errors::UNAUTHORIZED,
        "{PHASE}: MARK_CHECKPOINT from svctest replied {got:#x}"
    );
    assert_eq!(
        object_flags(handle, PHASE).0,
        0,
        "{PHASE}: a refused MARK_CHECKPOINT marked the object"
    );
}
