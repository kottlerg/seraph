// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/teardown_windows.rs

//! Interrupts taken inside the teardowns whose length an owner chose.
//!
//! The dealloc cascade takes the interrupts pending on its CPU between two
//! teardowns, and a dying `CSpace`'s release pass, a death-observer chain's
//! release, an address space's frame release and an `Mmio` object's mapping
//! withdrawal take them between bounded batches
//! (core/kernel/docs/capability-internals.md § Teardown), and so does an
//! exiting thread's death posts to its observers
//! (core/kernel/docs/scheduling-internals.md, Thread death observers). Each
//! case builds one such stretch well past one batch, deletes its owner (or,
//! for the death posts, exits) on the `crate::latency` rig, and judges the call by a [`Bracket`] around the
//! stretch: two reads of state the stretch changes at its first and its last
//! step, so that only a probe acknowledged between the two passes the case,
//! and the other windows of the same call (a `CSpace`'s drain, its arena-page
//! pass and its pool return, a thread's or an address space's teardown gates)
//! pass none.
//!
//! The sort of a dying `CSpace`'s kept arena pages, their leases and the
//! release of its holds on them change nothing a guest can read while they
//! run, so their batching is checked by the kernel's host tests instead.

use core::cell::Cell;

use init_protocol::{CapType, InitInfo};
use syscall::{
    cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_create_notification,
    cap_create_thread, cap_delete, cap_derive, cap_info, cap_info_memory_mappings, cap_insert,
    cap_move, event_queue_create_observed, event_try_recv_death, mem_map, memory_merge,
    memory_split, mmio_map, thread_bind_notification,
};
use syscall_abi::{
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_SIZE, CAP_INFO_SOLE_REFERENCE, PAGE_SIZE, RIGHTS_ALL,
};

use crate::latency::{self, Bracket, Call, Measured};
use crate::{TestContext, TestResult};

/// Endpoints whose last capabilities the cascade case's dying `CSpace`
/// holds: as many teardowns, each popped from the cascade.
const ENDPOINTS: u32 = 4096;
/// Pages of the Memory piece the cascade case retypes its endpoints from:
/// [`ENDPOINTS`] 128-byte bodies fill 128 pages, and the rest is margin.
const ENDPOINT_PIECE_PAGES: u64 = 192;
/// Copies of one notification between the release-pass case's first and last
/// slots: 293 slot leaves, 73 batches of the kernel's `RELEASE_BATCH_LEAVES`.
const RELEASED_COPIES: u32 = 16_384;
/// Death-observer nodes of the bulk queue the observer case binds, 64
/// batches of the kernel's `OBSERVER_BATCH_NODES`.
const OBSERVERS: u32 = 4096;
/// Pages of the region the frame-release case maps, one leaf table's worth.
const REGION_PAGES: u64 = 512;
/// Leaf tables the frame-release case fills, each a window apart.
const MAPPED_TABLES: u64 = 256;
/// Pages of the frame-release case's address space: its leaf tables, the
/// tables above them, and the pool's spare.
const MAPPED_ASPACE_PAGES: u64 = MAPPED_TABLES + 16;
/// Mappings of the `Mmio` case's object into its bulk address space, each a
/// record the withdrawal visits a window apart.
const BULK_MAPPINGS: u64 = 1024;
/// Bulk mappings made before the `Mmio` case's last address space's: the
/// inline records but the first, and the first spill chunk but its last
/// record, so that the last address space holds the record the withdrawal
/// visits last (the oldest chunk's last).
const BULK_BEFORE_LAST: u64 = 3 + 6;
/// Pages donated to ktest's `CSpace` for the `Mmio` case's spill chunks:
/// seven records a chunk, 31 chunks an arena page, and a spare.
const MMIO_ARENA_PAGES: u64 = BULK_MAPPINGS / 7 / 31 + 2;
/// Base of the mappings in the fresh address spaces the frame-release and
/// `Mmio` cases make, inside every paging mode's user range; no thread runs
/// in them.
const SPACE_VA: u64 = 0x8_0000_0000;
/// Bytes one leaf table maps.
const TABLE_SPAN: u64 = REGION_PAGES * PAGE_SIZE;

/// A capability of ktest's own `CSpace`, deleted on drop unless taken.
struct Owned(u64);

impl Owned
{
    /// Give the capability up to a call that consumed it.
    fn take(&mut self)
    {
        self.0 = 0;
    }
}

impl Drop for Owned
{
    fn drop(&mut self)
    {
        if self.0 != 0
        {
            cap_delete(self.0).ok();
        }
    }
}

/// A Memory piece split off the top of `memory_base`, merged back on drop
/// (`SYS_MEMORY_MERGE` takes a piece whose retyped objects are all freed and
/// whose mappings are all gone).
struct Piece<'a>
{
    ctx: &'a TestContext,
    cap: u64,
}

impl<'a> Piece<'a>
{
    fn split(ctx: &'a TestContext, pages: u64) -> Result<Self, &'static str>
    {
        let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
            .map_err(|_| "teardown_windows: cap_info(memory_base, SIZE) failed")?;
        let keep = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| size.checked_sub(bytes))
            .ok_or("teardown_windows: memory_base is smaller than the piece")?;
        let cap = memory_split(ctx.memory_base, keep)
            .map_err(|_| "teardown_windows: split the piece off memory_base failed")?;
        Ok(Self { ctx, cap })
    }
}

impl Drop for Piece<'_>
{
    fn drop(&mut self)
    {
        if memory_merge(self.ctx.memory_base, self.cap).is_err()
        {
            crate::log("ktest: teardown_windows: a piece did not merge back into memory_base");
        }
    }
}

/// Whether `cap` is the only reference to its object.
fn sole(cap: u64) -> Result<bool, &'static str>
{
    cap_info(cap, CAP_INFO_SOLE_REFERENCE)
        .map(|answer| answer == 1)
        .map_err(|_| "teardown_windows: cap_info(SOLE_REFERENCE) failed")
}

/// Available bytes of the Memory capability `cap`.
fn available(cap: u64) -> Result<u64, &'static str>
{
    cap_info(cap, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "teardown_windows: cap_info(MEMORY_AVAILABLE) failed")
}

/// User leaves naming a page of the `REGION_PAGES`-page region `cap`.
fn mappings(cap: u64) -> Result<u64, &'static str>
{
    cap_info_memory_mappings(cap, 0, REGION_PAGES)
        .map_err(|_| "teardown_windows: cap_info(MEMORY_MAPPINGS) failed")
}

/// Have the worker delete `owner`, the last capability to the stretch's
/// owner, judged by the stretch `begun` and `ended` bracket; `owner` is
/// taken when the delete consumed it.
fn delete_bracketed(
    ctx: &TestContext,
    owner: &mut Owned,
    mut begun: impl FnMut() -> Result<bool, &'static str>,
    mut ended: impl FnMut() -> Result<bool, &'static str>,
    what: &'static str,
) -> Result<Measured, &'static str>
{
    let mut bracket = Bracket {
        begun: &mut begun,
        ended: &mut ended,
    };
    let m = latency::measure_bracketed(ctx, Call::Delete(owner.0), &mut bracket);
    if latency::worker_results().map(|r| r.0) == Some(0)
    {
        owner.take();
    }
    let m = m?;
    if m.result == u64::MAX
    {
        return Err(what);
    }
    Ok(m)
}

/// Run `once` on a fresh fixture per call until the rig's attempts end,
/// then check the measure, logged as `line`.
fn run(line: &'static str, once: impl FnMut() -> Result<Measured, &'static str>) -> TestResult
{
    let m = latency::attempt_until_acked(once)?;
    latency::check_measured(line, &m)
}

/// The dealloc cascade of a `CSpace` holding the last capabilities to
/// [`ENDPOINTS`] endpoints takes interrupts between their teardowns. The
/// endpoints are retyped from a piece of their own, whose available bytes
/// rise at the first teardown and are whole again at the last.
pub fn cascade_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    let piece = Piece::split(ctx, ENDPOINT_PIECE_PAGES)?;
    let whole = available(piece.cap)?;
    run("ktest: teardown_windows call=cascade", || {
        let pages = crate::cspace_geometry::pages_to_cover(u64::from(ENDPOINTS)).saturating_add(1);
        let mut dying = Owned(
            cap_create_cspace(ctx.memory_base, 0, pages)
                .map_err(|_| "teardown_windows::cascade: create the dying CSpace failed")?,
        );
        for _ in 0..ENDPOINTS
        {
            let endpoint = cap_create_endpoint(piece.cap)
                .map_err(|_| "teardown_windows::cascade: create an endpoint failed")?;
            if cap_move(endpoint, dying.0, 0).is_err()
            {
                cap_delete(endpoint).ok();
                return Err("teardown_windows::cascade: move an endpoint failed");
            }
        }
        let held = available(piece.cap)?;
        let m = delete_bracketed(
            ctx,
            &mut dying,
            || Ok(available(piece.cap)? != held),
            || Ok(available(piece.cap)? == whole),
            "teardown_windows::cascade: the worker's delete failed",
        )?;
        if available(piece.cap)? != whole
        {
            return Err("teardown_windows::cascade: an endpoint outlived its CSpace");
        }
        Ok(m)
    })
}

/// A dying `CSpace`'s release pass over [`RELEASED_COPIES`] copies takes
/// interrupts between its batches of slot leaves. The pass visits the slots
/// in order: the copy of `first` at the first slot, whose release leaves
/// ktest's `first` sole, and the copy of `last` past every bulk copy.
pub fn release_pass_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    run("ktest: teardown_windows call=release_pass", || {
        let notification = || {
            cap_create_notification(ctx.memory_base)
                .map(Owned)
                .map_err(|_| "teardown_windows::release_pass: create a notification failed")
        };
        let (first, last, bulk) = (notification()?, notification()?, notification()?);
        let last_slot = RELEASED_COPIES
            .checked_add(2)
            .ok_or("teardown_windows::release_pass: slot index out of range")?;
        let pages = crate::cspace_geometry::pages_to_cover(u64::from(last_slot)).saturating_add(1);
        let mut dying = Owned(
            cap_create_cspace(ctx.memory_base, 0, pages)
                .map_err(|_| "teardown_windows::release_pass: create the dying CSpace failed")?,
        );
        let insert = |cap: u64, slot: u32| {
            cap_insert(cap, dying.0, slot, RIGHTS_ALL)
                .map(|_| ())
                .map_err(|_| "teardown_windows::release_pass: insert a copy failed")
        };
        insert(first.0, 1)?;
        for slot in 2..last_slot
        {
            insert(bulk.0, slot)?;
        }
        insert(last.0, last_slot)?;
        if sole(first.0)? || sole(last.0)?
        {
            return Err("teardown_windows::release_pass: a copy did not take a reference");
        }
        let m = delete_bracketed(
            ctx,
            &mut dying,
            || sole(first.0),
            || sole(last.0),
            "teardown_windows::release_pass: the worker's delete failed",
        )?;
        if !sole(first.0)? || !sole(last.0)?
        {
            return Err("teardown_windows::release_pass: a copy outlived its CSpace");
        }
        Ok(m)
    })
}

/// A dying thread's release of its death-observer chain takes interrupts
/// between its batches of nodes. The chain is walked newest binding first:
/// `first`'s binding, made last, then [`OBSERVERS`] bindings of a bulk
/// queue, then `last`'s, made first; each queue is sole once its node's
/// reference is released.
pub fn observer_release_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    run("ktest: teardown_windows call=observer_release", || {
        let queue = |observers: u32| {
            event_queue_create_observed(ctx.memory_base, 1, observers)
                .map(Owned)
                .map_err(|_| "teardown_windows::observer_release: create a queue failed")
        };
        let (first, last, bulk) = (queue(1)?, queue(1)?, queue(OBSERVERS)?);
        let mut thread = Owned(
            cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
                .map_err(|_| "teardown_windows::observer_release: create the thread failed")?,
        );
        let bind = |queue: u64, correlator: u64| {
            thread_bind_notification(thread.0, queue, correlator)
                .map_err(|_| "teardown_windows::observer_release: bind an observer failed")
        };
        bind(last.0, 0)?;
        for correlator in 0..u64::from(OBSERVERS)
        {
            bind(bulk.0, correlator)?;
        }
        bind(first.0, 0)?;
        if sole(first.0)? || sole(last.0)?
        {
            return Err("teardown_windows::observer_release: a binding took no reference");
        }
        let m = delete_bracketed(
            ctx,
            &mut thread,
            || sole(first.0),
            || sole(last.0),
            "teardown_windows::observer_release: the worker's delete failed",
        )?;
        if !sole(first.0)? || !sole(last.0)?
        {
            return Err("teardown_windows::observer_release: a binding outlived its thread");
        }
        Ok(m)
    })
}

/// An address space's teardown lowers the frame-map count of every leaf it
/// maps, taking interrupts between its page tables: a region mapped into
/// [`MAPPED_TABLES`] leaf tables, whose mapping count falls at the first
/// leaf and reaches zero at the last.
pub fn frame_release_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    let region = Piece::split(ctx, REGION_PAGES)?;
    let full = MAPPED_TABLES
        .checked_mul(REGION_PAGES)
        .ok_or("teardown_windows::frame_release: mapping count out of range")?;
    run("ktest: teardown_windows call=frame_release", || {
        let mut space = Owned(
            cap_create_aspace(ctx.memory_base, 0, MAPPED_ASPACE_PAGES)
                .map_err(|_| "teardown_windows::frame_release: create the space failed")?,
        );
        for table in 0..MAPPED_TABLES
        {
            let va = table
                .checked_mul(TABLE_SPAN)
                .and_then(|offset| SPACE_VA.checked_add(offset))
                .ok_or("teardown_windows::frame_release: mapping address out of range")?;
            // SAFETY: the space is fresh and no thread runs in it, so no Rust
            // object or IPC page of ktest is at the address; the region holds
            // none either (a piece split off for the case).
            unsafe { mem_map(region.cap, space.0, va, 0, REGION_PAGES, 0) }
                .map_err(|_| "teardown_windows::frame_release: map the region failed")?;
        }
        if mappings(region.cap)? != full
        {
            return Err("teardown_windows::frame_release: a leaf was not counted");
        }
        let m = delete_bracketed(
            ctx,
            &mut space,
            || Ok(mappings(region.cap)? < full),
            || Ok(mappings(region.cap)? == 0),
            "teardown_windows::frame_release: the worker's delete failed",
        )?;
        if mappings(region.cap)? != 0
        {
            return Err("teardown_windows::frame_release: a leaf outlived its space");
        }
        Ok(m)
    })
}

/// A dead `Mmio` object's withdrawal of its mappings takes interrupts
/// between its records. The object is a derivation of the side-effect-free
/// register page (`crate::arch::MMIO_PROBE_PHYS`) mapped into three fresh
/// address spaces: `first`'s mapping takes the first inline record, the
/// withdrawal's first, and `last`'s the first spill chunk's last record,
/// the withdrawal's last, with [`BULK_MAPPINGS`] mappings into a bulk space
/// between them; each space is sole once its record's reference is released.
pub fn mmio_withdrawal_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let Some(boot_cap) = crate::init_info::descriptors(info)
        .iter()
        .find(|d| d.cap_type == CapType::Mmio && d.aux0 == crate::arch::MMIO_PROBE_PHYS)
        .map(|d| d.slot)
    else
    {
        return Err("teardown_windows::mmio_withdrawal: no Mmio cap covers MMIO_PROBE_PHYS");
    };
    // The spill chunks come from ktest's own CSpace's arena.
    cap_create_cspace(ctx.memory_base, ctx.cspace_cap, MMIO_ARENA_PAGES)
        .map_err(|_| "teardown_windows::mmio_withdrawal: fund ktest's arena failed")?;
    run("ktest: teardown_windows call=mmio_withdrawal", || {
        let space = |pages: u64| {
            cap_create_aspace(ctx.memory_base, 0, pages)
                .map(Owned)
                .map_err(|_| "teardown_windows::mmio_withdrawal: create a space failed")
        };
        let (first, last, bulk) = (space(8)?, space(8)?, space(16)?);
        let mut granted = Owned(
            cap_derive(boot_cap, RIGHTS_ALL)
                .map_err(|_| "teardown_windows::mmio_withdrawal: derive the object failed")?,
        );
        let map = |space: u64, place: u64| {
            let va = place
                .checked_mul(PAGE_SIZE)
                .and_then(|offset| SPACE_VA.checked_add(offset))
                .ok_or("teardown_windows::mmio_withdrawal: mapping address out of range")?;
            // SAFETY: the space is fresh and no thread runs in it, so nothing
            // reads the mapping and no Rust object of ktest is at the address
            // (`mmio_map` § Safety).
            unsafe { mmio_map(space, granted.0, va, 0) }
                .map_err(|_| "teardown_windows::mmio_withdrawal: map the object failed")
        };
        map(first.0, 0)?;
        for place in 0..BULK_BEFORE_LAST
        {
            map(bulk.0, place)?;
        }
        map(last.0, 0)?;
        for place in BULK_BEFORE_LAST..BULK_MAPPINGS
        {
            map(bulk.0, place)?;
        }
        if sole(first.0)? || sole(last.0)?
        {
            return Err("teardown_windows::mmio_withdrawal: a mapping took no reference");
        }
        let m = delete_bracketed(
            ctx,
            &mut granted,
            || sole(first.0),
            || sole(last.0),
            "teardown_windows::mmio_withdrawal: the worker's delete failed",
        )?;
        if !sole(first.0)? || !sole(last.0)?
        {
            return Err("teardown_windows::mmio_withdrawal: a mapping outlived its object");
        }
        Ok(m)
    })
}

/// A thread's exit posts its death to every observer bound to it, taking
/// interrupts between batches of nodes. The rig's worker is bound to `last`
/// first, to a bulk queue [`OBSERVERS`] times, and to `first` last, and the
/// walk posts newest binding first, so `first`'s queue receives the walk's
/// first post and `last`'s its last; then the worker exits.
pub fn death_post_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    run("ktest: teardown_windows call=death_post", || {
        let queue = |observers: u32| {
            event_queue_create_observed(ctx.memory_base, 1, observers)
                .map(Owned)
                .map_err(|_| "teardown_windows::death_post: create a queue failed")
        };
        let (first, last, bulk) = (queue(1)?, queue(1)?, queue(OBSERVERS)?);
        let mut setup = |thread: u64| -> TestResult {
            let bind = |queue: u64, correlator: u64| {
                thread_bind_notification(thread, queue, correlator)
                    .map_err(|_| "teardown_windows::death_post: bind an observer failed")
            };
            bind(last.0, 0)?;
            for correlator in 0..u64::from(OBSERVERS)
            {
                bind(bulk.0, correlator)?;
            }
            bind(first.0, 0)
        };
        // Whether `queue` has received its post; a received post stays seen.
        let posted = |queue: u64, seen: &Cell<bool>| {
            if !seen.get() && event_try_recv_death(queue).is_ok()
            {
                seen.set(true);
            }
            Ok(seen.get())
        };
        let (first_seen, last_seen) = (Cell::new(false), Cell::new(false));
        let mut begun = || posted(first.0, &first_seen);
        let mut ended = || posted(last.0, &last_seen);
        let mut bracket = Bracket {
            begun: &mut begun,
            ended: &mut ended,
        };
        let m = latency::measure_exit(ctx, &mut setup, &mut bracket)?;
        if !first_seen.get() || !last_seen.get()
        {
            return Err("teardown_windows::death_post: an observer missed the post");
        }
        Ok(m)
    })
}
