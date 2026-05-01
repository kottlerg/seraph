// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/retype_reclaim.rs

//! Integration: end-to-end auto-reclaim of every retyped kernel-object type.
//!
//! For each of the seven retypable `ObjectType` variants, mints a kernel
//! object from a dedicated Frame cap and asserts that destroying it returns
//! the source cap's `available_bytes` ledger to the pre-mint value. This is
//! the userspace-visible invariant relied on for process-death reclaim
//! correctness — when a child dies, every kernel object it created against
//! memmgr-derived inner caps cascades back through
//! `KernelObjectHeader.ancestor` and credits bytes to the source
//! `FrameObject`.
//!
//! Object types covered:
//! - `Endpoint`     (sub-page, in-place)
//! - `Signal`       (sub-page, in-place)
//! - `WaitSet`      (sub-page, in-place)
//! - `EventQueue`   (sub-page when small, page-aligned split when large)
//! - `Thread`       (page-aligned split — kstack + wrapper page)
//! - `AddressSpace` (page-aligned split — `init_pages` PT pool)
//! - `CSpaceObj`    (page-aligned split — `init_pages` slot pool)
//!
//! ## Test isolation
//!
//! Every retype runs against `ctx.memory_frame_base`. A throwaway
//! `cap_create_endpoint` + delete pays the per-`FrameObject` allocator-
//! metadata cost (paid once on the cap's lifetime) before the baseline
//! read, so the post-mint-then-delete equality check reflects steady
//! state. If an earlier test already paid the metadata cost, the warmup
//! is a no-op and the baseline simply reflects current `available_bytes`
//! — the round-trip equality still holds either way.

use syscall::{
    cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_create_signal,
    cap_create_thread, cap_delete, cap_info, event_queue_create, wait_set_create,
};
use syscall_abi::CAP_INFO_FRAME_AVAILABLE;

use crate::{TestContext, TestResult};

fn read_available(frame_cap: u32) -> Result<u64, &'static str>
{
    cap_info(frame_cap, CAP_INFO_FRAME_AVAILABLE)
        .map_err(|_| "integration::retype_reclaim: cap_info(FRAME_AVAILABLE) failed")
}

fn assert_baseline(label: &'static str, frame_cap: u32, baseline: u64) -> TestResult
{
    let now = read_available(frame_cap)?;
    if now != baseline
    {
        crate::log(label);
        return Err("integration::retype_reclaim: available_bytes did not return to baseline");
    }
    Ok(())
}

// too_many_lines: the seven object-type cycles plus the mixed-batch
// validator each need their own mint→mid-check→delete→assert sequence;
// extracting a helper would require passing closures over the cap-create
// wrappers (each with a distinct signature), buying nothing in clarity.
#[allow(clippy::too_many_lines)]
pub fn run(ctx: &TestContext) -> TestResult
{
    let frame = ctx.memory_frame_base;

    // Pre-warm: pay the per-FrameObject allocator metadata cost (if not
    // already paid by an earlier test) so the baseline reflects steady
    // state. The mint-and-immediate-delete cycle leaves `available_bytes`
    // exactly where it was after the metadata debit.
    let warmup = cap_create_endpoint(frame)
        .map_err(|_| "integration::retype_reclaim: warmup cap_create_endpoint failed")?;
    cap_delete(warmup).map_err(|_| "integration::retype_reclaim: warmup cap_delete failed")?;

    let baseline = read_available(frame)?;

    // ── Endpoint ─────────────────────────────────────────────────────────────
    let ep = cap_create_endpoint(frame)
        .map_err(|_| "integration::retype_reclaim: cap_create_endpoint failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err("integration::retype_reclaim: Endpoint mint did not debit available_bytes");
    }
    cap_delete(ep).map_err(|_| "integration::retype_reclaim: cap_delete(endpoint) failed")?;
    assert_baseline(
        "integration::retype_reclaim: Endpoint reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── Signal ───────────────────────────────────────────────────────────────
    let sig = cap_create_signal(frame)
        .map_err(|_| "integration::retype_reclaim: cap_create_signal failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err("integration::retype_reclaim: Signal mint did not debit available_bytes");
    }
    cap_delete(sig).map_err(|_| "integration::retype_reclaim: cap_delete(signal) failed")?;
    assert_baseline(
        "integration::retype_reclaim: Signal reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── WaitSet ──────────────────────────────────────────────────────────────
    let ws = wait_set_create(frame)
        .map_err(|_| "integration::retype_reclaim: wait_set_create failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err("integration::retype_reclaim: WaitSet mint did not debit available_bytes");
    }
    cap_delete(ws).map_err(|_| "integration::retype_reclaim: cap_delete(wait_set) failed")?;
    assert_baseline(
        "integration::retype_reclaim: WaitSet reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── EventQueue (small — sub-page) ────────────────────────────────────────
    //
    // capacity 4 → 24 + 56 + 5*8 = 120 B → BIN_128 in-place.
    let eq_small = event_queue_create(frame, 4)
        .map_err(|_| "integration::retype_reclaim: event_queue_create(4) failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err(
            "integration::retype_reclaim: small EventQueue mint did not debit available_bytes",
        );
    }
    cap_delete(eq_small).map_err(|_| "integration::retype_reclaim: cap_delete(eq_small) failed")?;
    assert_baseline(
        "integration::retype_reclaim: small EventQueue reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── EventQueue (large — page-aligned split) ──────────────────────────────
    //
    // capacity 64 → 24 + 56 + 65*8 = 600 B → exceeds BIN_512 → split mode.
    let eq_large = event_queue_create(frame, 64)
        .map_err(|_| "integration::retype_reclaim: event_queue_create(64) failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err(
            "integration::retype_reclaim: large EventQueue mint did not debit available_bytes",
        );
    }
    cap_delete(eq_large).map_err(|_| "integration::retype_reclaim: cap_delete(eq_large) failed")?;
    assert_baseline(
        "integration::retype_reclaim: large EventQueue reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── AddressSpace ─────────────────────────────────────────────────────────
    //
    // 8 pages of PT pool (page 0 root, pages 1..8 growth budget).
    let aspace_cap = cap_create_aspace(frame, 0, 8)
        .map_err(|_| "integration::retype_reclaim: cap_create_aspace failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err("integration::retype_reclaim: AddressSpace mint did not debit available_bytes");
    }
    cap_delete(aspace_cap).map_err(|_| "integration::retype_reclaim: cap_delete(aspace) failed")?;
    assert_baseline(
        "integration::retype_reclaim: AddressSpace reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── CSpaceObj ────────────────────────────────────────────────────────────
    //
    // 4 slot pages, max_slots 256 → fits in pool.
    let cspace_cap = cap_create_cspace(frame, 0, 4, 256)
        .map_err(|_| "integration::retype_reclaim: cap_create_cspace failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err("integration::retype_reclaim: CSpace mint did not debit available_bytes");
    }
    cap_delete(cspace_cap).map_err(|_| "integration::retype_reclaim: cap_delete(cspace) failed")?;
    assert_baseline(
        "integration::retype_reclaim: CSpace reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── Thread ───────────────────────────────────────────────────────────────
    //
    // Threads need an AddressSpace + CSpace; create both from the same source
    // cap, mint a thread, then delete in reverse-creation order. The thread
    // is never started — `cap_create_thread` constructs a suspended TCB; we
    // just verify mint-then-delete reclaims correctly.
    let aspace_for_thread = cap_create_aspace(frame, 0, 8)
        .map_err(|_| "integration::retype_reclaim: cap_create_aspace (for thread) failed")?;
    let cspace_for_thread = cap_create_cspace(frame, 0, 4, 16)
        .map_err(|_| "integration::retype_reclaim: cap_create_cspace (for thread) failed")?;
    let thread_cap = cap_create_thread(frame, aspace_for_thread, cspace_for_thread)
        .map_err(|_| "integration::retype_reclaim: cap_create_thread failed")?;
    let mid = read_available(frame)?;
    if mid >= baseline
    {
        return Err("integration::retype_reclaim: Thread mint did not debit available_bytes");
    }
    cap_delete(thread_cap).map_err(|_| "integration::retype_reclaim: cap_delete(thread) failed")?;
    cap_delete(cspace_for_thread)
        .map_err(|_| "integration::retype_reclaim: cap_delete(cspace_for_thread) failed")?;
    cap_delete(aspace_for_thread)
        .map_err(|_| "integration::retype_reclaim: cap_delete(aspace_for_thread) failed")?;
    assert_baseline(
        "integration::retype_reclaim: Thread reclaim mismatch",
        frame,
        baseline,
    )?;

    // ── Mixed batch — mint several types, delete all, verify reclaim. ────────
    //
    // Validates that the per-FrameObject sub-allocator's free lists handle
    // multi-type churn without leaking bytes. Endpoints land in BIN_128;
    // WaitSets in BIN_512; AddressSpace in the page-aligned free list.
    let e1 =
        cap_create_endpoint(frame).map_err(|_| "integration::retype_reclaim: batch ep1 failed")?;
    let e2 =
        cap_create_endpoint(frame).map_err(|_| "integration::retype_reclaim: batch ep2 failed")?;
    let s1 =
        cap_create_signal(frame).map_err(|_| "integration::retype_reclaim: batch sig1 failed")?;
    let w1 = wait_set_create(frame).map_err(|_| "integration::retype_reclaim: batch ws1 failed")?;
    let a1 = cap_create_aspace(frame, 0, 8)
        .map_err(|_| "integration::retype_reclaim: batch aspace1 failed")?;

    cap_delete(a1).map_err(|_| "integration::retype_reclaim: batch delete a1 failed")?;
    cap_delete(w1).map_err(|_| "integration::retype_reclaim: batch delete w1 failed")?;
    cap_delete(s1).map_err(|_| "integration::retype_reclaim: batch delete s1 failed")?;
    cap_delete(e2).map_err(|_| "integration::retype_reclaim: batch delete e2 failed")?;
    cap_delete(e1).map_err(|_| "integration::retype_reclaim: batch delete e1 failed")?;
    assert_baseline(
        "integration::retype_reclaim: mixed batch reclaim mismatch",
        frame,
        baseline,
    )?;

    Ok(())
}
