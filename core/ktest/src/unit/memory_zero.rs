// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/memory_zero.rs

//! Tier 1 tests for `SYS_MEMORY_ZERO`: the kernel zeroes a Memory cap's pages
//! through its direct map.
//!
//! Covers the zero itself (a range that crosses batch boundaries reads zero
//! and every page around it keeps its pattern), the short-count contract of
//! one call, the refusals (a cap without Map or without Write, a zero count,
//! a range past the cap's end or overflowing, a range below the retype
//! cursor, a deleted handle), each of which zeroes nothing, and, on the
//! latency rig of `crate::latency`, the interrupt windows between batches: a
//! TLB shootdown of the calling CPU issued while a large zero runs is
//! acknowledged before the call returns.
//!
//! Each case zeroes a piece split off the top of `memory_base` and merged
//! back afterwards, mapped, when it reads the bytes, at [`ZERO_VA`].

use syscall::{
    cap_create_cspace, cap_delete, cap_derive, cap_info, mem_map, mem_unmap, memory_merge,
    memory_split, memory_zero, memory_zero_all,
};
use syscall_abi::{
    CAP_INFO_MEMORY_SIZE, MAP_WRITABLE, PAGE_SIZE, RIGHTS_MEM_MAP, RIGHTS_MEM_MAP_RW,
    RIGHTS_MEM_WRITE, SyscallError,
};

use crate::latency::{self, Call};
use crate::{TestContext, TestResult};

/// The scratch VA a piece is mapped at to read its bytes (crate docs
/// § Scratch VAs).
const ZERO_VA: u64 = 0x1_7000_0000;
/// Pages of the piece the functional cases zero.
const PIECE_PAGES: u64 = 48;
/// Pages of the piece the latency case zeroes: 32 MiB, 2,048 batches.
const LATENCY_PIECE_PAGES: u64 = 8192;
/// The word every byte of a piece holds before a zero.
const PATTERN: u64 = 0xA5A5_5A5A_C3C3_3C3C;
/// `u64` words in a page.
const PAGE_WORDS: u64 = PAGE_SIZE / 8;

/// A Memory piece split off the top of `memory_base`, merged back on drop.
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
            .map_err(|_| "memory_zero: cap_info(memory_base, SIZE) failed")?;
        let keep = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| size.checked_sub(bytes))
            .ok_or("memory_zero: memory_base is smaller than the piece")?;
        let cap = memory_split(ctx.memory_base, keep)
            .map_err(|_| "memory_zero: split the piece off memory_base failed")?;
        Ok(Self { ctx, cap })
    }
}

impl Drop for Piece<'_>
{
    fn drop(&mut self)
    {
        if memory_merge(self.ctx.memory_base, self.cap).is_err()
        {
            crate::log("ktest: memory_zero: a piece did not merge back into memory_base");
        }
    }
}

/// A piece of [`PIECE_PAGES`] mapped writable at [`ZERO_VA`], every word
/// holding [`PATTERN`]; unmapped on drop, before the piece merges back.
struct Mapped<'a>
{
    piece: Piece<'a>,
}

impl<'a> Mapped<'a>
{
    fn new(ctx: &'a TestContext) -> Result<Self, &'static str>
    {
        let piece = Piece::split(ctx, PIECE_PAGES)?;
        // SAFETY: ZERO_VA is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        unsafe {
            mem_map(
                piece.cap,
                ctx.aspace_cap,
                ZERO_VA,
                0,
                PIECE_PAGES,
                MAP_WRITABLE,
            )
        }
        .map_err(|_| "memory_zero: map the piece failed")?;
        let mapped = Self { piece };
        for word in 0..PIECE_PAGES * PAGE_WORDS
        {
            // SAFETY: the word lies in the piece's mapping at ZERO_VA, which
            // no reference covers.
            unsafe { word_ptr(word).write_volatile(PATTERN) };
        }
        Ok(mapped)
    }

    /// Whether every word of pages `[first, end)` reads `value`.
    fn pages_read(&self, first: u64, end: u64, value: u64) -> bool
    {
        (first * PAGE_WORDS..end * PAGE_WORDS).all(|word| {
            // SAFETY: as in `new`; the mapping lives as long as `self`.
            unsafe { word_ptr(word).read_volatile() == value }
        })
    }
}

impl Drop for Mapped<'_>
{
    fn drop(&mut self)
    {
        // SAFETY: the span is the scratch mapping `new` made; no reference
        // into it is live.
        if unsafe { mem_unmap(self.piece.ctx.aspace_cap, ZERO_VA, PIECE_PAGES) }.is_err()
        {
            crate::log("ktest: memory_zero: unmapping the piece failed");
        }
    }
}

/// The address of word `word` of the mapping at [`ZERO_VA`].
fn word_ptr(word: u64) -> *mut u64
{
    (ZERO_VA + word * 8) as *mut u64
}

/// A zero of pages 3 to 40 of a 48-page piece, three batches of 16 pages and
/// a part of one, reads zero across the range, and every page around it
/// keeps its pattern; a single call returns a count of at least one page and
/// at most the pages asked for, short only at a batch's end.
pub fn zeroes_the_range_and_nothing_else(ctx: &TestContext) -> TestResult
{
    let mapped = Mapped::new(ctx)?;
    let cap = mapped.piece.cap;
    // SAFETY: the piece's only mapping in ktest is the scratch one at
    // ZERO_VA, which no reference covers.
    unsafe { memory_zero_all(cap, 3, 37) }.map_err(|_| "memory_zero: memory_zero_all failed")?;
    if !mapped.pages_read(3, 40, 0)
    {
        return Err("memory_zero: a page of the zeroed range does not read zero");
    }
    if !mapped.pages_read(0, 3, PATTERN) || !mapped.pages_read(40, PIECE_PAGES, PATTERN)
    {
        return Err("memory_zero: a page outside the zeroed range lost its pattern");
    }

    // SAFETY: as above.
    let count =
        unsafe { memory_zero(cap, 40, 8) }.map_err(|_| "memory_zero: memory_zero failed")?;
    if count == 0 || count > 8
    {
        crate::log_u64("unit::memory_zero: count=", count);
        return Err("memory_zero: one call returned a count outside 1..=page_count");
    }
    if !mapped.pages_read(40, 40 + count, 0) || !mapped.pages_read(40 + count, PIECE_PAGES, PATTERN)
    {
        return Err("memory_zero: a call's count does not match the pages it zeroed");
    }
    Ok(())
}

/// A cap without Write (Map alone) or without Map (Write alone) is refused
/// with `InsufficientRights`, and nothing is zeroed.
pub fn refuses_without_map_and_write(ctx: &TestContext) -> TestResult
{
    let mapped = Mapped::new(ctx)?;
    let refused = SyscallError::InsufficientRights as i64;
    for rights in [RIGHTS_MEM_MAP, RIGHTS_MEM_WRITE]
    {
        let derived = cap_derive(mapped.piece.cap, rights)
            .map_err(|_| "memory_zero: derive an attenuated cap failed")?;
        // SAFETY: as in zeroes_the_range_and_nothing_else.
        let got = unsafe { memory_zero(derived, 0, 1) };
        cap_delete(derived).map_err(|_| "memory_zero: delete the attenuated cap failed")?;
        if got != Err(refused)
        {
            crate::log_u64("unit::memory_zero: rights=", rights);
            return Err("memory_zero: a cap without Map or Write was not refused");
        }
    }
    // The full pair is enough.
    let derived = cap_derive(mapped.piece.cap, RIGHTS_MEM_MAP_RW)
        .map_err(|_| "memory_zero: derive a Map and Write cap failed")?;
    // SAFETY: as above.
    let got = unsafe { memory_zero(derived, PIECE_PAGES - 1, 1) };
    cap_delete(derived).map_err(|_| "memory_zero: delete the Map and Write cap failed")?;
    if got != Ok(1)
    {
        return Err("memory_zero: a cap with Map and Write alone was refused");
    }
    if !mapped.pages_read(0, PIECE_PAGES - 1, PATTERN)
    {
        return Err("memory_zero: a refused call zeroed a page");
    }
    Ok(())
}

/// A zero count, a range past the cap's end, an offset or a count whose
/// bytes overflow are refused with `InvalidArgument`, and nothing is zeroed:
/// the range is checked whole before the first batch.
pub fn refuses_a_malformed_range(ctx: &TestContext) -> TestResult
{
    let mapped = Mapped::new(ctx)?;
    let cap = mapped.piece.cap;
    let refused = SyscallError::InvalidArgument as i64;
    for (offset, count) in [
        (0, 0),
        (0, PIECE_PAGES + 1),
        (PIECE_PAGES - 1, 2),
        (PIECE_PAGES, 1),
        (u64::MAX, 1),
        (0, u64::MAX),
        (1, u64::MAX / PAGE_SIZE),
    ]
    {
        // SAFETY: as in zeroes_the_range_and_nothing_else.
        if unsafe { memory_zero(cap, offset, count) } != Err(refused)
        {
            crate::log_u64("unit::memory_zero: offset=", offset);
            crate::log_u64("unit::memory_zero: count=", count);
            return Err("memory_zero: a malformed range was not refused with InvalidArgument");
        }
    }
    if !mapped.pages_read(0, PIECE_PAGES, PATTERN)
    {
        return Err("memory_zero: a refused range zeroed a page");
    }
    Ok(())
}

/// A range that starts below the retype cursor, where a kernel object lives,
/// is refused with `InvalidArgument`, and a page past the cursor is zeroed.
pub fn refuses_below_the_retype_cursor(ctx: &TestContext) -> TestResult
{
    let piece = Piece::split(ctx, PIECE_PAGES)?;
    let cspace = cap_create_cspace(piece.cap, 0, 1)
        .map_err(|_| "memory_zero: retype a CSpace from the piece failed")?;
    // SAFETY: the piece is mapped nowhere in ktest; the call is refused or
    // zeroes the piece's own pages.
    let below = unsafe { memory_zero(piece.cap, 0, 1) };
    // SAFETY: as above.
    let past = unsafe { memory_zero(piece.cap, PIECE_PAGES - 1, 1) };
    // Returns the retyped pages to the piece; the cursor drains back to 0.
    cap_delete(cspace).map_err(|_| "memory_zero: delete the retyped CSpace failed")?;
    if below != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("memory_zero: a range below the retype cursor was not refused");
    }
    if past != Ok(1)
    {
        return Err("memory_zero: a page past the retype cursor was not zeroed");
    }
    Ok(())
}

/// A deleted handle is refused with `InvalidCapability`.
pub fn refuses_a_deleted_handle(ctx: &TestContext) -> TestResult
{
    let piece = Piece::split(ctx, PIECE_PAGES)?;
    let copy = cap_derive(piece.cap, RIGHTS_MEM_MAP_RW)
        .map_err(|_| "memory_zero: derive a copy of the piece failed")?;
    cap_delete(copy).map_err(|_| "memory_zero: delete the copy failed")?;
    // SAFETY: the piece is mapped nowhere in ktest.
    if unsafe { memory_zero(copy, 0, 1) } != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("memory_zero: a deleted handle was not refused with InvalidCapability");
    }
    Ok(())
}

/// A zero of 8,192 pages takes the interrupts pending on its CPU between
/// batches: a TLB shootdown of the calling CPU issued while it runs is
/// acknowledged before it returns, within the rig's bound.
pub fn zero_takes_interrupts(ctx: &TestContext) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    let piece = Piece::split(ctx, LATENCY_PIECE_PAGES)?;
    let m = latency::attempt_until_acked(|| {
        let m = latency::measure_call(
            ctx,
            Call::Zero {
                memory: piece.cap,
                offset: 0,
                pages: LATENCY_PIECE_PAGES,
            },
        )?;
        // A count, never an error: the worker's call zeroes at least a batch.
        if m.result == u64::MAX || m.result == 0 || m.result > LATENCY_PIECE_PAGES
        {
            return Err("memory_zero: the rig's zero failed");
        }
        Ok(m)
    })?;
    latency::check_measured("ktest: memory_zero_latency call=memory_zero", &m)
}
