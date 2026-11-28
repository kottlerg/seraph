// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/thread_list_pages.rs

//! Integration: a debugger lists the mapped pages of another address space,
//! with their protection, through a Thread capability
//! (`SYS_THREAD_LIST_PAGES`; core/kernel/docs/syscalls.md
//! § `SYS_THREAD_LIST_PAGES`), as a core writer does
//! (docs/fault-handling.md § Debugging).
//!
//! A thread is created, never started, in a fresh address space B, which maps
//! two writable pages, a read-only page right after them, an executable page
//! apart from them, and, when the boot hands ktest an `Mmio`, a device page.
//! Then:
//! - the listing from 0, continued from each call's resume address until a
//!   call returns no run and its own start, holds those mappings and nothing
//!   else, in address order: the writable pages one run, the read-only page a
//!   run of its own, the device page marked `PAGE_RUN_NO_COPY`;
//! - the listing made one run a call holds the same runs, once adjacent runs
//!   of one protection are joined, as a caller joins them across calls;
//! - a call at the top of the user half returns no run and the top;
//! - a run count of 0 or past `MAX_PAGE_RUNS` is refused
//!   (`InvalidArgument`); an unaligned start, a start past the top, and a
//!   null or kernel-half buffer are refused (`InvalidAddress`); a cap without
//!   `CONTROL` is refused (`InsufficientRights`);
//! - once B is deleted, its thread is refused (`InvalidState`).

use syscall::{
    MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PageRun, cap_create_aspace, cap_create_cspace,
    cap_create_thread, cap_delete, cap_derive, mem_map, mmio_map, mmio_split, raw_syscall4,
    thread_list_pages,
};
use syscall_abi::{
    MAX_PAGE_RUNS, PAGE_RUN_EXECUTE, PAGE_RUN_NO_COPY, PAGE_RUN_READ, PAGE_RUN_WRITE,
    RIGHTS_MEM_MAP_RX, RIGHTS_MMIO_MAP, RIGHTS_THREAD_OBSERVE, SYS_THREAD_LIST_PAGES, SyscallError,
};

use crate::{TestContext, TestResult};

const PAGE: u64 = 4096;

/// B's VA of the two writable pages; the read-only page follows them.
const B_RW: u64 = 0x4000_0000;
/// B's VA of the read-only page, right after the writable pages.
const B_RO: u64 = B_RW + 2 * PAGE;
/// B's VA of the executable page, apart from the others.
const B_TEXT: u64 = 0x4010_0000;
/// B's VA of the device page.
const B_DEVICE: u64 = 0x4050_0000;

/// Runs a [`Listing`] holds: more than B maps, so a listing that finds a
/// mapping B does not have fails instead of overflowing.
const LISTING_RUNS: usize = 8;

/// Calls one listing may make before it fails as one that never completes:
/// far more than a scan of an almost empty space takes at the kernel's bound
/// per call, or than one run a call takes for B's runs.
const MAX_CALLS: u32 = 4096;

/// Runs of the buffer of the many-runs listing: more than B maps, so its
/// calls end on the kernel's bound or the top, not on a full buffer.
const MANY_RUNS: usize = 16;

/// A kernel-half address, refused as a buffer on both architectures.
const KERNEL_HALF: u64 = 0xFFFF_FFC0_0000_0000;

/// The runs of a listing, adjacent runs of one protection joined.
struct Listing
{
    runs: [PageRun; LISTING_RUNS],
    len: usize,
}

impl Listing
{
    const fn new() -> Self
    {
        Self {
            runs: [PageRun {
                va: 0,
                pages: 0,
                prot: 0,
            }; LISTING_RUNS],
            len: 0,
        }
    }

    /// The runs held.
    fn runs(&self) -> &[PageRun]
    {
        self.runs.get(..self.len).unwrap_or(&[])
    }

    /// Add `run`, joining it to the last run when it continues that run with
    /// its protection.
    fn push(&mut self, run: PageRun) -> TestResult
    {
        if let Some(last) = self.len.checked_sub(1).and_then(|i| self.runs.get_mut(i))
            && last.prot == run.prot
            && last.va.checked_add(last.pages.saturating_mul(PAGE)) == Some(run.va)
        {
            last.pages = last.pages.saturating_add(run.pages);
            return Ok(());
        }
        let slot = self
            .runs
            .get_mut(self.len)
            .ok_or("integration::thread_list_pages: the listing holds more runs than B maps")?;
        *slot = run;
        self.len = self.len.saturating_add(1);
        Ok(())
    }
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut frames = [0u64; 4];
    for (i, cap) in frames.iter_mut().enumerate()
    {
        let Some(f) = crate::frame_pool::alloc()
        else
        {
            for f in frames.iter().take(i)
            {
                // SAFETY: allocated above, never mapped.
                unsafe { crate::frame_pool::free(*f) };
            }
            return Err("integration::thread_list_pages: frame pool exhausted");
        };
        *cap = f;
    }
    let result = in_space(ctx, frames);
    if result.is_ok()
    {
        for f in frames
        {
            // SAFETY: the frames were mapped only in B, which `in_space`
            // deleted on its success path.
            unsafe { crate::frame_pool::free(f) };
        }
    }
    result
}

/// Create B and its thread, run the checks, delete B, and check its thread is
/// then refused.
fn in_space(ctx: &TestContext, frames: [u64; 4]) -> TestResult
{
    let b = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "integration::thread_list_pages: cap_create_aspace failed")?;
    let Ok(cs) = cap_create_cspace(ctx.memory_base, 0, 4)
    else
    {
        cap_delete(b).ok();
        return Err("integration::thread_list_pages: cap_create_cspace failed");
    };
    let Ok(th) = cap_create_thread(ctx.memory_base, b, cs, 0, 0)
    else
    {
        cap_delete(cs).ok();
        cap_delete(b).ok();
        return Err("integration::thread_list_pages: cap_create_thread failed");
    };
    let result = map_all(b, frames).and_then(|()| with_device(ctx, b, th));
    let deleted = cap_delete(b).is_ok();
    let mut runs = [PageRun::default(); 1];
    let gone = thread_list_pages(th, 0, &mut runs);
    let ok = cap_delete(th).is_ok() & cap_delete(cs).is_ok();
    result?;
    if !deleted
    {
        return Err("integration::thread_list_pages: cap_delete(aspace) failed");
    }
    if gone != Err(SyscallError::InvalidState as i64)
    {
        return Err("integration::thread_list_pages: a thread of a deleted space was not refused");
    }
    if !ok
    {
        return Err("integration::thread_list_pages: thread or CSpace cleanup failed");
    }
    Ok(())
}

/// Map B's writable, read-only and executable pages.
fn map_all(b: u64, [w0, w1, ro, text]: [u64; 4]) -> TestResult
{
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_map(w0, b, B_RW, 0, 1, MAP_WRITABLE) }
        .and_then(|()| {
            // SAFETY: as above.
            unsafe { mem_map(w1, b, B_RW + PAGE, 0, 1, MAP_WRITABLE) }
        })
        .and_then(|()| {
            // SAFETY: as above.
            unsafe { mem_map(ro, b, B_RO, 0, 1, MAP_READ) }
        })
        .map_err(|_| "integration::thread_list_pages: B data mem_map failed")?;
    // Executable through an Execute-bearing, Write-less copy, as a loader
    // maps text; the mapping outlives the copy.
    let rx = cap_derive(text, RIGHTS_MEM_MAP_RX)
        .map_err(|_| "integration::thread_list_pages: cap_derive of the text frame failed")?;
    // SAFETY: as above.
    let mapped = unsafe { mem_map(rx, b, B_TEXT, 0, 1, MAP_EXECUTABLE) };
    cap_delete(rx).ok();
    mapped.map_err(|_| "integration::thread_list_pages: B text mem_map failed")
}

/// Map a device page into B when the boot hands ktest an `Mmio` (a Map-only
/// copy of the first boot `Mmio` cap, its handle the `InitInfo` descriptor's
/// ([`crate::unit::hw::boot_caps`]), one page carved off it, as
/// `crate::integration::thread_memory` does), then run the listing checks,
/// with the device page expected when it was mapped.
fn with_device(ctx: &TestContext, b: u64, th: u64) -> TestResult
{
    for boot in crate::unit::hw::boot_caps(ctx, init_protocol::CapType::Mmio)
    {
        let Ok(copy) = cap_derive(boot.slot, RIGHTS_MMIO_MAP)
        else
        {
            continue;
        };
        // A one-page region cannot be split at its first page
        // (`InvalidArgument`); any other refusal moves on to the next.
        let lo = match mmio_split(copy, PAGE)
        {
            Ok((lo, hi)) =>
            {
                cap_delete(hi).ok();
                lo
            }
            Err(e) if e == SyscallError::InvalidArgument as i64 => copy,
            Err(_) =>
            {
                cap_delete(copy).ok();
                continue;
            }
        };
        // SAFETY: `b` is an address space this test created, not ktest's own.
        let result = unsafe { mmio_map(b, lo, B_DEVICE, 0) }
            .map_err(|_| "integration::thread_list_pages: mmio_map of the device page failed")
            .and_then(|()| listings(th, Some(B_DEVICE)));
        // Deleting the page's cap withdraws its mapping from B.
        cap_delete(lo).ok();
        return result;
    }
    crate::log("ktest: integration::thread_list_pages device page SKIP (no Mmio)");
    listings(th, None)
}

/// The listing checks, then the refusals; `device` is the VA of B's device
/// page when B maps one.
fn listings(th: u64, device: Option<u64>) -> TestResult
{
    let mut expected = Listing::new();
    expected.push(PageRun {
        va: B_RW,
        pages: 2,
        prot: PAGE_RUN_READ | PAGE_RUN_WRITE,
    })?;
    expected.push(PageRun {
        va: B_RO,
        pages: 1,
        prot: PAGE_RUN_READ,
    })?;
    expected.push(PageRun {
        va: B_TEXT,
        pages: 1,
        prot: PAGE_RUN_READ | PAGE_RUN_EXECUTE,
    })?;
    if let Some(va) = device
    {
        expected.push(PageRun {
            va,
            pages: 1,
            prot: PAGE_RUN_READ | PAGE_RUN_NO_COPY,
        })?;
    }
    let mut many = [PageRun::default(); MANY_RUNS];
    let (full, top) = list(th, &mut many)?;
    if full.runs() != expected.runs()
    {
        log_runs(&full);
        return Err("integration::thread_list_pages: the listing is not B's mappings");
    }
    let mut one = [PageRun::default(); 1];
    let (paged, paged_top) = list(th, &mut one)?;
    if paged.runs() != expected.runs() || paged_top != top
    {
        log_runs(&paged);
        return Err("integration::thread_list_pages: the listing one run a call differs");
    }
    if thread_list_pages(th, top, &mut one) != Ok((0, top))
    {
        return Err("integration::thread_list_pages: a call at the top returned runs");
    }
    refusals(th, top)
}

/// List B from 0 with `buf` as each call's run buffer, continuing from each
/// call's resume address until a call returns no run and its own start: the
/// top of the user half, which is returned with the joined runs. A call that
/// returns more runs than `buf` holds, a run below its start or out of
/// order, or a resume address before its start fails the listing.
fn list(th: u64, buf: &mut [PageRun]) -> Result<(Listing, u64), &'static str>
{
    let mut listing = Listing::new();
    let mut start = 0u64;
    for _ in 0..MAX_CALLS
    {
        let (count, resume) = thread_list_pages(th, start, buf)
            .map_err(|_| "integration::thread_list_pages: a listing call was refused")?;
        let runs = buf
            .get(..count)
            .ok_or("integration::thread_list_pages: a call returned more runs than asked for")?;
        let mut next = start;
        for run in runs
        {
            if run.va < next
                || run.pages == 0
                || run.va.saturating_add(run.pages.saturating_mul(PAGE)) > resume
            {
                return Err("integration::thread_list_pages: a run lies out of order");
            }
            next = run.va.saturating_add(run.pages.saturating_mul(PAGE));
            listing.push(*run)?;
        }
        if resume < start
        {
            return Err("integration::thread_list_pages: a call resumed before its start");
        }
        if count == 0 && resume == start
        {
            return Ok((listing, start));
        }
        start = resume;
    }
    Err("integration::thread_list_pages: the listing did not complete")
}

/// Run counts of 0 and past `MAX_PAGE_RUNS`, an unaligned start, a start
/// past `top`, a null and a kernel-half buffer, and a cap without `CONTROL`
/// are refused.
fn refusals(th: u64, top: u64) -> TestResult
{
    let invalid_argument = Err(SyscallError::InvalidArgument as i64);
    let invalid_address = Err(SyscallError::InvalidAddress as i64);
    let mut one = [PageRun::default(); 1];
    if thread_list_pages(th, 0, &mut []) != invalid_argument
    {
        return Err("integration::thread_list_pages: a count of 0 was not refused");
    }
    if thread_list_pages(th, 1, &mut one) != invalid_address
        || thread_list_pages(th, top.saturating_add(PAGE), &mut one) != invalid_address
    {
        return Err("integration::thread_list_pages: a bad start was not refused");
    }
    // The kernel checks the count before the buffer, and refuses a buffer it
    // cannot write before it writes, so no call below writes memory.
    let raw = |buf: u64, count: u64| {
        // SAFETY: each call is refused before the kernel writes (the count, or
        // the buffer's range), so no memory changes.
        unsafe { raw_syscall4(SYS_THREAD_LIST_PAGES, th, 0, buf, count) }
    };
    if raw(one.as_mut_ptr() as u64, MAX_PAGE_RUNS.saturating_add(1))
        != SyscallError::InvalidArgument as i64
    {
        return Err("integration::thread_list_pages: a count past MAX_PAGE_RUNS was not refused");
    }
    if raw(0, 1) != SyscallError::InvalidAddress as i64
        || raw(KERNEL_HALF, 1) != SyscallError::InvalidAddress as i64
    {
        return Err("integration::thread_list_pages: a null or kernel-half buffer was not refused");
    }
    let observe = cap_derive(th, RIGHTS_THREAD_OBSERVE)
        .map_err(|_| "integration::thread_list_pages: cap_derive of the thread failed")?;
    let refused = thread_list_pages(observe, 0, &mut one);
    cap_delete(observe).ok();
    if refused != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("integration::thread_list_pages: a cap without CONTROL was not refused");
    }
    Ok(())
}

/// Log each run of a listing that failed its check.
fn log_runs(listing: &Listing)
{
    for run in listing.runs()
    {
        crate::log_u64("ktest: integration::thread_list_pages run va=", run.va);
        crate::log_u64(
            "ktest: integration::thread_list_pages run pages=",
            run.pages,
        );
        crate::log_u64("ktest: integration::thread_list_pages run prot=", run.prot);
    }
}
