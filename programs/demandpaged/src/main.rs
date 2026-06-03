// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/demandpaged/src/main.rs

//! Demand-paging fixture for the svctest pager phase.
//!
//! Spawned with `std::os::seraph::CommandExt::demand_paged(true)`, so procmgr
//! binds this process's fault handler to memmgr (the pager). Two modes,
//! selected by argv:
//!
//!   * default — reserve an unbacked region, register it as demand-paged, and
//!     write a per-page pattern across it. Each first touch faults to memmgr,
//!     which backs the page and resumes. A second read-back pass verifies the
//!     data persisted (no re-fault, no zero-fill), proving the round-trip.
//!     Exits `SUCCESS` on success; a register failure or mismatch exits
//!     non-zero.
//!   * `oor` — touch a reserved but *unregistered* page. The pager finds no
//!     region and declines, so the kernel kills this process. If the touch
//!     somehow survives (a pager bug), exit `SUCCESS` so the harness's "must
//!     be killed" assertion fails loudly rather than hanging.
//!
//! Driven by `services/svctest`'s pager phase.

use std::os::seraph::{register_demand_paged, reserve_pages};
use std::process::ExitCode;

const PAGES: usize = 4;
const PAGE: usize = 4096;

fn main() -> ExitCode
{
    if std::env::args().any(|a| a == "oor")
    {
        out_of_region()
    }
    else
    {
        in_region()
    }
}

// cast_possible_truncation: the pattern byte is intentionally the low 8 bits of
// a per-(page, byte) mix; truncation is the point.
#[allow(clippy::cast_possible_truncation)]
fn pattern(page: usize, byte: usize) -> u8
{
    (page as u8).wrapping_mul(31).wrapping_add(byte as u8)
}

fn in_region() -> ExitCode
{
    let Ok(range) = register_demand_paged(PAGES as u64)
    else
    {
        return ExitCode::from(2);
    };
    let base = range.va_start() as *mut u8;

    // First pass: write. The first store into each page faults; memmgr backs it
    // and the store retries against the now-mapped page.
    for p in 0..PAGES
    {
        let off = p * PAGE;
        for i in 0..PAGE
        {
            // SAFETY: [base, base + PAGES*PAGE) is a registered demand-paged
            // region; touches are backed by the pager on fault.
            unsafe {
                *base.add(off + i) = pattern(p, i);
            }
        }
    }

    // Second pass: read back. Proves the pages stayed mapped (no re-fault, no
    // zero-fill) and were mapped writable.
    for p in 0..PAGES
    {
        let off = p * PAGE;
        for i in 0..PAGE
        {
            // SAFETY: same region, now fully backed.
            let got = unsafe { *base.add(off + i) };
            if got != pattern(p, i)
            {
                return ExitCode::from(3);
            }
        }
    }
    ExitCode::SUCCESS
}

fn out_of_region() -> ExitCode
{
    let Ok(range) = reserve_pages(1)
    else
    {
        return ExitCode::from(2);
    };
    let p = range.va_start() as *mut u8;
    // SAFETY: deliberate fault on an unregistered VA. The pager replies KILL
    // and control should not return.
    unsafe {
        core::ptr::write_volatile(p, 0xAB);
    }
    // Reached only if the pager wrongly backed an unregistered fault; exit
    // success so the harness's "must be killed" assertion fails loudly.
    ExitCode::SUCCESS
}
