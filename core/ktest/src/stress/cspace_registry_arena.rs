// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cspace_registry_arena.rs

//! Stress test: more than 4096 `CSpace`s live at once.
//!
//! The kernel's `CSpace` registry is a RAM-sized arena with one id per page
//! of DRAM (core/kernel/docs/capability-internals.md § CSpace Registry), so
//! the live-`CSpace` count is bounded by the memory that pays for the
//! `CSpace`s, not by a fixed table. This test holds [`LIVE`] one-page
//! `CSpace`s at once, past the 4096 entries the former fixed registry held,
//! and fails if any creation is refused. It then deletes them all and checks
//! that `memory_base` gets back every page they took. It does not exhaust
//! the arena (131,072 ids at 512 MiB), so it does not show that a deleted
//! `CSpace`'s id returns to the registry; the kernel's `cap::registry` host
//! tests cover the free list's reuse.
//!
//! Each `CSpace` costs one page of `memory_base` and one slot in ktest's own
//! `CSpace`, which the test funds first through augment-mode
//! `cap_create_cspace`. The test logs the bytes it needs and the bytes
//! `memory_base` has before it starts, and skip-passes when they fall short.

use syscall::{cap_create_cspace, cap_delete, cap_info};
use syscall_abi::CAP_INFO_MEMORY_AVAILABLE;

use crate::{TestContext, TestResult};

/// `CSpace`s held live at once: one past the former fixed registry's 4096
/// entries, the least count that registry could not hold.
const LIVE: usize = 4097;

/// Slots per kernel `CSpace` leaf page (`cap::cspace::L2_SIZE`). An
/// underestimate here shows as a slot-pool failure of a creation, which the
/// test reports, not as a false pass.
const SLOTS_PER_PAGE: usize = 56;

/// Pages donated to ktest's `CSpace` for the [`LIVE`] caps: one leaf per
/// [`SLOTS_PER_PAGE`] slots, plus headroom for a directory page and the
/// harness's own later inserts.
const FUND_PAGES: u64 = LIVE.div_ceil(SLOTS_PER_PAGE) as u64 + 4;

const PAGE: u64 = 4096;

/// Handles of the live `CSpace`s. Static because the array (16.4 KB) is too
/// large for the harness stack; only this single-threaded test touches it.
static mut HANDLES: [u32; LIVE] = [0; LIVE];

pub fn run(ctx: &TestContext) -> TestResult
{
    let needed = (LIVE as u64 + FUND_PAGES) * PAGE;
    let had = available(ctx)?;
    log_budget(needed, had);
    if had < needed
    {
        crate::log("ktest: stress::cspace_registry_arena SKIP (memory-limited)");
        return Ok(());
    }

    cap_create_cspace(ctx.memory_base, ctx.cspace_cap, FUND_PAGES)
        .map_err(|_| "cspace_registry_arena: augmenting ktest's CSpace failed")?;
    let funded = available(ctx)?;

    // SAFETY: HANDLES is touched only by this test, which runs on the single
    // harness thread; no reference to it outlives this function.
    let handles = unsafe { &mut *core::ptr::addr_of_mut!(HANDLES) };
    let mut created: usize = 0;
    let mut outcome = Ok(());
    for slot in handles.iter_mut()
    {
        let Ok(cs) = cap_create_cspace(ctx.memory_base, 0, 1)
        else
        {
            crate::log_u64(
                "ktest: stress::cspace_registry_arena refused at live ",
                created as u64,
            );
            outcome = Err("cspace_registry_arena: cap_create_cspace refused below LIVE");
            break;
        };
        *slot = cs;
        created += 1;
    }

    for &cs in &handles[..created]
    {
        if cap_delete(cs).is_err() && outcome.is_ok()
        {
            outcome = Err("cspace_registry_arena: cap_delete failed");
        }
    }
    outcome?;

    // Every wrapper page came back: the teardown of each CSpace ran.
    if available(ctx)? != funded
    {
        return Err("cspace_registry_arena: memory_base did not get every CSpace page back");
    }
    Ok(())
}

/// `memory_base`'s retypable bytes.
fn available(ctx: &TestContext) -> Result<u64, &'static str>
{
    cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "cspace_registry_arena: cap_info(memory_base) failed")
}

/// Log `needed bytes <needed> available bytes <had>` on one line.
fn log_budget(needed: u64, had: u64)
{
    const PREFIX: &[u8] = b"ktest: stress::cspace_registry_arena needed bytes ";
    const MIDDLE: &[u8] = b" available bytes ";
    let (needed_digits, needed_len) = decimal(needed);
    let (had_digits, had_len) = decimal(had);
    let mut line = [0u8; 128];
    let mut len = 0;
    for part in [
        PREFIX,
        &needed_digits[..needed_len],
        MIDDLE,
        &had_digits[..had_len],
    ]
    {
        line[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    crate::log(core::str::from_utf8(&line[..len]).unwrap_or("?"));
}

/// The decimal digits of `value` and their count.
fn decimal(mut value: u64) -> ([u8; 20], usize)
{
    let mut digits = [0u8; 20];
    let mut n = 0;
    loop
    {
        // Lossless: a decimal digit.
        #[allow(clippy::cast_possible_truncation)]
        let digit = (value % 10) as u8;
        digits[n] = b'0' + digit;
        n += 1;
        value /= 10;
        if value == 0
        {
            break;
        }
    }
    digits[..n].reverse();
    (digits, n)
}
