// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/tally.rs

//! Failure tallies and receive-guard diagnostics shared by the stress cells.
//!
//! A race cell's children classify each result of the syscalls under test
//! into the results the scenario accepts and the rest. A child cannot return
//! a `TestResult`, so it counts the rest, keeping an offending result word,
//! in a [`BadTally`] the cell's report checks once the rounds are over; the
//! tally is the channel through which a child's failure reaches the
//! verdict. [`log_error`] prints a syscall error word the way the tallies
//! record it, [`log_cell_u64`] prints a value under a cell's name,
//! [`await_report`] is a cell's bounded wait for a child's report bits,
//! [`await_all`] its wait for every child's bit, and
//! [`recv_diag`] is the diagnostic hook the cells' blocking receive loops
//! hand their `RecvGuard`
//! ([docs/ipc-design.md](../../../docs/ipc-design.md) § Receive-Failure
//! Policy).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::recv_guard::RecvFailureStage;

use crate::TestResult;

/// Results a cell's children recorded as bad: their count, and one of the
/// last such result words (a value, or an error word) for the failure
/// report; the last, unless children record concurrently.
pub struct BadTally
{
    count: AtomicU32,
    last: AtomicU64,
}

impl BadTally
{
    /// An empty tally.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            count: AtomicU32::new(0),
            last: AtomicU64::new(0),
        }
    }

    /// Empty the tally, for a cell that runs several phases.
    pub fn reset(&self)
    {
        self.count.store(0, Ordering::Release);
        self.last.store(0, Ordering::Release);
    }

    /// Record a bad result `word`. The word and the count are two atomics,
    /// stored one after the other, so under concurrent recorders the word
    /// the report shows is one of the last recorded, not necessarily the
    /// last: the report needs a witness of the failure, not its order.
    pub fn record(&self, word: u64)
    {
        self.last.store(word, Ordering::Release);
        self.count.fetch_add(1, Ordering::AcqRel);
    }

    /// Record a bad syscall `error`.
    pub fn record_error(&self, error: i64)
    {
        // cast_sign_loss: the raw error word is only logged.
        #[allow(clippy::cast_sign_loss)]
        self.record(error as u64);
    }

    /// Fail with `message` if anything was recorded, logging the count and
    /// the recorded result word (one of the last, per [`record`](Self::record))
    /// under `cell`, the cell's log name (`stress::<name>`).
    pub fn check(&self, cell: &str, message: &'static str) -> TestResult
    {
        let n = self.count.load(Ordering::Acquire);
        if n == 0
        {
            return Ok(());
        }
        log_cell_u64(cell, " bad count=", u64::from(n));
        log_cell_u64(cell, " last bad result=", self.last.load(Ordering::Acquire));
        Err(message)
    }
}

impl Default for BadTally
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Log `value` after `ktest: <cell><suffix>`, composed in a stack buffer (no
/// heap); a prefix longer than the buffer is cut. `cell` is the cell's log
/// name (`stress::<name>`) and `suffix` starts with the separating space.
pub fn log_cell_u64(cell: &str, suffix: &str, value: u64)
{
    let mut prefix = [0u8; 96];
    let mut len = 0usize;
    for part in ["ktest: ", cell, suffix]
    {
        let bytes = part.as_bytes();
        let n = bytes.len().min(prefix.len() - len);
        prefix[len..len + n].copy_from_slice(&bytes[..n]);
        len += n;
    }
    crate::log_u64(core::str::from_utf8(&prefix[..len]).unwrap_or("?"), value);
}

/// Log a syscall error word after `label`.
pub fn log_error(label: &str, error: i64)
{
    // cast_sign_loss: the raw error word is only logged.
    #[allow(clippy::cast_sign_loss)]
    crate::log_u64(label, error as u64);
}

/// Diagnostic hook for a cell's `RecvGuard`: log the stage and the error
/// word. ktest logs each cell's name before running it, so the line names
/// none. At the fatal stage the guard then calls `SYS_PROCESS_EXIT` with
/// `EXIT_RECV_WEDGE`, which ends the calling thread alone, with that exit
/// reason, since ktest has no procmgr to reap the rest of the process
/// (core/kernel/docs/syscalls.md § `SYS_PROCESS_EXIT`). Every cell wait
/// that depends on the receiver is bounded or polls its exit, so the dead
/// receiver fails the cell's round rather than hanging the harness.
pub fn recv_diag(stage: RecvFailureStage, error: i64)
{
    let label = match stage
    {
        RecvFailureStage::First => "ktest: blocking receive failing, backing off; error=",
        RecvFailureStage::Fatal => "ktest: blocking receive wedged, exiting; error=",
    };
    log_error(label, error);
}

/// Each [`await_report`] or [`await_all`] waits in slices of this many
/// milliseconds, at most [`REPORT_SLICES`] of them (5 s in all), the count
/// applied through [`crate::scaled_bound`].
const REPORT_SLICE_MS: u64 = 5;
const REPORT_SLICES: u64 = 1000;

/// Accumulate the bits children send on `done` into `acc` until one of
/// `mask` is present, failing with `err` once [`REPORT_SLICES`] slices
/// (through [`crate::scaled_bound`]) pass without it, so a child that never
/// reports fails the cell instead of hanging the run. A child has no channel
/// but `done` to report on, so a report send it could not make surfaces
/// here, as the timeout.
///
/// # Errors
///
/// `err` when the bound runs out; a fixed message when the wait on `done`
/// itself fails.
pub fn await_report(done: u32, acc: &mut u64, mask: u64, err: &'static str) -> TestResult
{
    await_bits(done, acc, |bits| bits & mask != 0, err)
}

/// Like [`await_report`], but until every bit of `mask` is present: the wait
/// a cell makes for each of its children to report the same state (one bit
/// per child). A cell so awaits at most 64 children, the width of the `u64`
/// notification word.
///
/// # Errors
///
/// `err` when the bound runs out; a fixed message when the wait on `done`
/// itself fails.
pub fn await_all(done: u32, acc: &mut u64, mask: u64, err: &'static str) -> TestResult
{
    await_bits(done, acc, |bits| bits & mask == mask, err)
}

/// Accumulate `done`'s bits into `acc` until `reached` holds of them, in at
/// most [`REPORT_SLICES`] slices through [`crate::scaled_bound`]; the bound
/// [`await_report`] and [`await_all`] share.
fn await_bits(
    done: u32,
    acc: &mut u64,
    reached: impl Fn(u64) -> bool,
    err: &'static str,
) -> TestResult
{
    for _ in 0..crate::scaled_bound(REPORT_SLICES)
    {
        if reached(*acc)
        {
            return Ok(());
        }
        *acc |= syscall::notification_wait_timeout(done, REPORT_SLICE_MS)
            .map_err(|_| "tally: wait on the report notification failed")?;
    }
    if reached(*acc) { Ok(()) } else { Err(err) }
}
