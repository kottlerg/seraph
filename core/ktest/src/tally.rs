// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/tally.rs

//! Failure tallies and receive-guard diagnostics shared by the stress cells.
//!
//! A race cell's children classify each result of the syscalls under test
//! into the results the scenario accepts and the rest. A child cannot return
//! a `TestResult`, so it counts the rest, keeping the last offending result
//! word, in a [`BadTally`] the cell's report checks once the rounds are
//! over; the tally is the channel through which a child's failure reaches
//! the verdict. [`log_error`] prints a syscall error word the way the
//! tallies record it, and [`recv_diag`] is the diagnostic hook the cells'
//! blocking receive loops hand their `RecvGuard`
//! ([docs/ipc-design.md](../../../docs/ipc-design.md) § Receive-Failure
//! Policy).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::recv_guard::RecvFailureStage;

use crate::TestResult;

/// Results a cell's children recorded as bad: their count, and the last
/// such result word (a value, or an error word) for the failure report.
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

    /// Record a bad result `word`.
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
    /// the last result under `cell`, the cell's log name (`stress::<name>`).
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
/// heap); a prefix longer than the buffer is cut.
fn log_cell_u64(cell: &str, suffix: &str, value: u64)
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
/// none; at the fatal stage the guard then ends the harness with
/// `EXIT_RECV_WEDGE`.
pub fn recv_diag(stage: RecvFailureStage, error: i64)
{
    let label = match stage
    {
        RecvFailureStage::First => "ktest: blocking receive failing, backing off; error=",
        RecvFailureStage::Fatal => "ktest: blocking receive wedged, exiting; error=",
    };
    log_error(label, error);
}
