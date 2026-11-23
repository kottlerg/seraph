// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/ubench/src/fsbench.rs

//! The filesystem benchmarks: `/programs/fsbench` run at its full counts.
//!
//! fsbench measures `std::fs::File`'s read and write paths and the open of a
//! three-component path, and logs its own result lines, `fsbench.read`,
//! `fsbench.write` and `fsbench.open` (programs/fsbench/README.md § Output); the suite runs it as it is, so one
//! program owns the method whichever harness runs it.

use crate::harness::Outcome;

/// Where the build installs fsbench.
const FSBENCH: &str = "/programs/fsbench";

/// Run fsbench with no iteration count, its full benchmark, and wait for it.
///
/// # Errors
/// A spawn that fails, or an exit that is not a success: fsbench panics on
/// any failed step, so its result lines are then incomplete.
pub fn run() -> Outcome
{
    let status = std::process::Command::new(FSBENCH)
        .status()
        .map_err(|e| format!("spawn {FSBENCH}: {e}"))?;
    if status.success()
    {
        Ok(())
    }
    else
    {
        Err(format!("{FSBENCH} exited: {status}"))
    }
}
