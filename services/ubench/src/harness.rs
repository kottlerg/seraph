// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/ubench/src/harness.rs

//! What every ubench benchmark shares: the pinning of a measuring thread, the
//! span of its CPU's idle-halt count over a measured loop, the result line it
//! logs, and the SKIP line of a case it cannot run.
//!
//! A benchmark returns `Err` with a reason when it fails; `main` logs that
//! reason as the benchmark's FAIL line (services/ubench/README.md § Output).

use bench::{IDLE_HALTS, Report, Unit, Value};

/// The suite of every result line ubench logs itself.
pub const SUITE: &str = "ubench";

/// The CPU the harness thread, and every single-CPU benchmark, runs on: CPU 0
/// is online on every boot.
pub const BENCH_CPU: u32 = 0;

/// A benchmark's outcome: `Ok` once it logged its result lines and the SKIP
/// lines of the cases it could not run, `Err` with the reason it failed.
pub type Outcome = Result<(), String>;

/// Pin the calling thread to `cpu` and move it there.
///
/// Hard affinity moves a thread running elsewhere at its next entry to the
/// scheduler, so the thread yields once: it then runs on `cpu`, and a
/// `bench::Counters` it opens reads that CPU's counters.
pub fn pin_to(cpu: u32) -> Result<(), String>
{
    let thread = std::os::seraph::thread::current_thread_cap();
    syscall::thread_set_affinity(thread, cpu)
        .map_err(|e| format!("pin to CPU {cpu}: error {e}"))?;
    syscall::thread_yield().map_err(|e| format!("yield after the pin to CPU {cpu}: error {e}"))
}

/// CPUs the system runs (`SystemInfoType::CpuCount`).
pub fn cpu_count() -> Result<u32, String>
{
    let count = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .map_err(|e| format!("CPU count: error {e}"))?;
    u32::try_from(count).map_err(|_| format!("CPU count {count} does not fit in u32"))
}

/// The idle-halt count of the CPU the calling thread runs on, marked right
/// before a measured loop, whose halts since the mark [`IdleSpan::close`]
/// reads right after it (shared/bench/README.md § Idle halts). The thread is
/// pinned to that CPU for the whole loop and makes no other `IdleHalts` call
/// in it.
pub struct IdleSpan(());

impl IdleSpan
{
    /// Mark the count where the measured loop begins: an `IdleHalts` call
    /// whose value is not read.
    pub fn open() -> Self
    {
        let _ = syscall::idle_halts();
        Self(())
    }

    /// The halts of the CPU since [`IdleSpan::open`], read where the
    /// measured loop ends; `None` when the read failed, and the line then
    /// carries no `idle_halts=`.
    pub fn close(self) -> Option<u64>
    {
        // The span ends here: its marker is consumed, so a span is closed once.
        let Self(()) = self;
        syscall::idle_halts().ok()
    }
}

/// Log the result line of `name` and `variant` over `samples`, cycles each,
/// with `extras` after its summary and then `idle_halts`, the halts of the
/// measuring CPU over the measured loop ([`IdleSpan`]), when it has them.
///
/// # Errors
/// No sample, or a report the line's rules refuse
/// (shared/bench/README.md § Result line).
pub fn report(
    name: &str,
    variant: &[(&str, Value<'_>)],
    cpus: u32,
    samples: &mut [u64],
    extras: &[(&str, u64)],
    idle_halts: Option<u64>,
) -> Outcome
{
    let summary = bench::summarize(samples).ok_or_else(|| "no sample recorded".to_string())?;
    let mut extras = extras.to_vec();
    extras.extend(idle_halts.map(|halts| (IDLE_HALTS, halts)));
    let report = Report {
        suite: SUITE,
        name,
        variant,
        cpus,
        unit: Unit::Cycles,
        summary,
        extras: &extras,
    };
    let mut line = String::new();
    report
        .write(&mut line)
        .map_err(|e| format!("result line: {e}"))?;
    std::os::seraph::log!("{line}");
    Ok(())
}

/// Log the SKIP line of one case of `name`, the case and why it did not run in
/// `why`.
pub fn skip(name: &str, why: &str)
{
    std::os::seraph::log!("bench {name} SKIP ({why})");
}
