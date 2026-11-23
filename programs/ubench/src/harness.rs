// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/ubench/src/harness.rs

//! What every ubench benchmark shares: the pinning of a measuring thread, the
//! result line it logs, and the SKIP line of a case it cannot run.
//!
//! A benchmark returns `Err` with a reason when it fails; `main` logs that
//! reason as the benchmark's FAIL line (programs/ubench/README.md § Output).

use bench::{Report, Unit, Value};

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

/// Log the result line of `name` and `variant` over `samples`, cycles each,
/// with `extras` after its summary.
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
) -> Outcome
{
    let summary = bench::summarize(samples).ok_or_else(|| "no sample recorded".to_string())?;
    let report = Report {
        suite: SUITE,
        name,
        variant,
        cpus,
        unit: Unit::Cycles,
        summary,
        extras,
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
