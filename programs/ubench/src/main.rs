// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/ubench/src/main.rs

//! ubench: the userspace benchmark suite.
//!
//! Runs from `rootfs/config/svcmgr/tests/ubench.svc`, staged into a boot as
//! svctest's recipe is, and measures, in cycles, what the system's userspace
//! paths cost a process: an IPC round trip through `shared/ipc`, the backing
//! of fresh memory by a demand fault and by a grant, the fault path on several
//! CPUs at once, the stdio pipe's byte ring, console text on the framebuffer,
//! and `std::fs::File` reads and writes (programs/ubench/README.md
//! § Benchmarks).
//!
//! Each benchmark logs its result lines (shared/bench/README.md § Result
//! line), a SKIP line for a case the boot cannot run, or one FAIL line. The run
//! ends with `ALL TESTS PASSED` when no benchmark failed, `SOME TESTS FAILED`
//! otherwise, and powers the system off through the `pwrmgr.shutdown` seed.

mod console;
mod fault;
mod fsbench;
mod harness;
mod ipc_rt;
mod shmem_ring;

use bench::Counters;

use harness::{BENCH_CPU, Outcome};

/// The recipe's seeds, in its `seed =` order.
const SEED_SLOTS: usize = 2;

/// Slot of `devmgr.class.framebuffer`, the class `console_write` writes to.
const FB_CLASS_SLOT: usize = 0;

/// Slot of `pwrmgr.shutdown`, the authority that ends the boot.
const SHUTDOWN_SLOT: usize = 1;

fn main()
{
    std::os::seraph::log::register_name(b"ubench");
    let seeds = bootstrap_seeds();
    std::os::seraph::log!("starting");

    let failed = match setup()
    {
        Ok((counters, cpus)) => run_all(&counters, cpus, seeds[FB_CLASS_SLOT]),
        Err(e) =>
        {
            std::os::seraph::log!("set-up failed: {e}");
            1
        }
    };
    if failed == 0
    {
        std::os::seraph::log!("ALL TESTS PASSED");
    }
    else
    {
        std::os::seraph::log!("failed={failed}");
        std::os::seraph::log!("SOME TESTS FAILED");
    }
    shutdown(seeds[SHUTDOWN_SLOT]);
}

/// Pin the harness thread to [`BENCH_CPU`] and open its counters there; the
/// counters and the CPU count every result line carries.
fn setup() -> Result<(Counters, u32), String>
{
    harness::pin_to(BENCH_CPU)?;
    let cpus = harness::cpu_count()?;
    Ok((Counters::open(), cpus))
}

/// Run every benchmark in turn; the number that failed, each logged as its
/// FAIL line.
fn run_all(counters: &Counters, cpus: u32, fb_class: u64) -> usize
{
    let benches: [(&str, &dyn Fn() -> Outcome); 6] = [
        ("ipc_rt", &|| ipc_rt::run(counters, cpus)),
        ("fault_fill", &|| fault::fill(counters, cpus)),
        ("fault_scaling", &|| fault::scaling(cpus)),
        ("shmem_ring", &|| shmem_ring::run(counters, cpus)),
        ("console_write", &|| console::run(fb_class, counters, cpus)),
        ("fsbench", &fsbench::run),
    ];
    let mut failed = 0usize;
    for (name, bench) in benches
    {
        if let Err(why) = bench()
        {
            std::os::seraph::log!("bench {name} FAIL ({why})");
            failed = failed.saturating_add(1);
        }
    }
    failed
}

/// The recipe's seeds from the creator-endpoint rounds, an absent one as 0.
fn bootstrap_seeds() -> [u64; SEED_SLOTS]
{
    let info = std::os::seraph::startup_info();
    if info.creator_endpoint == 0
    {
        return [0; SEED_SLOTS];
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::bootstrap::request_slots::<SEED_SLOTS>(info.creator_endpoint, ipc_buf) }
        .unwrap_or([0; SEED_SLOTS])
}

/// Ask pwrmgr to power off. A reply arrives only when it cannot, and the log
/// then records why; without the seed the boot stays up.
fn shutdown(pwrmgr_auth: u64)
{
    if pwrmgr_auth == 0
    {
        std::os::seraph::log!("pwrmgr shutdown skipped: no authority cap");
        return;
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    match unsafe { ipc::ipc_call(pwrmgr_auth, &msg, ipc_buf) }
    {
        Ok(r) => std::os::seraph::log!(
            "pwrmgr SHUTDOWN returned unexpectedly (label={:#x})",
            r.label
        ),
        Err(e) => std::os::seraph::log!("pwrmgr SHUTDOWN ipc_call failed: error {e}"),
    }
}
