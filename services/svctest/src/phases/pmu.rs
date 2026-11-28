// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/pmu.rs

//! The performance-counter path end to end: svcmgr gives svctest the
//! `PmuControl` copy its `pmu_authority` recipe names, and svctest counts a
//! loop through `bench::EventCounters`, the columns a benchmark reports.
//!
//! The copy carries `Configure` alone, and `SYS_PMU_INFO` through it answers
//! or refuses `NotSupported`, which the kernel returns only after the
//! capability checks pass. On a CPU with counters a pinned thread opens
//! `Instructions` and `Cycles`, counts a loop of known length, and closes
//! them; riscv64 has counters under QEMU (Sscofpmf), so a refusal there
//! fails. On a CPU with none (x86-64 under QEMU, which gives the guest no
//! PMU) the open is refused `NotSupported`. Both check that a set of events a
//! reading cannot hold is refused `InvalidArgument` before any syscall.

use bench::EventCounters;
use pmu::client::Pmu;
use pmu::{PmuEvent, PmuMode};
use syscall_abi::SyscallError;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// Iterations of the counted loop.
const LOOP_N: u64 = 100_000;

/// Instructions retired per iteration of the counted loop, at most, with the
/// two reads around it: the loop body is a handful of instructions on either
/// architecture, so the bound fails only a count that is not the loop's.
const MAX_PER_ITERATION: u64 = 64;

/// The CPU the counting thread pins itself to.
const CPU: u32 = 0;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "pmu_authority",
        run: pmu_phase,
    }]
}

/// Check the copy svcmgr delivered, then count through it, or check the
/// refusals where the CPU has no counters.
fn pmu_phase(caps: &Caps)
{
    let cap = caps.pmu_authority;
    assert_ne!(
        cap, 0,
        "pmu_authority: no PmuControl cap in the bootstrap slot"
    );
    let rights = syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
        .map(|tr| tr & u64::from(u32::MAX))
        .expect("pmu_authority: cap_info on the PmuControl cap failed");
    assert_eq!(
        rights,
        syscall::RIGHTS_PMU_CONFIGURE,
        "pmu_authority: the delivered copy does not carry Configure alone"
    );
    let pmu = Pmu::new(cap);

    // More events than a reading holds, refused before any syscall.
    let too_many = [
        PmuEvent::Cycles,
        PmuEvent::LlcReferences,
        PmuEvent::LlcMisses,
        PmuEvent::BranchInstructions,
        PmuEvent::BranchMisses,
    ];
    assert_eq!(
        EventCounters::open(pmu, 0, &too_many, PmuMode::User).err(),
        Some(SyscallError::InvalidArgument as i64),
        "pmu_authority: an event set a reading cannot hold was not refused InvalidArgument"
    );

    let counting = match pmu.info()
    {
        Ok(info) => info.present(),
        Err(code) if code == SyscallError::NotSupported as i64 => false,
        Err(code) => panic!("pmu_authority: SYS_PMU_INFO failed: {code}"),
    };
    assert!(
        counting || !cfg!(target_arch = "riscv64"),
        "pmu_authority: SYS_PMU_INFO reports no counters on riscv64"
    );
    let counted = std::thread::spawn(move || {
        let thread = pin_self();
        if counting
        {
            count(pmu, thread)
        }
        else
        {
            open_refused(pmu, thread)
        }
    })
    .join()
    .expect("pmu_authority: the counting thread panicked");
    std::os::seraph::log!("pmu_authority: {counted}");
}

/// The events the phase opens.
const EVENTS: [PmuEvent; 2] = [PmuEvent::Instructions, PmuEvent::Cycles];

/// Pin the calling thread to [`CPU`] and yield, so that it runs there, and
/// return its Thread cap. The pin ends with the thread.
fn pin_self() -> u64
{
    let thread = std::os::seraph::thread::current_thread_cap();
    assert_ne!(
        thread, 0,
        "pmu_authority: no Thread cap for the counting thread"
    );
    syscall::thread_set_affinity(thread, CPU)
        .unwrap_or_else(|e| panic!("pmu_authority: thread_set_affinity({CPU}) failed: {e}"));
    std::thread::yield_now();
    thread
}

/// Open [`EVENTS`] for `thread`, the caller pinned to [`CPU`], count
/// [`LOOP_N`] iterations, and close them.
fn count(pmu: Pmu, thread: u64) -> String
{
    let counters = EventCounters::open(pmu, thread, &EVENTS, PmuMode::User)
        .unwrap_or_else(|e| panic!("pmu_authority: open failed: {e}"));
    let start = counters.read();
    core::hint::black_box(counted_loop(LOOP_N));
    let end = counters.read();
    let delta = counters.since(&end, &start);
    counters
        .close()
        .unwrap_or_else(|e| panic!("pmu_authority: close failed: {e}"));
    let instret = delta
        .instret
        .expect("pmu_authority: no instructions column");
    let cycles = delta.events[0].expect("pmu_authority: no cycles column");
    assert!(
        (LOOP_N..=LOOP_N * MAX_PER_ITERATION).contains(&instret),
        "pmu_authority: {instret} instructions counted across {LOOP_N} iterations"
    );
    assert_ne!(cycles, 0, "pmu_authority: no core cycles counted");
    format!("instructions={instret} cycles={cycles}")
}

/// On a CPU with no counters, the open of [`EVENTS`] for `thread`, the
/// caller pinned to [`CPU`], is refused.
fn open_refused(pmu: Pmu, thread: u64) -> String
{
    assert_eq!(
        EventCounters::open(pmu, thread, &EVENTS, PmuMode::User).err(),
        Some(SyscallError::NotSupported as i64),
        "pmu_authority: an open on a CPU with no counters was not refused NotSupported"
    );
    String::from("no counters, open refused")
}

/// A counted loop of `n` iterations.
#[inline(never)]
fn counted_loop(n: u64) -> u64
{
    let mut acc = 0u64;
    for i in 0..n
    {
        acc = core::hint::black_box(acc.wrapping_add(i));
    }
    acc
}
