// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/mod.rs

//! Tier 3 — Benchmarks / profiling. The file layout and what each benchmark
//! reports are specified in `core/ktest/README.md` § Source Layout and
//! § Tier 3.
//!
//! Every benchmark reads its thread's counters (`bench::Counters`, from
//! `shared/bench`) around each measured operation, records one sample per
//! operation into the one sample buffer, and reports one result line
//! (`shared/bench/README.md` § Result line) through [`Harness::report`]. The
//! counter read is an unprivileged instruction, so no syscall sits on the
//! measurement path: `rdtsc` on x86-64 (the kernel clears `CR4.TSD` on every
//! CPU) and `csrr cycle` on riscv64 (the kernel sets `scounteren.CY` on every
//! hart).
//!
//! # Adding a new benchmark
//!
//! 1. Add a `fn bench_<name>` taking `&mut Harness` to the surface's file
//!    under `bench/`, placed as the README's § Tier 3 layout rule says.
//! 2. Take the recorder and the counters with [`Harness::recorder`], run at
//!    most [`Harness::iters`] iterations, and record each measured
//!    operation's `Reading::since` cycles.
//! 3. Report the summary with [`Harness::report`], and call the benchmark
//!    from [`run_all`] below.

mod cap;
mod event;
mod ipc;
mod mm;
mod notification;
mod null;
mod thread;
mod tlb;
mod wait_set;

use ::bench::{Counters, Report, Samples, Summary, Unit, Value};

/// Most samples one benchmark records, and so most iterations it runs. The
/// bound limits only how many samples a summary covers, a p99 of 4096
/// samples resting on its 41 largest; its buffer, [`SAMPLES`], is 32 KiB of
/// BSS.
pub const MAX_ITERS: u32 = 4096;

/// [`MAX_ITERS`] as a buffer length.
pub(super) const MAX_SAMPLES: usize = MAX_ITERS as usize;

/// The `SYS_THREAD_SET_AFFINITY` argument that clears a thread's hard
/// affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// The sample buffer every benchmark records into in turn (ktest has no heap).
static mut SAMPLES: [u64; MAX_SAMPLES] = [0; MAX_SAMPLES];

/// What [`run_all`] hands each benchmark: its iteration count, the sample
/// buffer, ktest's counters and the CPU count its result lines carry.
pub(super) struct Harness
{
    /// Iterations each benchmark runs, at most [`MAX_ITERS`].
    iters: u32,
    /// CPUs the system runs (`SystemInfoType::CpuCount`).
    cpus: u32,
    /// The counters of ktest's harness thread, opened once.
    counters: Counters,
    /// The sample buffer, `SAMPLES`.
    buf: &'static mut [u64; MAX_SAMPLES],
}

impl Harness
{
    /// Iterations a benchmark runs: the configured count, cut to the samples
    /// the buffer holds.
    pub(super) const fn iters(&self) -> u32
    {
        self.iters
    }

    /// An empty recorder over the sample buffer, and the counters to time
    /// each operation with.
    pub(super) fn recorder(&mut self) -> (Samples<'_>, &Counters)
    {
        (Samples::new(&mut self.buf[..]), &self.counters)
    }

    /// The whole sample buffer, for a benchmark whose samples other threads
    /// record (`tlb::bench_tlb_shootdown_concurrent`).
    pub(super) fn buffer(&mut self) -> &mut [u64]
    {
        &mut self.buf[..]
    }

    /// Log `ktest: bench <name> SKIP (<reason>)`: the line of a benchmark
    /// that cannot run, logged in place of its result line, so that every
    /// benchmark [`run_all`] runs leaves one line or the other.
    #[expect(
        clippy::unused_self,
        reason = "a method, so that a benchmark logs its SKIP line through the Harness it \
                  reports through"
    )]
    pub(super) fn skip(&self, name: &str, reason: impl core::fmt::Display)
    {
        crate::log_args(format_args!("ktest: bench {name} SKIP ({reason})"));
    }

    /// Log the result line `bench ktest.<name> ...` of `summary`, with its
    /// variant parameters and extras; a benchmark that recorded no sample
    /// logs `ktest: bench <name> SKIP (no sample recorded)` instead. The line
    /// is streamed to the output channels whole, with no length cut.
    pub(super) fn report(
        &self,
        name: &str,
        variant: &[(&str, Value<'_>)],
        summary: Option<Summary>,
        extras: &[(&str, u64)],
    )
    {
        let Some(summary) = summary
        else
        {
            self.skip(name, "no sample recorded");
            return;
        };
        let report = Report {
            suite: "ktest",
            name,
            variant,
            cpus: self.cpus,
            unit: Unit::Cycles,
            summary,
            extras,
        };
        if let Err(e) = report.validate()
        {
            crate::log_args(format_args!("ktest: bench {name} FAIL (result line: {e})"));
            return;
        }
        // `write` cannot fail after `validate`: the output channels accept
        // every write.
        let _ = crate::log_with(|out| report.write(out));
    }
}

// ── Placement ─────────────────────────────────────────────────────────────────

/// The `CAP_INFO_THREAD_PLACEMENT` counts a round-trip benchmark reports, in
/// the order of their extras in [`Placement::extras`].
const COUNT_VIEWS: [u64; 4] = [
    syscall_abi::THREAD_PLACEMENT_REMOTE_WAKES,
    syscall_abi::THREAD_PLACEMENT_IDLE_WAKES,
    syscall_abi::THREAD_PLACEMENT_WAKE_MOVES,
    syscall_abi::THREAD_PLACEMENT_PULLS,
];

/// Where the two threads of a round trip were, the harness thread and its
/// child, and their placement counts, read at one end of the timed region
/// (core/kernel/docs/scheduler.md § Placement Counters). A benchmark reads it
/// before its first sample and after its last, outside the timed region, and
/// reports the two through [`Placement::extras`], so its line names whether
/// the round trips stayed on one CPU or paid a wake of another.
pub(super) struct Placement
{
    /// The harness thread's CPU and the child's (`THREAD_PLACEMENT_CPU`).
    cpus: [u64; 2],
    /// Each count of [`COUNT_VIEWS`], summed over the two threads, wrapping as
    /// the kernel's 32-bit counters do.
    counts: [u32; COUNT_VIEWS.len()],
}

impl Placement
{
    /// Read the placement of the threads `harness` and `child` name; `None`
    /// when a read fails.
    pub(super) fn read(harness: u64, child: u64) -> Option<Self>
    {
        let view = |thread: u64, view: u64| syscall::cap_info_thread_placement(thread, view).ok();
        let mut counts = [0u32; COUNT_VIEWS.len()];
        for (count, &which) in counts.iter_mut().zip(&COUNT_VIEWS)
        {
            for thread in [harness, child]
            {
                let one = u32::try_from(view(thread, which)?).ok()?;
                *count = count.wrapping_add(one);
            }
        }
        Some(Self {
            cpus: [
                view(harness, syscall_abi::THREAD_PLACEMENT_CPU)?,
                view(child, syscall_abi::THREAD_PLACEMENT_CPU)?,
            ],
            counts,
        })
    }

    /// The extras of a round trip whose timed region this reading began and
    /// `end` ended: the CPU of the harness thread and of the child at the end,
    /// the child's at the start, and how much each count grew over the region.
    pub(super) fn extras(&self, end: &Self) -> [(&'static str, u64); 7]
    {
        let [harness_cpu, child_cpu] = end.cpus;
        let [_, child_cpu_start] = self.cpus;
        let mut grown = [0u64; COUNT_VIEWS.len()];
        for ((grew, start), finish) in grown.iter_mut().zip(self.counts).zip(end.counts)
        {
            *grew = u64::from(finish.wrapping_sub(start));
        }
        let [remote_wakes, idle_wakes, wake_moves, pulls] = grown;
        [
            ("harness_cpu", harness_cpu),
            ("child_cpu_start", child_cpu_start),
            ("child_cpu", child_cpu),
            ("remote_wakes", remote_wakes),
            ("idle_wakes", idle_wakes),
            ("wake_moves", wake_moves),
            ("pulls", pulls),
        ]
    }
}

/// The extras of a round trip from the placement read before and after its
/// timed region: none when either read failed.
pub(super) fn placement_extras(
    start: Option<&Placement>,
    end: Option<&Placement>,
) -> Option<[(&'static str, u64); 7]>
{
    Some(start?.extras(end?))
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run all Tier 3 benchmarks, `iters` iterations each (cut to
/// [`MAX_ITERS`]).
///
/// Called once, from `main.rs`, after the other tiers complete. Results are
/// logged as result lines; no PASS/FAIL counters are updated.
pub fn run_all(ctx: &crate::TestContext, iters: u32)
{
    // SAFETY: `run_all` runs once, on ktest's harness thread, so this is the
    // only reference to `SAMPLES` there is.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    let cpus = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(1);
    // Every benchmark measures on CPU 0, which the workers of the TLB
    // benchmarks leave to the harness: a counter read is per-CPU, and no two
    // harts' `cycle` counters are kept in step on riscv64.
    if !pin_harness(ctx)
    {
        crate::log("ktest: bench SKIP (the harness thread did not move to CPU 0)");
        let _ = syscall::thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
        return;
    }
    let mut h = Harness {
        iters: iters.min(MAX_ITERS),
        cpus,
        counters: Counters::open(),
        buf,
    };

    null::bench_null_syscall(ctx, &mut h);
    ipc::bench_ipc_round_trip(ctx, &mut h);
    notification::bench_notification_roundtrip(ctx, &mut h);
    cap::bench_cap_create_delete(ctx, &mut h);
    cap::bench_cap_info_lookup(ctx, &mut h);
    mm::bench_mem_map_unmap(ctx, &mut h);
    mm::bench_mem_protect(ctx, &mut h);
    mm::bench_aspace_harvest(ctx, &mut h);
    thread::bench_thread_lifecycle(ctx, &mut h);
    thread::bench_context_switch(ctx, &mut h);
    thread::bench_thread_read_mem(ctx, &mut h);
    event::bench_event_post_recv(ctx, &mut h);
    wait_set::bench_wait_set(ctx, &mut h);
    tlb::bench_tlb_shootdown(ctx, &mut h);
    tlb::bench_tlb_shootdown_concurrent(ctx, &mut h);

    if syscall::thread_set_affinity(ctx.thread_cap, AFFINITY_ANY).is_err()
    {
        crate::log("ktest: bench: restoring the harness thread's affinity failed");
    }
}

/// Pin the harness thread to CPU 0 and yield, bounded, until it runs there;
/// whether it does.
fn pin_harness(ctx: &crate::TestContext) -> bool
{
    /// Yields that give the scheduler the chance to move the thread. A
    /// thread moves at its next pass through the scheduler, so the bound only
    /// ends the wait of a thread that never moves, whose tier then logs a
    /// SKIP line.
    const MAX_YIELDS: u32 = 1000;

    if syscall::thread_set_affinity(ctx.thread_cap, 0).is_err()
    {
        return false;
    }
    let on_cpu0 = || syscall::system_info(syscall_abi::SystemInfoType::CurrentCpu as u64) == Ok(0);
    for _ in 0..MAX_YIELDS
    {
        if on_cpu0()
        {
            return true;
        }
        let _ = syscall::thread_yield();
    }
    on_cpu0()
}
