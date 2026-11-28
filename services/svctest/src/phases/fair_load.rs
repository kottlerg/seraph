// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fair_load.rs

//! Core-service calls under fair-class load: a probe's calls to timed (the
//! wall clock, `GET_WALL_TIME`) and to logd (a log write) with no load, then
//! under each of three loads a child of svctest runs at the default fair
//! level: [`LOAD_THREADS`] CPU-bound threads, as many threads that call logd
//! in a loop, and both.
//!
//! Under the CPU-bound load nine timed calls in ten complete within
//! [`TIMED_BOUND`], every one within [`SLOWEST_BOUND`], and their median stays
//! within [`MEDIAN_FACTOR`] times the quiet median
//! (core/kernel/docs/scheduler.md § Service Call Latency). timed's request
//! path blocks only in IPC, the precondition of that bound; logd's waits on
//! its own state lock mid-request, so its calls, and every call under the
//! other two loads, are logged and not judged.

use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use ipc::IpcMessage;
use ipc::stream_labels::{LEVEL_INFO, STREAM_BYTES, WINDOW_FULL, level_bits};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "fair_load",
        run: fair_load_phase,
    }]
}

/// The threads of each kind of load: seven beside the probe fill 4 CPUs
/// twice over.
const LOAD_THREADS: u64 = 7;

/// The probe's rounds with no load, and at most as many under each load; a
/// round is one call to logd and one to timed.
const PROBE_ROUNDS: usize = 100;

/// The probe's pause after each call.
const GAP: Duration = Duration::from_millis(10);

/// How long a load runs.
const LOAD_FOR: Duration = Duration::from_secs(3);

/// How long a load runs before the probe's first call under it.
const SETTLE: Duration = Duration::from_millis(300);

/// The probe's last call under a load starts this long before the load ends.
const MARGIN: Duration = Duration::from_millis(300);

/// The bound on nine timed calls in ten under the CPU-bound load: a fifth of
/// the default level's slice. The bound the kernel gives this probe is two
/// switches, timed's request work and the RT work on the two CPUs, tens of
/// microseconds; the margin is for the host preempting a vCPU.
const TIMED_BOUND: Duration = Duration::from_millis(2);

/// The bound on every timed call under the CPU-bound load: half the default
/// level's slice, so a call that waited out the second half of a spinner's
/// slice fails, and with a call every 10 ms a probe that waits behind the
/// spinners does so on many calls. Above [`TIMED_BOUND`] by room for one
/// call the host delays past it (2.8 ms once on riscv64 under TCG in CI).
const SLOWEST_BOUND: Duration = Duration::from_millis(5);

/// The bound on the median timed call under the CPU-bound load, as a
/// multiple of the quiet median.
const MEDIAN_FACTOR: u32 = 10;

/// A load: the child's role, its CPU-bound threads, and its logd callers.
struct Load
{
    role: &'static str,
    spinners: u64,
    callers: u64,
}

/// The CPU-bound load, which the phase judges, then the two it logs.
const LOADS: [Load; 3] = [
    Load {
        role: "fair-load-spin",
        spinners: LOAD_THREADS,
        callers: 0,
    },
    Load {
        role: "fair-load-flood",
        spinners: 0,
        callers: LOAD_THREADS,
    },
    Load {
        role: "fair-load-mixed",
        spinners: LOAD_THREADS,
        callers: LOAD_THREADS,
    },
];

/// One probe's call times.
struct Probe
{
    logd: Vec<Duration>,
    timed: Vec<Duration>,
}

fn fair_load_phase(_: &Caps)
{
    let quiet = probe(Instant::now(), Duration::MAX);
    report("quiet", &quiet);
    let quiet_median = quantile(&quiet.timed, 50);
    for (n, load) in LOADS.iter().enumerate()
    {
        let mut child = Command::new("/tests/svctest")
            .arg(load.role)
            .spawn()
            .unwrap_or_else(|e| panic!("fair_load: spawning {} failed: {e}", load.role));
        let started = Instant::now();
        std::thread::sleep(SETTLE);
        let loaded = probe(started, LOAD_FOR.saturating_sub(MARGIN));
        let exit = child
            .wait()
            .unwrap_or_else(|e| panic!("fair_load: waiting for {} failed: {e}", load.role));
        assert!(exit.success(), "fair_load: {} exited {exit}", load.role);
        report(load.role, &loaded);
        if n == 0
        {
            judge(&loaded.timed, quiet_median);
        }
    }
}

/// Fail the phase unless nine timed calls in ten under the CPU-bound load took
/// at most [`TIMED_BOUND`], every one at most [`SLOWEST_BOUND`], and their
/// median at most [`MEDIAN_FACTOR`] times `quiet_median`.
fn judge(timed: &[Duration], quiet_median: Duration)
{
    assert!(
        !timed.is_empty(),
        "fair_load: no timed call under the CPU-bound load"
    );
    let p90 = quantile(timed, 90);
    assert!(
        p90 <= TIMED_BOUND,
        "fair_load: the p90 timed call under the CPU-bound load took {} us, past {} us",
        p90.as_micros(),
        TIMED_BOUND.as_micros()
    );
    let slowest = quantile(timed, 100);
    assert!(
        slowest <= SLOWEST_BOUND,
        "fair_load: a timed call under the CPU-bound load took {} us, past {} us",
        slowest.as_micros(),
        SLOWEST_BOUND.as_micros()
    );
    let median = quantile(timed, 50);
    assert!(
        median <= quiet_median.saturating_mul(MEDIAN_FACTOR),
        "fair_load: the median timed call under the CPU-bound load took {} us, past {MEDIAN_FACTOR} \
         times the quiet median of {} us",
        median.as_micros(),
        quiet_median.as_micros()
    );
}

fn report(what: &str, probe: &Probe)
{
    for (service, took) in [("timed", &probe.timed), ("logd", &probe.logd)]
    {
        std::os::seraph::log!(
            "fair_load: {what}: {service} calls {} median {} us p90 {} us p99 {} us slowest {} us",
            took.len(),
            quantile(took, 50).as_micros(),
            quantile(took, 90).as_micros(),
            quantile(took, 99).as_micros(),
            quantile(took, 100).as_micros()
        );
    }
}

/// Up to [`PROBE_ROUNDS`] rounds, each a logd call and a timed call, each
/// followed by [`GAP`], until `window` has passed since `from`.
fn probe(from: Instant, window: Duration) -> Probe
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut out = Probe {
        logd: Vec::with_capacity(PROBE_ROUNDS),
        timed: Vec::with_capacity(PROBE_ROUNDS),
    };
    // The first read resolves timed's capability; every later one is one call.
    let _ = SystemTime::now();
    let line = b"fair_load probe\n";
    let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
    let msg = IpcMessage::builder(label).bytes(0, line).build();
    for n in 0..PROBE_ROUNDS
    {
        if from.elapsed() >= window
        {
            break;
        }
        let at = Instant::now();
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, log::LOG_CALL_TIMEOUT_MS) }
            .unwrap_or_else(|e| panic!("fair_load: logd call {n} not answered ({e})"));
        out.logd.push(at.elapsed());
        if reply.label == WINDOW_FULL
        {
            std::thread::sleep(Duration::from_millis(reply.word(0)));
        }
        std::thread::sleep(GAP);
        let at = Instant::now();
        let _ = std::hint::black_box(SystemTime::now());
        out.timed.push(at.elapsed());
        std::thread::sleep(GAP);
    }
    out
}

/// The `percent` quantile of `took`, by the nearest rank; zero when empty.
fn quantile(took: &[Duration], percent: usize) -> Duration
{
    let mut sorted = took.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percent).div_ceil(100);
    sorted
        .get(rank.saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

/// Child mode: run the load `role` names, if it names one.
pub fn reentry_main(role: &str)
{
    if let Some(load) = LOADS.iter().find(|load| load.role == role)
    {
        run_load(load);
    }
}

/// Run `load`'s threads for [`LOAD_FOR`], log what they did, and exit.
fn run_load(load: &Load) -> !
{
    let started = Instant::now();
    let (blocks, calls) = std::thread::scope(|scope| {
        let spinners: Vec<_> = (0..load.spinners)
            .map(|_| scope.spawn(move || spin(started)))
            .collect();
        let callers: Vec<_> = (0..load.callers)
            .map(|_| scope.spawn(move || call_logd(started)))
            .collect();
        let blocks = spinners
            .into_iter()
            .map(|h| h.join().unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        let calls = callers
            .into_iter()
            .map(|h| h.join().unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        (blocks, calls)
    });
    std::os::seraph::log!(
        "fair_load: {}: {} spinners ran {blocks} blocks, {} callers made {calls} calls",
        load.role,
        load.spinners,
        load.callers
    );
    std::process::exit(0);
}

/// Spin until the load ends; returns the blocks of work done.
fn spin(started: Instant) -> u64
{
    let mut blocks = 0u64;
    let mut x = 1u64;
    while started.elapsed() < LOAD_FOR
    {
        for _ in 0..100_000
        {
            x = std::hint::black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
        }
        blocks = blocks.saturating_add(1);
    }
    blocks
}

/// Call logd in a loop until the load ends; returns the calls answered.
fn call_logd(started: Instant) -> u64
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let line = b"fair_load flood\n";
    let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
    let msg = IpcMessage::builder(label).bytes(0, line).build();
    let mut calls = 0u64;
    while started.elapsed() < LOAD_FOR
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        if unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, log::LOG_CALL_TIMEOUT_MS) }.is_ok()
        {
            calls = calls.saturating_add(1);
        }
    }
    calls
}
