// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/ubench/src/fault_rate.rs

//! `fault_rate`: the demand faults per second the system serves when k
//! processes, one per CPU, each fault fresh chunks of a region of its own at
//! once (services/ubench/README.md § Benchmarks).
//!
//! Each process is `program-modes faultstorm`
//! (services/fixtures/program-modes/README.md § faultstorm), pinned to its own
//! CPU and driven over its stdin and stdout. None of them can time the window:
//! the faults of all of them make it. ubench's own thread, pinned to
//! [`BENCH_CPU`], times it instead, as `pipeline`'s observer does: per window
//! it reads its counter, starts every process, waits for each one's word that
//! its chunks are backed, and reads again, so a sample is the window's elapsed
//! cycles on that CPU. The CPU may halt in a window, so every window is also
//! checked against the kernel's elapsed microseconds ([`bench::CycleRate`]),
//! and a window whose counter did not count its elapsed time is left out.

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use bench::{Counters, Value, WINDOW_OPS_KEY};

use crate::harness::{IdleSpan, Outcome, calibrate, elapsed_us, report, skip};

/// Where the build installs the fixture whose `faultstorm` mode faults.
const PROGRAM_MODES: &str = "/tests/fixtures/programs/program-modes";

/// The process counts measured.
const PROCS: [u32; 4] = [1, 2, 4, 8];

/// Pages in one chunk: `DEMAND_CHUNK_PAGES`.
const CHUNK_PAGES: u64 = 16;

/// Chunks each process faults per window, each the first touch of a chunk of
/// a region registered for that window.
const CHUNKS: u64 = 16;

/// Untimed windows before the timed ones.
const WARMUP_WINDOWS: u64 = 2;

/// Timed windows per process count.
const WINDOWS: u64 = 16;

/// Microseconds in a second, for `faults_per_s=`.
const MICROS_PER_SECOND: u64 = 1_000_000;

/// Run the benchmark: one result line per process count the CPUs online
/// allow, a SKIP line for each other.
pub fn run(counters: &Counters, cpus: u32) -> Outcome
{
    for procs in PROCS
    {
        if procs > cpus
        {
            skip(
                "fault_rate",
                &format!("procs={procs}: needs {procs} CPUs, {cpus} online"),
            );
            continue;
        }
        line(counters, cpus, procs).map_err(|e| format!("procs={procs}: {e}"))?;
    }
    Ok(())
}

/// The cycles `region` took, between two counter reads. Every window of the
/// benchmark, the calibration's included, is read here, so that all of them
/// read the counter at the same two addresses (`harness::Timed`).
#[inline(never)]
fn timed(counters: &Counters, region: &mut dyn FnMut() -> Outcome) -> Result<u64, String>
{
    let start = counters.read();
    let ran = region();
    let cycles = counters.read().since(&start).cycles;
    ran.map(|()| cycles)
}

/// What the observer measured of one process count.
struct Measured
{
    /// Each counted window's cycles.
    samples: Vec<u64>,
    /// Timed windows left out because their counter did not count their
    /// elapsed time.
    clock_stopped: u64,
    /// The mean elapsed microseconds of a timed window, over every one.
    window_us: u64,
    /// The halts of [`BENCH_CPU`] over the calibration and the windows.
    idle_halts: Option<u64>,
}

/// Measure `procs` processes and log their line.
fn line(counters: &Counters, cpus: u32, procs: u32) -> Outcome
{
    let mut storm = Storm::spawn(procs)?;
    let measured = observe(counters, &mut storm);
    let ended = storm.end();
    let measured = measured?;
    ended?;
    let window_ops = CHUNKS.saturating_mul(u64::from(procs));
    if measured.samples.is_empty()
    {
        return Err(format!(
            "no window counted its elapsed time: clock_stopped={} window_us={}",
            measured.clock_stopped, measured.window_us
        ));
    }
    let faults_per_s = window_ops
        .saturating_mul(MICROS_PER_SECOND)
        .checked_div(measured.window_us)
        .unwrap_or(0);
    let mut samples = measured.samples;
    report(
        "fault_rate",
        &[
            ("procs", Value::Num(u64::from(procs))),
            ("pages", Value::Num(CHUNK_PAGES)),
        ],
        cpus,
        &mut samples,
        &[
            (WINDOW_OPS_KEY, window_ops),
            ("clock_stopped", measured.clock_stopped),
            ("window_us", measured.window_us),
            ("faults_per_s", faults_per_s),
        ],
        measured.idle_halts,
    )
}

/// The observer: once every process registered its first region, calibrate
/// the counter and time each window; between two windows every process
/// replaces its region with a fresh one, outside the timed reads.
fn observe(counters: &Counters, storm: &mut Storm) -> Result<Measured, String>
{
    storm.expect_all(b'r')?;
    let mut samples = Vec::new();
    let mut clock_stopped = 0u64;
    let mut elapsed = 0u64;
    let idle = IdleSpan::open();
    let rate = calibrate(counters, timed)?;
    for i in 0..WARMUP_WINDOWS + WINDOWS
    {
        if i > 0
        {
            storm.send_all(b'n')?;
            storm.expect_all(b'r')?;
        }
        let (cycles, micros) = window(counters, storm)?;
        if i < WARMUP_WINDOWS
        {
            continue;
        }
        elapsed = elapsed.saturating_add(micros);
        if rate.counted(cycles, micros)
        {
            samples.push(cycles);
        }
        else
        {
            clock_stopped = clock_stopped.saturating_add(1);
        }
    }
    let idle_halts = idle.close();
    Ok(Measured {
        samples,
        clock_stopped,
        window_us: elapsed / WINDOWS,
        idle_halts,
    })
}

/// One window: the counter read, every process started, each one's word that
/// its chunks are backed awaited, the counter read again, between two reads
/// of the elapsed clock; its cycles and its elapsed microseconds.
fn window(counters: &Counters, storm: &mut Storm) -> Result<(u64, u64), String>
{
    let first = elapsed_us()?;
    let cycles = timed(counters, &mut || {
        storm.send_all(b'g')?;
        storm.expect_all(b'd')
    })?;
    let last = elapsed_us()?;
    Ok((cycles, last.saturating_sub(first)))
}

/// One `faultstorm` process and the ends of its stdin and stdout.
struct Faulter
{
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

/// The processes of one count: process i pinned to CPU i.
struct Storm(Vec<Faulter>);

impl Storm
{
    /// Spawn `procs` processes, each faulting [`CHUNKS`] chunks per round
    /// from one thread with one store each.
    fn spawn(procs: u32) -> Result<Self, String>
    {
        let mut storm = Self(Vec::new());
        for cpu in 0..procs
        {
            let mut child = Command::new(PROGRAM_MODES)
                .args([
                    "faultstorm",
                    &cpu.to_string(),
                    &CHUNKS.to_string(),
                    "1",
                    "touch",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| format!("spawn the process for CPU {cpu}: {e}"))?;
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take())
            else
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("the process for CPU {cpu} has no stdio pipes"));
            };
            storm.0.push(Faulter {
                child,
                stdin,
                stdout,
            });
        }
        Ok(storm)
    }

    /// Send `byte` to every process.
    fn send_all(&mut self, byte: u8) -> Outcome
    {
        for (cpu, f) in self.0.iter_mut().enumerate()
        {
            f.stdin
                .write_all(&[byte])
                .and_then(|()| f.stdin.flush())
                .map_err(|e| {
                    format!(
                        "send {:?} to the process for CPU {cpu}: {e}",
                        char::from(byte)
                    )
                })?;
        }
        Ok(())
    }

    /// Read one byte from every process, each `byte`.
    fn expect_all(&mut self, byte: u8) -> Outcome
    {
        for (cpu, f) in self.0.iter_mut().enumerate()
        {
            let mut got = [0u8; 1];
            f.stdout.read_exact(&mut got).map_err(|e| {
                format!(
                    "read {:?} from the process for CPU {cpu}: {e}",
                    char::from(byte)
                )
            })?;
            let [answer] = got;
            if answer != byte
            {
                return Err(format!(
                    "the process for CPU {cpu} answered {:?}, not {:?}",
                    char::from(answer),
                    char::from(byte)
                ));
            }
        }
        Ok(())
    }

    /// End every process: `x` to each, then its exit, which must be a
    /// success.
    fn end(mut self) -> Outcome
    {
        let sent = self.send_all(b'x');
        let mut first_error = sent.err();
        for (cpu, mut f) in self.0.into_iter().enumerate()
        {
            // A process that did not take its x ends at its stdin's end.
            drop(f.stdin);
            match f.child.wait()
            {
                Ok(status) if status.success() =>
                {}
                Ok(status) =>
                {
                    let _ = first_error.get_or_insert_with(|| {
                        format!("the process for CPU {cpu} exited: {status}")
                    });
                }
                Err(e) =>
                {
                    let _ = first_error
                        .get_or_insert_with(|| format!("wait for the process for CPU {cpu}: {e}"));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
