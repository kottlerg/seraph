// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/fsbench/src/unpinned.rs

//! The rows of a client with no affinity: `fsbench.read size=16 path=inline
//! affinity=any` and `fsbench.open depth=3 affinity=any`, at more than one
//! CPU, in the window-mean form (`shared/bench/README.md` § Window-mean rows).
//!
//! The pinned rows measure a client the synchronous wake rule keeps apart
//! from its RT server (`core/kernel/docs/scheduler.md` § Thread Assignment);
//! these measure the client real filesystem clients are, which the rule runs
//! on one CPU with its server. Each window, pinned to [`BENCH_CPU`], the
//! thread runs one untimed operation, which blocks and so leaves it on that
//! CPU, opens its idle-halt span, clears its affinity, and reads the counters;
//! it runs the window's operations, reads again, closes the span and pins
//! itself once more. Clearing an affinity, and naming the CPU the thread is
//! on, move nothing, and no blocking call falls between a read and the span's
//! open or close. The window counts when the span closes with no halt, so
//! both reads ran on `BENCH_CPU` and that CPU's counter ran throughout
//! (`docs/testing.md` § Benchmarks).

use std::fs::File;

use bench::{
    HALTED, IDLE_HALTS, MOVED, Report, Unit, Value, WINDOW_OPS_KEY, WindowEnd, WindowShape,
    WindowTally, window_mean,
};

use crate::open::{OPEN_DEPTH, OPEN_PATH, open};
use crate::{BENCH_CPU, Bench, IdleSpan, WARMUP_ITERS, read_inline};

/// `SYS_THREAD_SET_AFFINITY`'s value for no affinity (`AFFINITY_ANY`).
const AFFINITY_ANY: u32 = u32::MAX;

/// The read size of the read row: one `FS_READ` round trip per read.
const READ_SIZE: u64 = 16;

/// The extra counting the client's wakes linked on another CPU than its
/// waker's over the counted windows (`CAP_INFO_THREAD_PLACEMENT`).
const REMOTE_WAKES: &str = "remote_wakes";

/// What the windows of one row measured.
struct Windows
{
    /// One sample per counted window: its mean per operation.
    samples: Vec<u64>,
    tally: WindowTally,
    /// Halts of `BENCH_CPU` over every span that closed.
    idle_halts: u64,
    /// The client's remote wakes over the counted windows; `None` when a
    /// placement read failed.
    remote_wakes: Option<u64>,
}

/// Set the calling thread's affinity to `cpu`.
fn set_affinity(thread: u64, cpu: u32)
{
    syscall::thread_set_affinity(thread, cpu)
        .unwrap_or_else(|e| panic!("fsbench: set affinity to CPU {cpu}: error {e}"));
}

/// The thread's remote wakes so far; `None` when the read failed.
fn remote_wakes(thread: u64) -> Option<u64>
{
    syscall::cap_info_thread_placement(thread, syscall_abi::THREAD_PLACEMENT_REMOTE_WAKES).ok()
}

/// One call of a row's body.
#[derive(Clone, Copy)]
enum Step
{
    /// Run one untimed operation, which blocks on the filesystem.
    Untimed,
    /// Run this many operations between two counter reads and return their
    /// difference.
    Window(u32),
}

/// Time `shape.windows` windows of `body`, each after one untimed
/// operation. The thread enters and leaves pinned to [`BENCH_CPU`].
fn run_windows(shape: WindowShape, mut body: impl FnMut(Step) -> u64) -> Windows
{
    let thread = std::os::seraph::thread::current_thread_cap();
    let mut out = Windows {
        samples: Vec::with_capacity(shape.windows as usize),
        tally: WindowTally::default(),
        idle_halts: 0,
        remote_wakes: Some(0),
    };
    for _ in 0..shape.windows
    {
        let _ = body(Step::Untimed);
        let wakes_before = remote_wakes(thread);
        let idle = IdleSpan::open();
        set_affinity(thread, AFFINITY_ANY);
        let elapsed = body(Step::Window(shape.ops));
        let halts = idle.close();
        set_affinity(thread, BENCH_CPU);
        let wakes_after = remote_wakes(thread);

        out.idle_halts = out.idle_halts.saturating_add(halts.unwrap_or(0));
        let end = WindowEnd::from_close(halts);
        out.tally.record(end);
        if end == WindowEnd::Counted
        {
            out.samples.push(window_mean(elapsed, shape.ops));
            // The counter is a wrapping 32-bit count.
            let wakes = wakes_before
                .zip(wakes_after)
                .map(|(before, after)| after.wrapping_sub(before) & u64::from(u32::MAX));
            out.remote_wakes = out
                .remote_wakes
                .zip(wakes)
                .map(|(sum, w)| sum.saturating_add(w));
        }
    }
    out
}

/// Log the result line of `fsbench.<name>` with `variant` and
/// `affinity=any` from `measured`, or, when its counted windows fall below
/// the floor, a line saying so.
fn log_row(
    name: &str,
    variant: &[(&str, Value<'_>)],
    shape: WindowShape,
    run: &Bench,
    mut measured: Windows,
)
{
    let tally = measured.tally;
    if !tally.reaches_floor(shape)
    {
        std::os::seraph::log!(
            warn: "{name} affinity=any: counted windows below the floor, counted={} windows={} floor={} moved={} halted={}",
            tally.counted,
            shape.windows,
            shape.floor(),
            tally.moved,
            tally.halted
        );
        return;
    }
    let summary =
        bench::summarize(&mut measured.samples).expect("the floor is at least one counted window");
    let mut variant = variant.to_vec();
    variant.push(("affinity", Value::Word("any")));
    let mut extras = vec![
        (WINDOW_OPS_KEY, u64::from(shape.ops)),
        (MOVED, u64::from(tally.moved)),
        (HALTED, u64::from(tally.halted)),
        (IDLE_HALTS, measured.idle_halts),
    ];
    extras.extend(measured.remote_wakes.map(|w| (REMOTE_WAKES, w)));
    let report = Report {
        suite: "fsbench",
        name,
        variant: &variant,
        cpus: run.cpus,
        unit: Unit::Cycles,
        summary,
        extras: &extras,
    };
    let mut line = String::new();
    report
        .write(&mut line)
        .unwrap_or_else(|e| panic!("fsbench: result line of {name} affinity=any: {e}"));
    std::os::seraph::log!("{line}");
}

/// The read row: windows of 16-byte inline reads of `f`.
pub(crate) fn measure_read(f: &mut File, buf: &mut [u8], run: &Bench)
{
    let Some(shape) = WindowShape::for_ops(run.read_iters)
    else
    {
        return;
    };
    for _ in 0..WARMUP_ITERS
    {
        let _ = read_inline(f, READ_SIZE, buf);
    }
    let mut shortest = u64::MAX;
    let measured = run_windows(shape, |step| match step
    {
        Step::Untimed =>
        {
            let _ = read_inline(f, READ_SIZE, buf);
            0
        }
        Step::Window(ops) =>
        {
            let start = run.counters.read();
            for _ in 0..ops
            {
                let got = read_inline(f, READ_SIZE, buf);
                shortest = shortest.min(got);
            }
            run.counters.read().since(&start).cycles
        }
    });
    assert!(
        shortest >= READ_SIZE,
        "fsbench: short read on path=inline size={READ_SIZE} affinity=any: got {shortest}"
    );
    log_row(
        "read",
        &[
            ("size", Value::Num(READ_SIZE)),
            ("path", Value::Word("inline")),
        ],
        shape,
        run,
        measured,
    );
}

/// The open row: windows of opens of [`OPEN_PATH`], each window's files
/// closed after its closing read.
pub(crate) fn measure_open(run: &Bench)
{
    let Some(shape) = WindowShape::for_ops(run.read_iters)
    else
    {
        return;
    };
    for _ in 0..WARMUP_ITERS
    {
        drop(open());
    }
    let mut files: Vec<File> = Vec::with_capacity(shape.ops as usize);
    let measured = run_windows(shape, |step| match step
    {
        Step::Untimed =>
        {
            drop(open());
            0
        }
        Step::Window(ops) =>
        {
            let lookups = std::os::seraph::fs::ns_lookup_calls();
            let start = run.counters.read();
            for _ in 0..ops
            {
                files.push(open());
            }
            let elapsed = run.counters.read().since(&start).cycles;
            let made = std::os::seraph::fs::ns_lookup_calls().wrapping_sub(lookups);
            files.drain(..).for_each(drop);
            assert_eq!(
                made,
                u64::from(ops),
                "fsbench: {ops} opens of {OPEN_PATH} made {made} NS_LOOKUP calls"
            );
            elapsed
        }
    });
    log_row(
        "open",
        &[("depth", Value::Num(OPEN_DEPTH))],
        shape,
        run,
        measured,
    );
}
