// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/fsbench/src/main.rs

//! `std::fs::File` read and write benchmark.
//!
//! Measures the cycle cost of reading `bench.bin` via the inline `FS_READ`
//! path and the zero-copy `FS_READ_MEMORY` path across the size grid 16 B,
//! 1 KiB, 4 KiB, 16 KiB, 64 KiB, and of rewriting 4 KiB and 64 KiB of a
//! scratch file in place through the `FS_WRITE_MEMORY` path.
//!
//! Path forcing is by buffer chunking, since `read()`'s policy at
//! `runtime/ruststd/src/sys/fs/seraph.rs` is `want <= 504 AND
//! page_off + want <= PAGE_SIZE` picks inline, else frame:
//!
//! * Inline measurement: chunk into <= 504-byte reads that don't cross
//!   a page tail. Loop until `size` bytes consumed.
//! * Memory-cap measurement: always pass a `PAGE_SIZE` buffer (so `want` is
//!   4096 which exceeds 504). Each `read` returns up to one page. For
//!   `size < 4096` the call still pays the full single-page frame cost.
//!
//! The thread is pinned to CPU 0 before it reads anything, and opens its
//! counters there: each timed read blocks on the filesystem driver, and a
//! thread woken on another CPU would subtract one CPU's cycle counter from
//! another's, which riscv64 does not keep in step.
//!
//! Writes go through page-sized `write_all` calls on a page-aligned offset,
//! which the std client sends as one `FS_WRITE_MEMORY` each.
//!
//! Each size and path logs one result line (`shared/bench/README.md`
//! § Result line), which a host reads back from the serial log:
//!
//! ```text
//! bench fsbench.read size=4096 path=inline arch=x86_64 cpus=4 unit=cycles n=256 min=...
//! bench fsbench.read size=4096 path=frame arch=x86_64 cpus=4 unit=cycles n=256 min=...
//! bench fsbench.write size=4096 path=frame arch=x86_64 cpus=4 unit=cycles n=64 min=...
//! ```

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "fsbench is a benchmark harness that panics on failure so faults surface in the \
              log; `expect` and `panic!` are its intended idiom"
)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use bench::{Counters, Report, Unit, Value};

mod open;

const PAGE_SIZE: u64 = 4096;
const PAGE_SIZE_USIZE: usize = 4096;
const INLINE_CHUNK: u64 = 504;
const SIZES: &[u64] = &[16, 1024, 4096, 16384, 65536];
const WARMUP_ITERS: u32 = 8;
/// Timed read iterations per size and path when no count is given on the
/// command line: the full benchmark.
const MEASURE_ITERS: u32 = 256;
/// Timed write iterations per size when no count is given on the command
/// line. Each writes through to the disk, so fewer than the reads.
const WRITE_ITERS: u32 = 64;
const FIXTURE_PATH: &str = "/data/svctest/bench.bin";
/// The scratch file the writes rewrite, created at the largest write size
/// before the first timed write and removed after the last.
const WRITE_PATH: &str = "/data/svctest/fsbench-write.bin";
/// Write sizes: one page, and the read grid's largest size.
const WRITE_SIZES: &[u64] = &[4096, 65536];
/// The CPU the benchmark thread is pinned to: CPU 0 is online on every boot.
const BENCH_CPU: u32 = 0;

/// Read `size` bytes from `f` starting at offset 0, chunking into
/// <= 504-byte reads that don't cross a page tail so std picks the
/// inline `FS_READ` path for every call.
fn read_inline(f: &mut File, size: u64, buf: &mut [u8]) -> u64
{
    f.seek(SeekFrom::Start(0)).expect("seek failed");
    let mut consumed: u64 = 0;
    while consumed < size
    {
        // The loop condition keeps `consumed` below `size`, and the remainder
        // keeps `page_off` below `PAGE_SIZE`: neither subtraction saturates.
        let remaining = size.saturating_sub(consumed);
        let page_off = consumed % PAGE_SIZE;
        let chunk = remaining
            .min(INLINE_CHUNK)
            .min(PAGE_SIZE.saturating_sub(page_off));
        let chunk_usz = usize::try_from(chunk).expect("chunk is at most INLINE_CHUNK");
        let dst = buf
            .get_mut(..chunk_usz)
            .expect("the buffer holds INLINE_CHUNK bytes");
        let n = f.read(dst).expect("inline read failed");
        if n == 0
        {
            break;
        }
        consumed = consumed.saturating_add(n as u64);
    }
    consumed
}

/// `f.read(buf)`, read again while it returns `Interrupted`: a frame-path
/// read returns that, with the position unchanged, when std discarded a copy
/// whose page the driver may have released during it.
fn read_retrying(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize>
{
    loop
    {
        match f.read(buf)
        {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted =>
            {}
            r => return r,
        }
    }
}

/// Read `size` bytes from `f` starting at offset 0, passing a full
/// `PAGE_SIZE` buffer so std picks the frame path (`want > 504`) on
/// every call.
fn read_frame(f: &mut File, size: u64, buf: &mut [u8]) -> u64
{
    f.seek(SeekFrom::Start(0)).expect("seek failed");
    let mut consumed: u64 = 0;
    while consumed < size
    {
        let n = read_retrying(f, buf).expect("frame read failed");
        if n == 0
        {
            break;
        }
        consumed = consumed.saturating_add(n as u64);
    }
    consumed
}

/// The read path a measurement forces, by its buffer chunking.
#[derive(Clone, Copy)]
enum ReadPath
{
    /// `FS_READ`, through [`read_inline`].
    Inline,
    /// `FS_READ_MEMORY`, through [`read_frame`].
    Frame,
}

impl ReadPath
{
    /// The `path=` value of the output line.
    const fn name(self) -> &'static str
    {
        match self
        {
            Self::Inline => "inline",
            Self::Frame => "frame",
        }
    }

    /// The reader that forces this path.
    fn runner(self) -> fn(&mut File, u64, &mut [u8]) -> u64
    {
        match self
        {
            Self::Inline => read_inline,
            Self::Frame => read_frame,
        }
    }
}

/// The benchmark's fixed context: its counters, the CPU count its result
/// lines carry, and the timed iteration counts of the reads and the writes.
struct Bench
{
    counters: Counters,
    cpus: u32,
    read_iters: u32,
    write_iters: u32,
}

/// Time `iters` reads of `size` bytes on `read_path`, after
/// [`WARMUP_ITERS`] untimed ones, and log their result line.
fn measure(f: &mut File, size: u64, read_path: ReadPath, buf: &mut [u8], run: &Bench)
{
    let runner = read_path.runner();
    let path = read_path.name();

    for _ in 0..WARMUP_ITERS
    {
        let _ = runner(f, size, buf);
    }

    let mut samples = Vec::with_capacity(run.read_iters as usize);
    for _ in 0..run.read_iters
    {
        let start = run.counters.read();
        let got = runner(f, size, buf);
        let elapsed = run.counters.read().since(&start).cycles;
        assert!(
            got >= size.min(65536),
            "fsbench: short read on path={path} size={size}: got {got}"
        );
        samples.push(elapsed);
    }
    let summary = bench::summarize(&mut samples).expect("the iteration count is positive");
    log_line("read", size, path, run, summary);
}

/// Log the result line of `fsbench.<name> size=<size> path=<path>`.
fn log_line(name: &str, size: u64, path: &str, run: &Bench, summary: bench::Summary)
{
    let report = Report {
        suite: "fsbench",
        name,
        variant: &[("size", Value::Num(size)), ("path", Value::Word(path))],
        cpus: run.cpus,
        unit: Unit::Cycles,
        summary,
        extras: &[],
    };
    let mut line = String::new();
    report
        .write(&mut line)
        .unwrap_or_else(|e| panic!("fsbench: result line of {name} path={path} size={size}: {e}"));
    std::os::seraph::log!("{line}");
}

/// Rewrite `size` bytes of `f` from offset 0 with `page`, one
/// `write_all` of a page at a time, so std sends each as one
/// `FS_WRITE_MEMORY`. `size` is a whole number of pages.
fn write_pages(f: &mut File, size: u64, page: &[u8])
{
    f.seek(SeekFrom::Start(0)).expect("write: seek failed");
    for _ in 0..size / PAGE_SIZE
    {
        f.write_all(page).expect("write: write_all failed");
    }
}

/// Time `run.write_iters` rewrites of each of [`WRITE_SIZES`], after
/// [`WARMUP_ITERS`] untimed ones, and log their result lines.
///
/// The scratch file is written to the largest size first, so no timed write
/// extends it: each sample is the rewrite of allocated clusters alone. Its
/// content is read back once the timed writes end.
fn measure_writes(page: &[u8], run: &Bench)
{
    let mut f = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(WRITE_PATH)
        .unwrap_or_else(|e| panic!("fsbench: create {WRITE_PATH}: {e}"));
    let largest = WRITE_SIZES.iter().copied().max().unwrap_or(PAGE_SIZE);
    write_pages(&mut f, largest, page);

    for &size in WRITE_SIZES
    {
        for _ in 0..WARMUP_ITERS
        {
            write_pages(&mut f, size, page);
        }
        let mut samples = Vec::with_capacity(run.write_iters as usize);
        for _ in 0..run.write_iters
        {
            let start = run.counters.read();
            write_pages(&mut f, size, page);
            samples.push(run.counters.read().since(&start).cycles);
        }
        let summary = bench::summarize(&mut samples).expect("the iteration count is positive");
        log_line("write", size, "frame", run, summary);
    }

    verify_written(&mut f, largest, page);
    drop(f);
    std::fs::remove_file(WRITE_PATH)
        .unwrap_or_else(|e| panic!("fsbench: remove {WRITE_PATH}: {e}"));
}

/// Check that every page of the first `size` bytes of `f` reads back as
/// `page`: a write path that lost or misplaced data fails the run rather
/// than time it.
fn verify_written(f: &mut File, size: u64, page: &[u8])
{
    let mut back = vec![0u8; page.len()];
    f.seek(SeekFrom::Start(0))
        .expect("write verify: seek failed");
    for n in 0..size / PAGE_SIZE
    {
        back.fill(0);
        f.read_exact(&mut back)
            .unwrap_or_else(|e| panic!("fsbench: write verify: read page {n}: {e}"));
        assert!(
            back == page,
            "fsbench: write verify: page {n} differs from what was written"
        );
    }
}

/// CPUs the system runs (`SystemInfoType::CpuCount`).
fn cpu_count() -> u32
{
    let count = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .unwrap_or_else(|e| panic!("fsbench: CPU count: error {e}"));
    u32::try_from(count).expect("the CPU count fits in u32")
}

/// Sanity-check the fixture: byte i must equal `(i & 0xFF) as u8` for
/// the first page and the same pattern at page boundaries. Catches any
/// read-path corruption before the timing run.
fn verify_fixture(f: &mut File)
{
    let mut buf = [0u8; 64];
    f.seek(SeekFrom::Start(0)).expect("verify: seek 0 failed");
    let n = f.read(&mut buf).expect("verify: read failed");
    assert_eq!(n, buf.len(), "verify: short read at offset 0");
    for (i, &b) in buf.iter().enumerate()
    {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the mask keeps the value within a byte"
        )]
        let expected = (i & 0xFF) as u8;
        assert_eq!(
            b, expected,
            "verify: byte {i} mismatch ({b:#x} vs expected {expected:#x})"
        );
    }

    // Page-boundary spot check: byte at offset 4080 must equal
    // `(4080 & 0xFF) == 0xF0`. Read straddles into the next page so
    // the std-side policy picks the frame path.
    f.seek(SeekFrom::Start(4080))
        .expect("verify: seek 4080 failed");
    let n = read_retrying(f, &mut buf).expect("verify: page-straddle read failed");
    assert!(n > 0, "verify: page-straddle returned zero");
    let expected: u8 = 0xF0;
    assert_eq!(
        buf[0], expected,
        "verify: page-straddle first byte mismatch ({:#x} vs {expected:#x})",
        buf[0]
    );
}

/// The timed iteration count given on the command line: `argv[1]` when
/// given (a positive integer, so a harness can exercise every path in a few
/// iterations), which then sets every case's count; `None` for the full
/// benchmark, [`MEASURE_ITERS`] reads and [`WRITE_ITERS`] writes.
fn iters_arg() -> Option<u32>
{
    let arg = std::env::args().nth(1)?;
    match arg.parse::<u32>()
    {
        Ok(n) if n > 0 => Some(n),
        _ => panic!("fsbench: iteration count {arg:?} is not a positive integer"),
    }
}

/// Pin the calling thread to [`BENCH_CPU`], so that every timed sample
/// subtracts two reads of one CPU's cycle counter. A thread running on
/// another CPU moves at its next entry to the scheduler; the open, the fixture
/// check and the warm-up reads all block on the filesystem driver, so the
/// thread runs on `BENCH_CPU` by the first timed sample.
fn pin_to_bench_cpu()
{
    let thread = std::os::seraph::thread::current_thread_cap();
    syscall::thread_set_affinity(thread, BENCH_CPU)
        .unwrap_or_else(|e| panic!("fsbench: pin to CPU {BENCH_CPU} failed: error {e}"));
}

fn main()
{
    std::os::seraph::log::register_name(b"fsbench");
    let iters = iters_arg();
    pin_to_bench_cpu();
    let run = Bench {
        counters: Counters::open(),
        cpus: cpu_count(),
        read_iters: iters.unwrap_or(MEASURE_ITERS),
        write_iters: iters.unwrap_or(WRITE_ITERS),
    };
    std::os::seraph::log!(
        "starting, fixture={FIXTURE_PATH} read_iters={} write_iters={}",
        run.read_iters,
        run.write_iters
    );

    let mut f =
        File::open(FIXTURE_PATH).unwrap_or_else(|e| panic!("fsbench: open {FIXTURE_PATH}: {e}"));
    verify_fixture(&mut f);

    let mut buf = vec![0u8; PAGE_SIZE_USIZE];
    for &size in SIZES
    {
        measure(&mut f, size, ReadPath::Inline, &mut buf, &run);
        measure(&mut f, size, ReadPath::Frame, &mut buf, &run);
    }
    drop(f);

    // The write pattern differs from every fixture page's, so a write that
    // reached the fixture instead would fail its check.
    let page: Vec<u8> = (0..PAGE_SIZE_USIZE)
        .map(|i| u8::try_from(i % 251).expect("the remainder is below 251"))
        .collect();
    measure_writes(&page, &run);
    open::measure(&run);

    std::os::seraph::log!("done");
}
