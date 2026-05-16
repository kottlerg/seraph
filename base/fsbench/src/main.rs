// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/fsbench/src/main.rs

//! `FS_READ` vs `FS_READ_FRAME` crossover benchmark.
//!
//! Measures wall-clock cycle cost of reading `bench.bin` via the inline
//! `FS_READ` path and the zero-copy `FS_READ_FRAME` path across the size
//! grid called out in issue #10: 16 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB.
//!
//! Path forcing is by buffer chunking, since `read()`'s policy at
//! `runtime/ruststd/src/sys/fs/seraph.rs` is `want <= 504 AND
//! page_off + want <= PAGE_SIZE` picks inline, else frame:
//!
//! * Inline measurement: chunk into <= 504-byte reads that don't cross
//!   a page tail. Loop until `size` bytes consumed.
//! * Frame measurement: always pass a `PAGE_SIZE` buffer (so `want` is
//!   4096 which exceeds 504). Each `read` returns up to one page. For
//!   `size < 4096` the call still pays the full single-page frame cost.
//!
//! Output is line-oriented and machine-parseable so the host can scrape
//! it from the serial log:
//!
//! ```text
//! fsbench: arch=x86_64 size=4096 path=inline iters=256 cycles_min=...
//! fsbench: arch=x86_64 size=4096 path=frame  iters=256 cycles_min=...
//! ```

#![feature(restricted_std)]
// fsbench is a benchmark harness: panics on failure so faults surface
// in the log. `expect`/`unwrap` are the intended idiom here.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const PAGE_SIZE: u64 = 4096;
const PAGE_SIZE_USIZE: usize = 4096;
const INLINE_CHUNK: u64 = 504;
const SIZES: &[u64] = &[16, 1024, 4096, 16384, 65536];
const WARMUP_ITERS: u32 = 8;
const MEASURE_ITERS: u32 = 256;
const FIXTURE_PATH: &str = "/usertest/bench.bin";

fn cycles_now() -> u64
{
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: rdtsc is unprivileged on x86_64; reads TSC into edx:eax.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem, preserves_flags),
            );
        }
        u64::from(hi) << 32 | u64::from(lo)
    }
    #[cfg(target_arch = "riscv64")]
    {
        let c: u64;
        // SAFETY: `csrr cycle` is unprivileged when scounteren.CY = 1,
        // which the kernel sets in BSP and AP init
        // (`core/kernel/src/arch/riscv64/interrupts.rs`).
        unsafe {
            core::arch::asm!(
                "csrr {}, cycle",
                out(reg) c,
                options(nostack, nomem),
            );
        }
        c
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    {
        0
    }
}

#[cfg(target_arch = "x86_64")]
const ARCH_TAG: &str = "x86_64";
#[cfg(target_arch = "riscv64")]
const ARCH_TAG: &str = "riscv64";
#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
const ARCH_TAG: &str = "unknown";

/// Read `size` bytes from `f` starting at offset 0, chunking into
/// <= 504-byte reads that don't cross a page tail so std picks the
/// inline `FS_READ` path for every call.
fn read_inline(f: &mut File, size: u64, buf: &mut [u8]) -> u64
{
    f.seek(SeekFrom::Start(0)).expect("seek failed");
    let mut consumed: u64 = 0;
    while consumed < size
    {
        let remaining = size - consumed;
        let page_off = consumed % PAGE_SIZE;
        let chunk = remaining.min(INLINE_CHUNK).min(PAGE_SIZE - page_off);
        #[allow(clippy::cast_possible_truncation)]
        let chunk_usz = chunk as usize;
        let n = f.read(&mut buf[..chunk_usz]).expect("inline read failed");
        if n == 0
        {
            break;
        }
        consumed += n as u64;
    }
    consumed
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
        let n = f.read(buf).expect("frame read failed");
        if n == 0
        {
            break;
        }
        consumed += n as u64;
    }
    consumed
}

fn measure(f: &mut File, size: u64, path: &str, buf: &mut [u8])
{
    let runner: fn(&mut File, u64, &mut [u8]) -> u64 = match path
    {
        "inline" => read_inline,
        "frame" => read_frame,
        _ => unreachable!(),
    };

    for _ in 0..WARMUP_ITERS
    {
        let _ = runner(f, size, buf);
    }

    let mut min_c = u64::MAX;
    let mut max_c = 0u64;
    let mut sum_c: u64 = 0;
    for _ in 0..MEASURE_ITERS
    {
        let start = cycles_now();
        let got = runner(f, size, buf);
        let elapsed = cycles_now().wrapping_sub(start);
        assert!(
            got >= size.min(65536),
            "fsbench: short read on path={path} size={size}: got {got}"
        );
        if elapsed < min_c
        {
            min_c = elapsed;
        }
        if elapsed > max_c
        {
            max_c = elapsed;
        }
        sum_c = sum_c.wrapping_add(elapsed);
    }
    let mean_c = sum_c / u64::from(MEASURE_ITERS);

    let arch = ARCH_TAG;
    let iters = MEASURE_ITERS;
    std::os::seraph::log!(
        "arch={arch} size={size} path={path} iters={iters} \
         cycles_min={min_c} cycles_mean={mean_c} cycles_max={max_c}"
    );
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
        #[allow(clippy::cast_possible_truncation)]
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
    let n = f.read(&mut buf).expect("verify: page-straddle read failed");
    assert!(n > 0, "verify: page-straddle returned zero");
    let expected: u8 = 0xF0;
    assert_eq!(
        buf[0], expected,
        "verify: page-straddle first byte mismatch ({:#x} vs {expected:#x})",
        buf[0]
    );
}

fn main()
{
    std::os::seraph::log::register_name(b"fsbench");
    std::os::seraph::log!("starting, fixture={FIXTURE_PATH}");

    let mut f =
        File::open(FIXTURE_PATH).unwrap_or_else(|e| panic!("fsbench: open {FIXTURE_PATH}: {e}"));
    verify_fixture(&mut f);

    let mut buf = vec![0u8; PAGE_SIZE_USIZE];
    for &size in SIZES
    {
        measure(&mut f, size, "inline", &mut buf);
        measure(&mut f, size, "frame", &mut buf);
    }

    std::os::seraph::log!("done");
}
