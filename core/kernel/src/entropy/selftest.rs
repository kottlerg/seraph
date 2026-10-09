// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/entropy/selftest.rs

//! Boot-time entropy power-on self-test.
//!
//! Each CPU captures a sample from its own generator as it comes online (the
//! BSP during `init`, APs during AP entry). After SMP bringup the BSP runs the
//! checks over the CPUs that captured: every sample is non-trivial, samples are
//! pairwise distinct (per-CPU independence), and the aggregate bit balance is
//! sane. The result is printed as `entropy: SELFTEST PASS`/`FAIL`; how the FAIL
//! marker gates a run is specified in `core/kernel/docs/entropy.md` § Testing.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::mm::BuddyAllocator;

/// Bytes captured per CPU.
const SAMPLE: usize = 32;

/// One CPU's self-test row. `captured` marks a row whose CPU drew its sample.
/// Every CPU the boot reported captures before the BSP runs the checks (a CPU
/// that cannot be started halts the boot; see
/// `core/kernel/docs/initialization.md` § Phase 8), so an uncaptured row is a
/// defensive case: it is skipped, not scored as a failure.
#[repr(C)]
struct Sample
{
    bytes: [u8; SAMPLE],
    captured: bool,
}

static SAMPLES_PTR: AtomicPtr<Sample> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU sample slab. Called from `entropy::init_storage`.
pub fn init_storage(cpu_count: usize, allocator: &mut BuddyAllocator)
{
    let bytes = cpu_count * core::mem::size_of::<Sample>();
    let ptr = crate::sched::alloc_zeroed_slab::<Sample>(bytes, allocator, "ENTROPY_SELFTEST");
    SAMPLES_PTR.store(ptr, Ordering::Release);
}

/// Capture a sample from the calling CPU's generator into row `cpu`.
pub fn capture(cpu: usize)
{
    let base = SAMPLES_PTR.load(Ordering::Acquire);
    if base.is_null()
    {
        return;
    }
    let mut buf = [0u8; SAMPLE];
    super::fill_bytes(&mut buf);
    // SAFETY: slab sized to CPU_COUNT; each CPU writes only its own row; the
    // BSP reads after the APS_READY Acquire barrier.
    unsafe {
        core::ptr::write(
            base.add(cpu),
            Sample {
                bytes: buf,
                captured: true,
            },
        );
    }
}

/// Run the checks across the CPUs that captured (within `0..cpu_count`) and
/// print the result marker.
pub fn run(cpu_count: usize)
{
    let base = SAMPLES_PTR.load(Ordering::Acquire);
    if base.is_null()
    {
        crate::kprintln!("entropy: SELFTEST FAIL: samples not allocated");
        return;
    }
    // SAFETY: slab sized to CPU_COUNT >= cpu_count; all writes published before
    // this barrier-ordered read.
    let samples = unsafe { core::slice::from_raw_parts(base, cpu_count) };

    // Score only rows that captured a sample; an uncaptured row (defensive: every
    // CPU the boot reported has captured by now, per Sample) is skipped rather
    // than treated as a failure.
    let mut set_bits: u64 = 0;
    let mut online = 0usize;
    for (cpu, s) in samples.iter().enumerate()
    {
        if !s.captured
        {
            continue;
        }
        online += 1;
        if s.bytes.iter().all(|&b| b == 0)
        {
            crate::kprintln!("entropy: SELFTEST FAIL: cpu {} produced no output", cpu);
            return;
        }
        for b in s.bytes
        {
            set_bits += u64::from(b.count_ones());
        }
    }

    if online == 0
    {
        crate::kprintln!("entropy: SELFTEST FAIL: no CPU captured a sample");
        return;
    }

    // Per-CPU independence: pairwise-distinct samples among online CPUs.
    for i in 0..cpu_count
    {
        if !samples[i].captured
        {
            continue;
        }
        for j in (i + 1)..cpu_count
        {
            if samples[j].captured && samples[i].bytes == samples[j].bytes
            {
                crate::kprintln!("entropy: SELFTEST FAIL: cpus {} and {} match", i, j);
                return;
            }
        }
    }

    // Bit balance: total set bits within [25%, 75%] of the captured bit count.
    let total_bits = (online * SAMPLE * 8) as u64;
    if set_bits < total_bits / 4 || set_bits > total_bits * 3 / 4
    {
        crate::kprintln!(
            "entropy: SELFTEST FAIL: bit balance {}/{}",
            set_bits,
            total_bits
        );
        return;
    }

    crate::kprintln!("entropy: SELFTEST PASS ({} CPU(s))", online);
}
