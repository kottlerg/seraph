// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/selftest.rs

//! Boot-time entropy power-on self-test.
//!
//! Each CPU captures a sample from its own generator as it comes online (the
//! BSP during `init`, APs during AP entry). After SMP bringup the BSP runs the
//! checks: every sample is non-trivial, samples are pairwise distinct
//! (per-CPU independence), and the aggregate bit balance is sane. The result
//! is printed as `entropy: SELFTEST PASS`/`FAIL`; the FAIL marker is matched by
//! the run-parallel fail-regex, so a broken RNG turns a QEMU run red on both
//! architectures.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::mm::BuddyAllocator;

/// Bytes captured per CPU.
const SAMPLE: usize = 32;

static SAMPLES_PTR: AtomicPtr<[u8; SAMPLE]> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU sample slab. Called from `entropy::init_storage`.
pub fn init_storage(cpu_count: usize, allocator: &mut BuddyAllocator)
{
    let bytes = cpu_count * SAMPLE;
    let ptr = crate::sched::alloc_zeroed_slab::<[u8; SAMPLE]>(bytes, allocator, "ENTROPY_SELFTEST");
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
        core::ptr::write(base.add(cpu), buf);
    }
}

/// Run the checks across CPUs `0..cpu_count` and print the result marker.
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

    let mut set_bits: u64 = 0;
    for (cpu, s) in samples.iter().enumerate()
    {
        if s.iter().all(|&b| b == 0)
        {
            crate::kprintln!("entropy: SELFTEST FAIL: cpu {} produced no output", cpu);
            return;
        }
        for b in s
        {
            set_bits += u64::from(b.count_ones());
        }
    }

    // Per-CPU independence: pairwise distinct samples.
    for i in 0..cpu_count
    {
        for j in (i + 1)..cpu_count
        {
            if samples[i] == samples[j]
            {
                crate::kprintln!("entropy: SELFTEST FAIL: cpus {} and {} match", i, j);
                return;
            }
        }
    }

    // Bit balance: total set bits within [25%, 75%] of the bit count.
    let total_bits = (cpu_count * SAMPLE * 8) as u64;
    if set_bits < total_bits / 4 || set_bits > total_bits * 3 / 4
    {
        crate::kprintln!(
            "entropy: SELFTEST FAIL: bit balance {}/{}",
            set_bits,
            total_bits
        );
        return;
    }

    crate::kprintln!("entropy: SELFTEST PASS ({} CPU(s))", cpu_count);
}
