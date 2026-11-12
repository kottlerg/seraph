// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/entropy/jitter.rs

//! Per-CPU jitter entropy accumulator.
//!
//! Timing jitter is the always-available entropy source and the only
//! runtime source on platforms without a hardware RNG (riscv64, where any
//! firmware boot seed is absorbed at boot only; see
//! [entropy.md](../../docs/entropy.md) § Sources and graceful degradation). Each
//! CPU folds cycle-counter samples — taken at distinct event classes (per-tick,
//! per-IRQ) — into a small per-CPU buffer at interrupt time: allocation-free
//! and lock-free, as required of interrupt context. The buffer is folded into
//! the central pool off the interrupt path, at reseed time.
//!
//! The fold here is deliberately non-cryptographic; it only compresses many
//! samples into a few words without discarding entropy. The pool's sponge
//! provides the cryptographic mixing when the buffer is absorbed.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use super::pool;
use crate::mm::BuddyAllocator;

/// Staging words per CPU. Samples fold round-robin into them (`n % ACC_WORDS`),
/// so the 256-bit buffer bounds no sample count.
const ACC_WORDS: usize = 4;

/// Distinct event classes sampled, for source diversity (`tick`, `irq`).
#[derive(Clone, Copy)]
pub enum Source
{
    Tick = 0,
    Irq = 1,
}

/// Per-CPU staging buffer. All fields are atomic so the owning CPU's
/// interrupt-time writes and off-interrupt reads never tear; a zeroed slab slot
/// is a valid, empty accumulator.
#[repr(C)]
struct Acc
{
    words: [AtomicU64; ACC_WORDS],
    count: AtomicU64,
}

/// The per-CPU jitter accumulator slab: one [`Acc`] per CPU.
const JITTER_SLAB: crate::sched::PerCpuSlab = crate::sched::PerCpuSlab::of::<Acc>("ENTROPY_JITTER");
const _: () = assert!(
    JITTER_SLAB.sized_at_every_width(),
    "ENTROPY_JITTER slab overflows"
);

static ACC_PTR: AtomicPtr<Acc> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU accumulator slab. Called once from
/// `entropy::init_storage` (Phase 4).
pub fn init_storage(cpu_count: usize, allocator: &mut BuddyAllocator)
{
    let ptr = crate::sched::alloc_per_cpu_slab::<Acc>(JITTER_SLAB, cpu_count, allocator);
    ACC_PTR.store(ptr, Ordering::Release);
}

/// Borrow CPU `cpu`'s accumulator. Returns `None` before `init_storage`.
fn acc_for(cpu: usize) -> Option<&'static Acc>
{
    let base = ACC_PTR.load(Ordering::Acquire);
    if base.is_null()
    {
        return None;
    }
    // SAFETY: slab published by `init_storage` is sized to CPU_COUNT; callers
    // pass `cpu < CPU_COUNT`. Atomic fields give safe shared access.
    Some(unsafe { &*base.add(cpu) })
}

/// Fold a cycle-counter sample for `cpu` into its buffer. Interrupt-safe:
/// allocation-free and lock-free.
// cast_possible_truncation: `n as usize` is lossless (both targets are 64-bit,
// so usize == u64), and `(n & 63) as u32` narrows a value masked below 64.
#[allow(clippy::cast_possible_truncation)]
pub fn sample(cpu: usize, source: Source, cycle: u64)
{
    let Some(acc) = acc_for(cpu)
    else
    {
        return;
    };
    let n = acc.count.fetch_add(1, Ordering::Relaxed);
    let Some(word) = acc.words.get((n as usize) % ACC_WORDS)
    else
    {
        return;
    };
    // Non-crypto compression: distinguish the sample by sequence and source so
    // identical cycle deltas at different events do not cancel under XOR.
    let mixed = cycle.rotate_left((n & 63) as u32)
        ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ (source as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    word.fetch_xor(mixed, Ordering::Relaxed);
}

/// Serialise CPU `cpu`'s accumulator — staging words, sample count, and the
/// instantaneous cycle counter (so every contribution carries fresh timing
/// even when no interrupt-time samples accrued since the last fold). Returns
/// `None` before `init_storage`.
fn collect(cpu: usize) -> Option<[u8; (ACC_WORDS + 2) * 8]>
{
    let acc = acc_for(cpu)?;
    let words = acc.words.each_ref().map(|w| w.load(Ordering::Relaxed));
    let count = acc.count.load(Ordering::Relaxed);
    let cycle = crate::arch::current::entropy::read_cycle_counter();
    let mut buf = [0u8; (ACC_WORDS + 2) * 8];
    for (bytes, value) in buf
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(words.into_iter().chain([count, cycle]))
    {
        *bytes = value.to_le_bytes();
    }
    Some(buf)
}

/// Fold CPU `cpu`'s accumulated jitter into the central pool. Off the
/// interrupt path (takes the pool lock).
pub fn contribute_to_pool(cpu: usize)
{
    if let Some(buf) = collect(cpu)
    {
        pool::absorb(&buf);
    }
}

/// Fold CPU `cpu`'s accumulated jitter without spinning on the pool lock.
/// Returns `false` when the pool lock is contended (nothing folded).
pub fn try_contribute_to_pool(cpu: usize) -> bool
{
    match collect(cpu)
    {
        Some(buf) => pool::try_absorb(&buf),
        None => true,
    }
}
