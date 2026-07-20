// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/jitter.rs

//! Per-CPU jitter entropy accumulator.
//!
//! Timing jitter is the always-available entropy source and the *only* source
//! on platforms without a hardware RNG (riscv64 under default firmware). Each
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

/// Staging words per CPU.
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

static ACC_PTR: AtomicPtr<Acc> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU accumulator slab. Called once from `init_storage`.
pub fn init_storage(cpu_count: usize, allocator: &mut BuddyAllocator)
{
    let bytes = cpu_count * core::mem::size_of::<Acc>();
    let ptr = crate::sched::alloc_zeroed_slab::<Acc>(bytes, allocator, "ENTROPY_JITTER");
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
// cast_possible_truncation: both casts narrow values already masked below
// ACC_WORDS / 64; both targets are 64-bit so usize == u64.
#[allow(clippy::cast_possible_truncation)]
pub fn sample(cpu: usize, source: Source, cycle: u64)
{
    let Some(acc) = acc_for(cpu)
    else
    {
        return;
    };
    let n = acc.count.fetch_add(1, Ordering::Relaxed);
    let idx = (n % ACC_WORDS as u64) as usize;
    // Non-crypto compression: distinguish the sample by sequence and source so
    // identical cycle deltas at different events do not cancel under XOR.
    let mixed = cycle.rotate_left((n & 63) as u32)
        ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ (source as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    acc.words[idx].fetch_xor(mixed, Ordering::Relaxed);
}

/// Serialise CPU `cpu`'s accumulator — staging words, sample count, and the
/// instantaneous cycle counter (so every contribution carries fresh timing
/// even when no interrupt-time samples accrued since the last fold). Returns
/// `None` before `init_storage`.
fn collect(cpu: usize) -> Option<[u8; (ACC_WORDS + 2) * 8]>
{
    let acc = acc_for(cpu)?;
    let mut buf = [0u8; (ACC_WORDS + 2) * 8];
    for i in 0..ACC_WORDS
    {
        let w = acc.words[i].load(Ordering::Relaxed);
        buf[i * 8..][..8].copy_from_slice(&w.to_le_bytes());
    }
    let count = acc.count.load(Ordering::Relaxed);
    buf[ACC_WORDS * 8..][..8].copy_from_slice(&count.to_le_bytes());
    let cycle = crate::arch::current::entropy::read_cycle_counter();
    buf[(ACC_WORDS + 1) * 8..][..8].copy_from_slice(&cycle.to_le_bytes());
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
