// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cpu_mask.rs

//! Fixed-capacity sets of logical CPU indices.
//!
//! Two representations of a subset of `[0, MAX_CPUS)`, both vectors of 64-bit
//! words sized to cover [`crate::sched::MAX_CPUS`]:
//!
//! - [`CpuMask`] — a plain value for building, snapshotting, and iterating a
//!   set (the target set of a TLB shootdown, the online-CPU set).
//! - [`AtomicCpuMask`] — a concurrently-updated set where one CPU sets or
//!   clears its own bit while another reads or overwrites the whole set: the
//!   TLB-shootdown acknowledgement set, an address space's active-CPU set, and
//!   the reschedule-pending flag.
//!
//! These replace the single-`u64` masks that capped the system at 64 CPUs; the
//! word count scales with `MAX_CPUS` so per-CPU bit arithmetic lives in one
//! place rather than being open-coded as `1u64 << cpu` at each call site.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::sched::MAX_CPUS;

/// Number of 64-bit words needed to cover every CPU index in `[0, MAX_CPUS)`.
pub const CPU_MASK_WORDS: usize = MAX_CPUS.div_ceil(64);

/// Map a CPU index to its `(word, bit)` position.
#[inline]
const fn word_bit(cpu: usize) -> (usize, u64)
{
    (cpu / 64, 1u64 << (cpu % 64))
}

/// A plain (non-atomic) set of CPU indices in `[0, MAX_CPUS)`.
#[derive(Clone, Copy)]
pub struct CpuMask
{
    words: [u64; CPU_MASK_WORDS],
}

impl CpuMask
{
    /// The empty set.
    pub const fn empty() -> Self
    {
        Self {
            words: [0; CPU_MASK_WORDS],
        }
    }

    /// The set of all CPU indices in `[0, n)`. `n` must be `<= MAX_CPUS`.
    pub fn range(n: usize) -> Self
    {
        debug_assert!(n <= MAX_CPUS, "CpuMask::range: n exceeds MAX_CPUS");
        let mut m = Self::empty();
        let full = (n / 64).min(CPU_MASK_WORDS);
        for w in m.words.iter_mut().take(full)
        {
            *w = u64::MAX;
        }
        let rem = n % 64;
        if rem != 0 && full < CPU_MASK_WORDS
        {
            m.words[full] = (1u64 << rem) - 1;
        }
        m
    }

    /// Add `cpu` to the set.
    #[inline]
    pub fn set(&mut self, cpu: usize)
    {
        let (w, b) = word_bit(cpu);
        self.words[w] |= b;
    }

    /// Remove `cpu` from the set.
    #[inline]
    pub fn clear(&mut self, cpu: usize)
    {
        let (w, b) = word_bit(cpu);
        self.words[w] &= !b;
    }

    /// Whether the set is empty.
    #[inline]
    pub fn is_empty(&self) -> bool
    {
        self.words.iter().all(|&w| w == 0)
    }

    /// The lowest CPU index in the set, or `None` if empty.
    #[inline]
    pub fn first(&self) -> Option<usize>
    {
        for (i, &w) in self.words.iter().enumerate()
        {
            if w != 0
            {
                return Some(i * 64 + w.trailing_zeros() as usize);
            }
        }
        None
    }

    /// Iterate the CPU indices in the set in ascending order.
    #[inline]
    pub fn iter(&self) -> CpuMaskIter
    {
        CpuMaskIter {
            words: self.words,
            word: 0,
        }
    }
}

/// Ascending iterator over the CPU indices in a [`CpuMask`]. Consumes a copy
/// of the underlying words, so it does not borrow the source mask.
pub struct CpuMaskIter
{
    words: [u64; CPU_MASK_WORDS],
    word: usize,
}

impl Iterator for CpuMaskIter
{
    type Item = usize;

    fn next(&mut self) -> Option<usize>
    {
        while self.word < CPU_MASK_WORDS
        {
            let w = self.words[self.word];
            if w != 0
            {
                let bit = w.trailing_zeros() as usize;
                // Clear the lowest set bit so the next call advances.
                self.words[self.word] = w & (w - 1);
                return Some(self.word * 64 + bit);
            }
            self.word += 1;
        }
        None
    }
}

/// A concurrently-updated set of CPU indices in `[0, MAX_CPUS)`.
///
/// Each word is updated independently; whole-set [`store`](Self::store) and
/// [`snapshot`](Self::snapshot) are not atomic across words, which matches
/// every use here — the only cross-word readers (shootdown ack-poll, watchdog)
/// observe a monotonically draining set and re-read until it is empty.
pub struct AtomicCpuMask
{
    words: [AtomicU64; CPU_MASK_WORDS],
}

impl AtomicCpuMask
{
    /// The empty set.
    pub const fn new() -> Self
    {
        Self {
            words: [const { AtomicU64::new(0) }; CPU_MASK_WORDS],
        }
    }

    /// Add `cpu` to the set.
    #[inline]
    pub fn set_cpu(&self, cpu: usize, order: Ordering)
    {
        let (w, b) = word_bit(cpu);
        self.words[w].fetch_or(b, order);
    }

    /// Remove `cpu` from the set.
    #[inline]
    pub fn clear_cpu(&self, cpu: usize, order: Ordering)
    {
        let (w, b) = word_bit(cpu);
        self.words[w].fetch_and(!b, order);
    }

    /// Remove `cpu` from the set, returning whether it had been present.
    #[inline]
    pub fn take_cpu(&self, cpu: usize, order: Ordering) -> bool
    {
        let (w, b) = word_bit(cpu);
        self.words[w].fetch_and(!b, order) & b != 0
    }

    /// Whether `cpu` is in the set.
    #[inline]
    pub fn test_cpu(&self, cpu: usize, order: Ordering) -> bool
    {
        let (w, b) = word_bit(cpu);
        self.words[w].load(order) & b != 0
    }

    /// Whether the set is empty.
    #[inline]
    pub fn is_empty(&self, order: Ordering) -> bool
    {
        self.words.iter().all(|w| w.load(order) == 0)
    }

    /// Overwrite the set with `mask`.
    #[inline]
    pub fn store(&self, mask: &CpuMask, order: Ordering)
    {
        for (w, &v) in self.words.iter().zip(mask.words.iter())
        {
            w.store(v, order);
        }
    }

    /// Read the set into a plain [`CpuMask`].
    #[inline]
    pub fn snapshot(&self, order: Ordering) -> CpuMask
    {
        let mut m = CpuMask::empty();
        for (slot, w) in m.words.iter_mut().zip(self.words.iter())
        {
            *slot = w.load(order);
        }
        m
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Collect an iterator into a fixed buffer, returning the populated length.
    fn drain<I: Iterator<Item = usize>>(it: I, out: &mut [usize; 128]) -> usize
    {
        let mut n = 0;
        for cpu in it
        {
            out[n] = cpu;
            n += 1;
        }
        n
    }

    #[test]
    fn range_sets_low_bits()
    {
        let m = CpuMask::range(3);
        let mut buf = [0usize; 128];
        let n = drain(m.iter(), &mut buf);
        assert_eq!(&buf[..n], &[0, 1, 2]);
        assert!(!m.is_empty());
        assert_eq!(m.first(), Some(0));
    }

    #[test]
    fn range_spans_words()
    {
        // Only meaningful when MAX_CPUS > 64.
        if CPU_MASK_WORDS < 2
        {
            return;
        }
        let m = CpuMask::range(70);
        let mut buf = [0usize; 128];
        let n = drain(m.iter(), &mut buf);
        assert_eq!(n, 70);
        assert_eq!(buf[0], 0);
        assert_eq!(buf[n - 1], 69);
    }

    #[test]
    fn set_adds_bit()
    {
        let mut m = CpuMask::empty();
        m.set(2);
        m.set(65);
        let mut buf = [0usize; 128];
        let n = drain(m.iter(), &mut buf);
        assert_eq!(&buf[..n], &[2, 65]);
    }

    #[test]
    fn clear_removes_bit()
    {
        let mut m = CpuMask::range(4);
        m.clear(1);
        let mut buf = [0usize; 128];
        let n = drain(m.iter(), &mut buf);
        assert_eq!(&buf[..n], &[0, 2, 3]);
    }

    #[test]
    fn empty_is_empty()
    {
        let m = CpuMask::empty();
        assert!(m.is_empty());
        assert_eq!(m.first(), None);
        assert_eq!(m.iter().next(), None);
    }

    #[test]
    fn atomic_set_take_clear()
    {
        let a = AtomicCpuMask::new();
        assert!(a.is_empty(Ordering::Relaxed));
        a.set_cpu(5, Ordering::Relaxed);
        a.set_cpu(63, Ordering::Relaxed);
        assert!(a.test_cpu(5, Ordering::Relaxed));
        assert!(!a.is_empty(Ordering::Relaxed));
        assert!(a.take_cpu(5, Ordering::Relaxed));
        assert!(!a.take_cpu(5, Ordering::Relaxed));
        a.clear_cpu(63, Ordering::Relaxed);
        assert!(a.is_empty(Ordering::Relaxed));
    }

    #[test]
    fn atomic_store_snapshot_roundtrip()
    {
        let a = AtomicCpuMask::new();
        let src = CpuMask::range(4);
        a.store(&src, Ordering::Relaxed);
        let snap = a.snapshot(Ordering::Relaxed);
        let mut buf = [0usize; 128];
        let n = drain(snap.iter(), &mut buf);
        assert_eq!(&buf[..n], &[0, 1, 2, 3]);
    }
}
