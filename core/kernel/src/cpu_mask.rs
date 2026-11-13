// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cpu_mask.rs

//! Sets of logical CPU indices, as wide as this boot's CPU count.
//!
//! [`AtomicCpuMask`] is a concurrently-updated set where one CPU sets or clears
//! its own bit while another reads, copies, or iterates the whole set: the
//! TLB-shootdown acknowledgement set, an address space's active-CPU set, and the
//! reschedule-pending set.
//!
//! Every mask holds [`mask_words`] 64-bit words, `cpu_count.div_ceil(64)`, fixed
//! at Phase 4 ([`set_boot_cpu_count`]). A mask is a view over storage held with
//! its object (an address space's wrapper page, a TLB request's slab slot, the
//! scheduler's Phase 4 slab), so a boot pays only for the CPUs it has. No mask is
//! held by value on a kernel stack: copies between sets are word by word
//! ([`AtomicCpuMask::fill_from`]). `MAX_CPUS` bounds the CPU count but sizes no
//! mask. A hierarchical mask is not the design: it still fixes a maximum, and
//! adds a level to every bit test on the shootdown and context-switch paths.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::sched::MAX_CPUS;

/// Words a mask of this boot's CPUs needs: `cpu_count.div_ceil(64)`, set once
/// by [`set_boot_cpu_count`] before any mask is built. Zero until then.
static MASK_WORDS: AtomicUsize = AtomicUsize::new(0);

/// Words a mask of `cpu_count` CPUs needs.
#[must_use]
pub const fn words_for(cpu_count: usize) -> usize
{
    cpu_count.div_ceil(64)
}

/// Most words any boot's mask holds: [`words_for`] of `MAX_CPUS`. Bounds the
/// storage an object reserves for its mask (an address space's wrapper page).
pub const MAX_MASK_WORDS: usize = words_for(MAX_CPUS);

/// Record this boot's CPU count, which fixes every mask's width. Called once,
/// at Phase 4, before any mask is built.
pub fn set_boot_cpu_count(cpu_count: usize)
{
    debug_assert!(
        (1..=MAX_CPUS).contains(&cpu_count),
        "set_boot_cpu_count: CPU count outside 1..=MAX_CPUS"
    );
    MASK_WORDS.store(words_for(cpu_count), Ordering::Relaxed);
}

/// Words every mask of this boot holds ([`set_boot_cpu_count`]).
#[must_use]
pub fn mask_words() -> usize
{
    MASK_WORDS.load(Ordering::Relaxed)
}

/// Map a CPU index to its `(word, bit)` position.
#[inline]
const fn word_bit(cpu: usize) -> (usize, u64)
{
    (cpu / 64, 1u64 << (cpu % 64))
}

/// The set a mask is filled from by [`AtomicCpuMask::fill_from`].
pub enum MaskSource<'a>
{
    /// Every CPU index in another mask, read with the given ordering.
    Mask(&'a AtomicCpuMask, Ordering),
    /// Every CPU index below the given count.
    Below(usize),
}

/// A concurrently-updated set of CPU indices, a view over words held with its
/// object.
///
/// Each word is updated independently; whole-set [`fill_from`](Self::fill_from)
/// and [`iter`](Self::iter) are not atomic across words. Every reader needs only
/// per-CPU atomicity: the shootdown ack-poll and the watchdog's `any_pending`
/// re-read a draining set until it is empty, and the shootdown-target copy of an
/// address space's active-CPU set relies, per CPU, on the `tlb_gen` check (see
/// [memory-internals.md § SMP TLB Shootdown](../docs/memory-internals.md#smp-tlb-shootdown)).
pub struct AtomicCpuMask
{
    words: *const AtomicU64,
    len: usize,
}

// SAFETY: the view only reads and writes its words through atomics, and the
// storage it names lives as long as the object that holds the view.
unsafe impl Send for AtomicCpuMask {}
// SAFETY: as above.
unsafe impl Sync for AtomicCpuMask {}

impl AtomicCpuMask
{
    /// A mask with no storage yet: every set is empty and setting a bit is a
    /// caller error. The holder attaches storage ([`attach`](Self::attach))
    /// before any CPU uses it.
    pub const fn unattached() -> Self
    {
        Self {
            words: core::ptr::null(),
            len: 0,
        }
    }

    /// A view over the `len` words at `words`, which become the empty set.
    ///
    /// # Safety
    /// `words` is valid, 8-byte aligned, and reserved for this mask for as long
    /// as the view is used; nothing else accesses it except through views.
    pub unsafe fn attach(words: *mut AtomicU64, len: usize) -> Self
    {
        for i in 0..len
        {
            // SAFETY: caller contract: `len` reserved words at `words`, and
            // i < len, so the offset stays inside them.
            let word = unsafe { words.add(i) };
            // SAFETY: `word` is one of the reserved words, valid and aligned by
            // the caller contract.
            unsafe { word.write(AtomicU64::new(0)) };
        }
        Self { words, len }
    }

    /// A view over the `len` words at `words`, keeping the set they hold.
    ///
    /// # Safety
    /// `words` holds `len` initialised, 8-byte aligned atomic words that live
    /// as long as the view is used and are only accessed through views.
    pub unsafe fn from_words(words: *const AtomicU64, len: usize) -> Self
    {
        Self { words, len }
    }

    /// The mask's words.
    #[inline]
    fn words(&self) -> &[AtomicU64]
    {
        if self.len == 0
        {
            return &[];
        }
        // SAFETY: `attach` contract: `len` live words at `words`.
        unsafe { core::slice::from_raw_parts(self.words, self.len) }
    }

    /// The word holding `cpu`'s bit, and the bit. `cpu` must lie in the mask.
    #[inline]
    fn slot(&self, cpu: usize) -> (&AtomicU64, u64)
    {
        let (w, b) = word_bit(cpu);
        let Some(word) = self.words().get(w)
        else
        {
            cpu_past_mask()
        };
        (word, b)
    }

    /// Add `cpu` to the set.
    #[inline]
    pub fn set_cpu(&self, cpu: usize, order: Ordering)
    {
        let (word, b) = self.slot(cpu);
        word.fetch_or(b, order);
    }

    /// Remove `cpu` from the set.
    #[inline]
    pub fn clear_cpu(&self, cpu: usize, order: Ordering)
    {
        let (word, b) = self.slot(cpu);
        word.fetch_and(!b, order);
    }

    /// Remove `cpu` from the set, returning whether it had been present.
    #[inline]
    pub fn take_cpu(&self, cpu: usize, order: Ordering) -> bool
    {
        let (word, b) = self.slot(cpu);
        word.fetch_and(!b, order) & b != 0
    }

    /// Whether `cpu` is in the set.
    #[inline]
    pub fn test_cpu(&self, cpu: usize, order: Ordering) -> bool
    {
        let (word, b) = self.slot(cpu);
        word.load(order) & b != 0
    }

    /// Whether the set is empty.
    #[inline]
    pub fn is_empty(&self, order: Ordering) -> bool
    {
        self.words().iter().all(|w| w.load(order) == 0)
    }

    /// The lowest CPU index in the set, or `None` if empty.
    #[inline]
    pub fn first(&self, order: Ordering) -> Option<usize>
    {
        self.iter(order).next()
    }

    /// Iterate the CPU indices in the set in ascending order, loading each
    /// word with `order` when the iteration reaches it.
    #[inline]
    pub fn iter(&self, order: Ordering) -> AtomicCpuMaskIter<'_>
    {
        AtomicCpuMaskIter {
            words: self.words(),
            order,
            word: 0,
            bits: 0,
            loaded: false,
        }
    }

    /// Overwrite the set with `source` less `except` (a CPU index, or one past
    /// the mask to except none), storing each word with `order`. Returns
    /// whether the result is non-empty.
    pub fn fill_from(&self, source: &MaskSource<'_>, except: usize, order: Ordering) -> bool
    {
        let mut any = false;
        for (i, word) in self.words().iter().enumerate()
        {
            let v = source.word_except(i, except);
            any |= v != 0;
            word.store(v, order);
        }
        any
    }

    /// Whether [`fill_from`](Self::fill_from) with these arguments would leave
    /// the set non-empty, without storing anything.
    pub fn fill_would_be_nonempty(&self, source: &MaskSource<'_>, except: usize) -> bool
    {
        (0..self.len).any(|i| source.word_except(i, except) != 0)
    }
}

impl MaskSource<'_>
{
    /// Word `i` of the set, less `except`.
    fn word_except(&self, i: usize, except: usize) -> u64
    {
        let v = match self
        {
            MaskSource::Mask(src, load) => src.words().get(i).map_or(0, |w| w.load(*load)),
            MaskSource::Below(n) => below_word(*n, i),
        };
        let (except_word, except_bit) = word_bit(except);
        if i == except_word { v & !except_bit } else { v }
    }
}

/// Halt for a CPU index past the mask's words. Host test builds panic instead,
/// so a test can observe the stop.
#[cold]
fn cpu_past_mask() -> !
{
    #[cfg(not(test))]
    crate::fatal("AtomicCpuMask: CPU index past the mask");
    #[cfg(test)]
    panic!("AtomicCpuMask: CPU index past the mask");
}

/// Word `i` of the set of every CPU index below `n`.
const fn below_word(n: usize, i: usize) -> u64
{
    // A word whose first index does not fit a `usize` lies past every `n`.
    let Some(start) = i.checked_mul(64)
    else
    {
        return 0;
    };
    let below = n.saturating_sub(start);
    if below >= 64
    {
        u64::MAX
    }
    else
    {
        // `below` < 64; a zero `below` gives the empty word.
        (1u64 << below).wrapping_sub(1)
    }
}

/// Ascending iterator over the CPU indices in an [`AtomicCpuMask`], loading
/// each word once, when the iteration reaches it.
pub struct AtomicCpuMaskIter<'a>
{
    words: &'a [AtomicU64],
    order: Ordering,
    word: usize,
    bits: u64,
    loaded: bool,
}

impl Iterator for AtomicCpuMaskIter<'_>
{
    type Item = usize;

    fn next(&mut self) -> Option<usize>
    {
        // `self.word` stays below the mask's word count, at most
        // `MAX_MASK_WORDS`, so the index arithmetic below does not wrap.
        while let Some(word) = self.words.get(self.word)
        {
            if !self.loaded
            {
                self.bits = word.load(self.order);
                self.loaded = true;
            }
            if self.bits != 0
            {
                let bit = self.bits.trailing_zeros() as usize;
                // Clear the lowest set bit so the next call advances; `bits`
                // is non-zero, so the subtraction does not wrap.
                self.bits &= self.bits.wrapping_sub(1);
                return Some(self.word.wrapping_mul(64).wrapping_add(bit));
            }
            self.word = self.word.wrapping_add(1);
            self.loaded = false;
        }
        None
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A mask over freshly leaked storage for `cpus` CPUs.
    fn mask(cpus: usize) -> AtomicCpuMask
    {
        let words: &'static mut [AtomicU64] =
            Vec::from_iter((0..words_for(cpus)).map(|_| AtomicU64::new(u64::MAX))).leak();
        // SAFETY: leaked storage, reserved for this mask for the test's life.
        unsafe { AtomicCpuMask::attach(words.as_mut_ptr(), words.len()) }
    }

    const R: Ordering = Ordering::Relaxed;

    /// Widths that exercise the partial-word edges, a shipping two-socket part
    /// (768) and the ceiling.
    const WIDTHS: [usize; 7] = [1, 63, 64, 65, 512, 768, MAX_CPUS];

    // Defect caught: a per-boot word count that rounds a partial word away,
    // so the top CPUs of a boot past a multiple of 64 have no bit.
    #[test]
    fn a_boots_mask_holds_one_word_per_64_cpus_rounded_up()
    {
        assert_eq!(words_for(1), 1);
        assert_eq!(words_for(64), 1);
        assert_eq!(words_for(65), 2);
        assert_eq!(words_for(128), 2);
        assert_eq!(words_for(129), 3);
        assert_eq!(words_for(MAX_CPUS), MAX_MASK_WORDS);
    }

    // Defect caught: attached storage that keeps what it held before, so a
    // fresh address space starts active on CPUs it never ran on.
    #[test]
    fn an_attached_mask_starts_empty()
    {
        for cpus in WIDTHS
        {
            let m = mask(cpus);
            assert!(m.is_empty(R));
            assert_eq!(m.first(R), None);
        }
    }

    // Defect caught: a bit lost or misplaced at a word edge, or the top CPU of
    // a boot unreachable.
    #[test]
    fn every_cpu_of_a_boot_sets_tests_takes_and_clears_its_own_bit()
    {
        for cpus in WIDTHS
        {
            let m = mask(cpus);
            for cpu in [0, cpus / 2, cpus - 1]
            {
                m.set_cpu(cpu, R);
                assert!(m.test_cpu(cpu, R));
                assert_eq!(m.iter(R).collect::<Vec<_>>(), [cpu]);
                assert!(m.take_cpu(cpu, R));
                assert!(!m.take_cpu(cpu, R));
                m.set_cpu(cpu, R);
                m.clear_cpu(cpu, R);
                assert!(m.is_empty(R));
            }
        }
    }

    // Defect caught: an all-CPU target set that misses the top partial word or
    // reaches past the boot's CPUs, or keeps the initiator in its own targets.
    #[test]
    fn filling_from_every_cpu_below_a_count_excepts_one()
    {
        for cpus in WIDTHS
        {
            let m = mask(cpus);
            assert!(m.fill_from(&MaskSource::Below(cpus), cpus, R));
            assert_eq!(m.iter(R).count(), cpus);
            assert_eq!(m.iter(R).last(), Some(cpus - 1));
            let except = cpus - 1;
            let any = m.fill_from(&MaskSource::Below(cpus), except, R);
            assert_eq!(any, cpus > 1);
            assert_eq!(m.iter(R).count(), cpus - 1);
            assert!(!m.test_cpu(except, R));
        }
    }

    // Defect caught: a shootdown target copy that drops bits of the source,
    // keeps the initiator, or reports targets when only the initiator was
    // active.
    #[test]
    fn filling_from_a_mask_copies_it_less_the_excepted_cpu()
    {
        for cpus in WIDTHS
        {
            let src = mask(cpus);
            let dst = mask(cpus);
            let set: Vec<usize> = [0, 63, 64, cpus - 1]
                .into_iter()
                .filter(|&c| c < cpus)
                .collect();
            for &c in &set
            {
                src.set_cpu(c, R);
            }
            assert!(dst.fill_from(&MaskSource::Mask(&src, R), cpus, R));
            let mut want = set.clone();
            want.dedup();
            assert_eq!(dst.iter(R).collect::<Vec<_>>(), want);
            let only = mask(cpus);
            only.set_cpu(cpus - 1, R);
            assert!(!dst.fill_from(&MaskSource::Mask(&only, R), cpus - 1, R));
            assert!(dst.is_empty(R));
        }
    }

    // Defect caught: a shootdown gate that disagrees with the fill it guards,
    // so an initiator skips every remote shootdown, or one with no target.
    #[test]
    fn the_non_empty_check_agrees_with_the_fill_it_guards()
    {
        for cpus in WIDTHS
        {
            // `mask` attaches, which empties the storage.
            let dst = mask(cpus);
            let empty = mask(cpus);
            let only_last = mask(cpus);
            only_last.set_cpu(cpus - 1, R);
            let ends = mask(cpus);
            ends.set_cpu(0, R);
            ends.set_cpu(cpus - 1, R);
            let sources = [
                MaskSource::Below(cpus),
                MaskSource::Below(1),
                MaskSource::Below(0),
                MaskSource::Mask(&empty, R),
                MaskSource::Mask(&only_last, R),
                MaskSource::Mask(&ends, R),
            ];
            for source in &sources
            {
                for except in [0, cpus - 1, cpus]
                {
                    let predicted = dst.fill_would_be_nonempty(source, except);
                    assert_eq!(
                        predicted,
                        dst.fill_from(source, except, R),
                        "{cpus} CPUs, except {except}"
                    );
                    assert_eq!(predicted, !dst.is_empty(R));
                }
            }
            // Only the excepted CPU active: no target.
            assert!(!dst.fill_would_be_nonempty(&MaskSource::Mask(&only_last, R), cpus - 1));
        }
    }

    // Defect caught: an unattached mask that reports a member or faults on a
    // read before its holder attaches storage.
    #[test]
    fn an_unattached_mask_is_empty()
    {
        let m = AtomicCpuMask::unattached();
        assert!(m.is_empty(R));
        assert_eq!(m.first(R), None);
        assert_eq!(m.iter(R).next(), None);
    }
}
