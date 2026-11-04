// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/nospec.rs

//! Arch-neutral speculation-safe bounds, built on the active architecture's
//! `speculation::index_mask`.
//!
//! A bound enforced only by a conditional branch does not hold on a
//! mispredicted path: the loads behind the branch execute transiently with the
//! out-of-bound value. These helpers enforce a bound as data, so the address
//! of a dependent load is in range whichever way the branch is predicted. The
//! rule they serve is docs/capability-model.md § Capability Spaces; their use
//! on the capability-lookup path is core/kernel/docs/capability-internals.md
//! § Speculative-Execution Hardening.

use super::current::speculation;

/// All-ones when `index < bound`, zero otherwise, computed without a branch
/// (the active architecture's `speculation::index_mask`).
#[inline]
#[must_use]
pub fn index_mask(index: usize, bound: usize) -> usize
{
    speculation::index_mask(index, bound)
}

/// `index` when `index < bound`, else `0`, computed without a branch.
///
/// Callers keep their architectural bounds check: an out-of-range `index` is
/// still refused by that check, and the clamp only bounds the loads a
/// mispredicted check lets run.
#[inline]
#[must_use]
pub fn mask_index(index: usize, bound: usize) -> usize
{
    index & speculation::index_mask(index, bound)
}

// The kernel targets 64-bit architectures only, so `usize` and `u64` have one
// width and the conversions in `mask_index_u64` are exact.
const _: () = assert!(usize::BITS == u64::BITS);

/// [`mask_index`] for a `u64` index (a syscall register value).
#[inline]
#[must_use]
// cast_possible_truncation: `usize` is 64 bits wide on every kernel target
// (asserted above), so `u64 as usize` and back are exact.
#[allow(clippy::cast_possible_truncation)]
pub fn mask_index_u64(index: u64, bound: u64) -> u64
{
    mask_index(index as usize, bound as usize) as u64
}

/// All-ones when `cond` holds, zero otherwise, as an opaque value the compiler
/// cannot turn back into a branch.
///
/// The output is opaque, the input is not: `cond` MUST NOT be a condition a
/// dominating branch has already tested, or the compiler folds it to a
/// constant inside that branch's arm and the mask no longer depends on the
/// data. A mask taken inside such an arm compares a value passed through
/// [`hide`] ahead of the branch instead.
#[inline]
#[must_use]
pub fn mask_if(cond: bool) -> usize
{
    speculation::index_mask(0, usize::from(cond))
}

/// `value`, passed through the active architecture's `speculation::hide`: an
/// opaque copy the compiler cannot relate to `value`, taken where it is
/// written. A later branch on `value` tells the compiler nothing about it.
#[inline]
#[must_use]
pub fn hide(value: usize) -> usize
{
    speculation::hide(value)
}

/// `if_set` when `mask` is all-ones, `otherwise` when it is zero, selected
/// without a branch. `mask` MUST be one of those two values (an
/// [`index_mask`] or [`mask_if`] result).
///
/// The result carries exposed provenance: both inputs' provenance is exposed,
/// and the selected address is converted back under it.
#[inline]
#[must_use]
pub fn select_ptr<T>(mask: usize, if_set: *mut T, otherwise: *mut T) -> *mut T
{
    let a = if_set.expose_provenance();
    let b = otherwise.expose_provenance();
    core::ptr::with_exposed_provenance_mut((a & mask) | (b & !mask))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn index_mask_truth_table()
    {
        assert_eq!(index_mask(0, 1), usize::MAX);
        assert_eq!(index_mask(0, 0), 0);
        assert_eq!(index_mask(127, 128), usize::MAX);
        assert_eq!(index_mask(128, 128), 0);
        assert_eq!(index_mask(129, 128), 0);
        assert_eq!(index_mask(usize::MAX, 128), 0);
        assert_eq!(index_mask(usize::MAX - 1, usize::MAX), usize::MAX);
        assert_eq!(index_mask(usize::MAX, usize::MAX), 0);
    }

    #[test]
    fn mask_index_clamps_out_of_range_to_zero()
    {
        assert_eq!(mask_index(5, 128), 5);
        assert_eq!(mask_index(127, 128), 127);
        assert_eq!(mask_index(128, 128), 0);
        assert_eq!(mask_index(usize::MAX, 128), 0);
        assert_eq!(mask_index(0x00FF_FFFF, 3_677_184), 0);
    }

    #[test]
    fn mask_index_u64_clamps_out_of_range_to_zero()
    {
        assert_eq!(mask_index_u64(55, 56), 55);
        assert_eq!(mask_index_u64(56, 56), 0);
        assert_eq!(mask_index_u64(u64::MAX, 56), 0);
    }

    #[test]
    fn mask_if_is_all_ones_or_zero()
    {
        assert_eq!(mask_if(true), usize::MAX);
        assert_eq!(mask_if(false), 0);
    }

    #[test]
    fn hide_is_the_identity()
    {
        for v in [0, 1, 0xE, usize::MAX]
        {
            assert_eq!(hide(v), v);
        }
    }

    #[test]
    fn select_ptr_picks_by_mask()
    {
        let mut x = 1u32;
        let mut y = 2u32;
        let px: *mut u32 = &raw mut x;
        let py: *mut u32 = &raw mut y;
        assert_eq!(select_ptr(usize::MAX, px, py), px);
        assert_eq!(select_ptr(0, px, py), py);
        assert!(select_ptr(0, px, core::ptr::null_mut()).is_null());
    }
}
