// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/cov.rs

//! The edge counters `SanitizerCoverage` maintains (`-sanitizer-coverage-inline-8bit-counters`):
//! one byte per instrumented edge, which instrumented code increments in
//! place. Each instrumented module registers its counter array before `main`
//! through [`__sanitizer_cov_8bit_counters_init`], and its table of edge
//! addresses (`-sanitizer-coverage-pc-table`) through
//! [`__sanitizer_cov_pcs_init`]; the engine reads the arrays after each
//! execution and zeroes them before the next.

use std::ptr::{with_exposed_provenance, with_exposed_provenance_mut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// Each registered counter array: its address, its provenance exposed, and
/// its length in bytes.
static REGIONS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

/// The number of entries the registered PC tables hold, one per edge.
static PCS: AtomicUsize = AtomicUsize::new(0);

/// The size of one PC-table entry: the edge's address and its flags.
const PC_ENTRY: usize = 2 * size_of::<usize>();

/// Record the counter array `[start, stop)` of an instrumented module. The
/// module's constructor calls it before `main`.
///
/// # Safety
///
/// `[start, stop)` is an array of bytes that stays valid for the rest of the
/// program and that nothing but instrumented code writes, as the counter
/// array `SanitizerCoverage` emits for a module is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8)
{
    register(&REGIONS, start, stop);
}

/// Add the counter array `[start, stop)` to `regions`.
fn register(regions: &Mutex<Vec<(usize, usize)>>, start: *mut u8, stop: *mut u8)
{
    let len = stop.addr().saturating_sub(start.addr());
    if len == 0
    {
        return;
    }
    let mut regions = regions.lock().unwrap_or_else(PoisonError::into_inner);
    regions.push((start.expose_provenance(), len));
}

/// Record the PC table `[start, stop)` of an instrumented module, which sizes
/// its instrumentation: one entry per edge.
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_pcs_init(start: *const usize, stop: *const usize)
{
    let entries = stop
        .addr()
        .saturating_sub(start.addr())
        .checked_div(PC_ENTRY)
        .unwrap_or(0);
    PCS.fetch_add(entries, Ordering::Relaxed);
}

/// The counter arrays registered when a run starts.
///
/// Every module's constructor has run by then, so the set is complete. The
/// methods read and write the arrays, so [`Counters::registered`] makes its
/// caller promise that no instrumented code runs while one of them does.
pub struct Counters
{
    regions: Vec<(usize, usize)>,
    len: usize,
}

impl Counters
{
    /// The arrays registered so far.
    ///
    /// # Safety
    ///
    /// No instrumented code runs, on any thread, while a method of the value
    /// returned runs: the target's code runs only on the thread that calls
    /// them, between their calls.
    #[must_use]
    pub unsafe fn registered() -> Self
    {
        Self::over(&REGIONS)
    }

    /// The arrays `regions` holds.
    fn over(regions: &Mutex<Vec<(usize, usize)>>) -> Self
    {
        let regions = regions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let len = regions
            .iter()
            .fold(0usize, |sum, &(_, len)| sum.saturating_add(len));
        Self { regions, len }
    }

    /// The number of counters, one per instrumented edge.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.len
    }

    /// Whether no instrumented module registered a counter: the target was
    /// built without `SanitizerCoverage`.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The number of edges the registered PC tables name.
    #[must_use]
    pub fn edges() -> usize
    {
        PCS.load(Ordering::Relaxed)
    }

    /// Zero every counter, before an execution.
    pub fn clear(&self)
    {
        for &(addr, len) in &self.regions
        {
            let counters = with_exposed_provenance_mut::<u8>(addr);
            // SAFETY: `counters` and `len` are a counter array registered
            // under the contract of `__sanitizer_cov_8bit_counters_init`: an
            // array of `len` bytes that lives as long as the program, which
            // only instrumented code writes. By the contract of
            // `Counters::registered`, none of that code runs during this call.
            unsafe { counters.write_bytes(0, len) };
        }
    }

    /// Call `hit` with the index, counted across every array in registration
    /// order, and the count of each counter the last execution incremented.
    pub fn for_each_hit(&self, mut hit: impl FnMut(usize, u8))
    {
        let mut base = 0usize;
        for &(addr, len) in &self.regions
        {
            let counters = with_exposed_provenance::<u8>(addr);
            // SAFETY: as in `clear`, `counters` is a live array of `len` bytes,
            // and no instrumented code runs while the slice lives, so nothing
            // writes it meanwhile.
            let counters = unsafe { std::slice::from_raw_parts(counters, len) };
            for (index, &count) in counters.iter().enumerate()
            {
                if count != 0
                {
                    hit(base.wrapping_add(index), count);
                }
            }
            base = base.wrapping_add(len);
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a counter array read at the wrong offset or length, or
    // left uncleared, so one execution's coverage leaks into the next one's.
    #[test]
    fn registered_counters_are_read_across_arrays_and_cleared()
    {
        let mut arrays = [0u8; 7];
        let base = arrays.as_mut_ptr();
        // Every access below goes through `base`, from which the registered
        // addresses derive.
        let at = |offset: usize| base.wrapping_add(offset);
        let regions = Mutex::new(Vec::new());
        register(&regions, at(0), at(4));
        register(&regions, at(4), at(7));
        register(&regions, at(7), at(7));
        let counters = Counters::over(&regions);
        assert_eq!(counters.len(), 7);
        // SAFETY: offset 1 lies inside `arrays`, and no other access to it is
        // live.
        unsafe { at(1).write(5) };
        // SAFETY: as above, for offset 6.
        unsafe { at(6).write(1) };
        let mut hits = Vec::new();
        counters.for_each_hit(|index, count| hits.push((index, count)));
        assert_eq!(hits, [(1, 5), (6, 1)]);
        counters.clear();
        // SAFETY: `base` points at the 7 bytes of `arrays`, which `counters`
        // no longer accesses.
        let cleared = unsafe { std::slice::from_raw_parts(base, 7) };
        assert_eq!(cleared, [0u8; 7]);
    }
}
