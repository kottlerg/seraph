// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/pool.rs

//! Central entropy pool.
//!
//! A single forward-secure sponge that accumulates entropy from every source
//! (hardware RNG, jitter, boot-info) and hands seed material to the per-CPU
//! generators. Guarded by a leaf spinlock: it is never taken at interrupt time
//! (interrupt-time jitter lands in a per-CPU buffer and is folded in off the
//! interrupt path), and the lock is never held across a blocking operation.
//!
//! The raw pool is never exposed: callers absorb into it or draw *seed* bytes,
//! and consumer-facing output comes only from the per-CPU generators.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use super::sponge::Prng;
use crate::sync::Spinlock;

static POOL_LOCK: Spinlock = Spinlock::new();
static POOL_PTR: AtomicPtr<Prng> = AtomicPtr::new(core::ptr::null_mut());

/// Set once the pool has absorbed its initial seed and may be drawn from.
static SEEDED: AtomicBool = AtomicBool::new(false);

/// Publish the buddy-allocated pool storage. Called once from `init_storage`.
pub fn install(ptr: *mut Prng)
{
    POOL_PTR.store(ptr, Ordering::Release);
}

/// Absorb `data` into the pool. No-op before [`install`]. Safe from process
/// context only (takes the pool lock).
pub fn absorb(data: &[u8])
{
    let ptr = POOL_PTR.load(Ordering::Acquire);
    if ptr.is_null()
    {
        return;
    }
    // SAFETY: `ptr` was published by `install` over buddy-allocated storage
    // sized for one `Prng`; the lock serialises all pool access.
    unsafe {
        let saved = POOL_LOCK.lock_raw();
        (*ptr).absorb(data);
        POOL_LOCK.unlock_raw(saved);
    }
}

/// Absorb `data` into the pool without spinning on the pool lock.
///
/// Returns `false` when the lock is contended (nothing absorbed); the caller
/// defers its contribution. Keeps [`absorb`]'s no-op-before-[`install`]
/// semantics (returns `true`: there is nothing to defer to).
pub fn try_absorb(data: &[u8]) -> bool
{
    let ptr = POOL_PTR.load(Ordering::Acquire);
    if ptr.is_null()
    {
        return true;
    }
    // SAFETY: as in `absorb`; the lock serialises all pool access.
    unsafe {
        let Some(saved) = POOL_LOCK.try_lock_raw()
        else
        {
            return false;
        };
        (*ptr).absorb(data);
        POOL_LOCK.unlock_raw(saved);
    }
    true
}

/// Draw seed material from the pool into `out`.
///
/// # Panics
/// Debug-asserts the pool was installed; drawing before `init_storage` is a
/// kernel bug.
pub fn draw_seed(out: &mut [u8])
{
    let ptr = POOL_PTR.load(Ordering::Acquire);
    debug_assert!(!ptr.is_null(), "entropy pool drawn before install");
    // SAFETY: as in `absorb`; the lock serialises all pool access.
    unsafe {
        let saved = POOL_LOCK.lock_raw();
        (*ptr).fill(out);
        POOL_LOCK.unlock_raw(saved);
    }
}

/// Draw seed material without spinning on the pool lock.
///
/// Returns `false` when the lock is contended; `out` is untouched and the
/// caller defers its reseed.
///
/// # Panics
/// Debug-asserts the pool was installed, as in [`draw_seed`].
pub fn try_draw_seed(out: &mut [u8]) -> bool
{
    let ptr = POOL_PTR.load(Ordering::Acquire);
    debug_assert!(!ptr.is_null(), "entropy pool drawn before install");
    // SAFETY: as in `absorb`; the lock serialises all pool access.
    unsafe {
        let Some(saved) = POOL_LOCK.try_lock_raw()
        else
        {
            return false;
        };
        (*ptr).fill(out);
        POOL_LOCK.unlock_raw(saved);
    }
    true
}

/// Mark the pool seeded (initial entropy absorbed).
pub fn mark_seeded()
{
    SEEDED.store(true, Ordering::Release);
}

/// Whether the pool holds its initial seed and may be drawn from.
pub fn is_seeded() -> bool
{
    SEEDED.load(Ordering::Acquire)
}
