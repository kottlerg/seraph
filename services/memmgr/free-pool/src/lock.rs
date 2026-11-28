// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/lock.rs

//! The spin locks memmgr's receive threads share
//! (services/memmgr/docs/memory-pool.md § Concurrency): [`SpinMutex`], the
//! ledger lock G that owns every piece of memmgr's state the threads share,
//! and [`Stripes`], the per-process stripe locks that order the requests
//! acting on one process; and [`Claim`] and [`Once`], the checked cells of the
//! state those locks serialise or that is set once at start.
//!
//! Both are ticket locks: a taker draws a ticket and spins, without yielding,
//! until the lock serves it, so takers are served in the order they arrived.
//! Spinning is sound only where no two takers share a CPU and nothing that
//! outranks a holder runs on its CPU, as memmgr's receive threads are placed;
//! the locks themselves assume nothing about placement.

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

/// A FIFO spin lock with no data of its own.
pub struct TicketLock
{
    /// The ticket the next taker draws.
    next: AtomicU32,
    /// The ticket the lock serves: its holder's, while held.
    serving: AtomicU32,
}

impl TicketLock
{
    /// An unheld lock.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
        }
    }

    /// Take the lock, spinning until it serves this taker's ticket.
    pub fn lock(&self)
    {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.serving.load(Ordering::Acquire) != ticket
        {
            spin_loop();
        }
    }

    /// Take the lock only when no one holds it or waits for it.
    #[must_use]
    pub fn try_lock(&self) -> bool
    {
        let serving = self.serving.load(Ordering::Relaxed);
        self.next
            .compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Release the lock to the next ticket.
    ///
    /// # Safety
    /// The caller MUST hold the lock: only its holder writes `serving`.
    pub unsafe fn unlock(&self)
    {
        let serving = self.serving.load(Ordering::Relaxed);
        self.serving
            .store(serving.wrapping_add(1), Ordering::Release);
    }

    /// Whether some taker holds the lock.
    #[must_use]
    pub fn is_locked(&self) -> bool
    {
        self.next.load(Ordering::Relaxed) != self.serving.load(Ordering::Relaxed)
    }
}

impl Default for TicketLock
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// A value only the holder of its [`TicketLock`] reaches.
pub struct SpinMutex<T>
{
    lock: TicketLock,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a `SpinGuard`, which exists only
// while its thread holds the lock, so no two threads reach it at once; moving
// the value's access between threads needs it to be `Send`.
unsafe impl<T: Send> Sync for SpinMutex<T> {}

impl<T> SpinMutex<T>
{
    /// A mutex holding `value`, unheld.
    pub const fn new(value: T) -> Self
    {
        Self {
            lock: TicketLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    /// Take the lock and reach the value through the guard, which releases
    /// the lock when it drops.
    pub fn lock(&self) -> SpinGuard<'_, T>
    {
        self.lock.lock();
        SpinGuard { mutex: self }
    }

    /// Whether some thread holds the lock.
    #[must_use]
    pub fn is_locked(&self) -> bool
    {
        self.lock.is_locked()
    }
}

/// Proof that this thread holds a [`SpinMutex`], and the way to its value.
pub struct SpinGuard<'a, T>
{
    mutex: &'a SpinMutex<T>,
}

impl<T> SpinGuard<'_, T>
{
    /// Release the lock for the span of `f`, then take it again. The guard is
    /// borrowed mutably for the call, so no reference to the value lives
    /// across it, and `f` reaches the value only by taking the lock itself.
    pub fn unlocked<R>(&mut self, f: impl FnOnce() -> R) -> R
    {
        // SAFETY: the guard exists, so this thread holds the lock.
        unsafe { self.mutex.lock.unlock() };
        let r = f();
        self.mutex.lock.lock();
        r
    }
}

impl<T> Deref for SpinGuard<'_, T>
{
    type Target = T;

    fn deref(&self) -> &T
    {
        // SAFETY: the guard's thread holds the lock (`SpinMutex::lock`,
        // `Self::unlocked`), so no other thread reaches the value, and the
        // reference borrows the guard, which outlives it.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T>
{
    fn deref_mut(&mut self) -> &mut T
    {
        // SAFETY: as in `deref`; the mutable borrow of the guard makes the
        // reference the only one this thread holds.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T>
{
    fn drop(&mut self)
    {
        // SAFETY: the guard exists, so this thread holds the lock.
        unsafe { self.mutex.lock.unlock() };
    }
}

/// Stripe locks: [`STRIPES`] ticket locks, one of which a key names
/// ([`Self::of`]).
pub struct Stripes
{
    locks: [TicketLock; STRIPES],
}

/// Stripe locks in a [`Stripes`]. A tuning value that bounds no capacity:
/// two keys on one stripe only serialise each other.
pub const STRIPES: usize = 256;

impl Stripes
{
    /// Every stripe unheld.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            locks: [const { TicketLock::new() }; STRIPES],
        }
    }

    /// The stripe `key` takes: a mix of every bit of the key, so keys that
    /// differ only in their high bits or step by a power of two spread too.
    #[must_use]
    pub const fn of(key: u64) -> usize
    {
        // The 64-bit finaliser of MurmurHash3; the top bits index the array.
        let mut x = key;
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^= x >> 33;
        // STRIPES is a power of two below 2^32 (asserted below), so the shift
        // leaves an index below it, which fits a `usize`.
        (x >> STRIPE_SHIFT) as usize
    }

    /// The lock of the stripe `key` takes.
    #[expect(
        clippy::indexing_slicing,
        reason = "`Self::of` returns an index below STRIPES, the array's length"
    )]
    fn stripe(&self, key: u64) -> &TicketLock
    {
        &self.locks[Self::of(key)]
    }

    /// Take the stripe of `key`, released when the guard drops.
    pub fn lock(&self, key: u64) -> StripeGuard<'_>
    {
        let lock = self.stripe(key);
        lock.lock();
        StripeGuard { lock }
    }

    /// Take the stripe of `key` only when it is free.
    pub fn try_lock(&self, key: u64) -> Option<StripeGuard<'_>>
    {
        let lock = self.stripe(key);
        lock.try_lock().then(|| StripeGuard { lock })
    }
}

impl Default for Stripes
{
    fn default() -> Self
    {
        Self::new()
    }
}

const _: () = assert!(STRIPES.is_power_of_two() && STRIPES > 1 && STRIPES < (1 << 32));

/// The shift that leaves a mixed key's top bits, the stripe's index.
const STRIPE_SHIFT: u32 = u64::BITS - STRIPES.trailing_zeros();

/// A held stripe, released when it drops.
pub struct StripeGuard<'a>
{
    lock: &'a TicketLock,
}

impl Drop for StripeGuard<'_>
{
    fn drop(&mut self)
    {
        // SAFETY: the guard is made only once its stripe is taken.
        unsafe { self.lock.unlock() };
    }
}

/// The key of the process a request acts for, which picks its stripe
/// ([`Stripes::of`]): `child`, the process a label of procmgr's names
/// (`None` for a label that names none), when the caller is procmgr
/// (`caller` is `procmgr`), else the caller. A label naming a child from
/// any other caller is refused by its handler, so its stripe is the caller's.
#[must_use]
pub const fn acted_for(caller: u64, procmgr: u64, child: Option<u64>) -> u64
{
    match child
    {
        Some(child) if caller == procmgr => child,
        _ => caller,
    }
}

/// A value one claimant reaches at a time: [`Self::claim`] hands out the
/// only way to it, and a second claim while the first is held panics rather
/// than alias it. For state one lock already serialises (memmgr's eviction
/// and disk state, which only G's holder reaches), where the claim checks the
/// serialisation instead of making it.
pub struct Claim<T>
{
    claimed: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a `Claimed`, and the atomic flag
// lets one exist at a time, so no two threads reach it at once; moving the
// value's access between threads needs it to be `Send`.
unsafe impl<T: Send> Sync for Claim<T> {}

impl<T> Claim<T>
{
    /// An unclaimed value.
    pub const fn new(value: T) -> Self
    {
        Self {
            claimed: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Claim the value until the returned guard drops.
    ///
    /// # Panics
    /// When the value is claimed already: the serialisation its owner
    /// relies on has failed.
    pub fn claim(&self) -> Claimed<'_, T>
    {
        assert!(
            !self.claimed.swap(true, Ordering::Acquire),
            "a value claimed twice at once"
        );
        Claimed { claim: self }
    }
}

/// A held [`Claim`], released when it drops.
pub struct Claimed<'a, T>
{
    claim: &'a Claim<T>,
}

impl<T> Deref for Claimed<'_, T>
{
    type Target = T;

    fn deref(&self) -> &T
    {
        // SAFETY: this guard holds the claim, which only one guard holds at a
        // time, and the reference borrows the guard.
        unsafe { &*self.claim.value.get() }
    }
}

impl<T> DerefMut for Claimed<'_, T>
{
    fn deref_mut(&mut self) -> &mut T
    {
        // SAFETY: as in `deref`; the mutable borrow of the guard makes the
        // reference the only one.
        unsafe { &mut *self.claim.value.get() }
    }
}

impl<T> Drop for Claimed<'_, T>
{
    fn drop(&mut self)
    {
        self.claim.claimed.store(false, Ordering::Release);
    }
}

/// A value set once and read after (`OnceLock` without `std`).
pub struct Once<T>
{
    /// [`ONCE_EMPTY`], [`ONCE_WRITING`] or [`ONCE_READY`].
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

const ONCE_EMPTY: u8 = 0;
const ONCE_WRITING: u8 = 1;
const ONCE_READY: u8 = 2;

// SAFETY: the value is written once, by the one setter whose exchange from
// `ONCE_EMPTY` won, and read only after its `ONCE_READY` store, through shared
// references; sharing those across threads needs `Sync`, and the value may be
// dropped on another thread than its setter's, which needs `Send`.
unsafe impl<T: Send + Sync> Sync for Once<T> {}

impl<T> Once<T>
{
    /// An unset value.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            state: AtomicU8::new(ONCE_EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Set the value.
    ///
    /// # Errors
    /// `value` back when the value was set, or is being set, already.
    pub fn set(&self, value: T) -> Result<(), T>
    {
        if self
            .state
            .compare_exchange(
                ONCE_EMPTY,
                ONCE_WRITING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(value);
        }
        // SAFETY: the exchange above made this the one setter, and no reader
        // reads before the `ONCE_READY` store below.
        unsafe { (*self.value.get()).write(value) };
        self.state.store(ONCE_READY, Ordering::Release);
        Ok(())
    }

    /// The value, once set.
    #[must_use]
    pub fn get(&self) -> Option<&T>
    {
        if self.state.load(Ordering::Acquire) != ONCE_READY
        {
            return None;
        }
        // SAFETY: the value is never written again once `ONCE_READY` is
        // stored, so a shared reference to its cell aliases no write.
        let slot = unsafe { &*self.value.get() };
        // SAFETY: `ONCE_READY` is stored only after the value was written.
        Some(unsafe { slot.assume_init_ref() })
    }
}

impl<T> Default for Once<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> Drop for Once<T>
{
    fn drop(&mut self)
    {
        if *self.state.get_mut() == ONCE_READY
        {
            // SAFETY: the value was written (`ONCE_READY`) and is dropped once.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

#[cfg(test)]
mod tests
{
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    use super::*;

    #[test]
    fn a_mutex_serialises_every_increment_of_many_threads()
    {
        const THREADS: u64 = 8;
        const ROUNDS: u64 = 20_000;
        let m = Arc::new(SpinMutex::new((0u64, false)));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let m = Arc::clone(&m);
                thread::spawn(move || {
                    for _ in 0..ROUNDS
                    {
                        let mut g = m.lock();
                        // A second holder would see the flag set.
                        assert!(!g.1);
                        g.1 = true;
                        g.0 += 1;
                        g.1 = false;
                    }
                })
            })
            .collect();
        for h in handles
        {
            h.join().unwrap();
        }
        assert_eq!(m.lock().0, THREADS * ROUNDS);
        assert!(!m.is_locked());
    }

    #[test]
    fn unlocked_lets_another_thread_in_and_takes_the_lock_back()
    {
        let m = Arc::new(SpinMutex::new(0u64));
        let mut g = m.lock();
        *g = 1;
        let other = Arc::clone(&m);
        g.unlocked(|| {
            thread::spawn(move || *other.lock() += 10).join().unwrap();
        });
        assert_eq!(*g, 11);
        assert!(m.is_locked());
        drop(g);
        assert!(!m.is_locked());
    }

    #[test]
    fn try_lock_refuses_a_held_or_awaited_lock()
    {
        let l = TicketLock::new();
        assert!(l.try_lock());
        assert!(!l.try_lock());
        // SAFETY: taken just above.
        unsafe { l.unlock() };
        assert!(l.try_lock());
        // SAFETY: taken just above.
        unsafe { l.unlock() };
        assert!(!l.is_locked());
    }

    #[test]
    fn takers_are_served_in_ticket_order()
    {
        let l = Arc::new(TicketLock::new());
        let order = Arc::new(SpinMutex::new(Vec::new()));
        l.lock();
        let mut handles = Vec::new();
        for i in 0..4u32
        {
            let (l2, o2) = (Arc::clone(&l), Arc::clone(&order));
            let drew = Arc::new(AtomicBool::new(false));
            let d2 = Arc::clone(&drew);
            handles.push(thread::spawn(move || {
                // Draw the ticket the way `lock` does, then report it drawn.
                let ticket = l2.next.fetch_add(1, Ordering::Relaxed);
                d2.store(true, Ordering::Release);
                while l2.serving.load(Ordering::Acquire) != ticket
                {
                    spin_loop();
                }
                o2.lock().push(i);
                // SAFETY: served above.
                unsafe { l2.unlock() };
            }));
            // Each taker draws before the next starts, so tickets follow i.
            while !drew.load(Ordering::Acquire)
            {
                spin_loop();
            }
        }
        // SAFETY: taken above.
        unsafe { l.unlock() };
        for h in handles
        {
            h.join().unwrap();
        }
        assert_eq!(*order.lock(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_stripe_excludes_its_keys_and_not_others()
    {
        let s = Stripes::new();
        let held = s.lock(7);
        assert!(s.try_lock(7).is_none());
        let other = (0..u64::MAX)
            .find(|&k| Stripes::of(k) != Stripes::of(7))
            .unwrap();
        assert!(s.try_lock(other).is_some());
        drop(held);
        assert!(s.try_lock(7).is_some());
    }

    #[test]
    fn a_procmgr_label_acts_for_the_child_it_names()
    {
        assert_eq!(acted_for(7, 7, Some(42)), 42);
        assert_eq!(acted_for(7, 7, None), 7);
        assert_eq!(acted_for(9, 7, Some(42)), 9);
    }

    #[test]
    fn a_claim_is_released_by_its_guard()
    {
        let c = Claim::new(1u32);
        *c.claim() += 1;
        let g = c.claim();
        assert_eq!(*g, 2);
        drop(g);
        assert_eq!(*c.claim(), 2);
    }

    #[test]
    #[should_panic(expected = "a value claimed twice at once")]
    fn a_second_claim_while_held_panics()
    {
        let c = Claim::new(0u32);
        let _held = c.claim();
        let _ = c.claim();
    }

    #[test]
    fn once_is_set_once_and_read_from_other_threads()
    {
        let o = Arc::new(Once::new());
        assert!(o.get().is_none());
        assert_eq!(o.set(5u64), Ok(()));
        assert_eq!(o.set(6), Err(6));
        let r = Arc::clone(&o);
        assert_eq!(thread::spawn(move || *r.get().unwrap()).join().unwrap(), 5);
    }

    #[test]
    fn sequential_keys_spread_over_the_stripes()
    {
        let mut hits = [0u32; STRIPES];
        for key in 0..(STRIPES as u64 * 16)
        {
            hits[Stripes::of(key)] += 1;
        }
        // 16 keys a stripe on average; none is empty or takes four times that.
        assert!(hits.iter().all(|&h| h > 0 && h < 64));
    }
}
