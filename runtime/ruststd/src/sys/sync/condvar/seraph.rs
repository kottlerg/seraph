// seraph-overlay: std::sys::sync::condvar::seraph
//
// Condvar built on a monotonically-incrementing generation counter and a
// lazily-allocated Signal cap. Mirrors the upstream `sync/condvar/
// futex.rs` design: waiters snapshot the counter before unlocking the
// mutex, then block; notifiers bump the counter (invalidating in-flight
// snapshots) and signal. Because `signal_wait` has no address-compare,
// a waiter that awakes spuriously just re-acquires the mutex and
// returns — the std layer's loop-condition recheck absorbs it.
//
// `wait_timeout` passes the millisecond timeout through `arg1` of
// `SYS_SIGNAL_WAIT`. A non-zero bit return means signal wake; a `0`
// return means the timer expired.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};
use crate::sys::sync::Mutex;
use crate::time::Duration;

const WAKE_BURST: u32 = 16;

pub struct Condvar {
    gen_counter: AtomicU32,
    signal: AtomicU32,
}

impl Condvar {
    #[inline]
    pub const fn new() -> Self {
        Self { gen_counter: AtomicU32::new(0), signal: AtomicU32::new(0) }
    }

    pub fn notify_one(&self) {
        self.gen_counter.fetch_add(1, Relaxed);
        let sig = self.signal.load(Relaxed);
        if sig != 0 {
            let _ = syscall::signal_send(sig, 1);
        }
    }

    pub fn notify_all(&self) {
        self.gen_counter.fetch_add(1, Relaxed);
        let sig = self.signal.load(Relaxed);
        if sig == 0 {
            return;
        }
        for _ in 0..WAKE_BURST {
            if syscall::signal_send(sig, 1).is_err() {
                break;
            }
        }
    }

    /// # Safety
    /// `mutex` must be held by the calling thread; it is unlocked for the
    /// duration of the wait and reacquired before returning.
    pub unsafe fn wait(&self, mutex: &Mutex) {
        let _before = self.gen_counter.load(Relaxed);
        // SAFETY: contract inherited from caller.
        unsafe { mutex.unlock() };
        let sig = ensure_signal(&self.signal);
        if sig != 0 {
            let _ = syscall::signal_wait(sig);
        } else {
            core::hint::spin_loop();
        }
        mutex.lock();
    }

    /// # Safety
    /// `mutex` must be held by the calling thread.
    pub unsafe fn wait_timeout(&self, mutex: &Mutex, timeout: Duration) -> bool {
        let before = self.gen_counter.load(Relaxed);
        // SAFETY: contract inherited from caller.
        unsafe { mutex.unlock() };
        let sig = ensure_signal(&self.signal);
        // Round to milliseconds. `0` to the syscall means "block
        // indefinitely", so push any sub-millisecond non-zero duration
        // up to 1 and handle Duration::ZERO explicitly.
        let mut ms = timeout.as_millis();
        if ms == 0 && !timeout.is_zero() {
            ms = 1;
        }
        let ms = u64::try_from(ms).unwrap_or(u64::MAX);
        let woke_on_signal = if sig != 0 && ms != 0 {
            // Returns non-zero bits on signal wake, 0 on timeout.
            matches!(syscall::signal_wait_timeout(sig, ms), Ok(b) if b != 0)
        } else {
            false
        };
        mutex.lock();
        // Contract: return `true` if we did NOT time out. A signal wake
        // (non-zero bits) counts as "did not time out". If the generation
        // counter moved while we were parked, a notify happened even if
        // the kernel delivered it as a signal edge that merged with the
        // timeout, so report non-timeout.
        woke_on_signal || self.gen_counter.load(Relaxed) != before
    }
}

impl Drop for Condvar {
    fn drop(&mut self) {
        let sig = *self.signal.get_mut();
        if sig != 0 {
            let _ = syscall::cap_delete(sig);
        }
    }
}

fn ensure_signal(slot: &AtomicU32) -> u32 {
    let existing = slot.load(Acquire);
    if existing != 0 {
        return existing;
    }
    let Some(slab) = crate::sys::alloc::seraph::object_slab_acquire(120) else {
        return 0;
    };
    let Ok(fresh) = syscall::cap_create_signal(slab) else {
        return 0;
    };
    match slot.compare_exchange(0, fresh, AcqRel, Acquire) {
        Ok(_) => fresh,
        Err(other) => {
            let _ = syscall::cap_delete(fresh);
            other
        }
    }
}
