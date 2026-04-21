// seraph-overlay: std::sys::sync::mutex::seraph
//
// Futex-style three-state Mutex backed by a lazily-allocated Signal cap.
// Uncontended lock/unlock is a single CAS on `state`. Contention allocates
// a Signal (once per Mutex, cached in `signal`) and blocks via
// `SYS_SIGNAL_WAIT`; the releasing thread wakes one waiter via
// `SYS_SIGNAL_SEND`. Matches the state machine of the upstream
// `sync/mutex/futex.rs` impl.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

pub struct Mutex {
    state: AtomicU32,
    signal: AtomicU32,
}

impl Mutex {
    #[inline]
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(UNLOCKED), signal: AtomicU32::new(0) }
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        self.state.compare_exchange(UNLOCKED, LOCKED, Acquire, Relaxed).is_ok()
    }

    #[inline]
    pub fn lock(&self) {
        if self.state.compare_exchange(UNLOCKED, LOCKED, Acquire, Relaxed).is_err() {
            self.lock_contended();
        }
    }

    #[cold]
    fn lock_contended(&self) {
        let mut state = self.spin();
        if state == UNLOCKED
            && self.state.compare_exchange(UNLOCKED, LOCKED, Acquire, Relaxed).is_ok()
        {
            return;
        }
        loop {
            if state != CONTENDED && self.state.swap(CONTENDED, Acquire) == UNLOCKED {
                return;
            }
            let sig = ensure_signal(&self.signal);
            if sig != 0 {
                let _ = syscall::signal_wait(sig);
            } else {
                core::hint::spin_loop();
            }
            state = self.spin();
        }
    }

    fn spin(&self) -> u32 {
        let mut spin = 100;
        loop {
            let s = self.state.load(Relaxed);
            if s != LOCKED || spin == 0 {
                return s;
            }
            core::hint::spin_loop();
            spin -= 1;
        }
    }

    /// # Safety
    /// The calling thread must hold the lock (i.e. a prior `lock` or
    /// successful `try_lock` without a matching unlock).
    #[inline]
    pub unsafe fn unlock(&self) {
        if self.state.swap(UNLOCKED, Release) == CONTENDED {
            let sig = self.signal.load(Relaxed);
            if sig != 0 {
                let _ = syscall::signal_send(sig, 1);
            }
        }
    }
}

impl Drop for Mutex {
    fn drop(&mut self) {
        let sig = *self.signal.get_mut();
        if sig != 0 {
            let _ = syscall::cap_delete(sig);
        }
    }
}

/// Lazily allocate a Signal cap the first time a primitive experiences
/// contention. Returns 0 if allocation fails; callers fall back to busy-
/// spinning in that case.
fn ensure_signal(slot: &AtomicU32) -> u32 {
    let existing = slot.load(Acquire);
    if existing != 0 {
        return existing;
    }
    let Ok(fresh) = syscall::cap_create_signal() else {
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
