// seraph-overlay: std::sys::sync::rwlock::seraph
//
// RwLock using a single AtomicU32 state:
//   * low 30 bits — reader count (up to `MAX_READERS`).
//   * bit 30       — writer bit (set while a writer holds the lock).
//   * bit 31       — waiters bit (at least one thread has parked or is about
//                    to park on the lazy Signal).
//
// Blocking waiters share one Signal cap. `signal_send` wakes exactly one,
// so we rely on a chain-wake pattern: every unlock that observes the
// waiters bit does one `signal_send`; the awoken thread either takes the
// lock (and eventually unlocks, triggering the next wake) or re-parks,
// re-asserting the waiters bit. The design is simple but serialises
// waiters; good enough until contention profiles force a richer queue.
//
// Readers and writers park on the same Signal, so a wake_one may pick
// either a reader or a writer. A waking reader that acquires a shared
// lock before queued writers is the standard "reader preference" tradeoff.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};

const WRITER_BIT: u32 = 1 << 30;
const WAITERS_BIT: u32 = 1 << 31;
const READER_MASK: u32 = (1 << 30) - 1;
const MAX_READERS: u32 = READER_MASK - 1;

pub struct RwLock {
    state: AtomicU32,
    signal: AtomicU32,
}

impl RwLock {
    #[inline]
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(0), signal: AtomicU32::new(0) }
    }

    #[inline]
    pub fn read(&self) {
        if !self.try_read_fast() {
            self.read_contended();
        }
    }

    #[inline]
    pub fn try_read(&self) -> bool {
        self.try_read_fast()
    }

    #[inline]
    fn try_read_fast(&self) -> bool {
        let cur = self.state.load(Relaxed);
        if cur & WRITER_BIT != 0 {
            return false;
        }
        let readers = cur & READER_MASK;
        if readers >= MAX_READERS {
            return false;
        }
        // Preserve the waiters bit if present; bump the reader count.
        self.state
            .compare_exchange_weak(cur, cur + 1, Acquire, Relaxed)
            .is_ok()
    }

    #[cold]
    fn read_contended(&self) {
        let sig = ensure_signal(&self.signal);
        loop {
            if self.try_read_fast() {
                return;
            }
            self.state.fetch_or(WAITERS_BIT, Release);
            if sig != 0 {
                let _ = syscall::signal_wait(sig);
            } else {
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub fn write(&self) {
        if self.state.compare_exchange(0, WRITER_BIT, Acquire, Relaxed).is_err() {
            self.write_contended();
        }
    }

    #[inline]
    pub fn try_write(&self) -> bool {
        self.state.compare_exchange(0, WRITER_BIT, Acquire, Relaxed).is_ok()
    }

    #[cold]
    fn write_contended(&self) {
        let sig = ensure_signal(&self.signal);
        loop {
            let cur = self.state.load(Relaxed);
            if cur & (WRITER_BIT | READER_MASK) == 0
                && self
                    .state
                    .compare_exchange_weak(cur, WRITER_BIT | (cur & WAITERS_BIT), Acquire, Relaxed)
                    .is_ok()
            {
                return;
            }
            self.state.fetch_or(WAITERS_BIT, Release);
            if sig != 0 {
                let _ = syscall::signal_wait(sig);
            } else {
                core::hint::spin_loop();
            }
        }
    }

    /// # Safety
    /// Caller must hold a read lock.
    #[inline]
    pub unsafe fn read_unlock(&self) {
        let prev = self.state.fetch_sub(1, Release);
        if (prev & READER_MASK) == 1 && (prev & WAITERS_BIT) != 0 {
            self.wake_one();
        }
    }

    /// # Safety
    /// Caller must hold the write lock.
    #[inline]
    pub unsafe fn write_unlock(&self) {
        let prev = self.state.swap(0, Release);
        if (prev & WAITERS_BIT) != 0 {
            self.wake_one();
        }
    }

    /// # Safety
    /// Caller must hold the write lock.
    #[inline]
    pub unsafe fn downgrade(&self) {
        // Release writer bit, install one reader, preserve the waiters bit
        // so queued readers remain discoverable.
        let prev = self.state.fetch_and(!WRITER_BIT, Release);
        let _ = self.state.fetch_add(1, Relaxed);
        if (prev & WAITERS_BIT) != 0 {
            self.wake_one();
        }
        let _ = prev;
    }

    #[cold]
    fn wake_one(&self) {
        let sig = self.signal.load(Relaxed);
        if sig != 0 {
            let _ = syscall::signal_send(sig, 1);
        }
    }
}

impl Drop for RwLock {
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
