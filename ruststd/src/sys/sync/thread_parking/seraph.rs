// seraph-overlay: std::sys::sync::thread_parking::seraph
//
// Per-Parker AtomicU32 state (EMPTY / NOTIFIED / PARKED) backed by a
// lazily-allocated Signal cap. Patterned after `sync/thread_parking/
// futex.rs` but using `SYS_SIGNAL_WAIT` (kernel cap-based, no address
// expectation) in place of a futex. `park_timeout` uses the timeout
// variant (`signal_wait_timeout`, backed by `SYS_SIGNAL_WAIT` with
// `arg1 = ms`) so a concurrent `unpark` still wakes us early and the
// timer path wakes us otherwise.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::pin::Pin;
use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};
use crate::time::Duration;

const EMPTY: u32 = 0;
const NOTIFIED: u32 = 1;
const PARKED: u32 = 2;

pub struct Parker {
    state: AtomicU32,
    signal: AtomicU32,
}

impl Parker {
    /// # Safety
    /// `parker` must be a properly-aligned, writable `*mut Parker`.
    pub unsafe fn new_in_place(parker: *mut Parker) {
        unsafe {
            parker.write(Self { state: AtomicU32::new(EMPTY), signal: AtomicU32::new(0) });
        }
    }

    /// # Safety
    /// May only be called by the thread that owns this Parker.
    pub unsafe fn park(self: Pin<&Self>) {
        if self.state.swap(EMPTY, Acquire) == NOTIFIED {
            return;
        }
        let sig = ensure_signal(&self.signal);
        loop {
            match self.state.compare_exchange(EMPTY, PARKED, AcqRel, Acquire) {
                Ok(_) => {}
                Err(NOTIFIED) => {
                    let _ = self.state.compare_exchange(NOTIFIED, EMPTY, Acquire, Relaxed);
                    return;
                }
                Err(_) => continue,
            }
            if sig != 0 {
                let _ = syscall::signal_wait(sig);
            } else {
                core::hint::spin_loop();
            }
            if self.state.compare_exchange(NOTIFIED, EMPTY, Acquire, Relaxed).is_ok() {
                return;
            }
            // Spurious; loop around.
        }
    }

    /// # Safety
    /// May only be called by the thread that owns this Parker.
    pub unsafe fn park_timeout(self: Pin<&Self>, dur: Duration) {
        if self.state.swap(EMPTY, Acquire) == NOTIFIED {
            return;
        }
        // Publish PARKED so a concurrent `unpark` sees we want the signal.
        let _ = self.state.compare_exchange(EMPTY, PARKED, AcqRel, Acquire);
        let sig = ensure_signal(&self.signal);
        // Round the Duration to millisecond resolution. Guard against the
        // `timeout_ms == 0` special case: the syscall treats 0 as "block
        // indefinitely", which is the opposite of what `Duration::ZERO`
        // means here. Push any sub-millisecond non-zero duration up to 1.
        let mut ms = dur.as_millis();
        if ms == 0 && !dur.is_zero() {
            ms = 1;
        }
        let ms = u64::try_from(ms).unwrap_or(u64::MAX);
        if sig != 0 && ms != 0 {
            let _ = syscall::signal_wait_timeout(sig, ms);
        } else if ms == 0 {
            // Zero-duration park — don't block.
        } else {
            core::hint::spin_loop();
        }
        // Consume any pending notification; either way, clear to EMPTY.
        let _ = self.state.swap(EMPTY, Acquire);
    }

    #[inline]
    pub fn unpark(self: Pin<&Self>) {
        if self.state.swap(NOTIFIED, Release) == PARKED {
            let sig = self.signal.load(Relaxed);
            if sig != 0 {
                let _ = syscall::signal_send(sig, 1);
            }
        }
    }
}

impl Drop for Parker {
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
