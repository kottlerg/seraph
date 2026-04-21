// seraph-overlay: std::sys::sync::once::seraph
//
// Atomic state machine matching the upstream `sync/once/futex.rs` design,
// but with `futex_wait` replaced by `signal_wait` on a lazily-allocated
// Signal cap. Because signal_send wakes one thread at a time we emulate
// wake_all by issuing a bounded burst; a waiter that awakes spuriously
// just rechecks state and re-parks (setting the QUEUED bit again).

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::cell::Cell;
use crate::sync as public;
use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};
use crate::sync::once::OnceExclusiveState;

const INCOMPLETE: u32 = 3;
const POISONED: u32 = 2;
const RUNNING: u32 = 1;
const COMPLETE: u32 = 0;

const QUEUED: u32 = 4;
const STATE_MASK: u32 = 0b11;

/// Upper bound on the wake burst. Real waiter count is not tracked; a
/// surplus wake just causes a recheck-and-requeue cycle.
const WAKE_BURST: u32 = 16;

pub struct Once {
    state_and_queued: AtomicU32,
    signal: AtomicU32,
}

pub struct OnceState {
    poisoned: bool,
    set_state_to: Cell<u32>,
}

impl OnceState {
    #[inline]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[inline]
    pub fn poison(&self) {
        self.set_state_to.set(POISONED);
    }
}

struct CompletionGuard<'a> {
    once: &'a Once,
    set_state_on_drop_to: u32,
}

impl<'a> Drop for CompletionGuard<'a> {
    fn drop(&mut self) {
        let prev = self.once.state_and_queued.swap(self.set_state_on_drop_to, Release);
        if prev & QUEUED != 0 {
            self.once.wake_all();
        }
    }
}

impl Once {
    #[inline]
    pub const fn new() -> Once {
        Once { state_and_queued: AtomicU32::new(INCOMPLETE), signal: AtomicU32::new(0) }
    }

    #[inline]
    pub const fn new_complete() -> Once {
        Once { state_and_queued: AtomicU32::new(COMPLETE), signal: AtomicU32::new(0) }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.state_and_queued.load(Acquire) == COMPLETE
    }

    #[inline]
    pub(crate) fn state(&mut self) -> OnceExclusiveState {
        match *self.state_and_queued.get_mut() & STATE_MASK {
            INCOMPLETE => OnceExclusiveState::Incomplete,
            POISONED => OnceExclusiveState::Poisoned,
            COMPLETE => OnceExclusiveState::Complete,
            _ => unreachable!("invalid Once state"),
        }
    }

    #[inline]
    pub(crate) fn set_state(&mut self, new_state: OnceExclusiveState) {
        *self.state_and_queued.get_mut() = match new_state {
            OnceExclusiveState::Incomplete => INCOMPLETE,
            OnceExclusiveState::Poisoned => POISONED,
            OnceExclusiveState::Complete => COMPLETE,
        };
    }

    #[cold]
    #[track_caller]
    pub fn wait(&self, ignore_poisoning: bool) {
        let mut snapshot = self.state_and_queued.load(Acquire);
        loop {
            let state = snapshot & STATE_MASK;
            let queued = snapshot & QUEUED != 0;
            match state {
                COMPLETE => return,
                POISONED if !ignore_poisoning => {
                    panic!("Once instance has previously been poisoned");
                }
                _ => {
                    if !queued {
                        let want = snapshot | QUEUED;
                        if let Err(new) = self.state_and_queued.compare_exchange_weak(
                            snapshot,
                            want,
                            Relaxed,
                            Acquire,
                        ) {
                            snapshot = new;
                            continue;
                        }
                        snapshot = want;
                    }
                    let sig = ensure_signal(&self.signal);
                    if sig != 0 {
                        let _ = syscall::signal_wait(sig);
                    } else {
                        core::hint::spin_loop();
                    }
                    snapshot = self.state_and_queued.load(Acquire);
                }
            }
        }
    }

    #[cold]
    #[track_caller]
    pub fn call(&self, ignore_poisoning: bool, f: &mut dyn FnMut(&public::OnceState)) {
        let mut snapshot = self.state_and_queued.load(Acquire);
        loop {
            let state = snapshot & STATE_MASK;
            let queued = snapshot & QUEUED != 0;
            match state {
                COMPLETE => return,
                POISONED if !ignore_poisoning => {
                    panic!("Once instance has previously been poisoned");
                }
                INCOMPLETE | POISONED => {
                    let next = RUNNING | if queued { QUEUED } else { 0 };
                    if let Err(new) =
                        self.state_and_queued.compare_exchange_weak(snapshot, next, Acquire, Acquire)
                    {
                        snapshot = new;
                        continue;
                    }
                    let mut guard = CompletionGuard { once: self, set_state_on_drop_to: POISONED };
                    let f_state = public::OnceState {
                        inner: OnceState {
                            poisoned: state == POISONED,
                            set_state_to: Cell::new(COMPLETE),
                        },
                    };
                    f(&f_state);
                    guard.set_state_on_drop_to = f_state.inner.set_state_to.get();
                    return;
                }
                _ => {
                    assert!(state == RUNNING);
                    if !queued {
                        let want = snapshot | QUEUED;
                        if let Err(new) = self.state_and_queued.compare_exchange_weak(
                            snapshot,
                            want,
                            Relaxed,
                            Acquire,
                        ) {
                            snapshot = new;
                            continue;
                        }
                        snapshot = want;
                    }
                    let sig = ensure_signal(&self.signal);
                    if sig != 0 {
                        let _ = syscall::signal_wait(sig);
                    } else {
                        core::hint::spin_loop();
                    }
                    snapshot = self.state_and_queued.load(Acquire);
                }
            }
        }
    }

    #[cold]
    fn wake_all(&self) {
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
}

impl Drop for Once {
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
