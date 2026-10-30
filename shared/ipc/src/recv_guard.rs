// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/recv_guard.rs

//! Receive-failure policy for blocking service receive loops.
//!
//! The policy — why an unguarded `loop { ipc_recv }` wedges, the backoff,
//! the diagnostic hook, the fatal streak and [`EXIT_RECV_WEDGE`], the
//! `Interrupted` exemption, and which loops use the guard — is specified in
//! `docs/ipc-design.md` § Receive-Failure Policy. [`RecvGuard`] implements
//! it. Within a guarded (blocking) loop, `WouldBlock` is a defect like any
//! other failure and counts toward the fatal streak.

// When this crate is compiled as a std dep via rustc-dep-of-std, the
// crate root is `no_core` and the usual prelude is not auto-imported.
// The crate-root `use core::prelude::rust_2024::*;` only covers the
// root module; submodules need their own import. Harmless no-op
// otherwise.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use syscall_abi::SyscallError;

/// Voluntary exit code for a service whose blocking receive loop wedged
/// (a fatal streak of identical receive failures). Its place in the flat
/// voluntary exit-code space is in `docs/ipc-design.md` § Receive-Failure
/// Policy; new policy codes extend the block it starts.
pub const EXIT_RECV_WEDGE: u32 = 0x0F10;

/// Consecutive identical receive failures before the guard escalates to
/// [`syscall::process_exit`]. Combined with the backoff schedule this puts
/// death roughly 3 s after the first failure: long enough that a transient
/// slot-page-pool dip cannot kill a healthy service, short enough that a wedged
/// one dies before its clients' timeouts cascade.
pub const RECV_FAILURE_FATAL_STREAK: u32 = 32;

/// Ceiling of the exponential backoff applied between failed receives. A
/// tuning value: it only spaces retries and bounds no capacity.
pub const RECV_FAILURE_BACKOFF_CAP_MS: u64 = 128;

/// Which diagnostic event a [`RecvGuard`] hook invocation reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvFailureStage
{
    /// First failure of a streak (the error differs from the previous one,
    /// or the previous receive succeeded).
    First,
    /// The fatal streak was reached; the guard calls
    /// `process_exit(EXIT_RECV_WEDGE)` immediately after the hook returns.
    Fatal,
}

/// Failure-streak tracker for one blocking receive loop.
///
/// Owned by the loop (one guard per receiving thread). Feed every receive
/// outcome to it: [`on_success`](Self::on_success) after each successful
/// receive, [`on_failure`](Self::on_failure) with the negative error code
/// after each failed one.
///
/// The diagnostic hook is a plain `fn` pointer, invoked at most twice per
/// streak ([`RecvFailureStage::First`] and [`RecvFailureStage::Fatal`]).
/// Services with log access pass a hook that logs; services without one
/// (memmgr) pass an empty hook — their signal is the kernel's rate-limited
/// recv-failure line plus the loud death itself.
pub struct RecvGuard
{
    /// Never passes [`RECV_FAILURE_FATAL_STREAK`], where the guard exits the
    /// process, so the `u32` cannot overflow.
    streak: u32,
    last_err: i64,
    diag: fn(RecvFailureStage, i64),
}

impl RecvGuard
{
    /// New guard with a zero streak. `diag` is called with the stage and the
    /// error code at the first failure of a streak and before the fatal exit;
    /// pass a function that does nothing when the service has no log access.
    #[must_use]
    pub const fn new(diag: fn(RecvFailureStage, i64)) -> Self
    {
        Self {
            streak: 0,
            last_err: 0,
            diag,
        }
    }

    /// Record a successful receive: the failure streak resets.
    pub fn on_success(&mut self)
    {
        self.streak = 0;
        self.last_err = 0;
    }

    /// Record a failed blocking receive.
    ///
    /// `Interrupted` returns immediately without touching the streak. Any
    /// other error extends the streak when it matches the previous error and
    /// restarts it at 1 otherwise; the hook fires at streak 1. At
    /// [`RECV_FAILURE_FATAL_STREAK`] the hook fires once more and the
    /// process exits with [`EXIT_RECV_WEDGE`] — this call does not return.
    /// Below the fatal streak the call parks the thread for the backoff
    /// interval (`min(2^(streak-1), RECV_FAILURE_BACKOFF_CAP_MS)` ms); if
    /// the kernel sleep list is full it degrades to a single yield, keeping
    /// the loop bounded-but-busier rather than wedged.
    pub fn on_failure(&mut self, err: i64)
    {
        if err == SyscallError::Interrupted as i64
        {
            return;
        }

        if err == self.last_err
        {
            self.streak = self.streak.saturating_add(1);
        }
        else
        {
            self.streak = 1;
            self.last_err = err;
            (self.diag)(RecvFailureStage::First, err);
        }

        if self.streak >= RECV_FAILURE_FATAL_STREAK
        {
            (self.diag)(RecvFailureStage::Fatal, err);
            syscall::process_exit(EXIT_RECV_WEDGE);
        }

        let shift = self.streak.saturating_sub(1).min(63);
        let backoff_ms = (1u64 << shift).min(RECV_FAILURE_BACKOFF_CAP_MS);
        if syscall::thread_sleep(backoff_ms).is_err()
        {
            let _ = syscall::thread_yield();
        }
    }
}
