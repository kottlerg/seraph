// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_badges.rs

//! Reserved log-endpoint badges.
//!
//! Every badged SEND cap on the log endpoint carries a `u64` badge
//! (kernel-attached at `cap_derive_badge` time, immutable thereafter).
//! The cap's holder is identified to the receiver by that badge. For
//! procmgr-spawned children the badge equals the child's procmgr-
//! assigned process badge; the kernel-side identity, the receiver's
//! per-sender slot key, and procmgr's death-notification correlator
//! thus all share one u64. To leave room for system-special senders
//! whose identity is not a procmgr process badge, every per-child badge
//! is at least [`LOG_BADGE_FIRST_CHILD`].

/// init's self-identity. Init derives `cap_derive_badge(log_ep,
/// SEND, LOG_BADGE_INIT)` at boot and uses the cap for its own
/// log writes (`services/init/src/logging.rs`).
pub const LOG_BADGE_INIT: u64 = 1;
/// procmgr's self-identity. Init derives a badged SEND cap with
/// this badge at procmgr-bootstrap time and seeds it into
/// `ProcessInfo.log_send_cap` so procmgr's std `_start` can
/// install it. Procmgr's `seraph::log!` writes ride this cap.
pub const LOG_BADGE_PROCMGR: u64 = 2;
/// Floor of every per-child badge: procmgr draws child badges at
/// random and redraws any below it. Lower values are reserved for the
/// system specials above; raising this leaves room to reserve more.
pub const LOG_BADGE_FIRST_CHILD: u64 = 16;
