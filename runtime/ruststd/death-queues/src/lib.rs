// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/death-queues/src/lib.rs

//! Death-observer bookkeeping for Seraph userspace, as pure host-tested
//! policy.
//!
//! [`DeathQueues`] decides which death `EventQueue` an observer binds on and
//! when a further queue is created, with twice the last one's nodes
//! ([`queues`]). [`slots::Registry`] is the slot table ruststd's thread
//! reaper names in its observers' correlators ([`slots`]). Neither makes a
//! syscall: the binds, the queue creates and the reclaims are the caller's.
//! The crate is a host-tested workspace member and, under the
//! `rustc-dep-of-std` feature, a dependency of the seraph std overlay's
//! thread reaper. Services reach the policy through the `death-set` crate
//! (shared/death-set), whose `DeathSet` makes the syscalls for procmgr and
//! svcmgr; std does not re-export this crate, since the items of std's
//! dependencies are unstable (`rustc_private`) to std's users. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

// Under `rustc-dep-of-std` (build-std), use the core and alloc facades and
// no_core so this crate can sit inside std's dep graph. Mirrors
// shared/shmem and runtime/ruststd/argv-env. Normal builds retain
// `#![no_std]` with `alloc`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(any(feature = "rustc-dep-of-std", test)), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_alloc as alloc;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

pub mod queues;
pub mod slots;

pub use queues::DeathQueues;
