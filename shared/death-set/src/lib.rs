// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/src/lib.rs

//! A supervisor service's death queues and the main wait set they share with
//! its service endpoint, or that holds them alone (`DeathSet`, procmgr's,
//! svcmgr's and devmgr's), and how a drain of a death queue finds that the
//! queue may have dropped a post ([`overflow`]), which logd's drain of its
//! one death queue follows too.
//!
//! The kernel drops a death post to a full queue, so a service whose queues
//! have fixed rings counts what it takes from each ([`OverflowWatch`]) and
//! resyncs from the kernel's records when the count says a post may have been
//! dropped. [`overflow`] is pure and host-tested here against `model`, a
//! model of the kernel's event-queue ring, which the services' host-tested
//! crates also drive to test each service's resync. `DeathSet` makes the
//! syscalls and funds the objects through `std::os::seraph`, so it is
//! compiled only for seraph.

#[cfg(any(test, feature = "model"))]
pub mod model;
pub mod overflow;
#[cfg(target_os = "seraph")]
mod set;

pub use overflow::{OverflowWatch, drain_queues};
#[cfg(target_os = "seraph")]
pub use set::DeathSet;
