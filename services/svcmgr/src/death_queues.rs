// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/death_queues.rs

//! The sizes of svcmgr's death queues. The set itself, every supervised
//! service's death observer and the main wait set it shares with svcmgr's
//! service endpoint, is the `death-set` crate's `DeathSet`: its service
//! endpoint under `WS_BADGE_SERVICE` and every queue under
//! `WS_BADGE_DEATHS`.

/// Ring capacity of each death queue: a tuning value, not a service ceiling.
/// The kernel drops a death post to a full queue, so a burst of more deaths
/// than this on one queue between drains is recovered by the death resync
/// (`resync_deaths` in `main.rs`), which runs after any drain that took a
/// full queue's worth of events from one queue.
pub const DEATHS_EQ_CAPACITY: u32 = 64;

/// Observer nodes in svcmgr's first death queue; each further queue has
/// twice the last one's, up to `EVENT_QUEUE_MAX_CAPACITY`. Each supervised
/// service's main thread takes one, and a restarted service binds its new
/// thread before the old one's node returns. Sized below a boot's seven
/// supervised and adopted services, so every boot grows the set, and its
/// wait set, and runs the growth path; the pool is paid for as services
/// arrive.
pub const FIRST_POOL_OBSERVERS: u32 = 4;
