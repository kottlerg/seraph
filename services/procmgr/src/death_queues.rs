// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/death_queues.rs

//! The sizes of procmgr's death queues. The set itself, every death
//! observer procmgr binds (each child's main thread and address space, and
//! init's two threads) and the main wait set it shares with procmgr's
//! service endpoint, is the `death-set` crate's `DeathSet`: its service
//! endpoint under `WS_BADGE_SERVICE` and every queue under `WS_BADGE_DEATH`.
//! The first queue has `process_table::death_queues::FIRST_POOL_OBSERVERS`
//! nodes.

/// Ring capacity of each death queue: a tuning value, not a process ceiling.
/// The kernel drops a death post to a full queue, so a burst of more deaths
/// than this on one queue between drains is recovered by the death resync
/// (`resync_deaths` in `main.rs`), which runs after any drain that took a
/// full queue's worth of events from one queue.
pub const DEATH_EQ_CAPACITY: u32 = 256;
