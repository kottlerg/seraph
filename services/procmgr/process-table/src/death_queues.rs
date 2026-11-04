// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/death_queues.rs

//! The size of procmgr's first death queue. Where a bind goes and when the
//! set grows are the `ruststd-death-queues` crate's `DeathQueues` policy;
//! procmgr's `DeathSet` (the `death-set` crate) makes the syscalls.

/// Observer nodes in procmgr's first death queue; each further queue has
/// twice the last one's, up to `EVENT_QUEUE_MAX_CAPACITY`. Each live process
/// takes two (its main thread and its address space) and the init reap takes
/// init's two threads; a node returns when its thread or address space is
/// destroyed. Sized small so the pool is paid for as processes arrive. Public
/// so svctest's growth phase sizes its children from it.
pub const FIRST_POOL_OBSERVERS: u32 = 64;
