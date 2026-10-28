// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/once/seraph.rs

//! `Once` for seraph: upstream's queue-based `sync/once/queue.rs`, which parks
//! each waiting thread on its own `Thread` handle and wakes every queued
//! waiter when the initialiser finishes.
//!
//! The waiters form a linked list of nodes on their own stacks, threaded
//! through the `Once`'s state word; completion (or a poisoning panic) takes
//! the whole list and `unpark`s each node's thread. `park`/`unpark` run on the
//! per-thread `Parker` (`sys::sync::thread_parking`), whose notification cap
//! belongs to the parked thread alone, so each wake reaches exactly the thread
//! it names and no waiter count bounds `wake_all`. A shared notification, on
//! which each send wakes one queued waiter, cannot wake an unknown number of
//! waiters.
//!
//! The overlay copies this file beside upstream's `queue.rs` in the vendored
//! `library/std/src/sys/sync/once/`, and the `path` attribute below resolves
//! relative to that directory.

#[path = "queue.rs"]
mod queue;

pub use queue::{Once, OnceState};
