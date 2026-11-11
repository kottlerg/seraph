// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/rwlock/seraph.rs

//! `RwLock` for seraph: upstream's queue-based `sync/rwlock/queue.rs`, which
//! queues each waiting thread's node on the lock and parks it on its own
//! `Thread` handle.
//!
//! The lock holds no kernel object: a contended waiter parks on the
//! per-thread `Parker` (`sys::sync::thread_parking`), and an unlock `unpark`s
//! the oldest waiter when it is a writer, and every waiter otherwise. The overlay's
//! `Mutex` is this lock's write side (`sys::sync::mutex`). See
//! runtime/ruststd/README.md § Synchronization primitives.
//!
//! The overlay copies this file beside upstream's `queue.rs` in the vendored
//! `library/std/src/sys/sync/rwlock/`, and the `path` attribute below
//! resolves relative to that directory.

#[path = "queue.rs"]
mod queue;

pub use queue::RwLock;
