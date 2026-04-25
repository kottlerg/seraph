// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/mod.rs

//! IPC subsystem — synchronous endpoint messaging, signals, event queues, wait sets.
//!
//! Implements the kernel side of:
//! - [`endpoint`]: blocking call/recv/reply using intrusive TCB queues.
//! - [`signal`]: bitmask-based asynchronous notification (OR bits / wait).
//! - [`event_queue`]: ordered, non-coalescing ring buffer with a single waiter.
//! - [`wait_set`]: multiplexed blocking on any combination of the above.
//! - [`message`]: the `Message` struct transferred through both mechanisms.

pub mod endpoint;
pub mod event_queue;
pub mod message;
pub mod signal;
pub mod wait_set;
