// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/message.rs

//! IPC message type — label + inline data words + capability slot indices.
//!
//! A [`Message`] carries:
//! - A 64-bit `label` — caller-defined tag identifying the operation.
//! - Up to [`MSG_DATA_WORDS_MAX`] data words (u64 values).
//! - Up to [`MSG_CAP_SLOTS_MAX`] capability slot indices (u32 values).
//!
//! Messages are always copied by value through the kernel; no shared memory
//! is involved for the inline data (an optional IPC buffer in shared memory
//! handles larger payloads, deferred to a future phase).

use syscall::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

/// An IPC message transferred between threads via an [`Endpoint`] or reply.
///
/// # Adding message fields
/// Increase the `data` or `cap_slots` array bounds (also update the ABI
/// constants in `abi/syscall/src/lib.rs`) and update all construction sites.
#[derive(Clone, Copy, Debug)]
pub struct Message
{
    /// Operation tag — caller-defined; not interpreted by the kernel.
    pub label: u64,
    /// Token from the sender's endpoint capability slot. Zero if untokened.
    /// Set by `sys_ipc_call` from the caller's endpoint cap; delivered to the
    /// receiver via the third return register of `ipc_recv`.
    pub token: u64,
    /// Inline data words.
    pub data: [u64; MSG_DATA_WORDS_MAX],
    /// Actual number of valid entries in `data` (`0..=MSG_DATA_WORDS_MAX`).
    pub data_count: usize,
    /// Capability slot indices to transfer (from the sender's `CSpace`).
    pub cap_slots: [u32; MSG_CAP_SLOTS_MAX],
    /// Actual number of valid entries in `cap_slots`.
    pub cap_count: usize,
}

impl Default for Message
{
    fn default() -> Self
    {
        Self {
            label: 0,
            token: 0,
            data: [0u64; MSG_DATA_WORDS_MAX],
            data_count: 0,
            cap_slots: [0u32; MSG_CAP_SLOTS_MAX],
            cap_count: 0,
        }
    }
}

impl Message
{
    /// Construct an empty message with the given label.
    pub fn new(label: u64) -> Self
    {
        Self {
            label,
            ..Self::default()
        }
    }
}
