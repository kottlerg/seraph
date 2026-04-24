// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/bootstrap.rs

//! Bootstrap IPC protocol — child-side and creator-side primitives.
//!
//! Every userspace process starts with exactly one cap installed beyond the
//! self-caps: `creator_endpoint_cap` (in `process_abi::ProcessInfo`). The
//! child calls [`request_round`] in a loop on that cap; the creator serves
//! each request with [`reply_round`] or [`reply_error`], transferring up to
//! `MSG_CAP_SLOTS_MAX` caps plus payload words per round. When the creator
//! sets the `done` flag, the child stops.
//!
//! Per-(creator, child-type) payload formats are defined in each child's
//! crate. This module only implements the generic protocol.

// When this crate is compiled as a std dep via rustc-dep-of-std, the
// crate root is `no_core` and the usual prelude is not auto-imported.
// The crate-root `use core::prelude::rust_2024::*;` only covers the
// root module; submodules need their own import. Harmless no-op
// otherwise.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use crate::{IpcMessage, bootstrap_errors};
use syscall_abi::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

// ── Protocol labels ─────────────────────────────────────────────────────────

/// Child → creator: request the next batch of startup caps.
pub const REQUEST: u64 = 1;

/// Creator → child: caps delivered; more rounds pending.
pub const MORE: u64 = 0;

/// Creator → child: caps delivered; bootstrap complete.
pub const DONE: u64 = 1;

// ── Round data ──────────────────────────────────────────────────────────────

/// One round's worth of data delivered to a child.
///
/// Owns its payload: `data[..data_words]` is a stack-owned snapshot of the
/// data words delivered in this round. Subsequent IPC cannot clobber it.
pub struct BootstrapRound
{
    /// Child-CSpace slot indices of received caps. Only the first
    /// `cap_count` entries are valid.
    pub caps: [u32; MSG_CAP_SLOTS_MAX],
    /// Number of valid cap indices in `caps`.
    pub cap_count: usize,
    /// Owned data words delivered with this round. Only the first
    /// `data_words` entries are valid.
    pub data: [u64; MSG_DATA_WORDS_MAX],
    /// Number of valid data words in `data`.
    pub data_words: usize,
    /// `true` when this is the final round.
    pub done: bool,
}

// ── Label packing ───────────────────────────────────────────────────────────

/// Pack a successful reply label: base (`MORE`/`DONE`) + cap count + data count.
#[must_use]
pub const fn pack_reply_label(done: bool, cap_count: usize, data_words: usize) -> u64
{
    let base = if done { DONE } else { MORE };
    base | ((cap_count as u64) << 8) | ((data_words as u64) << 16)
}

/// Extract the base label (`MORE`/`DONE` or error code) from a packed label.
#[must_use]
pub const fn unpack_base(label: u64) -> u64
{
    label & 0xFF
}

/// Extract cap count from a packed success label.
#[must_use]
pub const fn unpack_cap_count(label: u64) -> usize
{
    ((label >> 8) & 0xFF) as usize
}

/// Extract data word count from a packed success label.
#[must_use]
pub const fn unpack_data_words(label: u64) -> usize
{
    ((label >> 16) & 0xFF) as usize
}

// ── Child side ──────────────────────────────────────────────────────────────

/// Request the next bootstrap round from the creator.
///
/// Blocks until the creator replies. On a `MORE`/`DONE` reply, returns a
/// [`BootstrapRound`] whose `caps` and `data` fields are stack-owned copies
/// of the received payload — the per-thread IPC buffer is scratch after
/// return and nested IPC cannot clobber the round.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// * `Err(code)` where `code` is [`bootstrap_errors::NO_CHILD`],
///   [`bootstrap_errors::EXHAUSTED`], or [`bootstrap_errors::INVALID`].
/// * `Err(bootstrap_errors::INVALID)` if the underlying IPC fails.
pub unsafe fn request_round(creator_ep: u32, ipc_buf: *mut u64) -> Result<BootstrapRound, u64>
{
    let request = IpcMessage::new(REQUEST);
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { crate::ipc_call(creator_ep, &request, ipc_buf) }
        .map_err(|_| bootstrap_errors::INVALID)?;

    let base = unpack_base(reply.label);
    match base
    {
        MORE | DONE =>
        {
            let reply_caps = reply.caps();
            let declared_cap_count = unpack_cap_count(reply.label);
            let data_words = unpack_data_words(reply.label);
            debug_assert_eq!(reply_caps.len(), declared_cap_count);
            debug_assert!(data_words <= MSG_DATA_WORDS_MAX);
            let mut caps = [0u32; MSG_CAP_SLOTS_MAX];
            caps[..reply_caps.len()].copy_from_slice(reply_caps);
            let mut data = [0u64; MSG_DATA_WORDS_MAX];
            let words = reply.words();
            data[..words.len()].copy_from_slice(words);
            Ok(BootstrapRound {
                caps,
                cap_count: reply_caps.len(),
                data,
                data_words: data_words.min(words.len()),
                done: base == DONE,
            })
        }
        err => Err(err),
    }
}

// ── Creator side ────────────────────────────────────────────────────────────

/// Reply to a pending `BOOTSTRAP_REQUEST` with the next round.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// Returns a negative kernel error code from the underlying IPC.
pub unsafe fn reply_round(
    done: bool,
    cap_slots: &[u32],
    data: &[u64],
    ipc_buf: *mut u64,
) -> Result<(), i64>
{
    let cap_count = cap_slots.len().min(MSG_CAP_SLOTS_MAX);
    let label = pack_reply_label(done, cap_count, data.len());
    let mut builder = IpcMessage::builder(label);
    if !data.is_empty()
    {
        builder = builder.words(0, data);
    }
    for &slot in cap_slots.iter().take(cap_count)
    {
        builder = builder.cap(slot);
    }
    let msg = builder.build();
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { crate::ipc_reply(&msg, ipc_buf) }
}

/// Reply to a pending `BOOTSTRAP_REQUEST` with an error code.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// Returns a negative kernel error code from the underlying IPC.
pub unsafe fn reply_error(code: u64, ipc_buf: *mut u64) -> Result<(), i64>
{
    let msg = IpcMessage::new(code);
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { crate::ipc_reply(&msg, ipc_buf) }
}

/// Receive one bootstrap request, verify the sender's token, and reply
/// with the given round.
///
/// Blocks until a `BOOTSTRAP_REQUEST` arrives on `bootstrap_ep`. If the token
/// embedded in the received cap does not match `expected_token`, replies with
/// [`bootstrap_errors::NO_CHILD`] and returns `Err`. If the label is not
/// [`REQUEST`], replies with [`bootstrap_errors::INVALID`] and returns `Err`.
/// Otherwise, replies with the round (caps + data + done flag).
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// * `Err(bootstrap_errors::NO_CHILD)` — unexpected token.
/// * `Err(bootstrap_errors::INVALID)` — protocol error.
pub unsafe fn serve_round(
    bootstrap_ep: u32,
    expected_token: u64,
    ipc_buf: *mut u64,
    done: bool,
    caps: &[u32],
    data: &[u64],
) -> Result<(), u64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    let request =
        unsafe { crate::ipc_recv(bootstrap_ep, ipc_buf) }.map_err(|_| bootstrap_errors::INVALID)?;

    if request.token != expected_token
    {
        // SAFETY: same invariant.
        let _ = unsafe { reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
        return Err(bootstrap_errors::NO_CHILD);
    }

    if (request.label & 0xFFFF) != REQUEST
    {
        // SAFETY: same invariant.
        let _ = unsafe { reply_error(bootstrap_errors::INVALID, ipc_buf) };
        return Err(bootstrap_errors::INVALID);
    }

    // SAFETY: same invariant.
    unsafe { reply_round(done, caps, data, ipc_buf) }.map_err(|_| bootstrap_errors::INVALID)
}
