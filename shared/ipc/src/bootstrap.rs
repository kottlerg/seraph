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

use crate::{IpcBuf, bootstrap_errors};
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
pub struct BootstrapRound
{
    /// Child-CSpace slot indices of received caps. Only the first
    /// `cap_count` entries are valid.
    pub caps: [u32; MSG_CAP_SLOTS_MAX],
    /// Number of valid cap indices in `caps`.
    pub cap_count: usize,
    /// Number of valid data words in the IPC buffer at offsets `0..data_words`.
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
/// Blocks until the creator replies. On a `MORE`/`DONE` reply, returns the
/// round's caps and data-word count. On an error reply, returns the base
/// error label from [`bootstrap_errors`].
///
/// # Errors
///
/// * `Err(code)` where `code` is [`bootstrap_errors::NO_CHILD`],
///   [`bootstrap_errors::EXHAUSTED`], or [`bootstrap_errors::INVALID`].
/// * `Err(bootstrap_errors::INVALID)` if the underlying `ipc_call` fails.
pub fn request_round(creator_ep: u32, ipc: IpcBuf) -> Result<BootstrapRound, u64>
{
    let (reply_label, _) =
        syscall::ipc_call(creator_ep, REQUEST, 0, &[]).map_err(|_| bootstrap_errors::INVALID)?;

    // SAFETY: `ipc` wraps the registered IPC buffer; kernel just wrote cap
    // transfer metadata there.
    let (cap_count, caps) = unsafe { syscall::read_recv_caps(ipc.as_ptr()) };

    let base = unpack_base(reply_label);
    match base
    {
        MORE | DONE =>
        {
            let declared_cap_count = unpack_cap_count(reply_label);
            let data_words = unpack_data_words(reply_label);
            debug_assert_eq!(cap_count, declared_cap_count);
            debug_assert!(data_words <= MSG_DATA_WORDS_MAX);
            Ok(BootstrapRound {
                caps,
                cap_count,
                data_words: data_words.min(MSG_DATA_WORDS_MAX),
                done: base == DONE,
            })
        }
        err => Err(err),
    }
}

// ── Creator side ────────────────────────────────────────────────────────────

/// Reply to a pending `BOOTSTRAP_REQUEST` with the next round.
///
/// # Errors
///
/// Returns a negative kernel error code from the underlying `ipc_reply`.
pub fn reply_round(done: bool, cap_slots: &[u32], data_words: usize) -> Result<(), i64>
{
    let cap_count = cap_slots.len().min(MSG_CAP_SLOTS_MAX);
    let label = pack_reply_label(done, cap_count, data_words);
    syscall::ipc_reply(label, data_words, cap_slots)
}

/// Reply to a pending `BOOTSTRAP_REQUEST` with an error code.
///
/// # Errors
///
/// Returns a negative kernel error code from the underlying `ipc_reply`.
pub fn reply_error(code: u64) -> Result<(), i64>
{
    syscall::ipc_reply(code, 0, &[])
}

/// Receive one bootstrap request, verify the sender's token, pack data words,
/// and reply with the given round.
///
/// Blocks until a `BOOTSTRAP_REQUEST` arrives on `bootstrap_ep`. If the token
/// embedded in the received cap does not match `expected_token`, replies with
/// [`bootstrap_errors::NO_CHILD`] and returns `Err`. If the label is not
/// [`REQUEST`], replies with [`bootstrap_errors::INVALID`] and returns `Err`.
/// Otherwise, writes `data` to the IPC buffer and replies with the round
/// (caps + data words + done flag).
///
/// # Errors
///
/// * `Err(bootstrap_errors::NO_CHILD)` — unexpected token.
/// * `Err(bootstrap_errors::INVALID)` — protocol error.
pub fn serve_round(
    bootstrap_ep: u32,
    expected_token: u64,
    ipc: IpcBuf,
    done: bool,
    caps: &[u32],
    data: &[u64],
) -> Result<(), u64>
{
    let (label, token) = syscall::ipc_recv(bootstrap_ep).map_err(|_| bootstrap_errors::INVALID)?;

    if token != expected_token
    {
        let _ = reply_error(bootstrap_errors::NO_CHILD);
        return Err(bootstrap_errors::NO_CHILD);
    }

    if (label & 0xFFFF) != REQUEST
    {
        let _ = reply_error(bootstrap_errors::INVALID);
        return Err(bootstrap_errors::INVALID);
    }

    if !data.is_empty()
    {
        ipc.write_words(0, data);
    }

    reply_round(done, caps, data.len()).map_err(|_| bootstrap_errors::INVALID)
}
