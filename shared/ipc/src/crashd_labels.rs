// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/crashd_labels.rs

//! crashd's labels (services/crashd/docs/operation.md § Live Core): a holder
//! of the live-core authority asks for an ELF core of a process that keeps
//! running.
//!
//! crashd serves them on the endpoint its recipe provides, published
//! seed-only as [`crate::published_names::CRASHD_CORE`] (a `:grant` entry),
//! badged [`LIVE_CORE_AUTHORITY`], and refuses every other badge with
//! [`crate::crashd_errors::UNAUTHORIZED`]. The name is seed-only because a
//! live core holds the process for its capture and copies its memory, and
//! `:grant` because the request moves the account the capture is charged to.

/// The badge of the SEND svcmgr publishes under
/// [`crate::published_names::CRASHD_CORE`] (the recipe's `:grant` entry):
/// the authority to ask for a live core.
pub const LIVE_CORE_AUTHORITY: u64 = 1u64 << 63;

const _: () = core::assert!(LIVE_CORE_AUTHORITY & crate::VERB_BIT_MASK != 0);

/// Write a core of the live process named in the name block at `data[0]`
/// ([`crate::with_name_block`]; at most [`crate::svcmgr_labels::NAME_MAX`]
/// bytes), the first in badge order of the processes `LIST_PROCESSES` lists
/// under that name. `caps[0]` is the **account**: a memmgr SEND of the
/// requester's, which crashd presents to procmgr's `SNAPSHOT` as the account
/// the capture's frames are charged to, so the requester, not crashd, pays
/// for them. crashd deletes it, and any further cap the message carried,
/// before it replies.
///
/// Replies [`crate::crashd_errors::SUCCESS`] with `data[0]` the process
/// badge, `data[1]` the core's sequence number (its file is
/// `<seq>-<label>.core` in crashd's core directory, `/crash`), `data[2]` the
/// core's bytes, and `data[3]` [`LIVE_CORE_COMPLETE`] when the snapshot
/// holds every page it listed, else `0`. The refusals are
/// [`crate::crashd_errors`]'s; on every one crashd has released the
/// snapshot, so none stays charged to the account.
pub const LIVE_CORE: u64 = 1;

/// [`LIVE_CORE`]'s `data[3]` flag: the snapshot captured every page it
/// listed, as procmgr's `SNAPSHOT_COMPLETE`.
pub const LIVE_CORE_COMPLETE: u64 = 1;
