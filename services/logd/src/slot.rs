// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// logd/src/slot.rs

//! Per-sender state: display name, partial-line buffer, and the bounded
//! history ring of completed lines retained for future query/disk/syslog
//! sinks.
//!
//! Slots are keyed by the kernel-delivered token on every IPC message —
//! the same `u64` procmgr uses as the child's process token and the
//! correlator on its death-EQ binding. Slot eviction is driven by the
//! death-EQ event drained inside logd's main loop.

use std::collections::HashMap;

/// Per-sender line-buffer size. Lines longer than this are flushed
/// without a trailing newline (preserves the prefix attribution).
pub const LINE_BUF_SIZE: usize = 256;

/// Maximum per-slot display-name length in bytes.
pub const MAX_NAME_LEN: usize = 48;

/// Number of completed log lines retained per slot for future query
/// surfaces. Bounded to keep total memory predictable at ~10k senders
/// (10k * 16 * 256 ≈ 40 MiB worst case if every sender saturates;
/// in practice most slots stay near empty).
pub const PER_SLOT_HISTORY: usize = 16;

/// One retained completed line. Fields are written at line-flush
/// time and read by future query / disk-persistence / network-syslog
/// sinks — those sinks land in follow-up PRs (see issue #1 scope
/// out-of-scope items), so the fields are dead-code-flagged today
/// but the storage is part of this PR's deliverable.
#[allow(dead_code)]
#[derive(Clone)]
pub struct LineRecord
{
    /// Receipt microseconds since boot
    /// (`system_info(ElapsedUs)`-derived).
    pub us: u64,
    /// Line bytes, no trailing `\n`. Length bounded by
    /// [`LINE_BUF_SIZE`].
    pub bytes: Vec<u8>,
}

/// Per-sender bucket. Stores the display name registered via
/// `STREAM_REGISTER_NAME`, the in-progress line buffer, and the
/// bounded ring of completed lines.
#[derive(Default)]
pub struct Slot
{
    pub name: Vec<u8>,
    pub partial: Vec<u8>,
    pub history: std::collections::VecDeque<LineRecord>,
}

impl Slot
{
    pub fn push_history(&mut self, us: u64, bytes: &[u8])
    {
        if self.history.len() == PER_SLOT_HISTORY
        {
            self.history.pop_front();
        }
        self.history.push_back(LineRecord {
            us,
            bytes: bytes.to_vec(),
        });
    }
}

/// Token-keyed slot map. `Default::default()` is the empty state at
/// boot; the ingested handover state from init-logd is merged in via
/// [`Self::install_from_handover`].
#[derive(Default)]
pub struct SlotTable
{
    pub slots: HashMap<u64, Slot>,
}

impl SlotTable
{
    pub fn get_or_create(&mut self, token: u64) -> &mut Slot
    {
        self.slots.entry(token).or_default()
    }

    /// Look up `token`, returning `None` when the sender has been
    /// evicted (by death-EQ) or never logged. Used by future query
    /// surfaces; kept for symmetry with `get_or_create` even though
    /// no caller in this PR exercises it.
    #[allow(dead_code)]
    pub fn get(&self, token: u64) -> Option<&Slot>
    {
        self.slots.get(&token)
    }

    /// Evict the slot for `token`. Called when procmgr's death-EQ
    /// notification fires (correlator = process token). Idempotent on
    /// unknown tokens.
    pub fn evict(&mut self, token: u64) -> bool
    {
        self.slots.remove(&token).is_some()
    }

    /// Install one slot's (token, name) pair from the init-logd
    /// handover replies. History lines arrive separately as
    /// [`Self::install_history_line`].
    pub fn install_from_handover(&mut self, token: u64, name: &[u8])
    {
        let slot = self.get_or_create(token);
        let n = name.len().min(MAX_NAME_LEN);
        slot.name.clear();
        slot.name.extend_from_slice(&name[..n]);
    }

    /// Append one history line from the init-logd handover into the
    /// matching slot's ring. Creates the slot if absent (some history
    /// lines may have originated from senders whose slot was evicted
    /// from init-logd's small ring; the line itself still attributes
    /// to its token).
    pub fn install_history_line(&mut self, token: u64, us: u64, bytes: &[u8])
    {
        self.get_or_create(token).push_history(us, bytes);
    }
}
