// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/src/slot.rs

//! Per-sender state: display name, partial-line buffer, and the bounded
//! history ring of completed lines retained for future query/disk/syslog
//! sinks.
//!
//! Slots are keyed by the kernel-delivered badge on every IPC message —
//! the same `u64` procmgr uses as the child's process badge and posts as
//! the correlator of the child's death to logd's death queue. Slot
//! eviction is driven by the death event drained inside logd's main loop.

use std::collections::HashMap;

pub use logd_codec::{LINE_BUF_SIZE, MAX_NAME_LEN};

/// Number of completed log lines retained per slot for future query
/// surfaces. Bounded to keep total memory predictable at ~10k senders
/// (10k * 16 * 256 ≈ 40 MiB worst case if every sender saturates;
/// in practice most slots stay near empty). A retention tuning value that
/// bounds no capacity: `push_history` drops the oldest line, never a sender.
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
    /// The line's level, an `ipc::stream_labels::LEVEL_*` code.
    pub level: u64,
    /// Line bytes, no trailing `\n`. Length bounded by
    /// [`LINE_BUF_SIZE`].
    pub bytes: Vec<u8>,
}

/// Per-sender bucket. Stores the display name registered via
/// `STREAM_REGISTER_NAME`, the in-progress line buffer and its level, and
/// the bounded ring of completed lines.
#[derive(Default)]
pub struct Slot
{
    pub name: Vec<u8>,
    pub partial: Vec<u8>,
    /// Level of the in-progress line: that of the `STREAM_BYTES` message
    /// that carried its first byte. Meaningful only once that byte has
    /// arrived ([`Self::begin_byte`]).
    pub partial_level: u64,
    pub history: std::collections::VecDeque<LineRecord>,
}

impl Slot
{
    /// Note that the next byte, a line byte or the newline that ends the
    /// line, arrived in a message at `level`; it sets the line's level when
    /// it is the line's first.
    pub fn begin_byte(&mut self, level: u64)
    {
        if self.partial.is_empty()
        {
            self.partial_level = level;
        }
    }

    pub fn push_history(&mut self, us: u64, level: u64, bytes: &[u8])
    {
        if self.history.len() == PER_SLOT_HISTORY
        {
            self.history.pop_front();
        }
        self.history.push_back(LineRecord {
            us,
            level,
            bytes: bytes.to_vec(),
        });
    }
}

/// Badge-keyed slot map. `Default::default()` is the empty state at
/// boot; the ingested handover state from init-logd is merged in via
/// [`Self::install_from_handover`].
#[derive(Default)]
pub struct SlotTable
{
    /// Live slots by badge. Grows with the sender count, so it sets no ceiling.
    pub slots: HashMap<u64, Slot>,
}

impl SlotTable
{
    pub fn get_or_create(&mut self, badge: u64) -> &mut Slot
    {
        self.slots.entry(badge).or_default()
    }

    /// Look up `badge`, returning `None` when the sender has been
    /// evicted (by death-EQ) or never logged. Used by future query
    /// surfaces; kept for symmetry with `get_or_create` even though
    /// no caller in this PR exercises it.
    #[allow(dead_code)]
    pub fn get(&self, badge: u64) -> Option<&Slot>
    {
        self.slots.get(&badge)
    }

    /// Evict the slot for `badge` and return it, for the reclaim line to
    /// name. Called with each death event's correlator, and by the resync.
    /// Idempotent on unknown badges, which return `None`.
    pub fn evict(&mut self, badge: u64) -> Option<Slot>
    {
        self.slots.remove(&badge)
    }

    /// Install one slot's (badge, name) pair from the init-logd
    /// handover replies. History lines arrive separately as
    /// [`Self::install_history_line`].
    pub fn install_from_handover(&mut self, badge: u64, name: &[u8])
    {
        let slot = self.get_or_create(badge);
        let n = name.len().min(MAX_NAME_LEN);
        slot.name.clear();
        slot.name.extend_from_slice(&name[..n]);
    }

    /// Append one history line from the init-logd handover into the
    /// matching slot's ring. Creates the slot if absent (some history
    /// lines may have originated from senders whose slot was evicted
    /// from init-logd's small ring; the line itself still attributes
    /// to its badge).
    pub fn install_history_line(&mut self, badge: u64, us: u64, level: u64, bytes: &[u8])
    {
        self.get_or_create(badge).push_history(us, level, bytes);
    }
}
