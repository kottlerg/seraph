// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/sender-table/src/lib.rs

//! init-logd's per-sender slot table.
//!
//! init-logd keys each log sender by the badge the kernel delivers with its
//! `STREAM_BYTES` messages and keeps, per sender, the display name it
//! registered (`STREAM_REGISTER_NAME`) and the bytes received since its last
//! newline. This crate owns that bookkeeping: slot allocation and eviction,
//! name registration with the collision-suffix policy, and the line buffer.
//! It performs no IPC and issues no syscalls, so it stays host-testable; init
//! keeps the serial output, the history ring, and the handover drain. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

// The receivers' shared line and name widths: real-logd keeps the same per
// sender, so a name or line survives the handover unclipped.
pub use logd_codec::{LINE_BUF_SIZE, MAX_NAME_LEN};

use ipc::stream_labels::LEVEL_INFO;

/// One sender's state: its badge (opaque identity; `0` marks a free slot),
/// its registered display name, the bytes accumulated since its last
/// newline, and the level of that line.
#[derive(Clone, Copy)]
pub struct SenderSlot
{
    badge: u64,
    name: [u8; MAX_NAME_LEN],
    name_used: usize,
    buf: [u8; LINE_BUF_SIZE],
    used: usize,
    level: u64,
}

impl SenderSlot
{
    const fn empty() -> Self
    {
        Self {
            badge: 0,
            name: [0u8; MAX_NAME_LEN],
            name_used: 0,
            buf: [0u8; LINE_BUF_SIZE],
            used: 0,
            level: LEVEL_INFO,
        }
    }

    /// The sender's badge, or `0` for a free slot.
    #[must_use]
    pub fn badge(&self) -> u64
    {
        self.badge
    }

    /// The registered display name; empty when the sender has not registered
    /// one (init-logd renders it as `[?]`).
    #[must_use]
    pub fn name(&self) -> &[u8]
    {
        self.name.get(..self.name_used).unwrap_or_default()
    }

    /// The bytes buffered since the last newline.
    #[must_use]
    pub fn line(&self) -> &[u8]
    {
        self.buf.get(..self.used).unwrap_or_default()
    }

    /// The level of the buffered line: that of the message that carried its
    /// first byte ([`Self::begin_byte`]).
    #[must_use]
    pub fn level(&self) -> u64
    {
        self.level
    }

    /// Note that the next byte, a line byte or the newline that ends the
    /// line, arrived in a message at `level`. While no byte of the line is
    /// buffered it is the line's first, so `level` becomes the line's level;
    /// later bytes leave it as it is.
    pub fn begin_byte(&mut self, level: u64)
    {
        if self.used == 0
        {
            self.level = level;
        }
    }

    /// Append `b` to the line buffer. Returns `true` when the buffer is now
    /// full, so the caller flushes it before the next byte; a full buffer is
    /// flushed and cleared by the caller, never appended to.
    pub fn push_byte(&mut self, b: u8) -> bool
    {
        if let Some(slot) = self.buf.get_mut(self.used)
        {
            *slot = b;
            // `used` indexed a byte of the buffer, so it is below its length.
            self.used = self.used.saturating_add(1);
        }
        self.used == LINE_BUF_SIZE
    }

    /// Discard the buffered line (after the caller flushed it).
    pub fn clear_line(&mut self)
    {
        self.used = 0;
    }

    /// Give the slot to `badge` with an empty line and no name.
    fn claim(&mut self, badge: u64)
    {
        self.badge = badge;
        self.used = 0;
        self.name = [0u8; MAX_NAME_LEN];
        self.name_used = 0;
    }
}

/// A fixed table of `N` sender slots.
///
/// When every slot is occupied and a new badge arrives, a slot is evicted
/// and its partial line dropped. Eviction takes a slot whose sender has
/// registered no name before any named one: each sender registers its name
/// once, so an evicted named sender would log nameless (`[?]`) for the rest
/// of init-logd's life, while an unnamed one already renders as `[?]`.
/// Among candidates of the same kind, eviction is round-robin.
pub struct SenderTable<const N: usize>
{
    slots: [SenderSlot; N],
    next_evict: usize,
}

impl<const N: usize> SenderTable<N>
{
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self
    {
        const { assert!(N > 0, "a sender table needs at least one slot") };
        Self {
            slots: [SenderSlot::empty(); N],
            next_evict: 0,
        }
    }

    /// Every slot, in index order; a free slot has badge `0`.
    #[must_use]
    pub fn slots(&self) -> &[SenderSlot; N]
    {
        &self.slots
    }

    /// The slot at `idx` (an index [`Self::find_or_alloc`] returned);
    /// `None` when `idx >= N`.
    pub fn slot_mut(&mut self, idx: usize) -> Option<&mut SenderSlot>
    {
        self.slots.get_mut(idx)
    }

    /// The index of the slot for `badge`: its existing slot, else a free
    /// slot claimed for it, else an evicted one (see [`SenderTable`]).
    pub fn find_or_alloc(&mut self, badge: u64) -> usize
    {
        if badge != 0
            && let Some(i) = self.slots.iter().position(|s| s.badge == badge)
        {
            return i;
        }
        if let Some((i, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.badge == 0)
        {
            slot.claim(badge);
            return i;
        }
        // `next_evict` is always below `N`.
        let start = self.next_evict;
        let victim = (start..N)
            .chain(0..start)
            .find(|&i| self.slots.get(i).is_some_and(|s| s.name_used == 0))
            .unwrap_or(start);
        self.next_evict = victim.checked_add(1).filter(|&next| next < N).unwrap_or(0);
        if let Some(slot) = self.slots.get_mut(victim)
        {
            slot.claim(badge);
        }
        victim
    }

    /// Record `requested` (truncated to [`MAX_NAME_LEN`]) as the display name
    /// of the sender `badge`, claiming a slot for it if it has none.
    ///
    /// Re-registering the sender's current name, or an empty name, changes
    /// nothing and returns `None`. Otherwise the sender's previous name is
    /// released first, then the name is stored bare if no other sender holds
    /// it, else as `name.2`, `name.3`, …, the first free suffix; a name too
    /// long to hold its suffix within [`MAX_NAME_LEN`] gets truncated
    /// suffixed forms, and when every one of those collides, the bare name is
    /// stored, colliding. Returns the index of the slot whose name
    /// changed; [`SenderSlot::name`] gives the stored form.
    pub fn register_name(&mut self, badge: u64, requested: &[u8]) -> Option<usize>
    {
        let requested = requested.get(..MAX_NAME_LEN).unwrap_or(requested);
        if requested.is_empty()
        {
            return None;
        }
        let idx = self.find_or_alloc(badge);
        let slot = self.slots.get_mut(idx)?;
        if slot.name() == requested
        {
            return None;
        }

        // Release this sender's current name before resolving collisions, so
        // a rename frees the previous name for the new applicant.
        slot.name_used = 0;
        slot.name = [0u8; MAX_NAME_LEN];

        let mut stored = [0u8; MAX_NAME_LEN];
        let stored_len = self.resolve_unique_name(requested, &mut stored);
        let slot = self.slots.get_mut(idx)?;
        slot.name_used = copy_prefix(&mut slot.name, stored.get(..stored_len).unwrap_or_default());
        Some(idx)
    }

    /// Write into `out` the bare `requested` name if no occupied slot holds
    /// it, else the first `requested.<n>` (`n` from 2) no slot holds, else the
    /// bare name; return its length. The `N` suffixes `2..=N + 1` leave one
    /// free against the at most `N - 1` other names, unless truncation
    /// collapses them into names already held.
    fn resolve_unique_name(&self, requested: &[u8], out: &mut [u8; MAX_NAME_LEN]) -> usize
    {
        if !self.name_in_use(requested)
        {
            return copy_prefix(out, requested);
        }
        // `N` is an array length, so `N + 1` does not overflow.
        for suffix in 2..=N.saturating_add(1)
        {
            let n = compose_suffixed(requested, suffix, out);
            if !self.name_in_use(out.get(..n).unwrap_or_default())
            {
                return n;
            }
        }
        copy_prefix(out, requested)
    }

    /// Whether an occupied slot stores `name` verbatim.
    fn name_in_use(&self, name: &[u8]) -> bool
    {
        self.slots.iter().any(|s| s.badge != 0 && s.name() == name)
    }
}

impl<const N: usize> Default for SenderTable<N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Write `name` followed by `.<n>` into `out` and return the byte count,
/// truncating whatever does not fit in [`MAX_NAME_LEN`].
fn compose_suffixed(name: &[u8], n: usize, out: &mut [u8; MAX_NAME_LEN]) -> usize
{
    // Every increment below follows a write at `idx`, so `idx` stays at most
    // `MAX_NAME_LEN`.
    let mut idx = copy_prefix(out, name);
    if let Some(dot) = out.get_mut(idx)
    {
        *dot = b'.';
        idx = idx.saturating_add(1);
    }
    // A `usize` has at most 20 decimal digits.
    let mut digits = [0u8; 20];
    let mut dlen = 0usize;
    let mut value = n;
    loop
    {
        if let Some(digit) = digits.get_mut(dlen)
        {
            *digit = b"0123456789".get(value % 10).copied().unwrap_or(b'0');
        }
        dlen = dlen.saturating_add(1);
        value /= 10;
        if value == 0
        {
            break;
        }
    }
    for &digit in digits.get(..dlen).unwrap_or_default().iter().rev()
    {
        let Some(byte) = out.get_mut(idx)
        else
        {
            break;
        };
        *byte = digit;
        idx = idx.saturating_add(1);
    }
    idx
}

/// Copy as much of `src` as fits into the front of `out`; return the count.
fn copy_prefix(out: &mut [u8], src: &[u8]) -> usize
{
    let n = src.len().min(out.len());
    for (dst, &byte) in out.iter_mut().zip(src)
    {
        *dst = byte;
    }
    n
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_known_badge_keeps_its_slot()
    {
        let mut t = SenderTable::<4>::new();
        let a = t.find_or_alloc(11);
        let b = t.find_or_alloc(22);
        assert_ne!(a, b);
        assert_eq!(t.find_or_alloc(11), a);
        assert_eq!(t.slots()[a].badge(), 11);
    }

    #[test]
    fn a_full_table_evicts_an_unnamed_sender_before_a_named_one()
    {
        let mut t = SenderTable::<3>::new();
        let named_a = t.register_name(1, b"a").expect("name stored");
        let named_b = t.register_name(2, b"b").expect("name stored");
        let unnamed = t.find_or_alloc(3);

        let victim = t.find_or_alloc(4);
        assert_eq!(victim, unnamed);
        assert_eq!(t.slots()[named_a].name(), b"a");
        assert_eq!(t.slots()[named_b].name(), b"b");
        assert_eq!(t.find_or_alloc(1), named_a);
        assert_eq!(t.find_or_alloc(2), named_b);
    }

    #[test]
    fn a_full_table_of_named_senders_evicts_them_round_robin()
    {
        let mut t = SenderTable::<3>::new();
        for badge in 1..=3
        {
            assert!(t.register_name(badge, b"s").is_some());
        }
        // Each newcomer registers a name, so every slot stays named and the
        // victim advances one slot per eviction.
        let first = t.register_name(4, b"n").expect("name stored");
        let second = t.register_name(5, b"n").expect("name stored");
        let third = t.register_name(6, b"n").expect("name stored");
        assert_eq!([first, second, third], [0, 1, 2]);
        assert_eq!(t.register_name(7, b"n"), Some(0));
    }

    #[test]
    fn an_evicted_slot_starts_with_no_name_and_no_line()
    {
        let mut t = SenderTable::<1>::new();
        let slot = t.register_name(1, b"a").expect("name stored");
        t.slot_mut(slot).unwrap().push_byte(b'x');

        assert_eq!(t.find_or_alloc(2), slot);
        assert_eq!(t.slots()[slot].badge(), 2);
        assert!(t.slots()[slot].name().is_empty());
        assert!(t.slots()[slot].line().is_empty());
    }

    #[test]
    fn suffixes_past_nine_keep_their_digit_order()
    {
        let mut t = SenderTable::<12>::new();
        let mut last = 0;
        for badge in 1..=11
        {
            last = t.register_name(badge, b"w").expect("stored");
        }
        assert_eq!(t.slots()[last].name(), b"w.11");
        assert!(t.slots().iter().any(|s| s.name() == b"w.10"));
    }

    #[test]
    fn reregistering_the_current_name_changes_nothing()
    {
        let mut t = SenderTable::<4>::new();
        assert!(t.register_name(1, b"svc").is_some());
        assert_eq!(t.register_name(1, b"svc"), None);
    }

    #[test]
    fn an_empty_name_claims_no_slot()
    {
        let mut t = SenderTable::<4>::new();
        assert_eq!(t.register_name(1, b""), None);
        assert!(t.slots().iter().all(|s| s.badge() == 0));
    }

    #[test]
    fn a_name_another_sender_holds_gets_the_first_free_suffix()
    {
        let mut t = SenderTable::<4>::new();
        let a = t.register_name(1, b"fatfs").expect("stored");
        let b = t.register_name(2, b"fatfs").expect("stored");
        let c = t.register_name(3, b"fatfs").expect("stored");
        assert_eq!(t.slots()[a].name(), b"fatfs");
        assert_eq!(t.slots()[b].name(), b"fatfs.2");
        assert_eq!(t.slots()[c].name(), b"fatfs.3");
    }

    #[test]
    fn a_rename_frees_the_previous_name()
    {
        let mut t = SenderTable::<4>::new();
        assert!(t.register_name(1, b"a").is_some());
        let second = t.register_name(2, b"a").expect("stored");
        assert_eq!(t.slots()[second].name(), b"a.2");
        assert!(t.register_name(1, b"b").is_some());
        // Badge 2 asks for its bare name again; badge 1 released it.
        assert_eq!(t.register_name(2, b"a"), Some(second));
        assert_eq!(t.slots()[second].name(), b"a");
    }

    #[test]
    fn a_colliding_full_length_name_is_stored_unsuffixed()
    {
        let mut t = SenderTable::<4>::new();
        let long = [b'n'; MAX_NAME_LEN + 4];
        let a = t.register_name(1, &long).expect("stored");
        let b = t.register_name(2, &long).expect("stored");
        assert_eq!(t.slots()[a].name(), &long[..MAX_NAME_LEN]);
        assert_eq!(t.slots()[b].name(), &long[..MAX_NAME_LEN]);
    }

    #[test]
    fn a_line_takes_the_level_of_the_message_carrying_its_first_byte()
    {
        use ipc::stream_labels::{LEVEL_DEBUG, LEVEL_WARN};
        let mut t = SenderTable::<1>::new();
        let i = t.find_or_alloc(1);
        let slot = t.slot_mut(i).unwrap();
        slot.begin_byte(LEVEL_WARN);
        slot.push_byte(b'a');
        // A later message continues the line; the level stays.
        slot.begin_byte(LEVEL_DEBUG);
        slot.push_byte(b'b');
        assert_eq!(slot.level(), LEVEL_WARN);
        slot.clear_line();
        // The next line starts at the level of its own first message.
        slot.begin_byte(LEVEL_DEBUG);
        assert_eq!(slot.level(), LEVEL_DEBUG);
    }

    #[test]
    fn the_line_buffer_reports_full_at_capacity()
    {
        let mut t = SenderTable::<1>::new();
        let i = t.find_or_alloc(1);
        let slot = t.slot_mut(i).unwrap();
        for _ in 0..LINE_BUF_SIZE - 1
        {
            assert!(!slot.push_byte(b'x'));
        }
        assert!(slot.push_byte(b'x'));
        assert_eq!(slot.line().len(), LINE_BUF_SIZE);
        slot.clear_line();
        assert!(slot.line().is_empty());
    }
}
