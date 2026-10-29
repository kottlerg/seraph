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

/// Maximum per-slot display-name length in bytes. Sized for typical
/// contextual names like `"fatfs /some/deeply/nested/mount"`. Longer names
/// are truncated.
pub const MAX_NAME_LEN: usize = 48;

/// Per-sender line-buffer size. A line longer than this is flushed without
/// a trailing newline.
pub const LINE_BUF_SIZE: usize = 256;

/// One sender's state: its badge (opaque identity; `0` marks a free slot),
/// its registered display name, and the bytes accumulated since its last
/// newline.
#[derive(Clone, Copy)]
pub struct SenderSlot
{
    badge: u64,
    name: [u8; MAX_NAME_LEN],
    name_used: usize,
    buf: [u8; LINE_BUF_SIZE],
    used: usize,
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
        &self.name[..self.name_used]
    }

    /// The bytes buffered since the last newline.
    #[must_use]
    pub fn line(&self) -> &[u8]
    {
        &self.buf[..self.used]
    }

    /// Append `b` to the line buffer. Returns `true` when the buffer is now
    /// full, so the caller flushes it before the next byte; a full buffer is
    /// flushed and cleared by the caller, never appended to.
    pub fn push_byte(&mut self, b: u8) -> bool
    {
        if self.used < LINE_BUF_SIZE
        {
            self.buf[self.used] = b;
            self.used += 1;
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

    /// The slot at `idx` (an index [`Self::find_or_alloc`] returned).
    ///
    /// # Panics
    /// When `idx >= N`.
    pub fn slot_mut(&mut self, idx: usize) -> &mut SenderSlot
    {
        &mut self.slots[idx]
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
        if let Some(i) = self.slots.iter().position(|s| s.badge == 0)
        {
            self.slots[i].claim(badge);
            return i;
        }
        let start = self.next_evict % N;
        let victim = (0..N)
            .map(|k| (start + k) % N)
            .find(|&i| self.slots[i].name_used == 0)
            .unwrap_or(start);
        self.next_evict = (victim + 1) % N;
        self.slots[victim].claim(badge);
        victim
    }

    /// Record `requested` (truncated to [`MAX_NAME_LEN`]) as the display name
    /// of the sender `badge`, claiming a slot for it if it has none.
    ///
    /// Re-registering the sender's current name, or an empty name, changes
    /// nothing and returns `None`. Otherwise the sender's previous name is
    /// released first, then the name is stored bare if no other sender holds
    /// it, else as `name.2`, `name.3`, …, the first free suffix; when every
    /// suffix collides (a full-length name leaves no room for one), the bare
    /// name is stored, colliding. Returns the index of the slot whose name
    /// changed; [`SenderSlot::name`] gives the stored form.
    pub fn register_name(&mut self, badge: u64, requested: &[u8]) -> Option<usize>
    {
        let requested = &requested[..requested.len().min(MAX_NAME_LEN)];
        if requested.is_empty()
        {
            return None;
        }
        let idx = self.find_or_alloc(badge);
        if self.slots[idx].name() == requested
        {
            return None;
        }

        // Release this sender's current name before resolving collisions, so
        // a rename frees the previous name for the new applicant.
        self.slots[idx].name_used = 0;
        self.slots[idx].name = [0u8; MAX_NAME_LEN];

        let mut stored = [0u8; MAX_NAME_LEN];
        let stored_len = self.resolve_unique_name(requested, &mut stored);
        self.slots[idx].name[..stored_len].copy_from_slice(&stored[..stored_len]);
        self.slots[idx].name_used = stored_len;
        Some(idx)
    }

    /// Write into `out` the bare `requested` name if no occupied slot holds
    /// it, else the first `requested.<n>` (`n` from 2) no slot holds, else the
    /// bare name; return its length. `N + 1` suffixes always leave one free
    /// unless truncation makes every suffixed form equal the bare name.
    fn resolve_unique_name(&self, requested: &[u8], out: &mut [u8; MAX_NAME_LEN]) -> usize
    {
        if !self.name_in_use(requested)
        {
            out[..requested.len()].copy_from_slice(requested);
            return requested.len();
        }
        for suffix in 2..=N + 1
        {
            let n = compose_suffixed(requested, suffix, out);
            if !self.name_in_use(&out[..n])
            {
                return n;
            }
        }
        out[..requested.len()].copy_from_slice(requested);
        requested.len()
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
    let copy_len = name.len().min(out.len());
    out[..copy_len].copy_from_slice(&name[..copy_len]);
    let mut idx = copy_len;
    if idx < out.len()
    {
        out[idx] = b'.';
        idx += 1;
    }
    let mut digits = [0u8; 20];
    let mut dlen = 0;
    let mut value = n;
    loop
    {
        digits[dlen] = b"0123456789"[value % 10];
        dlen += 1;
        value /= 10;
        if value == 0
        {
            break;
        }
    }
    while dlen > 0 && idx < out.len()
    {
        dlen -= 1;
        out[idx] = digits[dlen];
        idx += 1;
    }
    idx
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
    fn a_full_table_of_named_senders_evicts_round_robin_with_a_clean_slot()
    {
        let mut t = SenderTable::<2>::new();
        let first = t.register_name(1, b"a").expect("name stored");
        let second = t.register_name(2, b"b").expect("name stored");
        t.slot_mut(first).push_byte(b'x');

        assert_eq!(t.find_or_alloc(3), first);
        assert_eq!(t.slots()[first].badge(), 3);
        assert!(t.slots()[first].name().is_empty());
        assert!(t.slots()[first].line().is_empty());
        // Badge 3 is unnamed now, so the next newcomer takes its slot again.
        assert_eq!(t.find_or_alloc(4), first);
        assert_eq!(t.slots()[second].name(), b"b");
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
    fn the_line_buffer_reports_full_at_capacity()
    {
        let mut t = SenderTable::<1>::new();
        let i = t.find_or_alloc(1);
        let slot = t.slot_mut(i);
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
