// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/hold.rs

//! logd's hold on its own serial lines while init-logd still writes the UART.
//!
//! Until init-logd acknowledges `HANDOVER_RELEASE`, it forwards every log
//! line to the UART directly, byte by byte, while logd writes through the
//! serial driver to the same UART; the two share no lock, so a line each
//! writes at once interleaves byte by byte. logd therefore holds the lines it
//! writes of its own in a [`HeldLines`] until the release, and writes them in
//! order once the hold is [opened](HeldLines::open). The hold is bounded: a
//! line past its capacity is dropped and counted, and the count is reported
//! when it opens. See `services/logd/docs/handover-protocol.md`
//! § Startup ordering.

/// A bounded, ordered hold on up to `N` items, opened once.
///
/// While closed, [`Self::hold`] keeps an item, or drops and counts it once
/// `N` are held. [`Self::open`] hands the held items over in the order they
/// were held and returns the dropped count; from then on [`Self::hold`]
/// returns each item for its caller to write at once.
pub struct HeldLines<T, const N: usize>
{
    items: [Option<T>; N],
    len: usize,
    dropped: u64,
    open: bool,
}

impl<T, const N: usize> HeldLines<T, N>
{
    /// A closed, empty hold.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            items: [const { None }; N],
            len: 0,
            dropped: 0,
            open: false,
        }
    }

    /// Hold `item` while closed (or drop and count it once `N` are held), and
    /// return `None`; once open, return `item` for the caller to write now.
    pub fn hold(&mut self, item: T) -> Option<T>
    {
        if self.open
        {
            return Some(item);
        }
        if self.len < N
        {
            self.items[self.len] = Some(item);
            self.len += 1;
        }
        else
        {
            self.dropped = self.dropped.saturating_add(1);
        }
        None
    }

    /// Open the hold: pass each held item to `write`, in the order held, and
    /// return how many were dropped past the capacity. Opening an open hold
    /// writes nothing and returns 0.
    pub fn open(&mut self, mut write: impl FnMut(T)) -> u64
    {
        self.open = true;
        for slot in &mut self.items[..self.len]
        {
            if let Some(item) = slot.take()
            {
                write(item);
            }
        }
        self.len = 0;
        core::mem::take(&mut self.dropped)
    }

    /// Whether the hold has been opened.
    #[must_use]
    pub const fn is_open(&self) -> bool
    {
        self.open
    }
}

impl<T, const N: usize> Default for HeldLines<T, N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a line logd writes of its own reaching the UART while
    // init-logd still writes it, or held lines lost or reordered at the
    // release.
    #[test]
    fn held_lines_are_written_only_at_the_open_and_in_order()
    {
        let mut h: HeldLines<u32, 4> = HeldLines::new();
        assert!(!h.is_open());
        assert_eq!(h.hold(1), None);
        assert_eq!(h.hold(2), None);
        assert_eq!(h.hold(3), None);
        let mut out = Vec::new();
        assert_eq!(h.open(|x| out.push(x)), 0);
        assert_eq!(out, [1, 2, 3]);
        assert!(h.is_open());
        assert_eq!(h.hold(4), Some(4));
    }

    // Defect caught: a hold that grows past its bound, or that drops a line
    // past it without saying so.
    #[test]
    fn lines_past_the_capacity_are_dropped_and_counted()
    {
        let mut h: HeldLines<u32, 2> = HeldLines::new();
        for i in 0..5
        {
            assert_eq!(h.hold(i), None);
        }
        let mut out = Vec::new();
        assert_eq!(h.open(|x| out.push(x)), 3);
        assert_eq!(out, [0, 1]);
    }

    // Defect caught: a second open (the halt path after the release, say)
    // writing a line twice or reporting the drops again.
    #[test]
    fn a_second_open_writes_nothing()
    {
        let mut h: HeldLines<u32, 1> = HeldLines::new();
        assert_eq!(h.hold(7), None);
        assert_eq!(h.hold(8), None);
        let mut out = Vec::new();
        assert_eq!(h.open(|x| out.push(x)), 1);
        assert_eq!(h.open(|x| out.push(x)), 0);
        assert_eq!(out, [7]);
    }
}
