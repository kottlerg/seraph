// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/console/src/lib.rs

//! Host-testable logic of the `VirtIO` console driver.
//!
//! The driver binary (`main.rs`) owns the device, its two virtqueues, and the
//! IPC loop. This library holds the service endpoint's verb-bit gate, which
//! is the serial protocol's ([`authorized`]), and the byte queue received
//! bytes wait in between the device's receive buffers and a client's read
//! ([`RxQueue`]).

#![no_std]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

use ipc::serial_labels;

/// Whether a request with label `label` from a caller badged `badge` may be
/// served: [`serial_labels::SERIAL_WRITE_BYTES`] needs
/// [`serial_labels::WRITE_AUTHORITY`], [`serial_labels::SERIAL_READ_BYTES`]
/// and [`serial_labels::SERIAL_REGISTER_RX_NOTIFY`] need
/// [`serial_labels::READ_AUTHORITY`] (see `docs/capability-model.md` on verb
/// bits). The opcode is the label's low 16 bits; a write's length rides the
/// bits above. Every other opcode carries no gate and is answered
/// `UNKNOWN_OPCODE`.
#[must_use]
pub fn authorized(label: u64, badge: u64) -> bool
{
    let required = match label & 0xFFFF
    {
        serial_labels::SERIAL_WRITE_BYTES => serial_labels::WRITE_AUTHORITY,
        serial_labels::SERIAL_READ_BYTES | serial_labels::SERIAL_REGISTER_RX_NOTIFY =>
        {
            serial_labels::READ_AUTHORITY
        }
        _ => 0,
    };
    (badge & required) == required
}

/// A first-in, first-out queue of `N` received bytes.
///
/// The device fills whole receive buffers, and a read replies with at most
/// one message's worth of bytes, so a buffer's bytes can outlast the read
/// that drained it. The driver takes a filled buffer off the used ring only
/// when the queue has room for all of it ([`Self::free`]), so no received
/// byte is dropped: while the queue is full, buffers stay with the device
/// and it stops taking input.
pub struct RxQueue<const N: usize>
{
    bytes: [u8; N],
    /// Slot of the oldest byte; below `N` (0 when `N` is 0).
    head: usize,
    /// Bytes held; at most `N`.
    len: usize,
}

impl<const N: usize> Default for RxQueue<N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<const N: usize> RxQueue<N>
{
    /// An empty queue.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            bytes: [0; N],
            head: 0,
            len: 0,
        }
    }

    /// The number of bytes the queue holds.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the queue holds no byte.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The number of bytes the queue has room for.
    #[must_use]
    pub fn free(&self) -> usize
    {
        // `len` is at most `N`: no saturation.
        N.saturating_sub(self.len)
    }

    /// The slot `offset` bytes past the oldest one, wrapped around the
    /// storage; `offset` is at most `N`.
    fn slot(&self, offset: usize) -> usize
    {
        // `head` is below `N` and `offset` at most `N`, so the sum does not
        // saturate; `N` of 0 holds no slot, and every offset names slot 0.
        self.head.saturating_add(offset).checked_rem(N).unwrap_or(0)
    }

    /// Append as much of `src` as fits, in order; returns the count appended.
    pub fn push(&mut self, src: &[u8]) -> usize
    {
        let n = src.len().min(self.free());
        let tail = self.slot(self.len);
        let Some((front, back)) = self.bytes.split_at_mut_checked(tail)
        else
        {
            return 0;
        };
        // The free slots in ring order: from the tail to the end of the
        // storage, then from its start.
        for (slot, &b) in back.iter_mut().chain(front).zip(src.iter().take(n))
        {
            *slot = b;
        }
        // `n` is at most `free()`: no saturation.
        self.len = self.len.saturating_add(n);
        n
    }

    /// Move the oldest bytes into `dst`, as many as it holds or the queue
    /// has; returns the count moved.
    pub fn pop(&mut self, dst: &mut [u8]) -> usize
    {
        let n = dst.len().min(self.len);
        let Some((front, back)) = self.bytes.split_at_checked(self.head)
        else
        {
            return 0;
        };
        // The held bytes in ring order: from the head to the end of the
        // storage, then from its start.
        for (slot, &b) in dst.iter_mut().zip(back.iter().chain(front)).take(n)
        {
            *slot = b;
        }
        self.head = self.slot(n);
        // `n` is at most `len`: no saturation.
        self.len = self.len.saturating_sub(n);
        n
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn each_verb_needs_its_own_bit()
    {
        let write = serial_labels::SERIAL_WRITE_BYTES | (5 << 16);
        assert!(authorized(write, serial_labels::WRITE_AUTHORITY));
        assert!(!authorized(write, serial_labels::READ_AUTHORITY));
        for read in [
            serial_labels::SERIAL_READ_BYTES,
            serial_labels::SERIAL_REGISTER_RX_NOTIFY,
        ]
        {
            assert!(authorized(read, serial_labels::READ_AUTHORITY));
            assert!(!authorized(read, serial_labels::WRITE_AUTHORITY));
            assert!(!authorized(read, 0));
        }
    }

    #[test]
    fn an_unknown_opcode_is_not_gated()
    {
        assert!(authorized(0xFFFF, 0));
    }

    #[test]
    fn bytes_leave_in_the_order_they_arrived_across_the_wrap()
    {
        let mut q = RxQueue::<8>::new();
        assert_eq!(q.push(b"abcdef"), 6);
        let mut out = [0u8; 4];
        assert_eq!(q.pop(&mut out), 4);
        assert_eq!(&out, b"abcd");
        // The next push wraps past the end of the storage.
        assert_eq!(q.push(b"ghijk"), 5);
        let mut out = [0u8; 16];
        assert_eq!(q.pop(&mut out), 7);
        assert_eq!(&out[..7], b"efghijk");
        assert!(q.is_empty());
    }

    #[test]
    fn a_push_past_the_room_left_takes_only_what_fits()
    {
        let mut q = RxQueue::<4>::new();
        assert_eq!(q.push(b"abc"), 3);
        assert_eq!(q.free(), 1);
        assert_eq!(q.push(b"de"), 1);
        assert_eq!(q.free(), 0);
        assert_eq!(q.push(b"f"), 0);
        let mut out = [0u8; 8];
        assert_eq!(q.pop(&mut out), 4);
        assert_eq!(&out[..4], b"abcd");
    }

    #[test]
    fn a_queue_of_no_bytes_takes_and_gives_none()
    {
        let mut q = RxQueue::<0>::new();
        assert_eq!(q.free(), 0);
        assert_eq!(q.push(b"ab"), 0);
        let mut out = [0u8; 2];
        assert_eq!(q.pop(&mut out), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn a_full_queue_wraps_its_head_back_to_the_first_slot()
    {
        let mut q = RxQueue::<4>::new();
        assert_eq!(q.push(b"abcd"), 4);
        let mut out = [0u8; 4];
        assert_eq!(q.pop(&mut out), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(q.push(b"efgh"), 4);
        assert_eq!(q.pop(&mut out), 4);
        assert_eq!(&out, b"efgh");
    }

    #[test]
    fn a_pop_into_a_short_buffer_leaves_the_rest_queued()
    {
        let mut q = RxQueue::<8>::new();
        q.push(b"xyz");
        let mut out = [0u8; 2];
        assert_eq!(q.pop(&mut out), 2);
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop(&mut []), 0);
        let mut out = [0u8; 2];
        assert_eq!(q.pop(&mut out), 1);
        assert_eq!(out[0], b'z');
    }
}
