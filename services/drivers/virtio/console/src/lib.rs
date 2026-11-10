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
    head: usize,
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
        N - self.len
    }

    /// Append as much of `src` as fits, in order; returns the count appended.
    pub fn push(&mut self, src: &[u8]) -> usize
    {
        let n = src.len().min(self.free());
        for (i, &b) in src[..n].iter().enumerate()
        {
            self.bytes[(self.head + self.len + i) % N] = b;
        }
        self.len += n;
        n
    }

    /// Move the oldest bytes into `dst`, as many as it holds or the queue
    /// has; returns the count moved.
    pub fn pop(&mut self, dst: &mut [u8]) -> usize
    {
        let n = dst.len().min(self.len);
        for (i, slot) in dst[..n].iter_mut().enumerate()
        {
            *slot = self.bytes[(self.head + i) % N];
        }
        if n > 0
        {
            self.head = (self.head + n) % N;
        }
        self.len -= n;
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
