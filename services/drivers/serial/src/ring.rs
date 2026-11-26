// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/ring.rs

//! The driver's byte rings: the transmit ring, which holds the bytes writes
//! handed the driver and the UART has not yet taken, and the receive ring,
//! which holds the bytes the UART received and no read has yet taken.
//!
//! One consumer takes bytes from the front and one producer appends at the
//! back; the two meet only in atomics, so neither holds a lock the other
//! waits on, and a thread stopped anywhere on one side (a debugger's stop)
//! leaves the other free until the ring is full or empty. A side the driver's
//! service threads share is serialised by its holder (the driver keeps it in
//! a `Mutex`), and [`Ring::split`] hands out one producer and one consumer
//! for the ring's life, so neither side can be duplicated. A write is
//! appended whole or not at all ([`Producer::push`]), so the bytes of two
//! writes never interleave.
//!
//! Positions are cumulative byte counts: `accepted` counts every byte ever
//! appended, `sent` every byte the consumer has taken, and `drained` every
//! byte known to have left the UART's transmitter. A write's mark is
//! `accepted` once its bytes are in, so it is sent once `sent` reaches the
//! mark and on the line once `drained` does. A count of bytes cannot reach
//! 2^64 in the life of a system, so the counts never wrap.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

/// Bytes the driver's transmit ring holds: eight writes of the most one
/// message carries (512 bytes), about 355 ms of output at 115200 baud
/// (`docs/limits.md`).
pub const TX_RING_BYTES: usize = 4096;

/// Bytes the driver's receive ring holds: two reads of the most one reply
/// carries (512 bytes), about 89 ms of input at 115200 baud
/// (`docs/limits.md`).
pub const RX_RING_BYTES: usize = 1024;

/// A ring of `N` bytes, `N` a power of two.
pub struct Ring<const N: usize>
{
    bytes: [AtomicU8; N],
    /// Bytes appended; written by the producer alone.
    accepted: AtomicU64,
    /// Bytes taken; written by the consumer alone.
    sent: AtomicU64,
    /// Bytes known to be off the transmitter, at most `sent`; written by
    /// the consumer alone.
    drained: AtomicU64,
    /// Whether [`Ring::split`] has handed out the two ends.
    split: AtomicBool,
}

impl<const N: usize> Ring<N>
{
    /// The position mask: `N` is a power of two, checked at compile time.
    const MASK: u64 = {
        assert!(N.is_power_of_two(), "a ring's size is a power of two");
        // A power of two of usize fits u64 on every target the driver builds for.
        (N as u64).wrapping_sub(1)
    };

    /// An empty ring.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            bytes: [const { AtomicU8::new(0) }; N],
            accepted: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            drained: AtomicU64::new(0),
            split: AtomicBool::new(false),
        }
    }

    /// The ring's producer and consumer, the first time it is called; `None`
    /// after.
    pub fn split(&self) -> Option<(Producer<'_, N>, Consumer<'_, N>)>
    {
        if self.split.swap(true, Ordering::AcqRel)
        {
            return None;
        }
        Some((Producer { ring: self }, Consumer { ring: self }))
    }

    /// Bytes the consumer has taken.
    pub fn sent(&self) -> u64
    {
        self.sent.load(Ordering::Acquire)
    }

    /// Bytes known to have left the transmitter.
    pub fn drained(&self) -> u64
    {
        self.drained.load(Ordering::Acquire)
    }

    /// The slot of position `pos`.
    fn slot(&self, pos: u64) -> Option<&AtomicU8>
    {
        // The mask keeps the index below N, which fits usize.
        self.bytes.get(usize::try_from(pos & Self::MASK).ok()?)
    }
}

impl<const N: usize> Default for Ring<N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// The appending end of a [`Ring`].
pub struct Producer<'a, const N: usize>
{
    ring: &'a Ring<N>,
}

impl<const N: usize> Producer<'_, N>
{
    /// Bytes the ring has room for.
    #[must_use]
    pub fn room(&self) -> usize
    {
        let accepted = self.ring.accepted.load(Ordering::Relaxed);
        let queued = accepted.wrapping_sub(self.ring.sent.load(Ordering::Acquire));
        // At most N bytes are queued, so the difference fits usize.
        N.saturating_sub(usize::try_from(queued).unwrap_or(N))
    }

    /// Append `bytes` whole and return the write's mark, the count of bytes
    /// accepted once they are in; `None`, appending nothing, when the ring
    /// has no room for all of them.
    pub fn push(&mut self, bytes: &[u8]) -> Option<u64>
    {
        if bytes.len() > self.room()
        {
            return None;
        }
        let start = self.ring.accepted.load(Ordering::Relaxed);
        let mut pos = start;
        for &byte in bytes
        {
            self.ring.slot(pos)?.store(byte, Ordering::Relaxed);
            pos = pos.wrapping_add(1);
        }
        // Release: the consumer that reads the new count reads the bytes.
        self.ring.accepted.store(pos, Ordering::Release);
        Some(pos)
    }
}

/// The taking end of a [`Ring`].
pub struct Consumer<'a, const N: usize>
{
    ring: &'a Ring<N>,
}

impl<const N: usize> Consumer<'_, N>
{
    /// Whether the ring holds no byte.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.ring.accepted.load(Ordering::Acquire) == self.ring.sent.load(Ordering::Relaxed)
    }

    /// Hand up to `max` of the oldest bytes to `emit`, in order, and count
    /// them sent; the number handed.
    pub fn take(&mut self, max: usize, mut emit: impl FnMut(u8)) -> usize
    {
        let accepted = self.ring.accepted.load(Ordering::Acquire);
        let start = self.ring.sent.load(Ordering::Relaxed);
        let mut pos = start;
        let mut taken = 0usize;
        while taken < max && pos != accepted
        {
            let Some(slot) = self.ring.slot(pos)
            else
            {
                break;
            };
            emit(slot.load(Ordering::Relaxed));
            pos = pos.wrapping_add(1);
            taken = taken.saturating_add(1);
        }
        // Release: the producer that reads the new count, and so reuses the
        // slots, does so after their bytes were read.
        self.ring.sent.store(pos, Ordering::Release);
        taken
    }

    /// Record that every byte taken has left the transmitter: the consumer
    /// saw the UART's transmitter empty with nothing taken since.
    pub fn settle(&mut self)
    {
        let sent = self.ring.sent.load(Ordering::Relaxed);
        self.ring.drained.store(sent, Ordering::Release);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn taken<const N: usize>(consumer: &mut Consumer<'_, N>, max: usize) -> Vec<u8>
    {
        let mut out = Vec::new();
        consumer.take(max, |b| out.push(b));
        out
    }

    // Defect caught: a split that hands out a second producer or consumer,
    // which would let two threads append or take at once.
    #[test]
    fn a_ring_splits_once()
    {
        let ring = Ring::<8>::new();
        assert!(ring.split().is_some());
        assert!(ring.split().is_none());
    }

    // Defect caught: a write appended in part when it does not fit, which
    // would let another writer's bytes land inside it on the line.
    #[test]
    fn a_write_that_does_not_fit_appends_nothing()
    {
        let ring = Ring::<8>::new();
        let (mut producer, mut consumer) = ring.split().unwrap();
        assert_eq!(producer.push(&[1, 2, 3, 4, 5]), Some(5));
        assert_eq!(producer.push(&[6, 7, 8, 9]), None);
        assert_eq!(producer.room(), 3);
        assert_eq!(taken(&mut consumer, 8), vec![1, 2, 3, 4, 5]);
    }

    // Defect caught: a full ring that accepts one byte more, or an empty one
    // that refuses a write of exactly its size.
    #[test]
    fn a_write_of_exactly_the_room_fits()
    {
        let ring = Ring::<8>::new();
        let (mut producer, _consumer) = ring.split().unwrap();
        assert_eq!(producer.push(&[0; 8]), Some(8));
        assert_eq!(producer.room(), 0);
        assert_eq!(producer.push(&[0]), None);
        assert_eq!(producer.push(&[]), Some(8));
    }

    // Defect caught: an index that does not wrap at the ring's end, or a take
    // that reorders, drops or repeats bytes across the wrap.
    #[test]
    fn bytes_come_out_in_order_across_the_wrap()
    {
        let ring = Ring::<8>::new();
        let (mut producer, mut consumer) = ring.split().unwrap();
        let mut expected = Vec::new();
        let mut out = Vec::new();
        for round in 0u8..10
        {
            let write: Vec<u8> = (0..5).map(|i| round * 5 + i).collect();
            assert_eq!(producer.push(&write), Some(u64::from(round + 1) * 5));
            expected.extend_from_slice(&write);
            // Take in two pieces, the second past the end of the write.
            out.extend(taken(&mut consumer, 3));
            out.extend(taken(&mut consumer, 16));
            assert!(consumer.is_empty());
        }
        assert_eq!(out, expected);
        assert_eq!(ring.sent(), 50);
    }

    // Defect caught: a take that hands more than its limit, which would
    // overrun the UART's transmit FIFO.
    #[test]
    fn a_take_hands_at_most_its_limit()
    {
        let ring = Ring::<16>::new();
        let (mut producer, mut consumer) = ring.split().unwrap();
        producer.push(&[9; 12]).unwrap();
        assert_eq!(consumer.take(5, |_| {}), 5);
        assert_eq!(ring.sent(), 5);
        assert_eq!(producer.room(), 9);
    }

    // Defect caught: a drained count that passes what was sent, which would
    // answer a write before its bytes left the UART.
    #[test]
    fn drained_counts_only_bytes_taken()
    {
        let ring = Ring::<8>::new();
        let (mut producer, mut consumer) = ring.split().unwrap();
        producer.push(&[1, 2, 3, 4]).unwrap();
        consumer.take(2, |_| {});
        consumer.settle();
        assert_eq!(ring.drained(), 2);
        consumer.take(2, |_| {});
        assert_eq!(ring.drained(), 2);
        consumer.settle();
        assert_eq!(ring.drained(), 4);
    }
}
