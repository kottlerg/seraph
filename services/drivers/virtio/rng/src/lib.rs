// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/rng/src/lib.rs

//! Host-testable logic of the `VirtIO` entropy driver.
//!
//! The driver binary (`main.rs`) owns the device, the request virtqueue, and
//! the IPC loop. This library holds the service endpoint's verb-bit gate,
//! [`hwrng_protocol::READ`] gated on [`hwrng_protocol::READ_AUTHORITY`] in
//! the caller's badge, and the length arithmetic of a read: how much of the
//! request buffer the driver posts, and how many bytes of a completion it
//! hands the caller, given a length the device wrote and so does not vouch
//! for.

use hwrng_protocol::{MAX_READ_BYTES, READ, READ_AUTHORITY};

/// Whether a request with label `label` from a caller badged `badge` may be
/// served: `false` when `label` is [`READ`] and `badge` lacks
/// [`READ_AUTHORITY`]. Unknown labels carry no gate and are answered
/// `UNKNOWN_OPCODE`.
#[must_use]
pub fn authorized(label: u64, badge: u64) -> bool
{
    label != READ || badge & READ_AUTHORITY != 0
}

/// The length of the device-writable buffer the driver posts for a read of
/// `asked` bytes: `asked`, at most [`MAX_READ_BYTES`], so the device is
/// asked for no more than the caller takes and the reply carries.
#[must_use]
pub fn post_len(asked: usize) -> u32
{
    u32::try_from(asked.min(MAX_READ_BYTES)).unwrap_or(0)
}

/// The bytes of a completion the driver hands a read of `asked` bytes: the
/// length the device reports writing, `written`, clamped to the `posted`
/// buffer's length, since the used ring is device-written and a length past
/// the buffer would read memory the device did not fill, then to `asked`.
/// A buffer posted for an earlier read that timed out may be longer or
/// shorter than `asked`; the caller gets at most what it asked for.
#[must_use]
pub fn delivered_len(written: u32, posted: u32, asked: usize) -> usize
{
    usize::try_from(written.min(posted)).map_or(0, |n| n.min(asked))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn read_is_refused_without_read_authority()
    {
        // A badge carrying some other bit is no substitute for the verb bit.
        assert!(!authorized(READ, 0));
        assert!(!authorized(READ, 1u64 << 62));
        assert!(authorized(READ, READ_AUTHORITY));
    }

    #[test]
    fn unknown_label_is_not_gated()
    {
        assert!(authorized(0xFFFF, 0));
    }

    #[test]
    fn post_len_asks_the_device_for_no_more_than_one_reply_carries()
    {
        assert_eq!(post_len(16), 16);
        assert_eq!(
            post_len(MAX_READ_BYTES + 1),
            u32::try_from(MAX_READ_BYTES).unwrap()
        );
    }

    #[test]
    fn delivered_len_never_reads_past_the_posted_buffer()
    {
        // A device reporting more than the buffer holds gets the buffer.
        assert_eq!(delivered_len(4096, 32, 64), 32);
    }

    #[test]
    fn delivered_len_never_hands_more_than_was_asked()
    {
        // A buffer posted for an earlier, longer read that timed out.
        assert_eq!(delivered_len(64, 64, 8), 8);
    }

    #[test]
    fn delivered_len_hands_a_short_completion_as_it_is()
    {
        assert_eq!(delivered_len(5, 32, 32), 5);
        assert_eq!(delivered_len(0, 32, 32), 0);
    }
}
