// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/input/src/lib.rs

//! Host-testable logic of the `VirtIO` input driver.
//!
//! The driver binary (`main.rs`) owns the device, the event virtqueue, and
//! the IPC loop. This library holds the service endpoint's verb-bit gate:
//! [`input_labels::INPUT_READ_EVENTS`] is gated on
//! [`input_labels::READ_AUTHORITY`] in the caller's badge (see
//! `docs/capability-model.md` on verb bits), so a holder of a SEND without
//! the bit cannot read keystrokes; and the judgement of an eventq
//! completion's length ([`is_whole_event`]).

use ipc::input_labels;

/// Whether a request with label `label` from a caller badged `badge` may be
/// served.
///
/// Returns `false` when `label` is [`input_labels::INPUT_READ_EVENTS`] and
/// `badge` lacks [`input_labels::READ_AUTHORITY`]; the driver then replies
/// `input_errors::UNAUTHORIZED` as soon as it reaches the request, without
/// waiting for input, though the request still waits behind any authorized
/// read already blocked. Returns `true` for every
/// other request: unknown labels carry no gate and are answered
/// `UNKNOWN_OPCODE`.
#[must_use]
pub fn authorized(label: u64, badge: u64) -> bool
{
    label != input_labels::INPUT_READ_EVENTS || badge & input_labels::READ_AUTHORITY != 0
}

/// Bytes of one virtio-input event (`VirtIO` 1.2 §5.8.6.2: `type` and `code`,
/// 16 bits each, and `value`, 32 bits), the length of each eventq buffer.
pub const EVENT_SIZE: u32 = 8;

/// Whether an eventq completion whose used element reports `len` bytes
/// written holds a whole event. The driver reads nothing past the first
/// `len` bytes of a buffer (`VirtIO` 1.2 §2.7.8.2), so a shorter completion
/// carries no event: the bytes it did not write are the slot's previous
/// event, or zeros. A `len` past the buffer is the device's error; the
/// event's 8 bytes lie inside the buffer, so it is read.
#[must_use]
pub fn is_whole_event(len: u32) -> bool
{
    len >= EVENT_SIZE
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn read_events_is_refused_without_read_authority()
    {
        // A badge carrying some other bit is no substitute for the verb bit.
        let label = input_labels::INPUT_READ_EVENTS;
        assert!(!authorized(label, 0));
        assert!(!authorized(label, 1u64 << 62));
        assert!(authorized(label, input_labels::READ_AUTHORITY));
    }

    #[test]
    fn unknown_label_is_not_gated()
    {
        assert!(authorized(0xFFFF, 0));
    }

    #[test]
    fn a_completion_shorter_than_an_event_holds_none()
    {
        for len in 0..EVENT_SIZE
        {
            assert!(!is_whole_event(len), "a {len}-byte completion was read");
        }
    }

    #[test]
    fn a_completion_of_an_event_or_more_holds_one()
    {
        assert!(is_whole_event(EVENT_SIZE));
        assert!(is_whole_event(9));
        assert!(is_whole_event(u32::MAX));
    }
}
