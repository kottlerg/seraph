// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/input_labels.rs

//! IPC labels for the keyboard/input device driver
//! (`services/drivers/virtio/input` today; future USB / PS-2 backends reuse
//! this same protocol).
//!
//! The driver decodes hardware key events into a **keysym stream** and
//! answers a single read operation. It owns its transport device end-to-end
//! (virtio-input PCI today) and is the sole driver-mediated source of
//! keyboard input. devmgr spawns it and hands clients an
//! [`input_labels::READ_AUTHORITY`](crate::input_labels::READ_AUTHORITY)-badged SEND via
//! [`devmgr_labels::QUERY_DEVICE`](crate::devmgr_labels::QUERY_DEVICE) on the `input` class. Key-repeat configuration, layout
//! switching, pointer/mouse events, and multi-device fan-out are out of
//! scope (see the driver `README.md`); they are not on the wire.

/// Read a batch of pending keyboard events (blocking).
///
/// Request: empty body; the caller's badge must carry
/// [`READ_AUTHORITY`], else the driver replies
/// [`super::input_errors::UNAUTHORIZED`] as soon as it reaches the request,
/// without waiting for input; the request still waits behind any authorized
/// read already blocked.
/// The driver blocks until at least one event is available, then replies
/// with up to [`super::keysym::INPUT_MAX_EVENTS_PER_READ`] events.
///
/// Reply ([`super::input_errors::SUCCESS`]): `word[0]` = event count `n`
/// (`1..=INPUT_MAX_EVENTS_PER_READ`); `word[1 + i]` = event `i` packed via
/// [`super::keysym::pack_event`] (keysym in bits 0-31, modifier mask in
/// bits 32-62, press/release in bit 63). Consumers decode with
/// [`super::keysym::unpack_event`].
pub const INPUT_READ_EVENTS: u64 = 1;

/// Authority bit in the input-service-endpoint badge's high u64 bit. Set
/// on caps devmgr mints in response to [`devmgr_labels::QUERY_DEVICE`] on
/// the `input` class. It gates [`INPUT_READ_EVENTS`]:
/// the driver answers the label with [`super::input_errors::UNAUTHORIZED`]
/// when the caller's badge lacks it. A verb ("may read"), not an identity.
pub const READ_AUTHORITY: u64 = 1u64 << 63;
