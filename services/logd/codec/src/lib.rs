// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/lib.rs

//! Pure handover-protocol and line-formatting logic for logd and init-logd.
//!
//! Holds the init-logd → real-logd handover wire contract ([`handover`]): its
//! reply, chunk-kind, and release-status codes, the sender's chunk encoders,
//! history-ring sequencing, and tracker of names that change after their
//! slot was sent, and the receiver's chunk decoder.
//! Also holds [`BoundedStr`], the fixed-capacity formatter logd uses for its
//! own diagnostics. None of this touches a syscall, IPC, or `std::os::seraph`
//! surface — the decoder reads a stack [`ipc::IpcMessage`] snapshot — so the
//! crate is host-reachable and host-tested; logd and init-logd keep the IPC
//! calls and drive this logic across the crate boundary. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)
//! and [handover-protocol.md](../../docs/handover-protocol.md).

#![cfg_attr(not(test), no_std)]

pub mod handover;

mod bounded_str;

pub use bounded_str::BoundedStr;
