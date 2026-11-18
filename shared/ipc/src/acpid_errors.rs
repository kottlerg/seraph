// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/acpid_errors.rs

//! Error replies from acpid.

/// The request was carried out and the platform still runs.
pub const SUCCESS: u64 = 0;
/// The caller's badge lacks [`super::acpid_labels::POWER_AUTHORITY`].
pub const UNAUTHORIZED: u64 = 1;
/// A [`super::acpid_labels::SLEEP`] state acpid does not serve.
pub const INVALID_REQUEST: u64 = 2;
/// `data[0]` is not acpid's compiled [`super::ACPID_LABELS_VERSION`].
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// The platform has no register or object the request needs.
pub const NO_DEVICE: u64 = 4;
/// A [`super::acpid_labels::WAIT_EVENT`] was superseded by a later one
/// before an event arrived.
pub const SUPERSEDED: u64 = 5;
/// Unknown opcode on acpid's endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
