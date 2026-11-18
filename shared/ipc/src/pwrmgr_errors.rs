// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/pwrmgr_errors.rs

//! Error replies from pwrmgr.

/// Request handled (never observed for SHUTDOWN / REBOOT, whose
/// success path does not return).
pub const SUCCESS: u64 = 0;
/// Caller's badge lacks the verb bit required by the handler
/// ([`pwrmgr_labels::SHUTDOWN_AUTHORITY`] for SHUTDOWN / REBOOT).
pub const UNAUTHORIZED: u64 = 1;
/// An authorised SHUTDOWN / REBOOT could not be carried out: pwrmgr has
/// no platform actuator (its startup acquisition from devmgr failed), or
/// the platform call returned without powering off or resetting
/// (`services/pwrmgr/README.md`).
pub const INVALID_REQUEST: u64 = 2;
/// Reserved for a future per-message version handshake; not emitted.
/// `PWRMGR_LABELS_VERSION` is marker-only.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// Unknown opcode on pwrmgr endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
