// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/pwrmgr_labels.rs

//! IPC labels for the power manager (`pwrmgr`).
//!
//! pwrmgr owns the platform shutdown surface: ACPI S5 and the FADT reset
//! register on x86-64, which it reaches through acpid
//! ([`acpid_labels::SLEEP`](crate::acpid_labels::SLEEP), [`acpid_labels::RESET`](crate::acpid_labels::RESET)), and SBI SRST on
//! RISC-V, through the `SbiControl` cap it acquires from devmgr at startup
//! via [`devmgr_labels::QUERY_SHUTDOWN_DEVICE`](crate::devmgr_labels::QUERY_SHUTDOWN_DEVICE). Callers that may invoke
//! shutdown receive a badged SEND on pwrmgr's service endpoint with the
//! [`pwrmgr_labels::SHUTDOWN_AUTHORITY`](crate::pwrmgr_labels::SHUTDOWN_AUTHORITY) verb bit set.
//!
//! See `services/pwrmgr/README.md` for the authoritative description.

/// Power off the platform.
///
/// Wire format: empty body. The handler verifies the caller's badge
/// carries [`SHUTDOWN_AUTHORITY`] and replies
/// [`pwrmgr_errors::UNAUTHORIZED`] otherwise. On the success path the
/// platform powers off and no reply is delivered (QEMU exits the
/// process). A reply arrives only on a rejection, when pwrmgr has no
/// actuator, or when the platform call fails (see
/// [`pwrmgr_errors::INVALID_REQUEST`]).
pub const SHUTDOWN: u64 = 1;
/// Cold reboot the platform.
///
/// Same authorization gate as [`SHUTDOWN`]. On the success path the
/// machine cold-boots back through the bootloader.
pub const REBOOT: u64 = 2;

/// Authority bit in the pwrmgr-service-endpoint badge's high u64
/// bit. Set on caps minted for consumers permitted to call
/// [`SHUTDOWN`] and [`REBOOT`]. Without it the handler replies
/// [`pwrmgr_errors::UNAUTHORIZED`].
pub const SHUTDOWN_AUTHORITY: u64 = 1u64 << 63;
