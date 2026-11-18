// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/acpid_labels.rs

//! IPC labels for acpid's power surface, which pwrmgr calls.
//!
//! acpid runs the firmware's AML and holds the FADT's fixed register blocks
//! and the SCI (`services/acpid/README.md`), so the ACPI sleep and reset
//! sequences run in it and the fixed events reach the OS through it: pwrmgr,
//! the power policy, reaches them through a SEND badged
//! [`acpid_labels::POWER_AUTHORITY`](crate::acpid_labels::POWER_AUTHORITY) (`acpid.power`). Every request carries
//! the caller's compiled [`super::ACPID_LABELS_VERSION`] in `data[0]`.
//! The handler checks the label first, then the badge, then the version,
//! then the argument.

/// Enter a sleep state: write `SLP_TYP` and then `SLP_TYP | SLP_EN` to
/// `PM1a_CNT`, the `SLP_TYP` read from the state's `\_Sx_` package,
/// after `\_PTS` of the state when the tables define it and after
/// acpid disables the events it armed but the power button and clears
/// every event status.
///
/// Request: `data[0]` = the version; `data[1]` = the state, of which
/// only [`STATE_S5`] (soft-off) is served. On the success path the
/// platform powers off and no reply arrives; a
/// [`super::acpid_errors::SUCCESS`] reply means the platform still runs
/// 10 s after the writes, when acpid has enabled its GPEs again, and the
/// caller decides how long to wait.
/// Replies [`super::acpid_errors::INVALID_REQUEST`] for another state and
/// [`super::acpid_errors::NO_DEVICE`] when the platform has no
/// `PM1a_CNT`, the tables no usable `\_S5_`, or no AML loaded (always
/// on RISC-V, whose platforms power off through SBI).
pub const SLEEP: u64 = 1;
/// Reset the platform: write the FADT's `RESET_VALUE` to its
/// `RESET_REG`.
///
/// Request: `data[0]` = the version. On the success path the machine
/// resets and no reply arrives; a [`super::acpid_errors::SUCCESS`]
/// reply means the write returned and the platform still runs. Replies
/// [`super::acpid_errors::NO_DEVICE`] when the FADT places no
/// `RESET_REG` in the I/O space (always on RISC-V).
pub const RESET: u64 = 2;
/// Wait for a power event: acpid holds the call until one is pending,
/// with no bound, then replies with every event pending.
///
/// Request: `data[0]` = the version. Reply
/// ([`super::acpid_errors::SUCCESS`]): `data[0]` = the events, a mask of
/// [`EVENT_POWER_BUTTON`]. An event is consumed by the reply that
/// delivers it; one whose reply cannot be delivered (the caller died) is
/// kept for the next `WAIT_EVENT`, and one acpid had not delivered when
/// it died stays latched in the hardware and is delivered by the restarted
/// acpid, unless a `SLEEP` that returned cleared its status first. One caller waits at a time: a `WAIT_EVENT` that arrives while
/// another waits takes its place, and the earlier one is replied
/// [`super::acpid_errors::SUPERSEDED`]. Replies
/// [`super::acpid_errors::NO_DEVICE`] when acpid has no event to wait
/// for: devmgr served it no SCI or no `PM1a` event block, or the FADT
/// declares no fixed power button (always on RISC-V).
pub const WAIT_EVENT: u64 = 3;

/// [`SLEEP`]'s state argument for S5, soft-off.
pub const STATE_S5: u64 = 5;

/// [`WAIT_EVENT`]'s event bit: the fixed power button was pressed
/// (`PWRBTN_STS`).
pub const EVENT_POWER_BUTTON: u64 = 1;

/// Authority bit in the acpid-service-endpoint badge's high u64 bit, set
/// on `acpid.power`. Without it [`SLEEP`], [`RESET`] and [`WAIT_EVENT`]
/// reply [`super::acpid_errors::UNAUTHORIZED`].
pub const POWER_AUTHORITY: u64 = 1u64 << 63;
