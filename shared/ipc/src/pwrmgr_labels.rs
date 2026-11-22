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
//! The module also names the correlators of the core-death queue's entries
//! ([`CORE_DEATH_SVCMGR`], [`CORE_DEATH_MEMMGR`], [`CORE_DEATH_PROCMGR`]),
//! which svcmgr binds the death observers of the core set under, with
//! [`CORE_DEATH_ADDRESS_SPACE`] on each address-space observer's, and pwrmgr
//! reads.
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

/// The correlator of the death observer on svcmgr's own main thread, and
/// the base of the one on its address space, which has
/// [`CORE_DEATH_ADDRESS_SPACE`] set too; both post to the core-death queue
/// svcmgr serves pwrmgr, the shutdown actuator, a receive-only derivation
/// of (`docs/supervision.md` § Core Set and System Death). A consumer masks
/// the flag off before it matches a member.
pub const CORE_DEATH_SVCMGR: u64 = 0;
/// The correlator of the death observer svcmgr binds on memmgr's main
/// thread, and the base of the one on its address space
/// ([`CORE_DEATH_ADDRESS_SPACE`] set too), on the same queue.
pub const CORE_DEATH_MEMMGR: u64 = 1;
/// The correlator of the death observer svcmgr binds on procmgr's main
/// thread, and the base of the one on its address space
/// ([`CORE_DEATH_ADDRESS_SPACE`] set too), on the same queue.
pub const CORE_DEATH_PROCMGR: u64 = 2;
/// The flag svcmgr ORs into a member's correlator for the observer it binds
/// on the member's address space, and leaves clear for the one on its main
/// thread, so an entry says which end it is: the main thread's own end, or
/// the address space's first terminal end, of any of its threads. The two
/// can carry different reasons (`docs/process-lifecycle.md` § Exit reason).
pub const CORE_DEATH_ADDRESS_SPACE: u64 = 1 << 8;

// The flag is clear in every member's correlator.
const _: () = core::assert!(
    (CORE_DEATH_SVCMGR | CORE_DEATH_MEMMGR | CORE_DEATH_PROCMGR) & CORE_DEATH_ADDRESS_SPACE == 0
);

/// Authority bit in the pwrmgr-service-endpoint badge's high u64
/// bit. Set on caps minted for consumers permitted to call
/// [`SHUTDOWN`] and [`REBOOT`]. Without it the handler replies
/// [`pwrmgr_errors::UNAUTHORIZED`].
pub const SHUTDOWN_AUTHORITY: u64 = 1u64 << 63;
