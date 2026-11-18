// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/vfsd_labels.rs

//! IPC labels for the VFS daemon (`vfsd`).

/// Mount a filesystem at a path. The request body carries a
/// `MountRole` byte (see `services/vfsd/docs/vfs-ipc-interface.md`)
/// selecting which GPT type-GUID role to mount; vfsd looks the
/// partition up itself. The caller's badge MUST carry
/// [`MOUNT_AUTHORITY`]; vfsd replies `UNAUTHORIZED` otherwise, before it
/// reads the request.
pub const MOUNT: u64 = 10;
/// Unmount the filesystem mounted at a path, which then falls through
/// to the root filesystem's directory of the same name
/// (`services/vfsd/docs/vfs-ipc-interface.md` § Label 11).
///
/// Request: `data[0]` = caller's compiled [`super::VFSD_LABELS_VERSION`],
/// `data[1]` = path length, `data[2..]` = path bytes; [`UNMOUNT_FORCE`]
/// in the label. The caller's badge MUST carry [`MOUNT_AUTHORITY`].
/// Reply: `SUCCESS` once the driver is gone; `BUSY` with the driver's
/// count of live opens in `data[0]`, the mount kept, when the request
/// lacks [`UNMOUNT_FORCE`] and a file is open; `UNAUTHORIZED` without
/// [`MOUNT_AUTHORITY`] and for `/`, which is never unmounted;
/// `LABEL_VERSION_MISMATCH` when `data[0]` differs; `NOT_FOUND` for a
/// path length the data words do not carry; `NO_MOUNT` when no mount
/// is at the path or its unmount is already under way.
pub const UNMOUNT: u64 = 11;
/// [`UNMOUNT`] flag (label bit 16): unmount even while files are open.
/// The driver releases every open, which revokes each client's
/// liveness and cache-page caps.
pub const UNMOUNT_FORCE: u64 = 1 << 16;
// Label 12 is reserved and MUST NOT be reused for an unrelated request
// (services/vfsd/docs/vfs-ipc-interface.md).
/// Mint a fresh badged SEND on vfsd's namespace endpoint addressing
/// the synthetic system root at full namespace rights and return it
/// to the caller.
///
/// Request: `data[0]` = caller's compiled [`super::VFSD_LABELS_VERSION`].
/// Reply: `SUCCESS` with `caps[0]` = the system-root cap;
/// `UNAUTHORIZED` when the caller's badge lacks [`SEED_AUTHORITY`];
/// `LABEL_VERSION_MISMATCH` when `data[0]` differs; `NO_MOUNT` before
/// vfsd's own root mount completes; `IO_ERROR` when the derivation
/// fails. Init calls this once during bootstrap to obtain the seed cap
/// from which all later namespace-cap distribution flows.
pub const GET_SYSTEM_ROOT_CAP: u64 = 13;

/// Hand the caller a cap on the swap partition: a `SEND_GRANT` on the
/// block driver of the disk that holds the partition of
/// `boot_protocol::role_guids::SERAPH_SWAP` type, badged with that
/// partition's range. At most one cap vfsd handed out reaches the
/// partition: each hand-out revokes the one before it.
///
/// Request: `data[0]` = caller's compiled [`super::VFSD_LABELS_VERSION`].
/// Reply: `SUCCESS` with `caps[0]` = the partition cap; `UNAUTHORIZED`
/// when the caller's badge lacks [`SWAP_AUTHORITY`];
/// `LABEL_VERSION_MISMATCH` when `data[0]` differs; `NO_MOUNT` when no
/// held disk carries a swap partition or two tie at the highest priority;
/// `IO_ERROR` when the registration, the revoke, or the derivation fails.
pub const GET_SWAP_PARTITION: u64 = 14;

/// Authority bit in the vfsd-service-endpoint badge. Set on caps
/// minted for consumers permitted to call
/// [`GET_SYSTEM_ROOT_CAP`]. Without it the handler replies
/// `UNAUTHORIZED`. Holding this cap is equivalent to holding the
/// system-root cap (the handler is a seed source), so it is only
/// distributed to init. Distributing it to svcmgr's restart path is
/// design intent; not yet implemented.
pub const SEED_AUTHORITY: u64 = 1u64 << 62;

/// Authority bit in the vfsd-service-endpoint badge gating [`MOUNT`]
/// and [`UNMOUNT`]: who may mount may unmount. init mints it, alone,
/// onto the SEND it endows svcmgr with; svcmgr publishes that SEND
/// seed-only as
/// [`crate::published_names::VFSD_MOUNT`], which svctest alone seeds.
/// The cap is badged, so its holder cannot add [`SEED_AUTHORITY`].
/// Disjoint position from [`SEED_AUTHORITY`].
pub const MOUNT_AUTHORITY: u64 = 1u64 << 63;

/// Authority bit in the vfsd-service-endpoint badge gating
/// [`GET_SWAP_PARTITION`]. init mints it, alone, onto a SEND it endows
/// svcmgr with; svcmgr publishes that SEND seed-only as
/// [`crate::published_names::VFSD_SWAP`], which only the swap service's
/// recipe is to seed (svctest's recipe seeds it while no swap service
/// exists). The cap is badged, so its holder cannot add another bit.
/// Disjoint position from [`MOUNT_AUTHORITY`] and [`SEED_AUTHORITY`].
pub const SWAP_AUTHORITY: u64 = 1u64 << 61;

/// The badge init stamps on the no-authority SEND on vfsd's service
/// endpoint that svcmgr publishes seed-only as
/// [`crate::published_names::VFSD_DENY`]: no verb bit, so [`MOUNT`],
/// [`UNMOUNT`] and [`GET_SYSTEM_ROOT_CAP`] refuse it, and non-zero,
/// since a holder may badge an un-badged SEND itself
/// (docs/capability-model.md § Verb-bit authority pattern). svctest
/// asserts the `MOUNT` and `UNMOUNT` refusals through it.
pub const DENY_BADGE: u64 = 1;
