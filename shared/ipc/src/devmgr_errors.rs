// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/devmgr_errors.rs

//! Error replies from devmgr.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// The request cannot be served: a reply-cap derivation failed, the
/// badge indexes no catalog entry with startup info
/// (`QUERY_DEVICE_INFO`), a `DRIVER_READY` badge names no live driver of
/// the batch, `SET_DRIVERS_DIR` carried no cap, or a label-specific
/// argument was rejected (see `MINT_CLASS_SEND`, `QUERY_ACPI_TABLE`, and
/// `QUERY_SHUTDOWN_DEVICE`).
pub const INVALID_REQUEST: u64 = 1;
/// Caller's badge lacks what the handler requires: an authority bit
/// (e.g. `CLASS_AUTHORITY` for `MINT_CLASS_SEND`), or, for
/// `QUERY_DEVICE` and `WATCH_CLASS`, a class slot
/// (`devmgr_labels::class_badge`).
pub const UNAUTHORIZED: u64 = 2;
/// Caller's compiled `DEVMGR_LABELS_VERSION`, carried in `data[0]` of
/// every devmgr request, does not match the receiver's: the caller was
/// built against a different revision of `shared/ipc`.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// Requested device or table is unavailable. Returned by `QUERY_DEVICE`
/// when the requested instance ordinal is past the last served driver
/// of the class, which it is for every ordinal while devmgr either (a)
/// has not yet received [`super::devmgr_labels::SET_DRIVERS_DIR`], so
/// it has not spawned the class's on-disk drivers, or (b) attempted the
/// disk-walked spawn and failed (missing binary, ELF corrupt, hardware
/// carve failed, OOM, the driver died or did not report ready within
/// the settle bound, etc.), or (c) binds no driver of the class on this
/// machine. A query received while the drivers-directory pass or its
/// settle runs waits until both are done and gets no case (a) reply.
/// Case (a) ends once `SET_DRIVERS_DIR` arrives, and (b) and (c) end
/// only when a later bind pass serves a driver of the class
/// (`BIND_DRIVERS`), which a client cannot foresee: a client with a
/// no-device path (timed) MUST treat the reply as terminal and take
/// that path, and a client that cannot proceed without the device
/// waits on a `WATCH_CLASS` watch and queries again when it is
/// signalled ([`super::await_device`]), never polling `QUERY_DEVICE`.
/// Also returned by `QUERY_ACPI_TABLE` (table not found) and
/// `QUERY_SHUTDOWN_DEVICE` (no SBI authority to serve; always on x86-64).
pub const NO_DEVICE: u64 = 4;
/// The driver the query names was served and has since died, so devmgr
/// withdrew it: its service endpoint is revoked, and callers queued on
/// it returned. Returned by `QUERY_DEVICE` at the withdrawn driver's
/// instance ordinal, which stays held for the rest of the boot so the
/// ordinals after it keep their drivers (a client probing ordinals
/// continues at the next one). Sticky for the boot: a driver devmgr
/// restarts after its death is a new instance, served at the class's next
/// ordinal (services/devmgr/docs/responsibilities.md § Driver Restart).
pub const WITHDRAWN: u64 = 5;
/// The class holds `devmgr_labels::MAX_CLASS_WATCHERS` watches and
/// none of them is gone (`WATCH_CLASS`).
pub const WATCHERS_FULL: u64 = 6;
/// A well-formed request devmgr's policy refuses: an
/// `ACPI_REGION_GRANT` range, an `ACPI_PCI_CONFIG` write, or a
/// `PRT_TABLE` or `BRIDGE_WINDOWS` push that fails devmgr's check. The
/// refusal is logged.
pub const REFUSED: u64 = 7;
/// Unknown opcode on devmgr endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
