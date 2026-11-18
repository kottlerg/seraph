// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/vfsd_errors.rs

//! Error replies from vfsd.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// File / path not found, or mount-path invalid.
pub const NOT_FOUND: u64 = 1;
/// No mount covers the requested path / partition not found.
pub const NO_MOUNT: u64 = 2;
/// Reserved; not emitted by the current vfsd.
pub const NO_FS_MODULE: u64 = 3;
/// Failed to spawn filesystem driver.
pub const SPAWN_FAILED: u64 = 4;
/// I/O error or mount failed at the driver.
pub const IO_ERROR: u64 = 5;
/// Mount table full.
pub const TABLE_FULL: u64 = 6;
/// Caller's badge lacks the verb bit required by the handler
/// (e.g. `SEED_AUTHORITY` for `GET_SYSTEM_ROOT_CAP`).
pub const UNAUTHORIZED: u64 = 9;
/// Caller's compiled `VFSD_LABELS_VERSION` does not match the receiver's.
/// The handshake-checked entry point (`GET_SYSTEM_ROOT_CAP`) and
/// `UNMOUNT` carry the caller's version as `data[0]`; mismatch here
/// means the caller was built against a different revision of
/// `shared/ipc`.
pub const LABEL_VERSION_MISMATCH: u64 = 10;
/// `UNMOUNT` without `UNMOUNT_FORCE` found files open on the mount,
/// which stays mounted; `data[0]` carries the driver's count of live
/// opens. Codes 7 and 8 are retired and not reused.
pub const BUSY: u64 = 11;
/// Unknown opcode on vfsd endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
