// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/fs_errors.rs

//! Error replies from filesystem drivers (FAT, …).

/// Request handled.
pub const SUCCESS: u64 = 0;
/// File not found, or filesystem failed to validate on mount.
pub const NOT_FOUND: u64 = 1;
/// I/O error, or out of memory other than a session's page memmgr refuses
/// (`OUT_OF_MEMORY`).
pub const IO_ERROR: u64 = 2;
/// Out of file-handle slots.
pub const TOO_MANY_OPEN: u64 = 3;
/// File badge is invalid or expired.
pub const INVALID_BADGE: u64 = 4;
/// Reserved; not emitted by the current fs driver (the fat driver's
/// cooperative-release watchdog revokes without replying this code).
pub const RELEASE_TIMEOUT: u64 = 5;
/// `FS_READ_MEMORY` cookie is invalid (zero — collides with the
/// `OutstandingPage::None` sentinel in fs driver tracking), or an
/// `FS_WRITE_MEMORY` byte range does not fit its source page (zero
/// count, or offset plus count past the page).
pub const BAD_MEMORY_OFFSET: u64 = 6;
/// Caller's node-cap badge lacks a rights bit required by the
/// requested operation (see `namespace-protocol::rights`).
pub const PERMISSION_DENIED: u64 = 7;
/// Caller's compiled `FS_LABELS_VERSION` does not match the receiver's.
/// `FS_MOUNT` is the handshake entry point and carries the caller's
/// version as `data[0]`; mismatch here means the caller was built
/// against a different revision of `shared/ipc`.
pub const LABEL_VERSION_MISMATCH: u64 = 8;
/// Mutation refused: the target name already exists in the parent
/// directory (`FS_CREATE`, `FS_MKDIR`, `FS_RENAME` destination).
pub const EXISTS: u64 = 9;
/// Mutation refused: the volume has no free cluster, the parent
/// directory has no room for a new entry (FAT16 fixed root full;
/// FAT32 cluster-chain extension failed), or a write would end past
/// the largest file size the filesystem records.
pub const NO_SPACE: u64 = 10;
/// `FS_REMOVE` refused: the target directory is non-empty.
pub const NOT_EMPTY: u64 = 11;
/// Operation refused because the target is a directory (e.g.
/// `FS_WRITE` on a directory cap) or because the operation is
/// permitted only on files.
pub const IS_A_DIRECTORY: u64 = 12;
/// `FS_UNMOUNT` without `UNMOUNT_FORCE` refused: live opens remain;
/// `data[0]` carries their count.
pub const BUSY: u64 = 13;
/// Refused at a memory bound of the client: the page a session needs is
/// over the max of the session's node, or of an ancestor
/// (`FS_SESSION`, `FS_OPEN` and `FS_READ_MEMORY` in a session).
pub const LIMIT: u64 = 14;
/// The request is not one the label takes: a capability it carries is not
/// what the label takes (memmgr refuses the node handle of an `FS_SESSION`,
/// or of the session an `FS_OPEN` or `FS_READ_MEMORY` needs a page for, or
/// the handle is missing), or its lengths or names are malformed: an
/// `FS_WRITE` payload length of zero or past the message, an empty
/// `FS_REMOVE` name or one past the message, a name an `FS_CREATE` or
/// `FS_MKDIR` cannot create, an `FS_RENAME` source `validate_name` refuses
/// or destination it cannot create, and malformed `FS_RENAME` lengths.
pub const INVALID_ARGUMENT: u64 = 15;
/// Refused for want of memory: memmgr refused the page a session needs
/// (`FS_SESSION`, `FS_OPEN` and `FS_READ_MEMORY` in a session) as
/// exhaustion, the free pool at the growth floor its node may not take
/// (`memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS` or
/// `OUT_OF_MEMORY_BEST_EFFORT`), not by a max.
pub const OUT_OF_MEMORY: u64 = 16;
/// Unknown opcode on fs-driver endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFF;
