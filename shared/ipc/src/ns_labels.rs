// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/ns_labels.rs

//! IPC labels for the namespace protocol (cap-as-namespace surface).
//!
//! Numbered in a reserved range above the [`fs_labels`](crate::fs_labels) codes (2 through
//! 18) so node-cap and per-file requests share one fs-driver endpoint with
//! no opcode collisions.
//! [`fs_labels::END_OF_DIR`](crate::fs_labels::END_OF_DIR) is reused unchanged as the readdir
//! terminator.
//!
//! Protocol semantics, including caller-rights checks, name validation,
//! per-entry visibility (at `NS_LOOKUP` and `NS_READDIR`), and child-cap
//! minting, are owned by the `namespace-protocol` crate's
//! `dispatch_request` function; backends implement the
//! `NamespaceBackend` trait, run their own receive loop, and route each
//! `NS_*` message through `dispatch_request` for reply.

/// Walk one path component within a directory cap.
///
/// Request label encodes name length in bits 16..32; the field exceeds
/// `namespace_protocol::MAX_NAME_LEN`, which bounds a name. Request data:
/// `data[0]` = caller-requested namespace rights (low 24 bits;
/// `0xFFFF` is interpreted as "everything I'm allowed"); subsequent
/// data words carry the name bytes packed little-endian, length
/// taken from the label. No request caps. Reply on success: label =
/// 0, `data[0]` = entry kind (0 = File, 1 = Dir), `data[1]` =
/// cached size hint, `caps[0]` = derived child node cap. On error
/// the label is the matching `NsError` wire code with no caps.
pub const NS_LOOKUP: u64 = 20;
/// Attribute snapshot for the node addressed by the caller's badge.
///
/// Request: empty body. Reply on success: label = 0, `data[0]` =
/// size, `data[1]` = `mtime_us` (best-effort; zero on backends that
/// do not track it), `data[2]` = kind. Error replies match
/// [`NS_LOOKUP`].
pub const NS_STAT: u64 = 21;
/// One-entry-per-call enumeration of the directory addressed by the
/// caller's badge.
///
/// Request: `data[0]` = zero-based entry index. Reply on success:
/// label = 0, `data[0]` = kind, `data[1]` = name length in bytes,
/// subsequent data words carry the name bytes packed
/// little-endian. Reply label is [`fs_labels::END_OF_DIR`] (6) when
/// `index` is past the last entry. Error replies match
/// [`NS_LOOKUP`]. No caps in either direction — clients follow up
/// with [`NS_LOOKUP`] when they want a node cap for a returned
/// name.
pub const NS_READDIR: u64 = 22;
