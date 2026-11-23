// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/ns_labels.rs

//! IPC labels for the namespace protocol (cap-as-namespace surface).
//!
//! Numbered in a reserved range (20 through 22) that no
//! [`fs_labels`](crate::fs_labels) code takes, so node-cap and per-file
//! requests share one fs-driver endpoint with no opcode collisions.
//! [`fs_labels::END_OF_DIR`](crate::fs_labels::END_OF_DIR) is reused unchanged as the readdir
//! terminator.
//!
//! Protocol semantics, including caller-rights checks, name validation,
//! per-entry visibility (at `NS_LOOKUP` and `NS_READDIR`), and child-cap
//! minting, are owned by the `namespace-protocol` crate's
//! `dispatch_request` function; backends implement the
//! `NamespaceBackend` trait, run their own receive loop, and route each
//! `NS_*` message through `dispatch_request` for reply.

/// Walk a relative path of one or more components from a directory cap,
/// as far as the answering server owns the entries.
///
/// Request label encodes the path length in bits 16..32, at most
/// `namespace_protocol::MAX_LOOKUP_PATH_LEN`. Request data: `data[0]` =
/// caller-requested namespace rights (low 24 bits; `0xFFFF` is
/// interpreted as "everything I'm allowed"); subsequent data words carry
/// the path bytes packed little-endian, components joined by single `/`,
/// length taken from the label. No request caps. Reply on success: label
/// = 0, `data[0]` = kind of the last entry walked (0 = File, 1 = Dir),
/// `data[1]` = its cached size hint, `data[2]` = components consumed,
/// `caps[0]` = derived node cap of that entry. On error the label is the
/// matching `NsError` wire code, `data[0]` the zero-based index of the
/// failing component, with no caps.
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
