// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ns-client/src/lib.rs

//! No-std namespace walk helpers.
//!
//! Any service holding a tokened SEND on a vfsd namespace endpoint (the
//! seed cap obtained via `vfsd_labels::GET_SYSTEM_ROOT_CAP` for init, or
//! a subtree cap delivered to a child service) can use these helpers to
//!
//!   * resolve binary paths into per-file caps before issuing
//!     `procmgr_labels::CREATE_FROM_FILE` ([`walk_to_file`]);
//!   * derive attenuated subtree / cwd caps to install on children via
//!     `procmgr_labels::CONFIGURE_NAMESPACE` ([`walk_to_dir`]).
//!
//! Both helpers mirror the per-component `NS_LOOKUP` walk std performs
//! in `runtime/ruststd/src/sys/fs/seraph.rs`, reduced to `no_std`
//! primitives. `requested_rights` is the rights mask sent on every
//! intermediate hop; namespace-protocol intersects it against each
//! entry's `max_rights`, so the returned cap carries at most
//! `requested_rights` on every bit. Callers wanting "everything
//! permitted" pass `0xFFFF` (the sentinel that selects each entry's
//! full `max_rights`).

#![no_std]

use ipc::{IpcMessage, ns_labels};

/// Result of [`walk_to_file`].
pub struct WalkedFile
{
    /// Tokened SEND addressing the resolved file node. Caller owns and
    /// must `cap_delete` when no longer needed.
    pub file_cap: u32,
    /// Size hint reported by the resolving `NS_LOOKUP`.
    pub size: u64,
}

/// Walk `path` from `root_cap` requesting `requested_rights` per hop
/// and return the resolved file cap.
///
/// Each non-final hop must resolve to a directory; the final hop must
/// resolve to a file (kind 0).
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
pub fn walk_to_file(
    root_cap: u32,
    path: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Option<WalkedFile>
{
    let WalkResult { cap, kind, size } = walk(root_cap, path, requested_rights, ipc_buf)?;
    if kind != 0
    {
        let _ = syscall::cap_delete(cap);
        return None;
    }
    Some(WalkedFile {
        file_cap: cap,
        size,
    })
}

/// Walk `path` from `root_cap` requesting `requested_rights` per hop
/// and return the resolved directory cap.
///
/// Every hop (including the final) must resolve to a directory
/// (kind 1). Used to derive attenuated subtree / cwd caps for
/// `CONFIGURE_NAMESPACE`.
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
pub fn walk_to_dir(
    root_cap: u32,
    path: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let WalkResult { cap, kind, .. } = walk(root_cap, path, requested_rights, ipc_buf)?;
    if kind != 1
    {
        let _ = syscall::cap_delete(cap);
        return None;
    }
    Some(cap)
}

struct WalkResult
{
    cap: u32,
    kind: u64,
    size: u64,
}

/// Shared per-component walk used by [`walk_to_file`] and [`walk_to_dir`].
/// Returns the cap, kind, and size hint reported by the final hop.
/// Refuses empty paths (an empty walk would hand back the caller's
/// own input cap, which the helper does not own).
fn walk(root_cap: u32, path: &[u8], requested_rights: u64, ipc_buf: *mut u64)
-> Option<WalkResult>
{
    let mut current_cap = root_cap;
    let mut current_owns = false;
    let mut last_kind: u64 = 0;
    let mut size_hint: u64 = 0;
    let mut hop_count: usize = 0;

    let mut iter = PathComponents::new(path);
    while let Some(name) = iter.next_component()
    {
        if name.is_empty() || name.len() > 255
        {
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            return None;
        }
        // Reject `.`, `..`, `/`, NUL.
        if name == b"." || name == b".." || name.iter().any(|&b| b == b'/' || b == 0)
        {
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            return None;
        }

        let label = ns_labels::NS_LOOKUP | ((name.len() as u64) << 16);
        let msg = IpcMessage::builder(label)
            .word(0, requested_rights)
            .bytes(1, name)
            .build();

        // SAFETY: ipc_buf is the caller's registered IPC buffer page.
        let Ok(reply) = (unsafe { ipc::ipc_call(current_cap, &msg, ipc_buf) })
        else
        {
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            return None;
        };
        if reply.label != 0
        {
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            return None;
        }
        last_kind = reply.word(0);
        size_hint = reply.word(1);
        let Some(&next_cap) = reply.caps().first()
        else
        {
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            return None;
        };

        if current_owns
        {
            let _ = syscall::cap_delete(current_cap);
        }
        current_cap = next_cap;
        current_owns = true;
        hop_count += 1;
    }

    if hop_count == 0
    {
        // Empty path — `current_cap` is still the input `root_cap` and
        // not owned. Refuse rather than handing the caller someone
        // else's slot.
        return None;
    }

    Some(WalkResult {
        cap: current_cap,
        kind: last_kind,
        size: size_hint,
    })
}

/// Lazy iterator over path components (split on `/`, skipping empty segments).
struct PathComponents<'a>
{
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> PathComponents<'a>
{
    fn new(bytes: &'a [u8]) -> Self
    {
        Self { bytes, cursor: 0 }
    }

    fn next_component(&mut self) -> Option<&'a [u8]>
    {
        while self.cursor < self.bytes.len() && self.bytes[self.cursor] == b'/'
        {
            self.cursor += 1;
        }
        if self.cursor >= self.bytes.len()
        {
            return None;
        }
        let start = self.cursor;
        while self.cursor < self.bytes.len() && self.bytes[self.cursor] != b'/'
        {
            self.cursor += 1;
        }
        Some(&self.bytes[start..self.cursor])
    }
}
