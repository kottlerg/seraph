// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/walk.rs

//! No-std namespace walk helper for init.
//!
//! Init holds a tokened SEND on vfsd's namespace endpoint (the seed
//! cap obtained from `vfsd_labels::GET_SYSTEM_ROOT_CAP`) and uses it to
//! resolve binary paths into per-file caps before issuing
//! `procmgr_labels::CREATE_FROM_FILE`. Mirrors the per-component
//! `NS_LOOKUP` walk std performs in `runtime/ruststd/src/sys/fs/seraph.rs`,
//! reduced to `no_std` primitives.

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

/// Walk `path` from `root_cap` via per-component `NS_LOOKUP`. Each
/// non-final hop must resolve to a directory; the final hop must
/// resolve to a file.
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
pub fn walk_to_file(root_cap: u32, path: &[u8], ipc_buf: *mut u64) -> Option<WalkedFile>
{
    let mut current_cap = root_cap;
    let mut current_owns = false;
    let mut size_hint: u64 = 0;

    let mut iter = PathComponents::new(path);
    let mut last_kind: u64 = 0;
    let mut hop_count: usize = 0;
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
            .word(0, 0xFFFF)
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

    // Final hop must address a file (kind 0 per namespace-protocol).
    if last_kind != 0
    {
        let _ = syscall::cap_delete(current_cap);
        return None;
    }

    Some(WalkedFile {
        file_cap: current_cap,
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
