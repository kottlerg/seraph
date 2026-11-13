// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ns-client/src/lib.rs

//! No-std namespace walk helpers.
//!
//! Any service holding a badged SEND on a vfsd namespace endpoint (the
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
//! primitives. `requested_rights` is the rights word sent on every hop;
//! the server composes each hop's rights from the parent cap, the entry, and
//! the request (`shared/namespace-protocol/README.md` § `NS_LOOKUP`), so the
//! returned cap carries at most `requested_rights` on every bit. `0xFFFF`
//! requests everything the caller is allowed.

#![no_std]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

use ipc::{IpcMessage, ns_labels};

/// Result of [`walk_to_file`].
pub struct WalkedFile
{
    /// Badged SEND addressing the resolved file node. Caller owns and
    /// must `cap_delete` when no longer needed.
    pub file_cap: u64,
    /// Size hint reported by the resolving `NS_LOOKUP`.
    pub size: u64,
}

/// Walk `path` from `root_cap` requesting `requested_rights` per hop
/// and return the resolved file cap.
///
/// Each non-final hop must resolve to a directory; the final hop must
/// resolve to a file (kind 0).
///
/// - `root_cap`: badged SEND addressing the directory the walk starts from.
/// - `path`: `/`-separated components, resolved one `NS_LOOKUP` per component.
/// - `requested_rights`: the rights word sent on every hop (`0xFFFF` asks for
///   everything the server allows).
/// - `ipc_buf`: the calling thread's registered IPC buffer.
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer page
/// as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`, which each hop issues through it).
pub unsafe fn walk_to_file(
    root_cap: u64,
    path: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Option<WalkedFile>
{
    // SAFETY: the caller's contract makes `ipc_buf` the registered IPC page.
    let WalkResult { cap, kind, size } =
        unsafe { walk(root_cap, path, requested_rights, ipc_buf) }?;
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
/// - `root_cap`: badged SEND addressing the directory the walk starts from.
/// - `path`: `/`-separated components, resolved one `NS_LOOKUP` per component.
/// - `requested_rights`: the rights word sent on every hop (`0xFFFF` asks for
///   everything the server allows).
/// - `ipc_buf`: the calling thread's registered IPC buffer.
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer page
/// as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`, which each hop issues through it).
pub unsafe fn walk_to_dir(
    root_cap: u64,
    path: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    // SAFETY: the caller's contract makes `ipc_buf` the registered IPC page.
    let WalkResult { cap, kind, .. } = unsafe { walk(root_cap, path, requested_rights, ipc_buf) }?;
    if kind != 1
    {
        let _ = syscall::cap_delete(cap);
        return None;
    }
    Some(cap)
}

struct WalkResult
{
    cap: u64,
    kind: u64,
    size: u64,
}

/// Shared per-component walk used by [`walk_to_file`] and [`walk_to_dir`].
/// Returns the cap, kind, and size hint reported by the final hop.
/// Refuses empty paths (an empty walk would hand back the caller's
/// own input cap, which the helper does not own).
///
/// # Safety
/// The contract of [`walk_to_file`] for `ipc_buf`.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy, one set per \
              path component; on its caller's stack, 16 KiB at the smallest (init's)"
)]
unsafe fn walk(
    root_cap: u64,
    path: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Option<WalkResult>
{
    let mut current_cap = root_cap;
    let mut current_owns = false;
    let mut last_kind: u64 = 0;
    let mut size_hint: u64 = 0;
    // Counts hops only to detect an empty path; it cannot exceed the number
    // of components in `path`.
    let mut walked = false;

    // Components split on `/`, skipping empty segments.
    for name in path.split(|&b| b == b'/').filter(|c| !c.is_empty())
    {
        // 255 is `namespace_protocol::MAX_NAME_LEN`, the per-component limit
        // the server enforces; a longer name cannot resolve.
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

        // SAFETY: the caller's contract makes ipc_buf this thread's
        // registered IPC buffer page.
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
        walked = true;
    }

    if !walked
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
