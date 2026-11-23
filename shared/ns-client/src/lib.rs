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
//! Both helpers walk as std does in `runtime/ruststd/src/sys/fs/seraph.rs`,
//! through the same [`namespace_protocol::client::PathWalk`]: each
//! `NS_LOOKUP` carries as many of the remaining components as fit one
//! request, the server walks as many of them as it owns, and the walk
//! continues from the returned cap with the rest.
//! `requested_rights` is the rights word sent on every request; the
//! server composes each component's rights from its parent's, the entry,
//! and the request (`shared/namespace-protocol/README.md` § `NS_LOOKUP`), so
//! the returned cap carries at most `requested_rights` on every bit.
//! `0xFFFF` requests everything the caller is allowed.

#![no_std]

use ipc::IpcMessage;
use namespace_protocol::client::PathWalk;
use namespace_protocol::validate_name;

/// Result of [`walk_to_file`].
pub struct WalkedFile
{
    /// Badged SEND addressing the resolved file node. Caller owns and
    /// must `cap_delete` when no longer needed.
    pub file_cap: u64,
    /// Size hint reported by the resolving `NS_LOOKUP`.
    pub size: u64,
}

/// Walk `path` from `root_cap` requesting `requested_rights` at every
/// component and return the resolved file cap.
///
/// Each non-final component must resolve to a directory; the final one
/// must resolve to a file (kind 0).
///
/// - `root_cap`: badged SEND addressing the directory the walk starts from.
/// - `path`: `/`-separated components, resolved by as few `NS_LOOKUP`s as
///   the servers that own them allow.
/// - `requested_rights`: the rights word sent on every request (`0xFFFF` asks
///   for everything the server allows).
/// - `ipc_buf`: the calling thread's registered IPC buffer.
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer page
/// as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`, which each request is issued through).
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

/// Walk `path` from `root_cap` requesting `requested_rights` at every
/// component and return the resolved directory cap.
///
/// Every component (including the final) must resolve to a directory
/// (kind 1). Used to derive attenuated subtree / cwd caps for
/// `CONFIGURE_NAMESPACE`.
///
/// - `root_cap`: badged SEND addressing the directory the walk starts from.
/// - `path`: `/`-separated components, resolved by as few `NS_LOOKUP`s as
///   the servers that own them allow.
/// - `requested_rights`: the rights word sent on every request (`0xFFFF` asks
///   for everything the server allows).
/// - `ipc_buf`: the calling thread's registered IPC buffer.
///
/// Returns `None` on any failure. On error, any partially-derived cap
/// the helper owns is `cap_delete`d before returning.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer page
/// as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`, which each request is issued through).
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

/// Shared walk used by [`walk_to_file`] and [`walk_to_dir`]. Returns the
/// cap, kind, and size hint the final reply reports. Refuses an empty path
/// (an empty walk would hand back the caller's own input cap, which the
/// helper does not own) and a component that fails [`validate_name`],
/// before any request.
///
/// # Safety
/// The contract of [`walk_to_file`] for `ipc_buf`.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each), the builder's copy, and the \
              `LookupRequest` (520 B); on its caller's stack, 16 KiB at the smallest (init's)"
)]
unsafe fn walk(
    root_cap: u64,
    path: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Option<WalkResult>
{
    let mut walk = PathWalk::new(path);
    if walk.is_finished() || walk.components().any(|name| validate_name(name).is_err())
    {
        return None;
    }

    let mut current = WalkResult {
        cap: root_cap,
        kind: 0,
        size: 0,
    };
    // `current.cap` is the caller's `root_cap` until the first reply, and
    // a cap this walk owns from then on.
    let mut current_owns = false;
    while let Some(request) = walk.request()
    {
        let msg = IpcMessage::builder(request.label())
            .word(0, requested_rights)
            .bytes(1, request.path())
            .build();

        // SAFETY: the caller's contract makes ipc_buf this thread's
        // registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(current.cap, &msg, ipc_buf) }
            .ok()
            .filter(|reply| reply.label == 0);
        let next_cap = reply
            .as_ref()
            .and_then(|reply| reply.caps().first().copied());
        if current_owns
        {
            let _ = syscall::cap_delete(current.cap);
        }
        let (Some(reply), Some(next_cap)) = (reply, next_cap)
        else
        {
            return None;
        };
        current = WalkResult {
            cap: next_cap,
            kind: reply.word(0),
            size: reply.word(1),
        };
        current_owns = true;
        // A malformed consumed count, or a file with components after it.
        if walk.advance(&request, reply.word(2), current.kind).is_err()
        {
            let _ = syscall::cap_delete(current.cap);
            return None;
        }
    }

    // Every component passed `validate_name`, so each fits a request and
    // the loop ends only with the walk finished, after one reply at least.
    Some(current)
}
