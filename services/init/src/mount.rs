// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/mount.rs

//! Init-side system-root acquisition.
//!
//! vfsd self-mounts the Seraph root partition at `/` (and the ESP at
//! `/esp`) on its own startup, identifying partitions by GPT type-GUID
//! (per-arch root via `boot_protocol::role_guids`, plus the standard
//! EFI System Partition type). Init issues no MOUNT request.
//!
//! Init pulls a seed system-root cap from vfsd via `GET_SYSTEM_ROOT_CAP`
//! (see [`request_system_root`]) and uses it both to walk binary paths
//! for Phase 3 spawns (`crate::walk`) and to seed each child's
//! `ProcessInfo.system_root_cap` via `procmgr_labels::CONFIGURE_NAMESPACE`.
//! vfsd serves this only once root is mounted, so the call doubles as
//! init's wait-for-root barrier.

use ipc::vfsd_labels;

// ── VFS IPC operations ──────────────────────────────────────────────────────

/// Request vfsd's system-root cap via [`vfsd_labels::GET_SYSTEM_ROOT_CAP`].
///
/// Returns the badged SEND cap on vfsd's namespace endpoint addressing
/// the synthetic root at full namespace rights, or `0` on failure. vfsd
/// replies an error (and this returns `0`) until it has mounted root, so
/// the call blocks until the root filesystem is available. Init holds
/// this cap as the seed from which all later tier-3 namespace-cap
/// distribution flows (`cap_copy` for the parent-inherit default,
/// walk-and-attenuate for sandboxed views).
pub fn request_system_root(vfsd_ep: u32, ipc_buf: *mut u64) -> u32
{
    let msg = ipc::IpcMessage::builder(vfsd_labels::GET_SYSTEM_ROOT_CAP)
        .word(0, u64::from(ipc::VFSD_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the caller's registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(vfsd_ep, &msg, ipc_buf) })
    else
    {
        return 0;
    };
    if reply.label != 0
    {
        return 0;
    }
    reply.caps().first().copied().unwrap_or(0)
}
