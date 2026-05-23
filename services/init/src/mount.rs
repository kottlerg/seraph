// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/mount.rs

//! Init-side mount orchestration helpers.
//!
//! Boot protocol v8 dropped the kernel command line, removing the
//! `root=UUID=` parser that previously selected the rootfs partition.
//! vfsd now identifies partitions by GPT type-GUID (per-arch root via
//! `boot_protocol::role_guids`, plus the standard EFI System Partition
//! type for `/esp`), so init only names the *role* in the MOUNT request
//! and vfsd does the lookup. The historic `INGEST_CONFIG_MOUNTS` IPC
//! and `mounts.conf` ingest are likewise gone — additional partitions
//! are discovered and mounted by vfsd directly.
//!
//! After mounts complete init pulls a seed system-root cap from vfsd
//! via `GET_SYSTEM_ROOT_CAP` (see [`request_system_root`]) and uses it
//! both to walk binary paths for Phase 3 spawns (`crate::walk`) and to
//! seed each child's `ProcessInfo.system_root_cap` via
//! `procmgr_labels::CONFIGURE_NAMESPACE`.

use ipc::vfsd_labels;

// ── Mount roles ──────────────────────────────────────────────────────────────

/// Which partition-role vfsd should resolve and mount. The wire payload
/// is the discriminant byte; vfsd maps it to an arch-conditional GPT
/// type-GUID on its side.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountRole
{
    /// The Seraph root partition (`SERAPH_ROOT_X86_64` or
    /// `SERAPH_ROOT_RISCV64`, selected by the producer's compile-time
    /// `target_arch`).
    Root = 0,
}

// ── VFS IPC operations ──────────────────────────────────────────────────────

/// Outcome of a MOUNT request: success flag plus the optional
/// namespace-root cap minted by vfsd for this mount.
///
/// `root_cap` is a tokened SEND on the driver's namespace endpoint
/// representing the mount root at full namespace rights. The system-
/// root cap (delivered to every process via `ProcessInfo.system_root_cap`)
/// is the authoritative cap for VFS access; this per-mount cap is
/// retained only so the existing svctest direct-driver phase still
/// has a fatfs root to exercise.
pub struct MountOutcome
{
    pub success: bool,
    pub root_cap: u32,
}

/// Send a MOUNT IPC request to vfsd by role.
///
/// MOUNT data layout (post-boot-protocol-v8): `data[0]` low byte = role
/// discriminant, `data[1]` = `path_len`, `data[2..]` = path. Reply on
/// success carries `caps[0]` = mount-root node cap (zero if vfsd was
/// unable to mint one).
pub fn send_mount(vfsd_ep: u32, ipc_buf: *mut u64, role: MountRole, path: &[u8]) -> MountOutcome
{
    let path_bytes = path.len().min(8 * 8);
    let msg = ipc::IpcMessage::builder(vfsd_labels::MOUNT)
        .word(0, u64::from(role as u8))
        .word(1, path.len() as u64)
        .bytes(2, &path[..path_bytes])
        .build();

    // SAFETY: ipc_buf is the caller's registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(vfsd_ep, &msg, ipc_buf) })
    else
    {
        return MountOutcome {
            success: false,
            root_cap: 0,
        };
    };
    let success = reply.label == 0;
    let root_cap = if success
    {
        reply.caps().first().copied().unwrap_or(0)
    }
    else
    {
        0
    };
    MountOutcome { success, root_cap }
}

/// Request vfsd's system-root cap via [`vfsd_labels::GET_SYSTEM_ROOT_CAP`].
///
/// Returns the tokened SEND cap on vfsd's namespace endpoint addressing
/// the synthetic root at full namespace rights, or `0` on failure. Init
/// holds this cap as the seed from which all later tier-3 namespace-cap
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
