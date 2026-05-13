// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/mount.rs

//! Init-side mount orchestration helpers.
//!
//! init parses the kernel cmdline for the root partition UUID and
//! issues exactly one MOUNT to vfsd (the cmdline-driven root mount).
//! Every additional mount described in `/config/mounts.conf` is
//! issued by vfsd itself via `INGEST_CONFIG_MOUNTS` once the root
//! mount lands. After mounts complete init pulls a seed system-root
//! cap from vfsd via `GET_SYSTEM_ROOT_CAP` (see [`request_system_root`])
//! and uses it both to walk binary paths for Phase 3 spawns
//! (`crate::walk`) and to seed each child's
//! `ProcessInfo.system_root_cap` via `procmgr_labels::CONFIGURE_NAMESPACE`.

use ipc::vfsd_labels;

// ── UUID parsing ─────────────────────────────────────────────────────────────

/// Parse `root=UUID=<uuid>` from kernel cmdline bytes.
///
/// UUID format: `12345678-abcd-ef01-2345-6789abcdef01` (36 chars).
/// Converts to 16-byte mixed-endian GPT format.
pub fn parse_root_uuid(cmdline: &[u8], out: &mut [u8; 16]) -> bool
{
    let prefix = b"root=UUID=";
    let mut start = None;
    for i in 0..cmdline.len().saturating_sub(prefix.len())
    {
        if &cmdline[i..i + prefix.len()] == prefix
        {
            start = Some(i + prefix.len());
            break;
        }
    }

    let Some(uuid_start) = start
    else
    {
        return false;
    };
    if uuid_start + 36 > cmdline.len()
    {
        return false;
    }

    let uuid_str = &cmdline[uuid_start..uuid_start + 36];
    parse_uuid_to_gpt_bytes(uuid_str, out)
}

/// Parse a 36-byte UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
/// into 16-byte mixed-endian GPT format. The first three groups are
/// little-endian on disk; the last two groups are stored as-is.
fn parse_uuid_to_gpt_bytes(s: &[u8], out: &mut [u8; 16]) -> bool
{
    let mut hex = [0u8; 32];
    let mut hi = 0;
    for &b in s
    {
        if b == b'-'
        {
            continue;
        }
        if hi >= 32
        {
            return false;
        }
        let nibble = match b
        {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return false,
        };
        hex[hi] = nibble;
        hi += 1;
    }
    if hi != 32
    {
        return false;
    }

    let mut raw = [0u8; 16];
    for i in 0..16
    {
        raw[i] = (hex[i * 2] << 4) | hex[i * 2 + 1];
    }

    out[0] = raw[3];
    out[1] = raw[2];
    out[2] = raw[1];
    out[3] = raw[0];
    out[4] = raw[5];
    out[5] = raw[4];
    out[6] = raw[7];
    out[7] = raw[6];
    out[8..16].copy_from_slice(&raw[8..16]);

    true
}

// ── VFS IPC operations ──────────────────────────────────────────────────────

/// Outcome of a MOUNT request: success flag plus the optional
/// namespace-root cap minted by vfsd for this mount.
///
/// `root_cap` is a tokened SEND on the driver's namespace endpoint
/// representing the mount root at full namespace rights. The system-
/// root cap (delivered to every process via `ProcessInfo.system_root_cap`)
/// is the authoritative cap for VFS access; this per-mount cap is
/// retained only so the existing usertest direct-driver phase still
/// has a fatfs root to exercise.
pub struct MountOutcome
{
    pub success: bool,
    pub root_cap: u32,
}

/// Send a MOUNT IPC request to vfsd.
///
/// MOUNT data layout: `data[0..2]` = UUID, `data[2]` = `path_len`,
/// `data[3..]` = path. Reply on success carries `caps[0]` = mount-root
/// node cap (zero if vfsd was unable to mint one).
pub fn send_mount(vfsd_ep: u32, ipc_buf: *mut u64, uuid: &[u8; 16], path: &[u8]) -> MountOutcome
{
    let w0 = u64::from_le_bytes(uuid[..8].try_into().unwrap_or([0; 8]));
    let w1 = u64::from_le_bytes(uuid[8..].try_into().unwrap_or([0; 8]));

    let path_bytes = path.len().min(8 * 8);
    let msg = ipc::IpcMessage::builder(vfsd_labels::MOUNT)
        .word(0, w0)
        .word(1, w1)
        .word(2, path.len() as u64)
        .bytes(3, &path[..path_bytes])
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

/// Outcome of [`ingest_config_mounts`].
///
/// `Partial(n)` carries the number of `mounts.conf` lines that looked
/// like mount entries but failed to materialise. Init treats this as
/// a degraded-boot warning rather than a fatal error — Phase 3
/// proceeds with the mounts that did land.
pub enum IngestOutcome
{
    Success,
    Partial(u64),
    Fail,
}

/// Trigger vfsd to read `/config/mounts.conf` from the freshly-
/// mounted root and issue every MOUNT it describes.
///
/// Synchronous: returns once vfsd has replied. A missing or empty
/// `mounts.conf` is `Success`. `Partial(n)` signals that the config
/// parsed but `n` mount entries failed (vfsd-side
/// `vfsd_errors::PARTIAL_INGEST` reply, count in `data[0]`). `Fail`
/// covers both wire failures and `CONFIG_INGEST_ERROR` /
/// `UNAUTHORIZED` replies.
pub fn ingest_config_mounts(vfsd_ep: u32, ipc_buf: *mut u64) -> IngestOutcome
{
    let msg = ipc::IpcMessage::new(vfsd_labels::INGEST_CONFIG_MOUNTS);
    // SAFETY: ipc_buf is the caller's registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(vfsd_ep, &msg, ipc_buf) })
    else
    {
        return IngestOutcome::Fail;
    };
    match reply.label
    {
        ipc::vfsd_errors::SUCCESS => IngestOutcome::Success,
        ipc::vfsd_errors::PARTIAL_INGEST => IngestOutcome::Partial(reply.word(0)),
        _ => IngestOutcome::Fail,
    }
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
    let msg = ipc::IpcMessage::new(vfsd_labels::GET_SYSTEM_ROOT_CAP);
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
