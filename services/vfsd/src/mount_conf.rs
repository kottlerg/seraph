// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/mount_conf.rs

//! `INGEST_CONFIG_MOUNTS` handler — reads `/config/mounts.conf` from
//! the freshly-mounted root filesystem via vfsd's own namespace chain
//! and issues each described MOUNT internally.
//!
//! The walk uses `root_mount_cap` (captured at the cmdline-driven
//! root MOUNT) as its starting cap: `NS_LOOKUP("config")` →
//! `NS_LOOKUP("mounts.conf")` → `FS_READ` against the resulting
//! file node cap.

use std::sync::PoisonError;

use ipc::{IpcMessage, fs_errors, fs_labels, ns_labels};
use namespace_protocol::NodeKind;

use crate::VfsdRuntime;

/// Per-call `FS_READ` byte budget. Sized generously; the driver caps
/// its inline reply at its own ceiling and the chunked-read loop in
/// `fs_read_all` iterates until the driver returns zero bytes, so the
/// config file as a whole has no upper-size limit.
const FS_READ_CHUNK: usize = 4096;

/// Outcome of `read_mounts_conf`.
///
/// `NoConfig` and `IngestError` are reported as different reply labels
/// on the wire: `NoConfig` is a legitimate system state (no extra
/// mounts requested), while `IngestError` signals that `mounts.conf`
/// exists but could not be read — operator-relevant.
enum MountsConfRead
{
    /// `/config` or `/config/mounts.conf` does not exist, or vfsd has
    /// no root mount installed yet. Reply: `SUCCESS`.
    NoConfig,
    /// File present and empty. Reply: `SUCCESS`.
    Empty,
    /// File read OK. Vec carries the full contents.
    Bytes(Vec<u8>),
    /// File present but unreadable (lookup error other than `NotFound`,
    /// `FS_READ` wire failure, etc.). Reply: `CONFIG_INGEST_ERROR`.
    IngestError,
}

enum LookupOutcome
{
    Found(u32),
    NotFound,
    Error,
}

/// Service-loop entry. Walks the system root for
/// `/config/mounts.conf`, reads it via a chunked `FS_READ` loop, and
/// processes every non-comment entry by issuing internal MOUNTs.
///
/// Reply policy:
/// - `SUCCESS`: file missing, empty, or every described mount landed.
/// - `PARTIAL_INGEST` with `data[0]` = failed-line count: file parsed
///   but one or more mount entries failed.
/// - `CONFIG_INGEST_ERROR`: lookup-other-than-`NotFound` or `FS_READ`
///   failure on the config itself.
pub fn handle_ingest_config_mounts(ipc_buf: *mut u64, rt: &VfsdRuntime)
{
    let reply = match read_mounts_conf(rt, ipc_buf)
    {
        MountsConfRead::Empty =>
        {
            std::os::seraph::log!("INGEST_CONFIG_MOUNTS: mounts.conf empty");
            IpcMessage::new(ipc::vfsd_errors::SUCCESS)
        }
        MountsConfRead::Bytes(data) =>
        {
            std::os::seraph::log!("INGEST_CONFIG_MOUNTS: parsing {} bytes", data.len());
            let failed = process_mounts_conf(rt, ipc_buf, &data);
            if failed > 0
            {
                std::os::seraph::log!("INGEST_CONFIG_MOUNTS: {failed} mount line(s) failed");
                IpcMessage::builder(ipc::vfsd_errors::PARTIAL_INGEST)
                    .word(0, failed as u64)
                    .build()
            }
            else
            {
                IpcMessage::new(ipc::vfsd_errors::SUCCESS)
            }
        }
        MountsConfRead::NoConfig =>
        {
            std::os::seraph::log!("INGEST_CONFIG_MOUNTS: no mounts.conf");
            IpcMessage::new(ipc::vfsd_errors::SUCCESS)
        }
        MountsConfRead::IngestError =>
        {
            std::os::seraph::log!("INGEST_CONFIG_MOUNTS: ingest error");
            IpcMessage::new(ipc::vfsd_errors::CONFIG_INGEST_ERROR)
        }
    };

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Walk `/config/mounts.conf` from the root mount and read it in
/// full via a chunked `FS_READ` loop. The outcome distinguishes
/// "config not present" from "config present but unreadable" so the
/// caller can pick the correct reply label.
fn read_mounts_conf(rt: &VfsdRuntime, ipc_buf: *mut u64) -> MountsConfRead
{
    let root_mount = {
        let backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        backend.root_mount_cap()
    };
    if root_mount == 0
    {
        std::os::seraph::log!("mount_conf: no root_mount_cap installed");
        return MountsConfRead::NoConfig;
    }

    let cfg_cap = match ns_lookup(root_mount, b"config", ipc_buf, NodeKind::Dir)
    {
        LookupOutcome::Found(c) => c,
        LookupOutcome::NotFound => return MountsConfRead::NoConfig,
        LookupOutcome::Error => return MountsConfRead::IngestError,
    };
    let file_outcome = ns_lookup(cfg_cap, b"mounts.conf", ipc_buf, NodeKind::File);
    let _ = syscall::cap_delete(cfg_cap);
    let file_cap = match file_outcome
    {
        LookupOutcome::Found(c) => c,
        LookupOutcome::NotFound => return MountsConfRead::NoConfig,
        LookupOutcome::Error => return MountsConfRead::IngestError,
    };

    let read_result = fs_read_all(file_cap, ipc_buf);
    let _ = syscall::cap_delete(file_cap);
    match read_result
    {
        Some(data) if data.is_empty() => MountsConfRead::Empty,
        Some(data) => MountsConfRead::Bytes(data),
        None => MountsConfRead::IngestError,
    }
}

/// Issue `NS_LOOKUP` for `name` against `dir_cap`. Returns `Found` on
/// a kind-match success, `NotFound` when the entry does not exist (an
/// expected system state), or `Error` for any other failure (wire
/// error, kind mismatch, permission denied, …).
fn ns_lookup(dir_cap: u32, name: &[u8], ipc_buf: *mut u64, expect: NodeKind) -> LookupOutcome
{
    // 0xFFFF on the rights word is the "everything I'm allowed"
    // sentinel; vfsd's source cap was minted with full namespace
    // rights so the intersection collapses to the entry's
    // max_rights ceiling.
    let label = ns_labels::NS_LOOKUP | ((name.len() as u64) << 16);
    let msg = IpcMessage::builder(label)
        .word(0, 0xFFFF)
        .bytes(1, name)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("mount_conf: NS_LOOKUP ipc_call failed");
        return LookupOutcome::Error;
    };
    if reply.label != 0
    {
        if reply.label == namespace_protocol::NsError::NotFound.as_label()
        {
            return LookupOutcome::NotFound;
        }
        std::os::seraph::log!("mount_conf: NS_LOOKUP error label={}", reply.label);
        return LookupOutcome::Error;
    }
    let kind = reply.word(0);
    if kind != expect as u64
    {
        std::os::seraph::log!("mount_conf: NS_LOOKUP wrong kind");
        if let Some(&cap) = reply.caps().first()
        {
            let _ = syscall::cap_delete(cap);
        }
        return LookupOutcome::Error;
    }
    match reply.caps().first().copied()
    {
        Some(cap) => LookupOutcome::Found(cap),
        None => LookupOutcome::Error,
    }
}

/// Read the entire file behind `file_cap` via a chunked `FS_READ`
/// loop. Returns the full contents, or `None` on wire failure /
/// non-`SUCCESS` reply. A zero-length file returns `Some(empty)`.
///
/// The driver caps each reply at its inline-payload ceiling; this
/// loop iterates until a reply returns zero bytes, so the file size
/// is unbounded from vfsd's side.
fn fs_read_all(file_cap: u32, ipc_buf: *mut u64) -> Option<Vec<u8>>
{
    let mut result: Vec<u8> = Vec::new();
    loop
    {
        let msg = IpcMessage::builder(fs_labels::FS_READ)
            .word(0, result.len() as u64)
            .word(1, FS_READ_CHUNK as u64)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(reply) = (unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) })
        else
        {
            std::os::seraph::log!(
                "mount_conf: FS_READ ipc_call failed at offset {}",
                result.len()
            );
            return None;
        };
        if reply.label != fs_errors::SUCCESS
        {
            std::os::seraph::log!(
                "mount_conf: FS_READ error label={} at offset {}",
                reply.label,
                result.len()
            );
            return None;
        }
        let bytes_read = reply.word(0) as usize;
        if bytes_read == 0
        {
            return Some(result);
        }
        let payload = reply
            .data_bytes()
            .get(core::mem::size_of::<u64>()..)
            .unwrap_or(&[]);
        let chunk = bytes_read.min(payload.len());
        if chunk == 0
        {
            return Some(result);
        }
        result.extend_from_slice(&payload[..chunk]);
        // A driver returning fewer payload bytes than `bytes_read`
        // would be a wire-protocol violation; treat it as EOF rather
        // than loop forever.
        if chunk < bytes_read
        {
            return Some(result);
        }
    }
}

/// Parse `mounts.conf` (`UUID=<uuid> <path> <fstype>` per non-comment
/// line) and call `do_mount` for each entry. Returns the count of
/// lines that looked like mount entries but failed to materialise
/// (invalid UUID, `do_mount` error). Unrecognised / non-mount lines
/// are logged and skipped without contributing to the count.
fn process_mounts_conf(rt: &VfsdRuntime, ipc_buf: *mut u64, data: &[u8]) -> usize
{
    let mut failed: usize = 0;
    let mut offset = 0;
    while offset < data.len()
    {
        let line_end = data[offset..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(data.len(), |p| offset + p);
        let line = &data[offset..line_end];
        offset = line_end + 1;

        if line.is_empty() || line[0] == b'#'
        {
            continue;
        }
        let mut end = line.len();
        while end > 0 && (line[end - 1] == b' ' || line[end - 1] == b'\r')
        {
            end -= 1;
        }
        let line = &line[..end];

        // `UUID=<36-char>` then space then path; fstype field is
        // ignored (FAT is the only driver today).
        if line.len() < 43 || &line[..5] != b"UUID="
        {
            std::os::seraph::log!("mount_conf: skipping unrecognised line");
            continue;
        }
        let uuid_str = &line[5..41];
        let mut uuid = [0u8; 16];
        if !parse_uuid_to_gpt_bytes(uuid_str, &mut uuid)
        {
            std::os::seraph::log!("mount_conf: invalid UUID");
            failed += 1;
            continue;
        }
        let rest = &line[42..];
        let mount_path = rest
            .iter()
            .position(|&b| b == b' ')
            .map_or(rest, |sp| &rest[..sp]);

        match crate::do_mount(rt, ipc_buf, &uuid, mount_path)
        {
            Ok(root_cap) =>
            {
                std::os::seraph::log!("mount_conf: mount ok");
                // The synthetic-root copy is already captured by
                // do_mount; the caller-side cap returned here has
                // no consumer in this internal path.
                if root_cap != 0
                {
                    let _ = syscall::cap_delete(root_cap);
                }
            }
            Err(label) =>
            {
                std::os::seraph::log!("mount_conf: mount failed label={label}");
                failed += 1;
            }
        }
    }
    failed
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
