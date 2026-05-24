// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Raw `fs_labels::*` IPC helpers. Each wraps one wire transaction with
//! a typed signature so phases can call sites read as intent.

// svctest is an integration test harness; helpers panic on protocol
// violation so faults surface in the log. Matches main.rs's allow.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::ipc_util::ns::ns_lookup;

/// Walk the per-test `/data/svctest` directory from the std-overlay
/// root-dir cap and return the dir cap.
pub fn svctest_dir_cap(ipc_buf: *mut u64) -> u32
{
    let root = std::os::seraph::root_dir_cap();
    let (data_cap, _kind, _) =
        ns_lookup(root, b"data", 0xFFFF, ipc_buf).expect("ns_lookup /data failed");
    let (cap, _kind, _) =
        ns_lookup(data_cap, b"svctest", 0xFFFF, ipc_buf).expect("ns_lookup /data/svctest failed");
    let _ = syscall::cap_delete(data_cap);
    cap
}

/// `FS_CREATE` returns `(node_cap, kind)` on success. Returns the wire
/// error code on failure.
pub fn fs_create(parent_cap: u32, name: &[u8], ipc_buf: *mut u64) -> Result<(u32, u64), u64>
{
    let label = ipc::fs_labels::FS_CREATE | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(parent_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    let cap = *reply.caps().first().ok_or(0u64)?;
    Ok((cap, reply.word(0)))
}

/// `FS_MKDIR`. Same shape as `FS_CREATE`.
pub fn fs_mkdir(parent_cap: u32, name: &[u8], ipc_buf: *mut u64) -> Result<(u32, u64), u64>
{
    let label = ipc::fs_labels::FS_MKDIR | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(parent_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    let cap = *reply.caps().first().ok_or(0u64)?;
    Ok((cap, reply.word(0)))
}

/// `FS_REMOVE`. Returns `Ok(())` on success.
pub fn fs_remove(parent_cap: u32, name: &[u8], ipc_buf: *mut u64) -> Result<(), u64>
{
    let label = ipc::fs_labels::FS_REMOVE | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(parent_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    Ok(())
}

/// `FS_RENAME` within a single directory. Returns `Ok(())` on success.
pub fn fs_rename(dir_cap: u32, src: &[u8], dst: &[u8], ipc_buf: *mut u64) -> Result<(), u64>
{
    let mut combined = Vec::with_capacity(src.len() + dst.len());
    combined.extend_from_slice(src);
    combined.extend_from_slice(dst);
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_RENAME)
        .word(0, src.len() as u64)
        .word(1, dst.len() as u64)
        .bytes(2, &combined)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    Ok(())
}

/// `FS_WRITE` inline: returns `bytes_written`.
#[allow(clippy::doc_markdown)]
pub fn fs_write_inline(
    file_cap: u32,
    offset: u64,
    payload: &[u8],
    ipc_buf: *mut u64,
) -> Result<u64, u64>
{
    let label = ipc::fs_labels::FS_WRITE | ((payload.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label)
        .word(0, offset)
        .bytes(1, payload)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    Ok(reply.word(0))
}

/// Round-trip `FS_READ`: returns the bytes the driver reports.
pub fn fs_read_bytes(
    file_cap: u32,
    offset: u64,
    max_len: u64,
    ipc_buf: *mut u64,
) -> Result<Vec<u8>, u64>
{
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, offset)
        .word(1, max_len)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    #[allow(clippy::cast_possible_truncation)]
    let n = reply.word(0) as usize;
    Ok(reply.data_bytes()[8..8 + n].to_vec())
}
