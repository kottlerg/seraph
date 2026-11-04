// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/ipc_util/fs.rs

//! Raw `fs_labels::*` IPC helpers. Each wraps one wire transaction with
//! a typed signature so phase call sites read as intent.

// svctest is an integration test harness; helpers panic on protocol
// violation so faults surface in the log. Matches main.rs's allow.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::ipc_util::ns::ns_lookup;

/// Walk the per-test `/data/svctest` directory from the std-overlay
/// root-dir cap and return the dir cap.
pub fn svctest_dir_cap(ipc_buf: *mut u64) -> u64
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
pub fn fs_create(parent_cap: u64, name: &[u8], ipc_buf: *mut u64) -> Result<(u64, u64), u64>
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
pub fn fs_mkdir(parent_cap: u64, name: &[u8], ipc_buf: *mut u64) -> Result<(u64, u64), u64>
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
pub fn fs_remove(parent_cap: u64, name: &[u8], ipc_buf: *mut u64) -> Result<(), u64>
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
pub fn fs_rename(dir_cap: u64, src: &[u8], dst: &[u8], ipc_buf: *mut u64) -> Result<(), u64>
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
pub fn fs_write_inline(
    file_cap: u64,
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
    file_cap: u64,
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
    // cast_possible_truncation: both Seraph targets are 64-bit, so usize
    // holds every u64 byte count.
    #[allow(clippy::cast_possible_truncation)]
    let n = reply.word(0) as usize;
    Ok(reply.data_bytes()[8..8 + n].to_vec())
}

/// `FS_OPEN` on file node cap `node_cap`, carrying `release` (a release
/// endpoint SEND, moved to fatfs) in `caps[0]` when it is non-zero. Returns
/// the open cap, or the wire error code.
pub fn fs_open(node_cap: u64, release: u64, ipc_buf: *mut u64) -> Result<u64, u64>
{
    let mut builder = ipc::IpcMessage::builder(ipc::fs_labels::FS_OPEN);
    if release != 0
    {
        builder = builder.cap(release);
    }
    let msg = builder.build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(node_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    Ok(*reply
        .caps()
        .first()
        .expect("FS_OPEN success without an open cap"))
}

/// `FS_CLOSE` on `cap`; returns the reply label (`u64::MAX` when the call
/// fails).
pub fn fs_close(cap: u64, ipc_buf: *mut u64) -> u64
{
    let msg = ipc::IpcMessage::new(ipc::fs_labels::FS_CLOSE);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }.map_or(u64::MAX, |r| r.label)
}

/// `FS_READ_MEMORY` on open cap `open` at byte `offset` with `cookie`.
/// Returns `(page_cap, bytes_valid)` (`page_cap` 0 at end of file), or the
/// wire error code.
pub fn fs_read_memory(
    open: u64,
    offset: u64,
    cookie: u64,
    ipc_buf: *mut u64,
) -> Result<(u64, u64), u64>
{
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
        .word(0, offset)
        .word(1, cookie)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(open, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    Ok((reply.caps().first().copied().unwrap_or(0), reply.word(0)))
}

/// `FS_RELEASE_MEMORY` of `cookie` on open cap `open`; returns the reply
/// label (`u64::MAX` when the call fails).
pub fn fs_release_memory(open: u64, cookie: u64, ipc_buf: *mut u64) -> u64
{
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_RELEASE_MEMORY)
        .word(0, cookie)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(open, &msg, ipc_buf) }.map_or(u64::MAX, |r| r.label)
}
