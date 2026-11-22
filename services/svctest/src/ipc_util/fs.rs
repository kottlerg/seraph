// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/ipc_util/fs.rs

//! Raw `fs_labels::*` IPC helpers. Each wraps one wire transaction with
//! a typed signature so phase call sites read as intent.

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
    let mut combined = Vec::with_capacity(
        src.len()
            .checked_add(dst.len())
            .expect("fs rename: combined name length overflowed"),
    );
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
    #[expect(
        clippy::cast_possible_truncation,
        reason = "both Seraph targets are 64-bit, so usize holds every u64 byte count"
    )]
    let n = reply.word(0) as usize;
    // A reply shorter than its length word is a server defect, not an error
    // status: it panics rather than reach a caller that tolerates an `Err`.
    let data = n
        .checked_add(8)
        .and_then(|end| reply.data_bytes().get(8..end))
        .expect("fs read: reply shorter than its length word");
    Ok(data.to_vec())
}

/// `FS_OPEN` on file node cap `node_cap` in svctest's own session with the
/// node's driver, the one std keeps (`std::os::seraph::fs::session_for`,
/// runtime/ruststd/README.md § Filesystem sessions), carrying `release` (a
/// release endpoint SEND, moved to fatfs) in `caps[1]` when it is non-zero.
/// Returns the open cap, or the wire error code (`u64::MAX` when the session
/// cannot be had or the call fails).
pub fn fs_open(node_cap: u64, release: u64, ipc_buf: *mut u64) -> Result<u64, u64>
{
    let copy = std::os::seraph::fs::session_for(node_cap).map_err(|_| u64::MAX)?;
    send_open(node_cap, copy, release, ipc_buf)
}

/// Send `FS_OPEN` on `node_cap` carrying `session`, a session cap copy
/// moved to the driver, in `caps[0]` and `release` in `caps[1]` when it is
/// non-zero; the copy is deleted when the kernel did not move it.
fn send_open(node_cap: u64, session: u64, release: u64, ipc_buf: *mut u64) -> Result<u64, u64>
{
    let mut builder = ipc::IpcMessage::builder(ipc::fs_labels::FS_OPEN).cap(session);
    if release != 0
    {
        builder = builder.cap(release);
    }
    let msg = builder.build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(node_cap, &msg, ipc_buf) };
    // A copy the kernel did not move is still svctest's; a moved one's
    // handle is stale, and the delete is refused.
    let _ = syscall::cap_delete(session);
    let reply = reply.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    match *reply.caps()
    {
        [open] => Ok(open),
        _ => panic!("FS_OPEN success without exactly one open cap"),
    }
}

/// `FS_SESSION` on node cap `node_cap`, carrying `handle`, a charge-only
/// node handle (moved to fatfs), in `caps[0]`, or no cap when `handle` is 0.
/// Returns `(session cap, liveness cap)`, the reply's `caps[0]` and
/// `caps[1]` (services/fs/docs/fs-driver-protocol.md § Label 23), or the wire
/// error code.
pub fn fs_session(node_cap: u64, handle: u64, ipc_buf: *mut u64) -> Result<(u64, u64), u64>
{
    let mut builder = ipc::IpcMessage::builder(ipc::fs_labels::FS_SESSION);
    if handle != 0
    {
        builder = builder.cap(handle);
    }
    let msg = builder.build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(node_cap, &msg, ipc_buf) }.map_err(|_| u64::MAX)?;
    if reply.label != ipc::fs_errors::SUCCESS
    {
        return Err(reply.label);
    }
    match *reply.caps()
    {
        [session, liveness] => Ok((session, liveness)),
        _ => panic!("FS_SESSION success without a session cap and a liveness cap"),
    }
}

/// `FS_OPEN` on file node cap `node_cap` in the session `session` names: a
/// copy of the session cap in `caps[0]`, and `release` (a release endpoint
/// SEND, moved to fatfs) in `caps[1]` when it is non-zero. Returns the open
/// cap, the reply's one cap (services/fs/docs/fs-driver-protocol.md
/// § Label 18), or the wire error code.
pub fn fs_open_in(node_cap: u64, session: u64, release: u64, ipc_buf: *mut u64)
-> Result<u64, u64>
{
    let copy = syscall::cap_copy(
        session,
        std::os::seraph::startup_info().self_cspace,
        syscall::RIGHTS_EP_SEND,
    )
    .map_err(|_| u64::MAX)?;
    send_open(node_cap, copy, release, ipc_buf)
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
