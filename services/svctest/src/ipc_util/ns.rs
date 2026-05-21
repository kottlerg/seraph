// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Namespace-protocol IPC helpers (`NS_LOOKUP`, `NS_STAT`, `NS_READDIR`).

/// Issue `NS_LOOKUP` against `dir_cap` and return `(node_cap, kind, size)`.
pub fn ns_lookup(
    dir_cap: u32,
    name: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Result<(u32, u64, u64), u64>
{
    let label = ipc::ns_labels::NS_LOOKUP | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label)
        .word(0, requested_rights)
        .bytes(1, name)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }
        .map_err(|_| namespace_protocol::NsError::IoError.as_label())?;
    if reply.label != 0
    {
        return Err(reply.label);
    }
    let kind = reply.word(0);
    let size = reply.word(1);
    let cap = *reply.caps().first().ok_or(0u64)?;
    Ok((cap, kind, size))
}

/// Issue `NS_STAT` against `node_cap` and return `(size, mtime, kind)`.
pub fn ns_stat(node_cap: u32, ipc_buf: *mut u64) -> Result<(u64, u64, u64), u64>
{
    let msg = ipc::IpcMessage::new(ipc::ns_labels::NS_STAT);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(node_cap, &msg, ipc_buf) }
        .map_err(|_| namespace_protocol::NsError::IoError.as_label())?;
    if reply.label != 0
    {
        return Err(reply.label);
    }
    Ok((reply.word(0), reply.word(1), reply.word(2)))
}

/// Issue `NS_READDIR(idx)` against `dir_cap`. Returns `Ok(None)` on
/// `END_OF_DIR`, `Ok(Some((kind, name)))` for a populated entry, and
/// `Err(code)` on protocol error.
pub fn ns_readdir(dir_cap: u32, idx: u64, ipc_buf: *mut u64)
-> Result<Option<(u64, Vec<u8>)>, u64>
{
    let msg = ipc::IpcMessage::builder(ipc::ns_labels::NS_READDIR)
        .word(0, idx)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }
        .map_err(|_| namespace_protocol::NsError::IoError.as_label())?;
    if reply.label == ipc::fs_labels::END_OF_DIR
    {
        return Ok(None);
    }
    if reply.label != 0
    {
        return Err(reply.label);
    }
    let kind = reply.word(0);
    // Name length is bounded by namespace_protocol::MAX_NAME_LEN (255);
    // truncating to usize is safe on every supported target.
    #[allow(clippy::cast_possible_truncation)]
    let len = reply.word(1) as usize;
    let bytes = reply.data_bytes();
    // Name bytes start at byte 16 (after words 0 and 1).
    let start = 16usize;
    let end = start.saturating_add(len).min(bytes.len());
    Ok(Some((kind, bytes[start..end].to_vec())))
}
