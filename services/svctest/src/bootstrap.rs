// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Decode the creator-endpoint bootstrap round into a typed [`Caps`].
//!
//! Slot layout (set by whichever launcher minted the round):
//!   * `caps[0]`: tokened SEND on the **root-filesystem's** namespace
//!     endpoint at its root directory (zero when the launcher could
//!     not mint one). The driver behind this cap (fatfs today, any
//!     FS driver tomorrow) is opaque to svctest.
//!   * `caps[1]`: `SHUTDOWN_AUTHORITY`-tokened SEND on pwrmgr's
//!     service endpoint (zero when pwrmgr is absent)
//!   * `caps[2]`: SEND on pwrmgr's service endpoint without the
//!     `SHUTDOWN_AUTHORITY` token bit (zero when pwrmgr is absent)
//!
//! The launcher requests the round from `info.creator_endpoint`; if no
//! creator endpoint is present (`== 0`), every slot stays zero and
//! dependent phases self-skip.

use std::os::seraph::startup_info;

/// Bootstrap caps delivered to svctest by its launcher.
#[derive(Default)]
pub struct Caps
{
    /// Tokened SEND on the root filesystem's namespace endpoint at
    /// its root directory. FS driver behind it is opaque.
    pub root_fs: u32,
    pub pwrmgr_auth: u32,
    pub pwrmgr_noauth: u32,
}

/// Drain the bootstrap round from `creator_endpoint` and pull caps out.
pub fn request() -> Caps
{
    let mut caps = Caps::default();

    let info = startup_info();
    if info.creator_endpoint == 0
    {
        return caps;
    }

    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by
    // the boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) })
    else
    {
        return caps;
    };

    if round.cap_count >= 1
    {
        caps.root_fs = round.caps[0];
    }
    if round.cap_count >= 2
    {
        caps.pwrmgr_auth = round.caps[1];
    }
    if round.cap_count >= 3
    {
        caps.pwrmgr_noauth = round.caps[2];
    }

    caps
}
