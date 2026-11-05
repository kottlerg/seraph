// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/phys.rs

//! devmgr's physical-address credential: one Memory page from memmgr that
//! carries `RIGHTS_MEM_PHYS`, which devmgr presents to read the physical base
//! of a driver's frames (`syscall::cap_info_phys_base`).
//!
//! A driver's grants lack `RIGHTS_MEM_PHYS` and so do the caps it sends with
//! `DMA_MAP`. memmgr registers devmgr phys-class, so devmgr's own grants keep
//! the right, and the kernel answers the base of any Memory cap devmgr holds
//! when it presents one of them (core/kernel/docs/cross-boundary-disclosure.md
//! § Physical-address surfaces). The page is taken once, at first use, and
//! held for devmgr's life; nothing maps it.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::sync::OnceLock;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};

/// The credential page's cap, or `0` when memmgr refused it.
static CREDENTIAL: OnceLock<u64> = OnceLock::new();

/// The credential cap, taking it from memmgr on first use. `0` when memmgr
/// refused the page, which makes every read that needs it fail with
/// `InsufficientRights`.
pub fn credential() -> u64
{
    *CREDENTIAL.get_or_init(request_page)
}

/// One-page grant from memmgr, or `0`. A reply of any other shape is
/// deleted; its run stays charged to devmgr, which never exits.
fn request_page() -> u64
{
    let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
    let Ok(reply) =
        (unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &req, current_ipc_buf()) })
    else
    {
        std::os::seraph::log!("physical-address credential: memmgr call failed");
        return 0;
    };
    let caps = reply.caps();
    if reply.label == memmgr_errors::SUCCESS && caps.len() == 1
    {
        return caps[0];
    }
    for &c in caps
    {
        let _ = syscall::cap_delete(c);
    }
    std::os::seraph::log!("physical-address credential: memmgr refused the page");
    0
}
