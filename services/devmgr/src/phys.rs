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
//! § Physical-address surfaces). The page is taken at the first read that needs
//! it and held for devmgr's life; nothing maps it. A refused request is not
//! remembered: the next read asks memmgr again.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::sync::atomic::{AtomicU64, Ordering};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};

/// The credential page's cap, or `0` before memmgr has granted one.
static CREDENTIAL: AtomicU64 = AtomicU64::new(0);

/// The credential cap, taking it from memmgr when none is held yet. `0` when
/// memmgr refuses the page this time, which fails the read that needs it
/// with `InsufficientRights`; a later call asks again. No lock is held across
/// the request: a caller that loses a race to publish its page deletes it.
pub fn credential() -> u64
{
    let held = CREDENTIAL.load(Ordering::Acquire);
    if held != 0
    {
        return held;
    }
    let page = request_page();
    if page == 0
    {
        return 0;
    }
    match CREDENTIAL.compare_exchange(0, page, Ordering::AcqRel, Ordering::Acquire)
    {
        Ok(_) => page,
        Err(winner) =>
        {
            let _ = syscall::cap_delete(page);
            winner
        }
    }
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
        std::os::seraph::log!(warn: "physical-address credential: memmgr call failed");
        return 0;
    };
    let caps = reply.caps();
    if reply.label == memmgr_errors::SUCCESS
        && let [cap] = caps
    {
        return *cap;
    }
    for &c in caps
    {
        let _ = syscall::cap_delete(c);
    }
    std::os::seraph::log!(warn: "physical-address credential: memmgr refused the page");
    0
}
