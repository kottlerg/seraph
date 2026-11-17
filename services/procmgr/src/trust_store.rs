// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/trust_store.rs

//! The trust store init hands procmgr in its bootstrap round: the store the
//! bootloader verified the boot against, which it exposes as the
//! `trust-store` boot module (docs/signing.md § Trust Store).

use crate::loader::map_module;
use syscall_abi::PAGE_SIZE;

/// Copy the store `len` bytes long that the Memory cap `cap` holds into
/// procmgr's own memory, delete the cap, and parse the copy once. Returns the
/// copy when it parses; `None`, logged, when it cannot be read or does not
/// parse, which stops procmgr: it creates no process without a store.
pub fn receive(self_aspace: u64, cap: u64, len: u64) -> Option<Vec<u8>>
{
    let copy = copy_out(self_aspace, cap, len);
    let _ = syscall::cap_delete(cap);
    let copy = copy?;
    match objsig::TrustStore::parse(&copy)
    {
        Ok(store) =>
        {
            std::os::seraph::log!(
                info: "trust store: {} anchors, security floor {}",
                store.anchors().count(),
                store.security_floor()
            );
            Some(copy)
        }
        Err(e) =>
        {
            std::os::seraph::log!(error: "trust store does not parse ({:?})", e);
            None
        }
    }
}

/// The `len` bytes at the start of the Memory cap `cap`, mapped read-only
/// for the copy and unmapped after; `None`, logged, when `len` is zero or
/// past the cap's pages, or the cap cannot be mapped.
fn copy_out(self_aspace: u64, cap: u64, len: u64) -> Option<Vec<u8>>
{
    let (scratch, pages) = map_module(cap, self_aspace)
        .inspect_err(|code| {
            std::os::seraph::log!(error: "trust store cap cannot be mapped (code {})", code);
        })
        .ok()?;
    if len == 0 || len > pages.saturating_mul(PAGE_SIZE)
    {
        std::os::seraph::log!(error: "trust store length {} is not within its cap", len);
        return None;
    }
    // SAFETY: `scratch` maps the cap's `pages` pages read-only at `va()`, and
    // `len` is within them; the slice is dropped before `scratch`.
    let bytes = unsafe {
        core::slice::from_raw_parts(scratch.va() as *const u8, usize::try_from(len).ok()?)
    };
    let mut copy = Vec::new();
    if copy.try_reserve_exact(bytes.len()).is_err()
    {
        std::os::seraph::log!(error: "no memory for the trust store's copy");
        return None;
    }
    copy.extend_from_slice(bytes);
    Some(copy)
}
