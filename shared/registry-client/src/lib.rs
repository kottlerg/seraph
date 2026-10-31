// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/registry-client/src/lib.rs

//! Client-side helper for the svcmgr name→cap discovery registry.
//!
//! Every process holds at most one cap on svcmgr's service endpoint —
//! the per-process `service_registry_cap` procmgr seeded into
//! [`process_abi::ProcessInfo`] at spawn. This crate caches that cap in
//! a process-global atomic so callers can issue `QUERY_ENDPOINT` without
//! threading it through every API surface (mirrors the
//! `shared/log` cap-install pattern).
//!
//! Concurrency: the install is single-writer (set once in `_start`
//! before any other thread is alive); `lookup` is reentrant and
//! concurrency-safe — the cached registry cap is loaded with
//! `Ordering::Acquire`, and the only mutation `lookup` performs is to
//! the IPC buffer the caller hands in. svcmgr derives a fresh SEND on
//! every lookup; callers cache the returned cap themselves if they wish
//! to avoid repeating the registry hit.

// In build-std mode (`rustc-dep-of-std`), cargo passes
// `--extern rustc_std_workspace_core=…` instead of providing `core` in
// the target sysroot. Switch the crate to `no_core` so the
// workspace-core stub's `pub extern crate core;` re-export is what
// resolves `use core::…`. Same incantation as `shared/log`,
// `shared/ipc`, etc.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(any(feature = "rustc-dep-of-std", test)), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

// Without `#![no_std]`, the prelude is implicit. With `no_core`, it is
// not — we must re-alias the workspace-core stub as `core` and pull
// the prelude in explicitly. Mirrors `shared/log`.
#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::{IpcMessage, svcmgr_errors, svcmgr_labels};

/// The svcmgr protocol's one name limit and its packing, shared with svcmgr,
/// its registry, and init's endowment: a name longer than [`NAME_MAX`] is
/// refused before any IPC.
pub use ipc::svcmgr_labels::{NAME_MAX, NAME_WORDS, pack_name};

/// Per-process cached SEND cap on svcmgr's service endpoint. Zero means
/// "no registry available" — `_start` did not install one, or the
/// process was spawned before svcmgr existed. `AtomicU32` because a cap
/// handle is `u32` in the syscall ABI.
static REGISTRY_CAP: AtomicU32 = AtomicU32::new(0);

/// Install the per-process registry cap. Called once by `_start` from
/// `ProcessInfo.service_registry_cap`. Idempotent; last writer wins.
pub fn install_registry_cap(cap: u32)
{
    REGISTRY_CAP.store(cap, Ordering::Release);
}

/// Return the installed registry cap, or zero if none.
pub fn registry_cap() -> u32
{
    REGISTRY_CAP.load(Ordering::Acquire)
}

/// Look up `name` in svcmgr's discovery registry. Returns `Some(cap)`
/// where the cap is a fresh SEND derived by svcmgr; `None` on any
/// failure (no registry cap installed, invalid name, IPC error,
/// name absent).
///
/// # Safety
/// `ipc_buf` must point at the registered IPC buffer page for this
/// thread.
#[must_use]
pub unsafe fn lookup(name: &[u8], ipc_buf: *mut u64) -> Option<u32>
{
    let registry = REGISTRY_CAP.load(Ordering::Acquire);
    if registry == 0 || name.is_empty()
    {
        return None;
    }
    // `pack_name` refuses a name longer than NAME_MAX.
    let mut words = [0u64; NAME_WORDS];
    let word_count = pack_name(name, &mut words)?;

    let mut builder =
        IpcMessage::builder(svcmgr_labels::QUERY_ENDPOINT | ((name.len() as u64) << 16));
    for (i, &w) in words.iter().take(word_count).enumerate()
    {
        builder = builder.word(i, w);
    }
    let request = builder.build();

    // SAFETY: ipc_buf is the caller-supplied registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry, &request, ipc_buf) }.ok()?;
    if reply.label != svcmgr_errors::SUCCESS
    {
        return None;
    }
    reply.caps().first().copied().filter(|&c| c != 0)
}
