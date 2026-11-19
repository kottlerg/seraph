// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_debug_client.rs

//! A debug-authority holder's access to another process's memory when a page
//! of it is evicted (`procmgr_labels::MAKE_RESIDENT`), re-exported at the
//! crate root.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::SyscallError;

use crate::{IpcMessage, ipc_call, procmgr_errors, procmgr_labels};

/// Ask procmgr, through the debug-authority cap `authority`, to make the
/// range of `len` bytes at `va` of the process whose process badge (as
/// `procmgr_labels::LIST_PROCESSES` lists it) is `process` resident
/// (`procmgr_labels::MAKE_RESIDENT`): memmgr restores each chunk of the
/// range it evicted into its compressed store, so a `SYS_THREAD_READ_MEM` or
/// `SYS_THREAD_WRITE_MEM` that failed with `InvalidAddress` on such a page
/// succeeds when retried (`services/memmgr/docs/memory-pool.md` § Eviction,
/// Debugger reads). A page no fault has backed stays not present. Whether
/// procmgr replied `SUCCESS`: `false` when the call failed, or procmgr
/// refused (`OUT_OF_MEMORY` when memmgr could not restore a chunk of the
/// range).
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
pub unsafe fn make_resident(
    authority: u64,
    process: u64,
    va: u64,
    len: u64,
    ipc_buf: *mut u64,
) -> bool
{
    let request = IpcMessage::builder(procmgr_labels::MAKE_RESIDENT)
        .word(0, process)
        .word(1, va)
        .word(2, len)
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { ipc_call(authority, &request, ipc_buf) }
        .is_ok_and(|reply| reply.label == procmgr_errors::SUCCESS)
}

/// Read `buf.len()` bytes at `va` of the address space of `thread`, a thread
/// of the process `process` names, as `SYS_THREAD_READ_MEM` reads them
/// (`syscall::thread_read_mem`). That read fails with `InvalidAddress` on a
/// page that is not present, as a page of a chunk memmgr evicted is until its
/// next fault; on that failure this asks procmgr to make the range resident
/// ([`make_resident`], through `authority`) and, when procmgr did, reads once
/// more.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// The error of the last `SYS_THREAD_READ_MEM`: the first read's when it
/// failed with anything but `InvalidAddress`, or when procmgr did not make
/// the range resident; else the second read's.
pub unsafe fn read_mem_resident(
    authority: u64,
    process: u64,
    thread: u64,
    va: u64,
    buf: &mut [u8],
    ipc_buf: *mut u64,
) -> Result<(), i64>
{
    let Err(first) = syscall::thread_read_mem(thread, va, buf)
    else
    {
        return Ok(());
    };
    if first != SyscallError::InvalidAddress as i64
    {
        return Err(first);
    }
    let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    if !unsafe { make_resident(authority, process, va, len, ipc_buf) }
    {
        return Err(first);
    }
    syscall::thread_read_mem(thread, va, buf).map(|_| ())
}
