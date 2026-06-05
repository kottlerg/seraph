// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/test-orphan/src/main.rs

//! Test-only fault-injection driver for devmgr's spawn-orphan unwind (#176).
//!
//! Spawned on demand by devmgr's `TEST_SPAWN_ORPHAN` shim. It completes
//! bootstrap round 1 normally, reserves a known block of memory, then
//! deliberately violates the round-2 protocol so devmgr's `serve_round`
//! rejects it and the spawn-orphan unwind runs. It then blocks forever —
//! it never `thread_exit`s — so procmgr's exit-reap cannot mask a missing
//! `DESTROY_PROCESS`: the reserved pages return to memmgr's free pool only
//! if devmgr's #176 teardown destroys this process.
//!
//! TODO(#165): remove with the devmgr enumeration redesign.

use ipc::IpcMessage;
use std::os::seraph::startup_info;

/// Bytes reserved and touched before the forced failure so the reclamation
/// delta clears boot-time allocator noise (1 MiB = 256 pages).
const RESERVE_BYTES: usize = 1 << 20;

/// A round-2 message whose low 16 label bits are not `bootstrap::REQUEST`
/// (`1`), so devmgr's `serve_round` rejects it with `INVALID` and unwinds.
const BAD_ROUND_LABEL: u64 = 0x7E57_0000;

fn main() -> !
{
    std::os::seraph::log::register_name(b"test-orphan");
    let info = startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let creator = info.creator_endpoint;
    if creator == 0
    {
        std::os::seraph::log!("test-orphan: no creator endpoint");
        syscall::thread_exit();
    }

    // Round 1: accept the [service, hw] caps normally. `service_ep` is the
    // endpoint we block on after forcing the failure.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let service_ep = match unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }
    {
        Ok(round) if round.cap_count >= 1 => round.caps[0],
        _ =>
        {
            std::os::seraph::log!("test-orphan: round 1 did not deliver a service endpoint");
            syscall::thread_exit();
        }
    };

    // Reserve and touch a known block so the process's footprint is large
    // enough to observe in memmgr's free total. `vec!` writes every byte,
    // faulting the pages in; `reserved` stays live across the block below.
    let reserved = std::vec![0xAB_u8; RESERVE_BYTES];
    // Defeat dead-store elimination with a volatile read of the first byte.
    // SAFETY: `reserved` owns RESERVE_BYTES bytes; offset 0 is in bounds.
    let probe = unsafe { core::ptr::read_volatile(reserved.as_ptr()) };
    std::os::seraph::log!(
        "test-orphan: reserved {} bytes (probe={:#x})",
        RESERVE_BYTES,
        u64::from(probe)
    );

    // Round 2: violate the protocol. devmgr's `serve_round` sees a
    // non-`REQUEST` label, replies `INVALID`, and returns `Err`, so the
    // spawn-orphan unwind runs. We ignore the reply.
    let bad = IpcMessage::new(BAD_ROUND_LABEL);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(creator, &bad, ipc_buf) };
    std::os::seraph::log!("test-orphan: forced round-2 failure; blocking until destroyed");

    // Block forever without exiting. Nothing sends on `service_ep`, so this
    // never returns; the process is reaped only when devmgr's #176 teardown
    // sends `DESTROY_PROCESS`. `reserved` is held live for the whole wait.
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_recv(service_ep, ipc_buf) };
    }
}
