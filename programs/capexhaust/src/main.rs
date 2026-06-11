// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/capexhaust/src/main.rs

//! CSpace-exhaustion fixture for the recv-wedge regression test (#365).
//!
//! Creates a private endpoint, then derives SEND caps from it until the
//! `CSpace` refuses the next slot — at that point zero free slots remain and
//! the kernel's `MSG_CAP_SLOTS_MAX` pre-allocate fails every `ipc_recv`
//! before parking. The fixture then enters a `RecvGuard`-protected blocking
//! receive loop on the endpoint, exactly as services do; the guard's streak
//! escalates and the process exits with `EXIT_RECV_WEDGE`.
//!
//! Termination of the derive loop is architectural: a `CSpace` holds at most
//! 14336 slots, and each successful derive consumes one.
//!
//! While exhausted, the fixture also validates memmgr's failed-grant
//! rollback: a `REQUEST_MEMORY_CAPS` whose cap-bearing reply cannot land in
//! this `CSpace` must leave memmgr's pool `free_bytes` unchanged.
//!
//! Driven by `services/svctest`'s `recv_wedge` phase, which spawns this
//! binary, waits for exit, and asserts the exit code.

/// `RecvGuard` diagnostic hook. The `First` line doubles as evidence that
/// logging still works from a fully exhausted `CSpace` (`STREAM_BYTES`
/// messages and their replies carry no caps).
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn main()
{
    std::os::seraph::log::register_name(b"capexhaust");
    let info = std::os::seraph::startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // Endpoint kernel object costs 88 B of retype slab.
    let Some(slab) = std::os::seraph::object_slab_acquire(88)
    else
    {
        std::os::seraph::log!("no retype slab from memmgr");
        std::process::exit(1);
    };
    let Ok(ep) = syscall::cap_create_endpoint(slab)
    else
    {
        std::os::seraph::log!("cap_create_endpoint failed");
        std::process::exit(1);
    };

    let mut derived: u32 = 0;
    while syscall::cap_derive(ep, syscall::RIGHTS_SEND).is_ok()
    {
        derived += 1;
    }
    std::os::seraph::log!("cspace exhausted after {derived} derives");

    // A cap-bearing grant into the exhausted CSpace fails at the kernel's
    // reply-side pre-allocate: memmgr's ipc_reply errors and the caller is
    // woken with a synthetic IPC_REPLY_TRANSFER_FAILED reply. memmgr must
    // roll the grant back — pool free_bytes is identical before and after,
    // or the frames stay accounted to this process and the derived caps
    // stranded in memmgr.
    let Some(free_before) = std::os::seraph::memmgr_pool_free_bytes()
    else
    {
        std::os::seraph::log!("QUERY_POOL_STATUS failed before grant attempts");
        std::process::exit(1);
    };
    for _ in 0..8
    {
        let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, 1)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        if let Ok(reply) = unsafe { ipc::ipc_call(info.memmgr_endpoint, &msg, ipc_buf) }
        {
            assert_eq!(
                reply.label,
                syscall::IPC_REPLY_TRANSFER_FAILED,
                "cap-bearing grant into an exhausted CSpace must fail"
            );
        }
    }
    let Some(free_after) = std::os::seraph::memmgr_pool_free_bytes()
    else
    {
        std::os::seraph::log!("QUERY_POOL_STATUS failed after grant attempts");
        std::process::exit(1);
    };
    assert_eq!(
        free_before, free_after,
        "memmgr must roll back grants whose reply failed"
    );
    std::os::seraph::log!(
        "failed-grant rollback verified (free_bytes unchanged); entering recv loop"
    );

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        match unsafe { ipc::ipc_recv(ep, ipc_buf) }
        {
            Ok(_) => guard.on_success(),
            Err(e) => guard.on_failure(e),
        }
    }
}
