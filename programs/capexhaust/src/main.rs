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
    std::os::seraph::log!("cspace exhausted after {derived} derives; entering recv loop");

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
