// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/capexhaust/src/main.rs

//! CSpace-exhaustion fixture for the reserve-then-wedge regression test
//! (#365, #41).
//!
//! Creates a private endpoint, then derives SEND caps from it until the
//! `CSpace` refuses the next general allocation with `OutOfMemory`. The
//! kernel keeps the last `CSPACE_IPC_RECV_RESERVE` free slots for IPC
//! capability transfer, so the general slots run out first: the fixture
//! then spends that reserve on cap-bearing memmgr grants, which still land.
//! Once the reserve is gone, memmgr's further grants fail at the reply-side
//! pre-allocate, and the kernel's `MSG_CAP_SLOTS_MAX` pre-allocate fails every
//! `ipc_recv` before parking. The fixture then enters a
//! `RecvGuard`-protected blocking receive loop on the endpoint, exactly as
//! services do; the guard's streak escalates and the process exits with
//! `EXIT_RECV_WEDGE`.
//!
//! Termination of the derive loop is architectural: the `CSpace`'s slot-page
//! pool is the fixed slab procmgr seeded at spawn, this fixture never
//! augments it, and each successful derive consumes one slot — the loop ends
//! at pool exhaustion (`OutOfMemory`) with the reserve still free.
//!
//! With the reserve spent, the fixture also validates memmgr's failed-grant
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

/// Bounded retries of the rollback sample window; see the comment at the
/// use site.
const ROLLBACK_WINDOW_TRIES: u32 = 8;

/// Bound on the grants that may land in the IPC receive reserve: the reserve
/// holds `CSPACE_IPC_RECV_RESERVE` slots and every landed grant takes at
/// least one, so a grant still landing past this bound means general
/// allocations were not stopped at the reserve.
const RESERVE_GRANTS_MAX: u64 = syscall_abi::CSPACE_IPC_RECV_RESERVE;

/// One one-page `REQUEST_MEMORY_CAPS` call: `Some(caps carried)` for a landed
/// grant, `None` for a reply whose cap transfer failed. Exits the process on
/// any other outcome.
fn request_one_page(memmgr: u32, ipc_buf: *mut u64) -> Option<usize>
{
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED => None,
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS && !reply.caps().is_empty() =>
        {
            Some(reply.caps().len())
        }
        Ok(reply) =>
        {
            std::os::seraph::log!("REQUEST_MEMORY_CAPS unexpected reply label {}", reply.label);
            std::process::exit(1);
        }
        Err(e) =>
        {
            std::os::seraph::log!("REQUEST_MEMORY_CAPS call failed (err={e})");
            std::process::exit(1);
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

    // An Endpoint costs the kernel's raw retype debit, `ENDPOINT_RETYPE_BYTES`
    // (wrapper plus state), served from the 128 B `BIN_128` size class.
    let Some(ep) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
    else
    {
        std::os::seraph::log!("cap_create_endpoint failed");
        std::process::exit(1);
    };

    let mut derived: u32 = 0;
    let refusal = loop
    {
        match syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
        {
            Ok(_) => derived += 1,
            Err(e) => break e,
        }
    };
    assert_eq!(
        refusal,
        syscall_abi::SyscallError::OutOfMemory as i64,
        "the general allocation that meets the exhausted pool must fail with OutOfMemory"
    );

    // The IPC receive reserve is still free: cap-bearing grants land in it
    // until it is spent, and then fail. Nothing between the derive loop and
    // this one may allocate (a log line could grow the heap, whose grant
    // would land in the reserve first), so the counts are logged after.
    let mut landed: u64 = 0;
    while request_one_page(info.memmgr_endpoint, ipc_buf).is_some()
    {
        landed += 1;
        assert!(
            landed <= RESERVE_GRANTS_MAX,
            "more grants landed than the IPC receive reserve holds"
        );
    }
    std::os::seraph::log!("general slots exhausted after {derived} derives");
    assert!(landed > 0, "no grant landed in the IPC receive reserve");
    std::os::seraph::log!("{landed} grants landed in the IPC receive reserve; reserve spent");

    // A cap-bearing grant into the spent CSpace fails at the kernel's
    // reply-side pre-allocate: memmgr's ipc_reply errors and the caller is
    // woken with a synthetic IPC_REPLY_TRANSFER_FAILED reply. memmgr must
    // roll the grant back — pool free_bytes is identical before and after,
    // or the frames stay accounted to this process and the derived caps
    // stranded in memmgr.
    //
    // free_bytes is a system-global figure, so an unrelated process
    // allocating or dying inside the sample window (crasher shares this
    // boot) moves it without any rollback defect. The window is retried on
    // inequality: transient churn is bounded and a quiet window follows,
    // while a genuine rollback leak shifts every window and keeps failing.
    let mut verified = false;
    for attempt in 0..ROLLBACK_WINDOW_TRIES
    {
        let Some(free_before) = std::os::seraph::memmgr_pool_free_bytes()
        else
        {
            std::os::seraph::log!("QUERY_POOL_STATUS failed before grant attempts");
            std::process::exit(1);
        };
        for _ in 0..8
        {
            assert!(
                request_one_page(info.memmgr_endpoint, ipc_buf).is_none(),
                "cap-bearing grant into a CSpace with its reserve spent must fail"
            );
        }
        let Some(free_after) = std::os::seraph::memmgr_pool_free_bytes()
        else
        {
            std::os::seraph::log!("QUERY_POOL_STATUS failed after grant attempts");
            std::process::exit(1);
        };
        if free_before == free_after
        {
            verified = true;
            break;
        }
        std::os::seraph::log!(
            "pool churned during rollback window (attempt {attempt}: \
             {free_before} -> {free_after}); retrying"
        );
    }
    assert!(
        verified,
        "memmgr must roll back grants whose reply failed \
         (free_bytes never stabilised across {ROLLBACK_WINDOW_TRIES} windows)"
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
