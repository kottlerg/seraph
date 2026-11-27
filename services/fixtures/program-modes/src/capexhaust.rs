// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/program-modes/src/capexhaust.rs

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
//! With the reserve spent, the fixture also validates memmgr's undo of a
//! request whose cap-bearing reply cannot land in this `CSpace`: a
//! `REQUEST_MEMORY_CAPS` and a `CREATE_SUB_NODE` that fail so must leave this
//! process's charge, memmgr's pool `free_bytes` and the used slots of
//! memmgr's own `CSpace` unchanged.
//!
//! Driven by `services/svctest`'s `recv_wedge` phase, which spawns this
//! mode, waits for exit, and asserts the exit code.

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

/// This process's own charge in pages (`QUERY_MEMORY_USAGE` `data[0]`).
/// Exits the process when the query fails.
fn own_pages(memmgr: u64, ipc_buf: *mut u64) -> u64
{
    let msg = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS => reply.word(0),
        _ =>
        {
            std::os::seraph::log!("QUERY_MEMORY_USAGE failed");
            std::process::exit(1);
        }
    }
}

/// memmgr's pool `free_bytes` and the used slots of its own `CSpace`
/// (`QUERY_POOL_STATUS` `data[3]` and `data[19]`). Exits the process when
/// the query fails.
fn pool_state(memmgr: u64, ipc_buf: *mut u64) -> (u64, u64)
{
    let msg = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_POOL_STATUS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS => (reply.word(3), reply.word(19)),
        _ =>
        {
            std::os::seraph::log!("QUERY_POOL_STATUS failed");
            std::process::exit(1);
        }
    }
}

/// One `CREATE_SUB_NODE` call with no max, into this `CSpace` with its
/// reserve spent: its reply carries the new node's handle, so it must fail
/// with `IPC_REPLY_TRANSFER_FAILED`. Exits the process on any other outcome.
fn sub_node_fails(memmgr: u64, ipc_buf: *mut u64)
{
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::CREATE_SUB_NODE)
        .word(0, u64::MAX)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED =>
        {}
        Ok(reply) =>
        {
            std::os::seraph::log!("CREATE_SUB_NODE unexpected reply label {}", reply.label);
            std::process::exit(1);
        }
        Err(e) =>
        {
            std::os::seraph::log!("CREATE_SUB_NODE call failed (err={e})");
            std::process::exit(1);
        }
    }
}

/// One one-page `REQUEST_MEMORY_CAPS` call: `Some(caps carried)` for a landed
/// grant, `None` for a reply whose cap transfer failed. Exits the process on
/// any other outcome.
fn request_one_page(memmgr: u64, ipc_buf: *mut u64) -> Option<usize>
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

pub fn main() -> !
{
    std::os::seraph::log::register_name(b"capexhaust");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // An Endpoint costs the kernel's raw retype debit for this boot
    // (`std::os::seraph::endpoint_retype_bytes`: wrapper, state and slot
    // hints), served from the 128 B `BIN_128` size class up to 224 CPUs.
    let Some(ep) = std::os::seraph::create_endpoint()
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
            Ok(_) => derived = derived.saturating_add(1),
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
        landed = landed.saturating_add(1);
        assert!(
            landed <= RESERVE_GRANTS_MAX,
            "more grants landed than the IPC receive reserve holds"
        );
    }
    std::os::seraph::log!("general slots exhausted after {derived} derives");
    assert!(landed > 0, "no grant landed in the IPC receive reserve");
    std::os::seraph::log!("{landed} grants landed in the IPC receive reserve; reserve spent");

    // A cap-bearing reply into the spent CSpace fails at the kernel's
    // reply-side pre-allocate, and the caller is woken with a synthetic
    // IPC_REPLY_TRANSFER_FAILED reply. memmgr must undo each such request: a
    // grant's frames go back to the pool, uncharged from this process, and
    // its derived caps are deleted; a sub-node's handle state is dropped and
    // its handle cap deleted. Otherwise this process's charge, the pool's
    // free_bytes or memmgr's used CSpace slots stay moved.
    //
    // free_bytes and memmgr's used slots are system-global, so an unrelated
    // process allocating or dying inside the sample window (crasher shares
    // this boot) moves them without any undo defect, and a first touch of a
    // stack page moves the charge. The window is retried while any of them
    // moves: transient churn is bounded and a quiet window follows, while a
    // missing undo moves them in every window and keeps failing.
    let memmgr = info.memmgr_endpoint;
    let mut verified = false;
    for attempt in 0..ROLLBACK_WINDOW_TRIES
    {
        let own_before = own_pages(memmgr, ipc_buf);
        let pool_before = pool_state(memmgr, ipc_buf);
        for _ in 0..8
        {
            assert!(
                request_one_page(memmgr, ipc_buf).is_none(),
                "cap-bearing grant into a CSpace with its reserve spent must fail"
            );
            sub_node_fails(memmgr, ipc_buf);
        }
        let pool_after = pool_state(memmgr, ipc_buf);
        let own_after = own_pages(memmgr, ipc_buf);
        if (own_before, pool_before) == (own_after, pool_after)
        {
            verified = true;
            break;
        }
        std::os::seraph::log!(
            "undo window moved, retrying: attempt={attempt} \
             charge={own_before}->{own_after} free_bytes={}->{} memmgr_slots={}->{}",
            pool_before.0,
            pool_after.0,
            pool_before.1,
            pool_after.1
        );
    }
    assert!(
        verified,
        "memmgr must undo requests whose reply failed (the charge, free_bytes \
         and its used slots never stabilised across {ROLLBACK_WINDOW_TRIES} windows)"
    );
    std::os::seraph::log!("failed-reply undo verified");

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
