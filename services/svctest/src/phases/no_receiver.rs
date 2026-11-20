// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/no_receiver.rs

//! A call to a server that died before receiving it: once no capability with
//! the Receive right on an endpoint is left, the kernel releases a call
//! queued on it with `NoReceiver` and fails a later call at once
//! (docs/ipc-design.md § Endpoints), and the runtime maps the error to
//! `StaleNetworkFileHandle` on the file-system path
//! (`runtime/ruststd/src/sys/fs/seraph.rs`, `call_error`).
//!
//! The `no-receiver-child` role holds the endpoint's only Receive right and
//! never receives; svctest holds a Send right alone. svctest's walk of a path
//! from that endpoint queues an `NS_LOOKUP` call, and the child is killed
//! while the call waits: the call returns `StaleNetworkFileHandle`, and so
//! does the next walk, at once. No step waits on a time: the queued call is
//! seen through a wait set holding the endpoint, and the release follows the
//! child's teardown.

use std::io::ErrorKind;
use std::os::seraph::process::CommandExt;
use std::process::Command;

use ipc::IpcMessage;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "call_no_receiver",
        run: call_no_receiver_phase,
    }]
}

/// argv[1] of the child that holds the endpoint's only Receive right.
const ROLE: &str = "no-receiver-child";

/// Label of the child's call that asks svctest for the endpoint.
const HANDOFF: u64 = 0x1185;

/// The wait-set badge of the endpoint.
const EP_BADGE: u64 = 0xE9;

/// Exit code of a child whose handoff call failed or delivered no cap.
const HANDOFF_FAILED: i32 = 61;

/// Bound on each wait for an event that follows from the step before it
/// (the child's handoff call, the walk's queued call): a bound for a hang,
/// not a timing.
const STEP_BOUND_MS: u64 = 30_000;

/// The path the walks look up; nothing serves the endpoint, so no name is
/// ever resolved.
const PATH: &str = "no-receiver";

/// Child-mode dispatch for argv tokens this module owns. The matching arm
/// parks until the spawner kills it; on a miss control returns.
pub fn reentry_main(role: &str)
{
    if role == ROLE
    {
        child_main();
    }
}

/// Ask svctest for the endpoint through the root cap it installed as this
/// child's namespace (`HANDOFF`), keep the Receive-right capability the reply
/// moves here, and park without ever receiving on it.
fn child_main() -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let handoff = std::os::seraph::root_dir_cap();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(handoff, &IpcMessage::new(HANDOFF), ipc_buf) };
    if !matches!(reply, Ok(ref r) if r.caps().len() == 1)
    {
        std::process::exit(HANDOFF_FAILED);
    }
    loop
    {
        std::thread::park();
    }
}

fn new_endpoint() -> u64
{
    std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("call_no_receiver: endpoint creation failed")
}

/// A walk from an endpoint whose only Receive right is in a child that never
/// receives: queued until the child is killed, then released with
/// `StaleNetworkFileHandle`; the next walk fails with it at once.
pub fn call_no_receiver_phase(_: &Caps)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // The handoff endpoint the child calls, installed as its namespace root
    // (procmgr gives the child a Send copy).
    let handoff = new_endpoint();
    let handoff_send = syscall::cap_derive(handoff, syscall::RIGHTS_EP_SEND)
        .expect("call_no_receiver: deriving the handoff Send cap failed");
    // The endpoint under test, in a wait set before its Receive right leaves.
    let ep = new_endpoint();
    let ep_send = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
        .expect("call_no_receiver: deriving the Send cap failed");
    let ws =
        std::os::seraph::object_slab_retype(std::os::seraph::wait_set_retype_bytes(1), |slab| {
            syscall::wait_set_create(slab, 1).ok()
        })
        .expect("call_no_receiver: wait set creation failed");
    syscall::wait_set_add(ws, ep, EP_BADGE).expect("call_no_receiver: wait_set_add failed");

    let mut child = Command::new("/tests/svctest")
        .arg(ROLE)
        .namespace_cap(handoff_send)
        .spawn()
        .expect("call_no_receiver: spawn of the child failed");

    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let asked = unsafe { ipc::ipc_recv_timeout(handoff, ipc_buf, STEP_BOUND_MS) }
        .expect("call_no_receiver: the child's handoff call never came");
    assert_eq!(
        asked.label, HANDOFF,
        "call_no_receiver: unexpected call on the handoff endpoint"
    );
    let moved = IpcMessage::builder(0).cap(ep).build();
    // SAFETY: as above; the reply goes to the handoff call just received.
    unsafe { ipc::ipc_reply(&moved, ipc_buf) }.expect("call_no_receiver: handoff reply failed");
    // The reply moved `ep`: the child's copy is the endpoint's only Receive
    // right.
    assert!(
        syscall::cap_delete(ep).is_err(),
        "call_no_receiver: the Receive-right capability is still here after the handoff"
    );
    let _ = syscall::cap_delete(handoff);

    let walker =
        std::thread::spawn(move || std::os::seraph::namespace_lookup_file(ep_send, PATH).err());
    assert_eq!(
        syscall::wait_set_wait_timeout(ws, STEP_BOUND_MS),
        Ok(EP_BADGE),
        "call_no_receiver: the walk's call never queued on the endpoint"
    );
    assert!(
        !walker.is_finished(),
        "call_no_receiver: the walk returned while the child held the Receive right"
    );

    child
        .kill()
        .expect("call_no_receiver: killing the child failed");
    let status = child
        .wait()
        .expect("call_no_receiver: waiting for the child failed");
    assert_ne!(
        status.code(),
        Some(HANDOFF_FAILED),
        "call_no_receiver: the child's handoff failed"
    );

    let queued = walker
        .join()
        .expect("call_no_receiver: the walk thread panicked");
    assert_eq!(
        queued.as_ref().map(std::io::Error::kind),
        Some(ErrorKind::StaleNetworkFileHandle),
        "call_no_receiver: the queued call was not released with NoReceiver: {queued:?}"
    );
    let later = std::os::seraph::namespace_lookup_file(ep_send, PATH).err();
    assert_eq!(
        later.as_ref().map(std::io::Error::kind),
        Some(ErrorKind::StaleNetworkFileHandle),
        "call_no_receiver: a call after the last Receive right went did not fail with \
         NoReceiver: {later:?}"
    );

    let _ = syscall::cap_delete(ep_send);
    let _ = syscall::cap_delete(ws);
    std::os::seraph::log!("call_no_receiver: queued and later calls failed with NoReceiver");
}
