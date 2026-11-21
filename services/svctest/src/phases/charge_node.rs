// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/charge_node.rs

//! Grants charged to a donated node: a server charging its per-client state to
//! a node its client hands it (services/memmgr/docs/ipc-interface.md § Node
//! Handles, § Label 1 `REQUEST_CHARGE_NODE`, § Label 33, § Label 34).
//!
//! The phase stands in for both sides first. Under a sub-node of its own it
//! makes two sub-nodes, takes a charge-only handle to one, and checks that a
//! grant charged through it lands on that node and nowhere else, that the
//! node's max refuses with `LIMIT` while the sibling still takes its grant,
//! that the charge returns on release, that the handle serves only the
//! charge-only labels and is no charge node to procmgr, and that a node
//! released while a grant is charged to it keeps the charge, inside its
//! owner's subtree, until the holder releases it, the holder being signalled.
//! It then checks the two deaths with a child each: a `charge-holder`
//! ([`charge_holder_main`]) that takes a grant charged to the phase's node
//! and exits holding it, whose death returns the charge; and a child created
//! with `CREATE_NODE_HANDLE`, never started, whose own node the phase charges
//! a grant to, whose destroy signals the phase and leaves the charge on the
//! node until the phase releases it.

use std::os::seraph::startup_info;
use std::time::Duration;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};

use crate::bootstrap::Caps;
use crate::phases::budget;
use crate::phases::node_handle::{
    call, expect, handle_copy, handle_of, node_usage, notification, release_refused,
};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_charge_node",
        run: charge_node_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == HOLDER_ROLE
    {
        charge_holder_main();
    }
}

/// argv[1] of the child that holds a grant charged to the phase's node.
const HOLDER_ROLE: &str = "charge-holder";
/// argv[1] of the child whose own node the phase charges, which is never
/// started.
const OWNER_ROLE: &str = "charge-owner";
/// The max of each donated sub-node, in pages.
const DONATED_MAX: u64 = 16;
/// Pages of the grant the phase charges first.
const FIRST_PAGES: u32 = 4;
/// Pages of each other charged grant.
const GRANT_PAGES: u32 = 2;
/// The bits the phase registers for the donation-end event.
const DONATION_END_BIT: u64 = 1 << 6;
/// How long the phase waits for an event or for the holder's call. A test
/// wait bound.
const EVENT_WAIT: Duration = Duration::from_secs(60);
/// Polls for a charge to leave a node after its holder's or owner's death,
/// each after a recheck of memmgr's deferred list. A test wait bound.
const SETTLE_POLLS: u32 = 256;
/// The badge of the holder's creator endpoint.
const HOLDER_BADGE: u64 = 0xC4A5;
/// `max` word of a node with no max.
const NO_MAX: u64 = u64::MAX;

/// Exit code: the holder has no creator endpoint.
const HOLDER_NO_ENDPOINT: i32 = 2;
/// Exit code: the phase's reply carried no handle.
const HOLDER_NO_HANDLE: i32 = 3;
/// Exit code: the grant charged through the handle was refused.
const HOLDER_REFUSED: i32 = 4;
/// Exit code: the holder's second call to the phase failed.
const HOLDER_REPORT_FAILED: i32 = 5;

/// Grants charged to donated nodes end to end.
fn charge_node_phase(_: &Caps)
{
    let (sig, notify) = notification();
    register_donation_end(notify);
    let top = sub_node(startup_info().memmgr_endpoint, NO_MAX, "CREATE_SUB_NODE");
    charged_on_one_node(top, sig);
    released_keeps_the_charge(top, sig);
    holder_death(top);
    owner_death(top, sig);
    release_refused(top, "the phase's sub-node");
    let _ = syscall::cap_delete(sig);
    std::os::seraph::log!("memmgr_charge_node phase passed");
}

/// Register `notify` as svctest's donation-end Notification with
/// [`DONATION_END_BIT`], after checking that zero bits and a missing cap are
/// refused.
fn register_donation_end(notify: u64)
{
    let memmgr = startup_info().memmgr_endpoint;
    expect(
        memmgr,
        memmgr_labels::REGISTER_DONATION_END,
        &[DONATION_END_BIT],
        memmgr_errors::INVALID_ARGUMENT,
        "REGISTER_DONATION_END without a cap",
    );
    let spare = syscall::cap_derive(notify, syscall::RIGHTS_NTF_NOTIFY).expect("cap_derive");
    let reply = call(
        memmgr,
        &IpcMessage::builder(memmgr_labels::REGISTER_DONATION_END)
            .word(0, 0)
            .cap(spare)
            .build(),
        "REGISTER_DONATION_END with zero bits",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::INVALID_ARGUMENT,
        "REGISTER_DONATION_END with zero bits"
    );
    let reply = call(
        memmgr,
        &IpcMessage::builder(memmgr_labels::REGISTER_DONATION_END)
            .word(0, DONATION_END_BIT)
            .cap(notify)
            .build(),
        "REGISTER_DONATION_END",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "REGISTER_DONATION_END: memmgr replied {}",
        reply.label
    );
}

/// A sub-node with the max `max` under the node `target` names: svctest's
/// own over its memmgr endpoint (`CREATE_SUB_NODE`), or a node handle's
/// (`NODE_CREATE`). Its handle.
fn sub_node(target: u64, max: u64, what: &str) -> u64
{
    let label = if target == startup_info().memmgr_endpoint
    {
        memmgr_labels::CREATE_SUB_NODE
    }
    else
    {
        memmgr_labels::NODE_CREATE
    };
    let reply = expect(target, label, &[max], memmgr_errors::SUCCESS, what);
    assert_eq!(reply.word(0), max, "{what}: the sub-node took another max");
    handle_of(&reply, what)
}

/// A charge-only handle to the node of the handle `handle`.
fn charge_handle(handle: u64, what: &str) -> u64
{
    let reply = expect(
        handle,
        memmgr_labels::NODE_CHARGE_HANDLE,
        &[],
        memmgr_errors::SUCCESS,
        what,
    );
    handle_of(&reply, what)
}

/// Ask memmgr over the caller's own endpoint for a contiguous grant of
/// `pages` pages charged to the node of `handle` (`REQUEST_CHARGE_NODE`), a
/// copy of which the request moves: `Ok((grant cap, region id))`, or `Err`
/// with memmgr's label.
fn request_charged(handle: u64, pages: u32) -> Result<(u64, u64), u64>
{
    let flags = memmgr_labels::REQUIRE_CONTIGUOUS | memmgr_labels::REQUEST_CHARGE_NODE;
    let copy = syscall::cap_copy(handle, startup_info().self_cspace, syscall::RIGHTS_EP_SEND)
        .map_err(|_| memmgr_errors::QUOTA)?;
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, u64::from(pages) | (u64::from(flags) << 32))
        .cap(copy)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            &msg,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .map_err(|_| memmgr_errors::QUOTA)?;
    if reply.label != memmgr_errors::SUCCESS
    {
        return Err(reply.label);
    }
    match reply.caps()
    {
        // One cap: data[1] is its page count, data[2] its region id.
        &[grant] => Ok((grant, reply.word(2))),
        _ => Err(memmgr_errors::QUOTA),
    }
}

/// Wait up to [`EVENT_WAIT`] for [`DONATION_END_BIT`] on `sig`.
fn await_donation_end(sig: u64, what: &str)
{
    let ms = u64::try_from(EVENT_WAIT.as_millis()).unwrap_or(u64::MAX - 1);
    let bits = syscall::notification_wait_timeout(sig, ms)
        .unwrap_or_else(|e| panic!("{what}: no donation-end event in {EVENT_WAIT:?} ({e})"));
    assert_eq!(
        bits & DONATION_END_BIT,
        DONATION_END_BIT,
        "{what}: donation-end event bits {bits:#x}"
    );
}

/// Whether the subtree of the node of `handle` reads `pages` within
/// [`SETTLE_POLLS`] polls, each after a recheck of memmgr's deferred list,
/// on which a dead process's runs the kernel still held wait.
fn settles_to(handle: u64, pages: u64, what: &str) -> bool
{
    (0..SETTLE_POLLS).any(|_| {
        crate::phases::memmgr::recheck_deferred();
        if node_usage(handle, what).2 == pages
        {
            return true;
        }
        std::thread::yield_now();
        false
    })
}

/// svctest as client and server: a grant charged through a charge-only
/// handle to one sub-node of `top` lands there only; that node's max refuses
/// with `LIMIT` while its sibling still takes a grant; the charge returns on
/// release; the charge-only handle serves only its own labels and is refused
/// as a charge node by procmgr.
fn charged_on_one_node(top: u64, sig: u64)
{
    let a = sub_node(top, DONATED_MAX, "NODE_CREATE of node A");
    let b = sub_node(top, DONATED_MAX, "NODE_CREATE of node B");
    let charge = charge_handle(a, "NODE_CHARGE_HANDLE of node A");
    let (own, _, _) = crate::phases::memmgr::memory_usage();
    let (grant, id) = request_charged(charge, FIRST_PAGES)
        .unwrap_or_else(|l| panic!("a grant charged to node A refused ({l})"));
    let (own_after, _, _) = crate::phases::memmgr::memory_usage();
    let first = u64::from(FIRST_PAGES);
    assert_eq!(
        node_usage(charge, "NODE_QUERY_USAGE over the charge-only handle"),
        (first, DONATED_MAX, first),
        "the grant's charge is not on node A"
    );
    assert_eq!(
        own_after, own,
        "the charged grant was charged to svctest's own node"
    );
    assert_eq!(
        node_usage(b, "NODE_QUERY_USAGE of node B"),
        (0, DONATED_MAX, 0)
    );
    assert_eq!(
        node_usage(top, "NODE_QUERY_USAGE of the phase's node").2,
        first
    );

    // Node A's max refuses what it has not left; node B is not held to it.
    let over =
        u32::try_from(DONATED_MAX.saturating_sub(first).saturating_add(1)).unwrap_or(u32::MAX);
    assert_eq!(
        request_charged(charge, over).map(|_| ()),
        Err(memmgr_errors::LIMIT),
        "a grant past node A's max"
    );
    let (b_grant, b_id) = request_charged(b, over)
        .unwrap_or_else(|l| panic!("a grant charged to node B refused ({l})"));
    assert_eq!(
        node_usage(b, "NODE_QUERY_USAGE of node B").0,
        u64::from(over)
    );
    assert_eq!(node_usage(a, "NODE_QUERY_USAGE of node A").0, first);

    charge_only_refusals(charge);

    crate::phases::memmgr::release_grant(grant, id);
    crate::phases::memmgr::release_grant(b_grant, b_id);
    assert_eq!(
        node_usage(a, "NODE_QUERY_USAGE of node A after the release"),
        (0, DONATED_MAX, 0)
    );
    assert_eq!(node_usage(top, "NODE_QUERY_USAGE of the phase's node").2, 0);
    // No donation ended: the phase holds no grant on a node whose state went.
    assert!(
        syscall::notification_try_wait(sig).unwrap_or(0) & DONATION_END_BIT == 0,
        "a donation-end event with no state ended"
    );
    let _ = syscall::cap_delete(charge);
    release_refused(a, "node A");
    release_refused(b, "node B");
}

/// The charge-only handle `charge` is served `NODE_QUERY_USAGE` and
/// `NODE_CHARGE_HANDLE` and refused every other node label, and procmgr
/// takes it as no charge node.
fn charge_only_refusals(charge: u64)
{
    for (label, what) in [
        (memmgr_labels::NODE_SET_MAX, "NODE_SET_MAX"),
        (memmgr_labels::NODE_CREATE, "NODE_CREATE"),
        (memmgr_labels::NODE_REGISTER_LIMIT, "NODE_REGISTER_LIMIT"),
        (memmgr_labels::NODE_RELEASE, "NODE_RELEASE"),
        (memmgr_labels::NODE_SET_RECLAIM, "NODE_SET_RECLAIM"),
        (memmgr_labels::QUERY_MEMORY_USAGE, "QUERY_MEMORY_USAGE"),
    ]
    {
        expect(
            charge,
            label,
            &[NO_MAX],
            memmgr_errors::UNAUTHORIZED,
            &format!("{what} over a charge-only handle"),
        );
    }
    let again = charge_handle(charge, "NODE_CHARGE_HANDLE over a charge-only handle");
    let (grant, id) = request_charged(again, GRANT_PAGES)
        .unwrap_or_else(|l| panic!("a grant charged through a second charge-only handle ({l})"));
    crate::phases::memmgr::release_grant(grant, id);
    let _ = syscall::cap_delete(again);
    // memmgr refuses procmgr the child's registration under a charge-only
    // handle, which procmgr reports as `OUT_OF_MEMORY`.
    let reply = budget::try_create_role(
        OWNER_ROLE,
        0,
        None,
        Some(handle_copy(charge)),
        None,
        "a child charged to a charge-only handle",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::OUT_OF_MEMORY,
        "procmgr took a charge-only handle as the child's charge node"
    );
}

/// A node released while a grant is charged to it keeps the charge, inside
/// its owner's subtree, and the holder is signalled; the charge-only handle
/// is refused from then on, and the charge returns on the holder's release.
fn released_keeps_the_charge(top: u64, sig: u64)
{
    let node = sub_node(top, DONATED_MAX, "NODE_CREATE of the released node");
    let charge = charge_handle(node, "NODE_CHARGE_HANDLE of the released node");
    let (grant, id) = request_charged(charge, GRANT_PAGES)
        .unwrap_or_else(|l| panic!("a grant charged to the released node ({l})"));
    let pages = u64::from(GRANT_PAGES);
    let _ = syscall::notification_try_wait(sig);
    expect(
        node,
        memmgr_labels::NODE_RELEASE,
        &[],
        memmgr_errors::SUCCESS,
        "NODE_RELEASE of a node with a charged grant",
    );
    await_donation_end(sig, "NODE_RELEASE of a node with a charged grant");
    expect(
        charge,
        memmgr_labels::NODE_QUERY_USAGE,
        &[],
        memmgr_errors::INVALID_ARGUMENT,
        "NODE_QUERY_USAGE over the released node's charge-only handle",
    );
    assert_eq!(
        request_charged(charge, 1).map(|_| ()),
        Err(memmgr_errors::INVALID_ARGUMENT),
        "a grant charged to a released node"
    );
    assert_eq!(
        node_usage(
            top,
            "NODE_QUERY_USAGE of the phase's node after the release"
        )
        .2,
        pages,
        "the released node's charge left its owner's subtree"
    );
    crate::phases::memmgr::release_grant(grant, id);
    assert_eq!(node_usage(top, "NODE_QUERY_USAGE of the phase's node").2, 0);
    let _ = syscall::cap_delete(charge);
    let _ = syscall::cap_delete(node);
}

/// A `charge-holder` child takes a grant charged to a sub-node of `top`
/// through the charge-only handle the phase hands it, reports, and exits
/// holding it: the charge is on the node while the child lives and returns
/// with the child's death.
fn holder_death(top: u64)
{
    let what = "the charge-holder child";
    let node = sub_node(top, DONATED_MAX, "NODE_CREATE of the holder's node");
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("endpoint retype");
    let send = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND_GRANT, HOLDER_BADGE)
        .expect("cap_derive_badge");
    let reply = budget::try_create_role(HOLDER_ROLE, 0, None, None, Some(send), what);
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "CREATE_FROM_FILE of {what}"
    );
    let &[process, thread] = reply.caps()
    else
    {
        panic!(
            "CREATE_FROM_FILE of {what} replied {} caps",
            reply.caps().len()
        )
    };
    budget::start(process, what);
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let ms = u64::try_from(EVENT_WAIT.as_millis()).unwrap_or(u64::MAX - 1);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_recv_timeout(endpoint, ipc_buf, ms) }
        .unwrap_or_else(|e| panic!("{what} never asked for its handle ({e})"));
    let charge = charge_handle(node, "NODE_CHARGE_HANDLE for the holder");
    let handed = IpcMessage::builder(memmgr_errors::SUCCESS)
        .cap(charge)
        .build();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_reply(&handed, ipc_buf) }.expect("handing the holder its handle");
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_recv_timeout(endpoint, ipc_buf, ms) }
        .unwrap_or_else(|e| panic!("{what} never reported its grant ({e})"));
    assert_eq!(
        node_usage(node, "NODE_QUERY_USAGE of the holder's node"),
        (u64::from(GRANT_PAGES), DONATED_MAX, u64::from(GRANT_PAGES)),
        "the holder's grant is not charged to the phase's node"
    );
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_reply(&IpcMessage::new(memmgr_errors::SUCCESS), ipc_buf) }
        .expect("answering the holder's report");
    let reason = budget::finish(process, what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
    assert_eq!(
        reason, 0,
        "{what} exit reason {reason:#x}: {HOLDER_NO_ENDPOINT}=no creator endpoint, \
         {HOLDER_NO_HANDLE}=no handle in the reply, {HOLDER_REFUSED}=the charged grant refused, \
         {HOLDER_REPORT_FAILED}=the report failed, a fault reason=the child was killed"
    );
    assert!(
        settles_to(node, 0, "NODE_QUERY_USAGE of the dead holder's node"),
        "the dead holder's grant is still charged to the phase's node"
    );
    let _ = syscall::cap_delete(endpoint);
    release_refused(node, "the holder's node");
}

/// A child created with `CREATE_NODE_HANDLE` under a sub-node of `top`, never
/// started: the phase charges a grant to the child's own node through a
/// charge-only handle, destroys the child, and is signalled on `sig`; the
/// charge stays on the node, inside `top`'s subtree, until the phase
/// releases the grant.
fn owner_death(top: u64, sig: u64)
{
    let what = "the charge-owner child";
    let parent = sub_node(top, NO_MAX, "NODE_CREATE of the owner's parent");
    let reply = budget::create_role(
        OWNER_ROLE,
        procmgr_labels::CREATE_NODE_HANDLE,
        None,
        Some(handle_copy(parent)),
        what,
    );
    let &[process, thread, node] = reply.caps()
    else
    {
        panic!(
            "CREATE_FROM_FILE of {what} replied {} caps",
            reply.caps().len()
        )
    };
    let charge = charge_handle(node, "NODE_CHARGE_HANDLE of the owner's node");
    let (_, _, before) = node_usage(parent, "NODE_QUERY_USAGE of the owner's parent");
    let (grant, id) = request_charged(charge, GRANT_PAGES)
        .unwrap_or_else(|l| panic!("a grant charged to the owner's node ({l})"));
    let pages = u64::from(GRANT_PAGES);
    assert_eq!(
        node_usage(parent, "NODE_QUERY_USAGE of the owner's parent").2,
        before.saturating_add(pages)
    );
    let _ = syscall::notification_try_wait(sig);
    let destroyed = call(
        process,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        "DESTROY_PROCESS of the charge-owner child",
    );
    assert_eq!(
        destroyed.label,
        procmgr_errors::SUCCESS,
        "DESTROY_PROCESS of {what}"
    );
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
    await_donation_end(sig, "the death of the node's owner");
    expect(
        charge,
        memmgr_labels::NODE_QUERY_USAGE,
        &[],
        memmgr_errors::INVALID_ARGUMENT,
        "NODE_QUERY_USAGE over the dead owner's charge-only handle",
    );
    assert!(
        settles_to(parent, pages, "NODE_QUERY_USAGE of the dead owner's parent"),
        "the charge on the dead owner's node did not stay, alone, in its parent's subtree"
    );
    crate::phases::memmgr::release_grant(grant, id);
    assert_eq!(
        node_usage(parent, "NODE_QUERY_USAGE of the dead owner's parent").2,
        0,
        "the charge did not return on the release"
    );
    let _ = syscall::cap_delete(charge);
    let _ = syscall::cap_delete(node);
    release_refused(parent, "the owner's parent");
}

// ── The charge-holder child ──────────────────────────────────────────────────

/// Child role: ask the phase on the creator endpoint for a charge-only
/// handle, take a grant of [`GRANT_PAGES`] charged through it, report it to
/// the phase, and exit 0 holding the grant; else exit with the step's code.
fn charge_holder_main() -> !
{
    use std::process::exit;

    let creator = startup_info().creator_endpoint;
    if creator == 0
    {
        exit(HOLDER_NO_ENDPOINT);
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let handle = match unsafe { ipc::ipc_call(creator, &IpcMessage::new(1), ipc_buf) }
    {
        Ok(reply) => match reply.caps()
        {
            &[handle] => handle,
            _ => exit(HOLDER_NO_HANDLE),
        },
        Err(_) => exit(HOLDER_NO_HANDLE),
    };
    if request_charged(handle, GRANT_PAGES).is_err()
    {
        exit(HOLDER_REFUSED);
    }
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    if unsafe { ipc::ipc_call(creator, &IpcMessage::new(2), ipc_buf) }.is_err()
    {
        exit(HOLDER_REPORT_FAILED);
    }
    exit(0);
}
