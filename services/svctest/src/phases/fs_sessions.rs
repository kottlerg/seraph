// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_sessions.rs

//! Filesystem sessions that pay for their own pages
//! (services/fs/docs/fs-driver-protocol.md § Label 23: `FS_SESSION`, § Label 18:
//! `FS_OPEN`): fatfs keeps a session's records in pages charged to the node
//! whose charge-only handle the session's client passed.
//!
//! The phase is the client. Under a sub-node of its own it makes nodes for
//! its sessions and checks that a session's first page lands on its node;
//! that opens in the session take further pages there until the node's max
//! refuses one with `LIMIT`, while a session on a sibling node, and an open
//! in svctest's own session (the one std keeps), still open; that the extra
//! page returns when the opens close, and the first when the close of the
//! last open finds the session's liveness cap gone, before that close is
//! answered; that a session whose liveness cap is held outlives that close's
//! end of another; and that a session whose liveness cap is gone but which
//! keeps an open ends at the sweep its node's release signals to fatfs. A `fs-session-client` child ([`session_client_main`]) makes a
//! session on a node of its own and exits holding it, opens and a held page
//! included: its death returns the charge. It also checks the refusals: a
//! session with no handle or with a cap that is no node handle, a first page
//! past the max, an open with no session cap or with a cap that names no live
//! session, and a session cap used as a node or an open cap; that a session
//! starts on a mount's root cap as on any node cap of the driver; that std's
//! session lookup on an empty slot fails `StaleNetworkFileHandle`; and that std
//! opens a file across the `/data` mount in its session with the `/data`
//! driver, which the `/esp` driver does not take, nor the other way round.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, fs_errors, memmgr_errors, memmgr_labels};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_close, fs_open, fs_open_in, fs_read_bytes, fs_read_memory, fs_release_memory, fs_remove,
    fs_session, svctest_dir_cap,
};
use crate::ipc_util::ns::ns_lookup;
use crate::phases::budget;
use crate::phases::node_handle::{expect, handle_copy, handle_of, node_usage, release_refused};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "fs_sessions",
        run: fs_sessions_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == CLIENT_ROLE
    {
        session_client_main();
    }
}

/// argv[1] of the child that exits holding a session.
const CLIENT_ROLE: &str = "fs-session-client";
/// The scratch file the phase and its child open.
const NAME: &str = "sessions.bin";
/// The max of the node whose session the phase fills, in pages: the session's
/// first page and one more.
const SESSION_MAX: u64 = 2;
/// `max` word of a node with no max.
const NO_MAX: u64 = u64::MAX;
/// Most opens the phase makes in one session before it expects `LIMIT`, far
/// above what two pages of records hold. A test bound.
const OPEN_BOUND: usize = 4096;
/// How long the phase waits for a charge to leave a node once its session
/// ends. A test wait bound.
const SETTLE_WAIT: Duration = Duration::from_secs(60);
/// A file of the `/esp` driver, which is not the `/data` driver.
const ESP_PROBE: &str = "/esp/EFI/seraph/bootstrap.bundle";
/// Opens the child makes in its session.
const CLIENT_OPENS: usize = 3;

/// Exit code: the child could not look up the scratch file.
const CLIENT_NO_FILE: i32 = 2;
/// Exit code: the child's sub-node or its charge-only handle was refused.
const CLIENT_NO_NODE: i32 = 3;
/// Exit code: the child's `FS_SESSION` was refused.
const CLIENT_NO_SESSION: i32 = 4;
/// Exit code: an `FS_OPEN` in the child's session was refused.
const CLIENT_NO_OPEN: i32 = 5;
/// Exit code: the child's `FS_READ_MEMORY` was refused.
const CLIENT_NO_READ: i32 = 6;
/// Exit code: the child's sub-node carries no charge for its session.
const CLIENT_NOT_CHARGED: i32 = 7;

/// Sessions charged to their client's nodes end to end.
fn fs_sessions_phase(_: &Caps)
{
    let ipc_buf = current_ipc_buf();
    let (svctest, node) = scratch_file(ipc_buf);
    let top = sub_node(startup_info().memmgr_endpoint, NO_MAX, "CREATE_SUB_NODE");
    one_session_per_driver(node, ipc_buf);
    refusals(top, node, ipc_buf);
    session_on_mount_root(top, ipc_buf);
    charged_to_the_client(top, node, ipc_buf);
    client_death(top);
    assert_eq!(
        node_usage(top, "NODE_QUERY_USAGE of the phase's node").2,
        0,
        "a session's page is still charged to the phase's node"
    );
    release_refused(top, "the phase's sub-node");
    let _ = syscall::cap_delete(node);
    fs_remove(svctest, NAME.as_bytes(), ipc_buf).expect("fs_sessions: cleanup");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_sessions phase passed");
}

/// Write a one-page file at `/data/svctest/` [`NAME`] and return the
/// `/data/svctest` directory cap and the file's node cap.
fn scratch_file(ipc_buf: *mut u64) -> (u64, u64)
{
    std::fs::write(format!("/data/svctest/{NAME}"), vec![0x5Au8; 4096])
        .expect("fs_sessions: write the scratch file");
    let svctest = svctest_dir_cap(ipc_buf);
    let (node, _kind, _size) =
        ns_lookup(svctest, NAME.as_bytes(), 0xFFFF, ipc_buf).expect("fs_sessions: lookup");
    (svctest, node)
}

/// A sub-node with the max `max` under the node `target` names: svctest's
/// own over its memmgr endpoint (`CREATE_SUB_NODE`), or a node handle's
/// (`NODE_CREATE`). Its handle.
pub(super) fn sub_node(target: u64, max: u64, what: &str) -> u64
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
    handle_of(&reply, what)
}

/// A charge-only handle to the node of the handle `handle`.
pub(super) fn charge_handle(handle: u64, what: &str) -> u64
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

/// Whether the subtree of the node of `handle` reads `pages` within
/// [`SETTLE_WAIT`], each read after a recheck of memmgr's deferred list.
fn settles_to(handle: u64, pages: u64, what: &str) -> bool
{
    let start = Instant::now();
    while start.elapsed() < SETTLE_WAIT
    {
        crate::phases::memmgr::recheck_deferred();
        if node_usage(handle, what).2 == pages
        {
            return true;
        }
        std::thread::yield_now();
    }
    false
}

/// Whether `open` still names an open: an `FS_READ` on it reads.
fn open_reads(open: u64, ipc_buf: *mut u64) -> bool
{
    match fs_read_bytes(open, 0, 8, ipc_buf)
    {
        Ok(bytes) => bytes.len() == 8,
        Err(fs_errors::INVALID_BADGE) => false,
        Err(e) => panic!("fs_sessions: FS_READ on an open cap status {e}"),
    }
}

/// std's session with the driver of `node`, a node of `/data` reached across
/// its mount, opens `node`; its session with the `/esp` driver opens a node
/// there; and each driver refuses the other's session as a cap on another
/// endpoint (`INVALID_ARGUMENT`), so the walk's mount decides the session.
fn one_session_per_driver(node: u64, ipc_buf: *mut u64)
{
    let file = std::fs::File::open(format!("/data/svctest/{NAME}"))
        .expect("fs_sessions: std open across the /data mount");
    drop(file);
    let esp = std::os::seraph::root_dir_cap();
    let mut esp_node = esp;
    for name in ESP_PROBE.split('/').filter(|n| !n.is_empty())
    {
        let (next, _, _) = ns_lookup(esp_node, name.as_bytes(), 0xFFFF, ipc_buf)
            .unwrap_or_else(|e| panic!("fs_sessions: lookup {name} of {ESP_PROBE}: {e:#x}"));
        if esp_node != esp
        {
            let _ = syscall::cap_delete(esp_node);
        }
        esp_node = next;
    }
    let session_for = |cap: u64, what: &str| {
        std::os::seraph::fs::session_for(cap)
            .unwrap_or_else(|e| panic!("fs_sessions: std's session with {what}: {e}"))
    };
    let data_session = session_for(node, "the /data driver");
    let esp_session = session_for(esp_node, "the /esp driver");
    // A node cap that names nothing, with std's sessions live, is a stale
    // handle, as on a call that reaches no session lookup.
    let dead = syscall::cap_derive(node, syscall::RIGHTS_EP_SEND).expect("cap_derive");
    syscall::cap_delete(dead).expect("cap_delete of the derived node cap");
    assert_eq!(
        std::os::seraph::fs::session_for(dead)
            .err()
            .map(|e| e.kind()),
        Some(std::io::ErrorKind::StaleNetworkFileHandle),
        "std's session lookup on an empty slot, with sessions live"
    );
    for (target, session, what) in [
        (node, data_session, "/data"),
        (esp_node, esp_session, "/esp"),
    ]
    {
        let open = fs_open_in(target, session, 0, ipc_buf)
            .unwrap_or_else(|e| panic!("FS_OPEN of a {what} node in std's session: {e:#x}"));
        assert_eq!(fs_close(open, ipc_buf), fs_errors::SUCCESS);
        let _ = syscall::cap_delete(open);
    }
    assert_eq!(
        fs_open_in(node, esp_session, 0, ipc_buf).err(),
        Some(fs_errors::INVALID_ARGUMENT),
        "the /data driver took a session of the /esp driver"
    );
    assert_eq!(
        fs_open_in(esp_node, data_session, 0, ipc_buf).err(),
        Some(fs_errors::INVALID_ARGUMENT),
        "the /esp driver took a session of the /data driver"
    );
    for cap in [data_session, esp_session, esp_node]
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// `FS_OPEN` on `node` carrying `caps` (moved to fatfs, or deleted when the
/// call does not move them); the reply's label, every reply cap deleted.
fn open_carrying(node: u64, caps: &[u64], ipc_buf: *mut u64) -> u64
{
    let msg = caps
        .iter()
        .fold(IpcMessage::builder(ipc::fs_labels::FS_OPEN), |b, &cap| {
            b.cap(cap)
        })
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(node, &msg, ipc_buf) };
    for &cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
    let reply = reply.expect("FS_OPEN ipc_call");
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    reply.label
}

/// `FS_SESSION` with no cap, with a cap that is no node handle, and with a
/// handle whose node's max refuses the first page; `FS_OPEN` with no session
/// cap, with a cap on another endpoint, and with a cap on the driver's that
/// names no live session; a session cap used as a node or an open cap.
fn refusals(top: u64, node: u64, ipc_buf: *mut u64)
{
    assert_eq!(
        fs_session(node, 0, ipc_buf).err(),
        Some(fs_errors::INVALID_ARGUMENT),
        "FS_SESSION without a handle"
    );
    let not_a_handle = syscall::cap_derive(node, syscall::RIGHTS_EP_SEND).expect("cap_derive");
    assert_eq!(
        fs_session(node, not_a_handle, ipc_buf).err(),
        Some(fs_errors::INVALID_ARGUMENT),
        "FS_SESSION with a cap that is no node handle"
    );

    // A node with room for one page takes one session and refuses the next.
    let one = sub_node(top, 1, "NODE_CREATE of the one-page node");
    let (session, liveness) = fs_session(node, charge_handle(one, "NODE_CHARGE_HANDLE"), ipc_buf)
        .expect("FS_SESSION on a one-page node");
    assert_eq!(
        node_usage(one, "NODE_QUERY_USAGE of the one-page node").0,
        1,
        "the session's first page is not on its node"
    );
    assert_eq!(
        fs_session(node, charge_handle(one, "NODE_CHARGE_HANDLE"), ipc_buf).err(),
        Some(fs_errors::LIMIT),
        "FS_SESSION past its node's max"
    );

    // A session cap names a session and takes no request of its own; an
    // open cap is no session to open in.
    assert_eq!(
        open_carrying(session, &[], ipc_buf),
        fs_errors::INVALID_BADGE,
        "FS_OPEN sent on a session cap"
    );
    assert_eq!(
        fs_close(session, ipc_buf),
        fs_errors::INVALID_BADGE,
        "FS_CLOSE on a session cap"
    );
    assert_eq!(
        fs_session(session, 0, ipc_buf).err(),
        Some(fs_errors::INVALID_BADGE),
        "FS_SESSION sent on a session cap"
    );

    // Every open is made in a session: none, or a cap on another endpoint,
    // is no session; a node or open cap of the driver's names none.
    assert_eq!(
        open_carrying(node, &[], ipc_buf),
        fs_errors::INVALID_ARGUMENT,
        "FS_OPEN with no session cap"
    );
    let other = syscall::cap_derive(startup_info().memmgr_endpoint, syscall::RIGHTS_EP_SEND)
        .expect("cap_derive of the memmgr endpoint");
    assert_eq!(
        open_carrying(node, &[other], ipc_buf),
        fs_errors::INVALID_ARGUMENT,
        "FS_OPEN carrying a cap on another endpoint"
    );
    let node_copy = syscall::cap_derive(node, syscall::RIGHTS_EP_SEND).expect("cap_derive");
    assert_eq!(
        open_carrying(node, &[node_copy], ipc_buf),
        fs_errors::INVALID_BADGE,
        "FS_OPEN carrying a node cap as its session"
    );
    let open = fs_open_in(node, session, 0, ipc_buf).expect("FS_OPEN in the one-page session");
    assert_eq!(
        fs_open_in(node, open, 0, ipc_buf).err(),
        Some(fs_errors::INVALID_BADGE),
        "FS_OPEN carrying an open cap as its session"
    );
    assert_eq!(fs_close(open, ipc_buf), fs_errors::SUCCESS);
    let _ = syscall::cap_delete(open);

    end_session(&[], liveness, one, "the one-page node");
    // The session ends in the sweep fatfs makes when memmgr signals the
    // node's release; its page leaving the phase's subtree shows the sweep
    // ran, and fatfs serves the next request after it.
    assert!(
        settles_to(top, 0, "NODE_QUERY_USAGE of the phase's node"),
        "the one-page node's session ended but its page is still charged"
    );
    assert_eq!(
        fs_open_in(node, session, 0, ipc_buf).err(),
        Some(fs_errors::INVALID_BADGE),
        "FS_OPEN in an ended session"
    );
    let _ = syscall::cap_delete(session);
}

/// `FS_SESSION` on the `/data` mount's root cap, whose badge names the root
/// (`NodeId(0)`, which no node table entry holds), makes a session as on any
/// node cap of the driver; its page leaves the phase's node as it ends.
fn session_on_mount_root(top: u64, ipc_buf: *mut u64)
{
    let (root, _kind, _size) = ns_lookup(std::os::seraph::root_dir_cap(), b"data", 0xFFFF, ipc_buf)
        .unwrap_or_else(|e| panic!("fs_sessions: lookup of the /data mount: {e:#x}"));
    let before = node_usage(top, "NODE_QUERY_USAGE before the root cap's session").2;
    let node = sub_node(top, NO_MAX, "NODE_CREATE of the root cap session's node");
    let (session, liveness) = fs_session(root, charge_handle(node, "NODE_CHARGE_HANDLE"), ipc_buf)
        .unwrap_or_else(|e| {
            panic!("fs_sessions: FS_SESSION on the /data mount's root cap: {e:#x}")
        });
    end_session(&[], liveness, node, "the /data root cap's session");
    assert!(
        settles_to(top, before, "NODE_QUERY_USAGE after the root cap's session"),
        "the session on the /data mount's root cap kept its page charged"
    );
    for cap in [session, root]
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// End a session: delete its liveness cap `liveness`, then release `node`
/// (`what`, for the messages), the node its pages are charged to, which
/// signals fatfs. The charge leaves the phase's subtree as the session ends;
/// each open of `opens` names no open afterwards.
fn end_session(opens: &[u64], liveness: u64, node: u64, what: &str)
{
    syscall::cap_delete(liveness).expect("deleting a session's liveness cap");
    release_refused(node, what);
    let ipc_buf = current_ipc_buf();
    let start = Instant::now();
    while opens.iter().any(|&open| open_reads(open, ipc_buf))
    {
        assert!(
            start.elapsed() < SETTLE_WAIT,
            "the session of {what} outlived its liveness cap and its node"
        );
        std::thread::yield_now();
    }
}

/// Delete the liveness cap `liveness` of the session charged to node
/// `node`, then close `open`, its last open: the close ends the session
/// before the reply, so its first page is off the node at once. Release the
/// node.
fn close_ends_session(open: u64, liveness: u64, node: u64, ipc_buf: *mut u64)
{
    syscall::cap_delete(liveness).expect("deleting a session's liveness cap");
    assert_eq!(
        fs_close(open, ipc_buf),
        fs_errors::SUCCESS,
        "FS_CLOSE of a session's last open"
    );
    assert_eq!(
        node_usage(node, "NODE_QUERY_USAGE after a session's last close").0,
        0,
        "the close of the last open of a session with no liveness cap left its page charged"
    );
    release_refused(node, "a session's node");
}

/// A session charged to node A takes a page there for its first, and opens
/// in it take one more, until A's max refuses with `LIMIT`; a session on
/// node B and svctest's own session still open. The extra page returns when
/// the opens close, the first when the close of the last open finds the
/// session's liveness cap gone, while B's session, whose liveness cap the
/// phase keeps, outlives that end of A's, and then ends at the sweep its own
/// release signals, with its open still in it.
fn charged_to_the_client(top: u64, node: u64, ipc_buf: *mut u64)
{
    let a = sub_node(top, SESSION_MAX, "NODE_CREATE of node A");
    let b = sub_node(top, SESSION_MAX, "NODE_CREATE of node B");
    let (own, _, _) = crate::phases::memmgr::memory_usage();
    let (session_a, live_a) = fs_session(node, charge_handle(a, "NODE_CHARGE_HANDLE"), ipc_buf)
        .expect("FS_SESSION on node A");
    assert_eq!(
        node_usage(a, "NODE_QUERY_USAGE of node A"),
        (1, SESSION_MAX, 1),
        "the session's first page is not on node A"
    );
    assert_eq!(
        node_usage(b, "NODE_QUERY_USAGE of node B").0,
        0,
        "node A's session charged node B"
    );

    // Opens fill the first page, take node A's last, and then meet its max.
    let mut opens = Vec::new();
    let refused = loop
    {
        assert!(
            opens.len() < OPEN_BOUND,
            "{OPEN_BOUND} opens in a two-page session"
        );
        match fs_open_in(node, session_a, 0, ipc_buf)
        {
            Ok(open) => opens.push(open),
            Err(e) => break e,
        }
    };
    assert_eq!(refused, fs_errors::LIMIT, "an open past node A's max");
    assert!(opens.len() > 1, "a session page held no more than one open");
    assert_eq!(
        node_usage(a, "NODE_QUERY_USAGE of node A at its max").0,
        SESSION_MAX
    );
    assert_eq!(
        crate::phases::memmgr::memory_usage().0,
        own,
        "a session's pages were charged to svctest's own node"
    );

    // Another client's session, and svctest's own, are not held to node A.
    let (session_b, live_b) = fs_session(node, charge_handle(b, "NODE_CHARGE_HANDLE"), ipc_buf)
        .expect("FS_SESSION on node B while node A is at its max");
    let open_b = fs_open_in(node, session_b, 0, ipc_buf).expect("FS_OPEN in node B's session");
    assert_eq!(node_usage(b, "NODE_QUERY_USAGE of node B").0, 1);
    let own_open = fs_open(node, 0, ipc_buf).expect("an open in svctest's session at A's max");
    assert_eq!(fs_close(own_open, ipc_buf), fs_errors::SUCCESS);
    let _ = syscall::cap_delete(own_open);

    // A session open reads, and holds and releases a page.
    let Some((&first, rest)) = opens.split_first()
    else
    {
        panic!("a full session holds no open")
    };
    let (page, valid) = fs_read_memory(first, 0, 1, ipc_buf).expect("FS_READ_MEMORY in a session");
    assert!(
        page != 0 && valid > 0,
        "FS_READ_MEMORY in a session read nothing"
    );
    assert_eq!(fs_release_memory(first, 1, ipc_buf), fs_errors::SUCCESS);
    let _ = syscall::cap_delete(page);

    // Closing every open but the first returns the page the opens took.
    for &open in rest
    {
        assert_eq!(
            fs_close(open, ipc_buf),
            fs_errors::SUCCESS,
            "FS_CLOSE in a session"
        );
    }
    assert_eq!(
        node_usage(a, "NODE_QUERY_USAGE of node A after the closes"),
        (1, SESSION_MAX, 1),
        "the closes did not return the page the opens took"
    );
    for &open in rest
    {
        assert_eq!(
            fs_close(open, ipc_buf),
            fs_errors::INVALID_BADGE,
            "FS_CLOSE on a closed session open"
        );
        let _ = syscall::cap_delete(open);
    }

    // B's session, whose liveness cap is held, stays.
    close_ends_session(first, live_a, a, ipc_buf);
    assert_eq!(
        node_usage(top, "NODE_QUERY_USAGE of the phase's node").2,
        1,
        "node A's session ended but its page is still charged"
    );
    assert!(
        open_reads(open_b, ipc_buf),
        "the sweep ended a session whose liveness cap is held"
    );
    let _ = syscall::cap_delete(first);
    let _ = syscall::cap_delete(session_a);

    end_session(&[open_b], live_b, b, "node B");
    assert!(
        settles_to(top, 0, "NODE_QUERY_USAGE of the phase's node"),
        "node B's session ended but its page is still charged"
    );
    let _ = syscall::cap_delete(open_b);
    let _ = syscall::cap_delete(session_b);
}

/// A `fs-session-client` child, charged to a sub-node of `top`, makes a
/// session on a sub-node of its own, opens in it, holds a page, and exits:
/// its death signals fatfs, which ends the session, and every page returns.
fn client_death(top: u64)
{
    let what = "the fs-session-client child";
    let parent = sub_node(top, NO_MAX, "NODE_CREATE of the client's parent");
    let reply = budget::create_role(CLIENT_ROLE, 0, None, Some(handle_copy(parent)), what);
    let &[process, thread] = reply.caps()
    else
    {
        panic!(
            "CREATE_FROM_FILE of {what} replied {} caps",
            reply.caps().len()
        )
    };
    let reason = budget::run_to_exit(process, what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
    assert_eq!(
        reason, 0,
        "{what} exit reason {reason:#x}: {CLIENT_NO_FILE}=no scratch file, {CLIENT_NO_NODE}=no \
         node or handle, {CLIENT_NO_SESSION}=FS_SESSION refused, {CLIENT_NO_OPEN}=FS_OPEN \
         refused, {CLIENT_NO_READ}=FS_READ_MEMORY refused, {CLIENT_NOT_CHARGED}=the session \
         charged no page to its node, a fault reason=the child was killed"
    );
    assert!(
        settles_to(parent, 0, "NODE_QUERY_USAGE of the dead client's parent"),
        "the dead client's session pages are still charged"
    );
    release_refused(parent, "the client's parent");
}

// ── The fs-session-client child ──────────────────────────────────────────────

/// Child role: make a sub-node of this process's own node and a session
/// charged to it, open the scratch file [`CLIENT_OPENS`] times in it, read
/// and hold a page, check that the sub-node carries the session's charge,
/// and exit 0 holding all of it; else exit with the step's code.
fn session_client_main() -> !
{
    use std::process::exit;

    let ipc_buf = current_ipc_buf();
    let svctest = svctest_dir_cap(ipc_buf);
    let Ok((node, _, _)) = ns_lookup(svctest, NAME.as_bytes(), 0xFFFF, ipc_buf)
    else
    {
        exit(CLIENT_NO_FILE)
    };
    let created = |target: u64, label: u64, words: &[u64]| {
        let msg = IpcMessage::builder(label).words(0, words).build();
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        match unsafe { ipc::ipc_call(target, &msg, ipc_buf) }
        {
            Ok(reply) if reply.label == memmgr_errors::SUCCESS => match *reply.caps()
            {
                [cap] => Some(cap),
                _ => None,
            },
            _ => None,
        }
    };
    let Some(own) = created(
        startup_info().memmgr_endpoint,
        memmgr_labels::CREATE_SUB_NODE,
        &[NO_MAX],
    )
    else
    {
        exit(CLIENT_NO_NODE)
    };
    let Some(charge) = created(own, memmgr_labels::NODE_CHARGE_HANDLE, &[])
    else
    {
        exit(CLIENT_NO_NODE)
    };
    let Ok((session, _liveness)) = fs_session(node, charge, ipc_buf)
    else
    {
        exit(CLIENT_NO_SESSION)
    };
    let mut first = 0;
    for _ in 0..CLIENT_OPENS
    {
        match fs_open_in(node, session, 0, ipc_buf)
        {
            Ok(open) if first == 0 => first = open,
            Ok(_) =>
            {}
            Err(_) => exit(CLIENT_NO_OPEN),
        }
    }
    if fs_read_memory(first, 0, 1, ipc_buf).is_err()
    {
        exit(CLIENT_NO_READ);
    }
    let msg = IpcMessage::new(memmgr_labels::NODE_QUERY_USAGE);
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let charged = unsafe { ipc::ipc_call(own, &msg, ipc_buf) }
        .is_ok_and(|r| r.label == memmgr_errors::SUCCESS && r.word(0) >= 1);
    if !charged
    {
        exit(CLIENT_NOT_CHARGED);
    }
    exit(0);
}
