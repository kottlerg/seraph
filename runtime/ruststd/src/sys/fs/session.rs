// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/fs/session.rs

//! This process's filesystem sessions, one per driver it opens files on
//! (runtime/ruststd/README.md § Filesystem sessions;
//! services/fs/docs/fs-driver-protocol.md § Label 23).
//!
//! A driver records each open in pages charged to a node of its client, and
//! makes an open only in a session, which names that node. [`session_copy`]
//! finds this process's session with the driver of a node cap, or starts one,
//! and returns a SEND-only copy of its session cap for the `FS_OPEN`'s
//! `caps[0]`. The driver mints the session cap with `RIGHTS_EP_IDENTIFY`, so
//! the table asks the kernel, with each session cap as the key, whether the
//! node cap names that driver's endpoint (`SYS_ENDPOINT_IDENTIFY`), and keeps
//! no other record of which driver a session serves; the copy it sends drops
//! the right. The decision is the `ruststd-fs-sessions` crate's [`lookup`].
//!
//! A session is charged to a sub-node of this process's node made for it
//! (`CREATE_SUB_NODE`) with no max of its own: this process's node and its
//! ancestors bound it, as they bound everything else the process spends.
//! The driver holds a charge-only handle to it; the table keeps the full
//! handle, the session cap, and the session's liveness cap, for the process's
//! life. A session whose key the kernel no longer answers for is ended when a
//! lookup finds it: its liveness cap is deleted, then its node released
//! (`NODE_RELEASE`) and its handle deleted, so the driver ends it at its next
//! sweep and the charge returns to this process's node. The process's death
//! ends every session the same way.
//!
//! An open stays in its session until its `FS_CLOSE` reaches the driver. A
//! `File` dropped when its thread cannot send the close (its call deadline
//! has passed, or it has no IPC buffer) leaves the open cap here
//! ([`keep_unclosed`]), and the next `File::open` or the exit hook sends the
//! close ([`close_unclosed`]), so a process that goes on opening files does
//! not accumulate opens it no longer reaches.

use ipc::{IpcMessage, fs_errors, fs_labels, memmgr_errors, memmgr_labels};
use syscall_abi::SyscallError;
use fs_sessions::{Found, lookup};

use crate::cell::Cell;
use crate::io;
use crate::os::seraph::checkpoint::{FILE, Held};
use crate::os::seraph::{deadline_call, memmgr_call, memmgr_call_until_answered};
use crate::sync::{Mutex, MutexGuard, PoisonError};
use crate::vec::Vec;

/// One session: its caps, all this process's.
struct Entry
{
    /// The session cap `FS_SESSION` returned, with `RIGHTS_EP_IDENTIFY`:
    /// the key a lookup asks the kernel with.
    session: u64,
    /// The session's liveness cap: the driver keeps the session while a copy
    /// lives outside it.
    liveness: u64,
    /// The full handle to the session's sub-node.
    node: u64,
    /// Set by a lookup that found the key dead; the entry is ended and
    /// removed before the lookup returns.
    dead: Cell<bool>,
}

/// The sessions, in the order they were started. Each names caps of this
/// process, so a restore forgets them ([`rebind_fs_sessions`]).
// restore: rebound
static SESSIONS: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

fn table() -> MutexGuard<'static, Vec<Entry>>
{
    SESSIONS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The open caps of the `File`s dropped before their `FS_CLOSE` could be
/// sent, each counted as an open file for a quiesce point until its close is
/// sent (docs/checkpoint-restore.md § Quiesce point).
// restore: rebound
static UNCLOSED: Mutex<Vec<(u64, Held<FILE>)>> = Mutex::new(Vec::new());

fn unclosed() -> MutexGuard<'static, Vec<(u64, Held<FILE>)>>
{
    UNCLOSED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keep `open_cap`, an open cap whose `FS_CLOSE` the dropping thread could
/// not send, for [`close_unclosed`] to close. When the list cannot grow, the
/// cap is deleted and the open left to its session, which ends with the
/// process.
pub(crate) fn keep_unclosed(open_cap: u64)
{
    let mut kept = unclosed();
    if kept.try_reserve(1).is_ok()
    {
        kept.push((open_cap, Held::new()));
        return;
    }
    drop(kept);
    let _ = syscall::cap_delete(open_cap);
}

/// Send `FS_CLOSE` on each open cap [`keep_unclosed`] kept, under the calling
/// thread's call deadline, and delete each cap whose call ended otherwise
/// than at the deadline: a close the driver answered, or one on an open or a
/// driver that is gone. A close the deadline stopped stays kept; a repeat of
/// one that did reach the driver is answered `INVALID_BADGE`, since an open
/// id never repeats (fs-driver-protocol.md § Label 18).
pub(crate) fn close_unclosed(ipc_buf: *mut u64)
{
    if ipc_buf.is_null()
    {
        return;
    }
    let mut pending = core::mem::take(&mut *unclosed());
    if pending.is_empty()
    {
        return;
    }
    let close = IpcMessage::new(fs_labels::FS_CLOSE);
    pending.retain(|&(cap, _)| {
        // SAFETY: the caller passes the registered IPC buffer page.
        let sent = unsafe { deadline_call(cap, &close, ipc_buf) };
        if sent.err() == Some(SyscallError::WouldBlock as i64)
        {
            return true;
        }
        let _ = syscall::cap_delete(cap);
        false
    });
    if pending.is_empty()
    {
        return;
    }
    let mut kept = unclosed();
    if kept.is_empty()
    {
        *kept = pending;
    }
    else if kept.try_reserve(pending.len()).is_ok()
    {
        kept.append(&mut pending);
    }
    else
    {
        drop(kept);
        for (cap, _) in pending
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// Forget the sessions in the process a restore created
/// (docs/checkpoint-restore.md § Restore entry and handle rebinding): their
/// caps name slots of the captured process, and their nodes' handle states
/// went with it. Nothing is deleted or released; the next open starts a new
/// session. The kept unclosed opens ([`UNCLOSED`]) are forgotten with them,
/// though a quiesce point leaves none, since each refuses it.
// restore: reset
pub(crate) fn rebind_fs_sessions()
{
    SESSIONS.lock().unwrap_or_else(PoisonError::into_inner).clear();
    UNCLOSED.lock().unwrap_or_else(PoisonError::into_inner).clear();
}

/// A SEND-only copy of this process's session cap with the driver of the node
/// cap `node_cap`, starting the session when there is none, for an
/// `FS_OPEN` on `node_cap` to carry in `caps[0]`. The caller owns the copy.
///
/// # Errors
/// `QuotaExceeded` when the max of this process's node, or of an ancestor's,
/// refuses the session's first page; `OutOfMemory` when memmgr cannot make
/// the sub-node; the error of a failed `FS_SESSION`, or of the kernel's
/// inquiry about `node_cap`, which is `StaleNetworkFileHandle` when
/// `node_cap`'s slot holds no capability, whichever of the two fails.
pub(crate) fn session_copy(node_cap: u64, ipc_buf: *mut u64) -> io::Result<u64>
{
    if let Some(copy) = find(&mut table(), node_cap, ipc_buf)?
    {
        return Ok(copy);
    }
    // Started with the table unlocked: the requests go to memmgr and to the
    // driver.
    let started = start(node_cap, ipc_buf)?;
    let mut sessions = table();
    match find(&mut sessions, node_cap, ipc_buf)
    {
        // Another thread started a session with this driver meanwhile: use
        // that one, and end this one.
        Ok(Some(copy)) =>
        {
            drop(sessions);
            end(&started, ipc_buf);
            Ok(copy)
        }
        Ok(None) =>
        {
            let copy = send_copy(started.session);
            if copy.is_ok() && sessions.try_reserve(1).is_ok()
            {
                sessions.push(started);
                return copy;
            }
            drop(sessions);
            if let Ok(copy) = copy
            {
                let _ = syscall::cap_delete(copy);
            }
            end(&started, ipc_buf);
            Err(io::const_error!(io::ErrorKind::OutOfMemory, "seraph fs: session table"))
        }
        Err(e) =>
        {
            drop(sessions);
            end(&started, ipc_buf);
            Err(e)
        }
    }
}

/// Look `node_cap`'s session up in `sessions`, ending and removing each
/// entry whose key is dead: a SEND-only copy of the session cap that serves
/// `node_cap`, or `None` when none does.
fn find(sessions: &mut Vec<Entry>, node_cap: u64, ipc_buf: *mut u64) -> io::Result<Option<u64>>
{
    let found = lookup(
        sessions.iter().map(|e| e.session),
        node_cap,
        syscall::endpoint_identify,
        |i| {
            if let Some(e) = sessions.get(i)
            {
                e.dead.set(true);
            }
        },
    );
    let result = match found
    {
        Found::Session(i) => sessions.get(i).map(|e| send_copy(e.session)).transpose(),
        Found::Missing => Ok(None),
        // As the `FS_SESSION` a lookup with no live key sends would fail: an
        // empty slot (a node an unmount revoked) is `StaleNetworkFileHandle`.
        Found::NodeError(_) => Err(super::call_failed(
            node_cap,
            "seraph fs: the node cap names no driver's endpoint",
        )),
    };
    sessions.retain(|e| {
        if e.dead.get()
        {
            end(e, ipc_buf);
        }
        !e.dead.get()
    });
    result
}

/// A SEND-only copy of `session`: no `RIGHTS_EP_IDENTIFY` leaves the table.
fn send_copy(session: u64) -> io::Result<u64>
{
    syscall::cap_copy(
        session,
        crate::os::seraph::startup_info().self_cspace,
        syscall::RIGHTS_EP_SEND,
    )
    .map_err(|_| io::const_error!(io::ErrorKind::OutOfMemory, "seraph fs: session cap copy"))
}

/// Start a session with the driver of `node_cap`: a sub-node of this
/// process's node with no max of its own (`CREATE_SUB_NODE`), a charge-only
/// handle to it (`NODE_CHARGE_HANDLE`) moved to the driver in `FS_SESSION`,
/// and the session cap and liveness cap the reply carries. On a failure the
/// sub-node is released and every cap deleted.
fn start(node_cap: u64, ipc_buf: *mut u64) -> io::Result<Entry>
{
    let memmgr = crate::os::seraph::startup_info().memmgr_endpoint;
    if memmgr == 0 || ipc_buf.is_null()
    {
        return Err(io::const_error!(
            io::ErrorKind::Unsupported,
            "seraph fs: no memmgr endpoint for a session"
        ));
    }
    let msg = IpcMessage::builder(memmgr_labels::CREATE_SUB_NODE)
        .word(0, u64::MAX)
        .build();
    // SAFETY: the caller passes the registered IPC buffer page.
    let reply = unsafe { memmgr_call(memmgr, &msg, ipc_buf) }
        .map_err(|_| io::const_error!(io::ErrorKind::Other, "seraph fs: CREATE_SUB_NODE failed"))?;
    let node = match (reply.label, reply.caps().first())
    {
        (memmgr_errors::SUCCESS, Some(&node)) => node,
        (memmgr_errors::QUOTA, _) =>
        {
            return Err(io::const_error!(
                io::ErrorKind::OutOfMemory,
                "seraph fs: memmgr cannot make a session's node"
            ));
        }
        _ => return Err(io::const_error!(io::ErrorKind::Other, "seraph fs: CREATE_SUB_NODE refused")),
    };
    let release = |liveness: u64| {
        end(
            &Entry {
                session: 0,
                liveness,
                node,
                dead: Cell::new(true),
            },
            ipc_buf,
        );
    };
    // SAFETY: as above.
    let charge = match unsafe {
        memmgr_call(node, &IpcMessage::new(memmgr_labels::NODE_CHARGE_HANDLE), ipc_buf)
    }
    {
        Ok(r) if r.label == memmgr_errors::SUCCESS && !r.caps().is_empty() => r.caps()[0],
        _ =>
        {
            release(0);
            return Err(io::const_error!(
                io::ErrorKind::Other,
                "seraph fs: NODE_CHARGE_HANDLE refused"
            ));
        }
    };
    let msg = IpcMessage::builder(fs_labels::FS_SESSION).cap(charge).build();
    // SAFETY: as above.
    let reply = unsafe { deadline_call(node_cap, &msg, ipc_buf) };
    // A handle the kernel did not move (a refused call) is still ours; a
    // moved one's slot is stale, and the delete is refused.
    let _ = syscall::cap_delete(charge);
    let reply = match reply
    {
        Ok(reply) => reply,
        Err(code) =>
        {
            release(0);
            return Err(super::call_error(node_cap, code, "seraph fs: FS_SESSION ipc_call failed"));
        }
    };
    match (reply.label, reply.caps())
    {
        (fs_errors::SUCCESS, &[session, liveness]) => Ok(Entry {
            session,
            liveness,
            node,
            dead: Cell::new(false),
        }),
        (label, caps) =>
        {
            for &cap in caps
            {
                let _ = syscall::cap_delete(cap);
            }
            release(0);
            Err(if label == fs_errors::SUCCESS
            {
                io::const_error!(
                    io::ErrorKind::Other,
                    "seraph fs: FS_SESSION reply carries no session cap and liveness cap"
                )
            }
            else
            {
                super::map_fs_error(label)
            })
        }
    }
}

/// End the session `entry` holds: delete its liveness cap, so the driver
/// ends it at its next sweep, and its session cap, then release its node
/// (`NODE_RELEASE`), which signals the driver, and delete the handle. Every
/// open made in the session is closed or dead by then: the table ends a
/// session only when its key is dead, or when it never served an open.
fn end(entry: &Entry, ipc_buf: *mut u64)
{
    for cap in [entry.liveness, entry.session]
    {
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
    }
    if !ipc_buf.is_null()
    {
        // SAFETY: the caller passes the registered IPC buffer page; a release
        // is safe to repeat (memmgr refuses a state it has dropped).
        let _ = unsafe {
            memmgr_call_until_answered(
                entry.node,
                &IpcMessage::new(memmgr_labels::NODE_RELEASE),
                ipc_buf,
            )
        };
    }
    let _ = syscall::cap_delete(entry.node);
}
