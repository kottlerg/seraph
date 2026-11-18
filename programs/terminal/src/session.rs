// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/session.rs

//! The terminal as an interface of sessiond
//! (services/sessiond/docs/ipc-interface.md): it registers itself once per
//! sessiond instance, and opens each session through the `sessiond.operator`
//! SEND, handing over the leader's three pipes and the relay its end is
//! posted to.
//!
//! The terminal's end reaches sessiond through an end queue the terminal
//! registers on itself with procmgr once, and of which it hands sessiond a
//! receive right at each registration: sessiond then ends the terminal's
//! sessions whatever ends the terminal.

use std::os::seraph::process::SessionStdio;
use std::time::Duration;

use ipc::{IpcMessage, procmgr_errors, procmgr_labels, sessiond_labels as sl};

/// How long the terminal waits before it asks again after a refusal other
/// than memory pressure.
const RETRY: Duration = Duration::from_secs(1);

/// The longest the terminal waits for the pressure level to change before it
/// asks again, while sessiond refuses to open for critical memory.
const PRESSURE_WAIT: Duration = Duration::from_secs(1);

/// Entries the end queue holds: procmgr's one post of the terminal's end.
const END_QUEUE_CAPACITY: u32 = 1;

/// What became of a session that sessiond opened but did not start.
enum Unstarted
{
    /// sessiond replied: the session is ended, or was lost with the instance
    /// that opened it, and its relay is posted.
    Ended,
    /// A call failed, so the relay may never be posted.
    Lost,
}

/// The terminal's standing with sessiond.
pub(crate) struct Client
{
    /// The `sessiond.operator` SEND.
    operator: u64,
    /// The end queue registered with procmgr; 0 until it is.
    end_queue: u64,
    /// The nonce sessiond knows the terminal by; 0 while unregistered.
    nonce: u64,
    /// Whether the wait for memory pressure to change was logged.
    pressure_logged: bool,
}

impl Client
{
    pub(crate) fn new(operator: u64) -> Self
    {
        Self {
            operator,
            end_queue: 0,
            nonce: 0,
            pressure_logged: false,
        }
    }

    /// Open and start a session, asking again until sessiond does; its
    /// leader's streams and relay.
    pub(crate) fn open(&mut self) -> SessionStdio
    {
        loop
        {
            if let Some(stdio) = self.try_open()
            {
                self.pressure_logged = false;
                return stdio;
            }
        }
    }

    /// One attempt of [`Self::open`]: `None`, after the wait the refusal
    /// asks for, when no session started.
    fn try_open(&mut self) -> Option<SessionStdio>
    {
        if self.nonce == 0 && !self.register()
        {
            std::thread::sleep(RETRY);
            return None;
        }
        let mut stdio = match SessionStdio::new()
        {
            Ok(stdio) => stdio,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "terminal: session streams not made ({e})");
                std::thread::sleep(RETRY);
                return None;
            }
        };
        let Ok(relay) = stdio.relay()
        else
        {
            stdio.refused();
            std::thread::sleep(RETRY);
            return None;
        };
        let req = IpcMessage::builder(sl::OPEN_SESSION)
            .word(0, self.nonce)
            .cap(relay)
            .build();
        // No ring is handed over before the open succeeds, so after any
        // refusal no leader holds one.
        let Some(reply) = call(self.operator, &req)
        else
        {
            stdio.refused();
            std::os::seraph::log!(warn: "terminal: OPEN_SESSION call failed");
            std::thread::sleep(RETRY);
            return None;
        };
        match reply.label
        {
            sl::SUCCESS =>
            {}
            sl::UNKNOWN_INTERFACE =>
            {
                // A new sessiond instance: register with it.
                stdio.refused();
                self.nonce = 0;
                return None;
            }
            sl::MEMORY_CRITICAL =>
            {
                stdio.refused();
                if !self.pressure_logged
                {
                    self.pressure_logged = true;
                    std::os::seraph::log!(
                        "terminal: memory is critical; waiting to open a session"
                    );
                }
                // A process with no pressure registration cannot wait for a
                // change: it asks again after the plain retry wait.
                if let Err(e) = std::os::seraph::wait_memory_pressure(Some(PRESSURE_WAIT))
                    && e.kind() != std::io::ErrorKind::TimedOut
                {
                    std::thread::sleep(RETRY);
                }
                return None;
            }
            label =>
            {
                stdio.refused();
                std::os::seraph::log!(
                    warn: "terminal: OPEN_SESSION refused ({label}, code {})",
                    reply.word(0)
                );
                std::thread::sleep(RETRY);
                return None;
            }
        }
        match self.hand_over(&mut stdio, reply.word(0))
        {
            Ok(()) => Some(stdio),
            Err(unstarted) =>
            {
                if matches!(unstarted, Unstarted::Ended)
                {
                    // The relay is posted: read it on a thread of its own, so
                    // the rings return once no leader maps them.
                    let _ = std::thread::Builder::new()
                        .name(String::from("terminal-unstarted"))
                        .spawn(move || {
                            let _ = stdio.wait();
                        });
                }
                std::thread::sleep(RETRY);
                None
            }
        }
    }

    /// Hand sessiond the leader's three streams, then start the session `key`
    /// names.
    fn hand_over(&mut self, stdio: &mut SessionStdio, key: u64) -> Result<(), Unstarted>
    {
        for direction in [
            procmgr_labels::PIPE_DIR_STDIN,
            procmgr_labels::PIPE_DIR_STDOUT,
            procmgr_labels::PIPE_DIR_STDERR,
        ]
        {
            let Some([memory, data, space]) = stdio.handoff(direction)
            else
            {
                return Err(Unstarted::Lost);
            };
            let req = IpcMessage::builder(sl::SESSION_STDIO)
                .word(0, self.nonce)
                .word(1, key)
                .word(2, direction)
                .word(3, stdio.ring_capacity())
                .cap(memory)
                .cap(data)
                .cap(space)
                .build();
            self.expect_success(&req, "SESSION_STDIO")?;
        }
        let req = IpcMessage::builder(sl::START_SESSION)
            .word(0, self.nonce)
            .word(1, key)
            .build();
        self.expect_success(&req, "START_SESSION")
    }

    /// Call `req` (`what`, for the log) and map its reply: any refusal
    /// ends the session.
    fn expect_success(&mut self, req: &IpcMessage, what: &str) -> Result<(), Unstarted>
    {
        let Some(reply) = call(self.operator, req)
        else
        {
            std::os::seraph::log!(warn: "terminal: {what} call failed");
            return Err(Unstarted::Lost);
        };
        match reply.label
        {
            sl::SUCCESS => Ok(()),
            label =>
            {
                if label == sl::UNKNOWN_INTERFACE
                {
                    self.nonce = 0;
                }
                std::os::seraph::log!(
                    warn: "terminal: {what} refused ({label}, code {})",
                    reply.word(0)
                );
                Err(Unstarted::Ended)
            }
        }
    }

    /// Register with sessiond under a fresh nonce, first registering the end
    /// queue with procmgr if it is not yet; `false`, logged, on a failure.
    fn register(&mut self) -> bool
    {
        if self.end_queue == 0
        {
            self.end_queue = register_end_queue().unwrap_or(0);
            if self.end_queue == 0
            {
                std::os::seraph::log!(warn: "terminal: end queue not registered");
                return false;
            }
        }
        let nonce = match syscall::random_u64()
        {
            Ok(nonce) if nonce != 0 => nonce,
            _ => return false,
        };
        let Ok(recv) = syscall::cap_derive(self.end_queue, syscall::RIGHTS_EQ_RECV)
        else
        {
            return false;
        };
        let req = IpcMessage::builder(sl::REGISTER_INTERFACE)
            .word(0, nonce)
            .word(1, u64::from(ipc::SESSIOND_LABELS_VERSION))
            .cap(recv)
            .build();
        match call(self.operator, &req).map(|r| r.label)
        {
            Some(sl::SUCCESS) =>
            {
                self.nonce = nonce;
                true
            }
            other =>
            {
                // sessiond deletes the cap of a refused request; a failed
                // call may have moved nothing.
                let _ = syscall::cap_delete(recv);
                std::os::seraph::log!(warn: "terminal: REGISTER_INTERFACE refused ({other:?})");
                false
            }
        }
    }
}

/// Make an event queue and register it with procmgr as the terminal's end
/// queue (`procmgr_labels::REGISTER_END_QUEUE`); its RECV cap, kept for
/// the terminal's life.
fn register_end_queue() -> Option<u64>
{
    let queue = std::os::seraph::object_slab_retype(
        std::os::seraph::event_queue_retype_bytes(u64::from(END_QUEUE_CAPACITY), 0),
        |s| syscall::event_queue_create(s, END_QUEUE_CAPACITY).ok(),
    )?;
    let Ok(post) = syscall::cap_derive(queue, syscall::RIGHTS_EQ_POST)
    else
    {
        let _ = syscall::cap_delete(queue);
        return None;
    };
    let req = IpcMessage::builder(procmgr_labels::REGISTER_END_QUEUE)
        .word(0, 0)
        .cap(post)
        .build();
    let ep = std::os::seraph::startup_info().procmgr_endpoint;
    if call(ep, &req).is_some_and(|r| r.label == procmgr_errors::SUCCESS)
    {
        Some(queue)
    }
    else
    {
        let _ = syscall::cap_delete(post);
        let _ = syscall::cap_delete(queue);
        None
    }
}

/// `ipc_call` on this thread's IPC buffer; `None` when the call fails.
fn call(ep: u64, req: &IpcMessage) -> Option<IpcMessage>
{
    // SAFETY: current_ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(ep, req, std::os::seraph::current_ipc_buf()) }.ok()
}
