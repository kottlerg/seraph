// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/sessiond/src/main.rs

//! sessiond: the supervisor of operator sessions
//! (services/sessiond/README.md, docs/session-supervision.md).
//!
//! An interface (the terminal) registers itself and opens sessions through
//! the SEND svcmgr publishes as `sessiond.operator`
//! (`ipc::sessiond_labels`). For each session sessiond makes a budget node
//! under its own, outside the system reserve, and creates the session's
//! leader, the binary its recipe's `argv[1]` names, charged to that node and
//! contained, so a leader's end destroys every process it started. The
//! interface hands it the leader's stdio pipes and death relay, and sessiond
//! starts the leader with its own namespace root.
//!
//! sessiond is a stop source of the program class: on a badge carrying
//! `stop_labels::STOP_AUTHORITY` it lists every started session and each
//! leader's children, its jobs, and stops one by its key. A job goes first
//! (`stop_labels::RANK_JOB`), then a whole session
//! (`stop_labels::RANK_SESSION`). It refuses to open a session while memory
//! is critical, so a stop of a session is not undone before the level falls.
//!
//! One thread serves the endpoint, and waits on one wait set over the
//! endpoint, the death queue every leader's end posts to, and each
//! interface's end queue. The list and stop paths allocate nothing: every
//! table is a fixed array, and the stack they use is touched at start. Each
//! handler is a frame of its own (`#[inline(never)]`), so the depth of the
//! list and stop paths stays within the touched stack, whatever the open
//! path's frames take.

use ipc::{
    IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels,
    sessiond_labels as sl, stop_labels as stop,
};
use sessiond_table::{Key, Page, Place, SESSION_NAME_MAX, Slots, session_name, slot_of_key};
use syscall_abi::SyscallError;

/// Sessions sessiond holds at once (docs/limits.md).
const SESSION_MAX: usize = 16;

/// Interfaces sessiond holds at once (docs/limits.md).
const INTERFACE_MAX: usize = 8;

/// Entries the death queue holds: each leader posts its main thread's end and
/// its first terminal fault at most, and a slot's old leader may have both
/// still queued while its new one posts.
const DEATH_CAPACITY: u32 = 64;

/// Observer nodes of the death queue: two bindings per leader, its main thread
/// and its address space.
const DEATH_OBSERVERS: u32 = 32;

/// Members of the wait set: the endpoint, the death queue, and each
/// interface's end queue.
const WAIT_SET_MEMBERS: u32 = 10;

const _: () = assert!(
    DEATH_CAPACITY as usize == 4 * SESSION_MAX
        && DEATH_OBSERVERS as usize == 2 * SESSION_MAX
        && WAIT_SET_MEMBERS as usize == 2 + INTERFACE_MAX
);

/// Wait-set badge of the endpoint.
const WAKE_ENDPOINT: u64 = 0;
/// Wait-set badge of the death queue.
const WAKE_DEATH: u64 = 1;
/// Wait-set badge of the end queue of the interface in slot 0; slot `n`
/// takes `WAKE_INTERFACE + n`.
const WAKE_INTERFACE: u64 = 2;

/// The leader when the recipe passes no `argv[1]`.
const DEFAULT_LEADER: &str = "/programs/shell";

/// Priority level, and the band ceiling, of every leader: the least-trusted
/// processes of the system, below the interface that serves them.
const LEADER_PRIORITY: u8 = 5;

/// Bytes of stack sessiond touches at start, below its loop's frame, so its
/// list and stop paths fault no new stack page while memory is critical.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

/// How long the loop waits after a failed wait before waiting again.
const WAIT_RETRY_MS: u64 = 100;

/// A registered interface.
struct Interface
{
    /// The nonce it named itself by.
    nonce: u64,
    /// A RECV cap on the queue procmgr posts its end to.
    end_queue: u64,
}

/// A session: its leader, created and maybe started.
struct Session
{
    /// The key of its interface in the interface table.
    interface: u64,
    /// The handle of its budget node.
    node: u64,
    /// The leader's process handle.
    handle: u64,
    /// The leader's main-thread cap.
    thread: u64,
    /// Whether `START_SESSION` started the leader.
    started: bool,
}

/// sessiond's state.
struct Sessiond
{
    endpoint: u64,
    death_queue: u64,
    wait_set: u64,
    /// The path of every leader's binary, and the name procmgr verifies it
    /// was signed under.
    leader: String,
    sessions: Slots<Session, SESSION_MAX>,
    interfaces: Slots<Interface, INTERFACE_MAX>,
    ipc_buf: *mut u64,
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"sessiond");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let endpoint = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
        .map_or(0, |[cap]| cap);
    if endpoint == 0
    {
        std::os::seraph::log!(error: "no service endpoint");
        syscall::thread_exit();
    }
    let leader = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_LEADER.to_owned());
    touch_stack();
    let Some(sessiond) = Sessiond::start(endpoint, leader, ipc_buf)
    else
    {
        syscall::thread_exit();
    };
    std::os::seraph::log!("serving; sessions led by {}", sessiond.leader);
    sessiond.serve()
}

impl Sessiond
{
    /// Make the death queue and the wait set; `None`, logged, when either
    /// cannot be made.
    fn start(endpoint: u64, leader: String, ipc_buf: *mut u64) -> Option<Self>
    {
        let death_queue = std::os::seraph::object_slab_retype(
            std::os::seraph::event_queue_retype_bytes(
                u64::from(DEATH_CAPACITY),
                u64::from(DEATH_OBSERVERS),
            ),
            |s| syscall::event_queue_create_observed(s, DEATH_CAPACITY, DEATH_OBSERVERS).ok(),
        )
        .unwrap_or(0);
        let wait_set = std::os::seraph::object_slab_retype(
            std::os::seraph::wait_set_retype_bytes(u64::from(WAIT_SET_MEMBERS)),
            |s| syscall::wait_set_create(s, WAIT_SET_MEMBERS).ok(),
        )
        .unwrap_or(0);
        let joined = death_queue != 0
            && wait_set != 0
            && syscall::wait_set_add(wait_set, endpoint, WAKE_ENDPOINT).is_ok()
            && syscall::wait_set_add(wait_set, death_queue, WAKE_DEATH).is_ok();
        if !joined
        {
            // Deleting the set removes the members it took.
            for cap in [wait_set, death_queue]
            {
                if cap != 0
                {
                    let _ = syscall::cap_delete(cap);
                }
            }
            std::os::seraph::log!(error: "death queue or wait set not made");
            return None;
        }
        Some(Self {
            endpoint,
            death_queue,
            wait_set,
            leader,
            sessions: Slots::default(),
            interfaces: Slots::default(),
            ipc_buf,
        })
    }

    /// Serve the endpoint, end the sessions whose leaders ended, and end the
    /// sessions of interfaces that ended.
    fn serve(mut self) -> !
    {
        loop
        {
            self.drain_deaths();
            match syscall::wait_set_wait(self.wait_set)
            {
                Ok(WAKE_ENDPOINT) =>
                {
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    if let Ok(msg) = unsafe { ipc::ipc_try_recv(self.endpoint, self.ipc_buf) }
                    {
                        let reply = self.dispatch(&msg);
                        // SAFETY: ipc_buf is the registered IPC buffer page.
                        let _ = unsafe { ipc::ipc_reply(&reply, self.ipc_buf) };
                    }
                }
                // Drained at the loop's top.
                Ok(WAKE_DEATH) =>
                {}
                Ok(badge) =>
                {
                    let slot =
                        usize::try_from(badge.saturating_sub(WAKE_INTERFACE)).unwrap_or(usize::MAX);
                    self.interface_woke(slot);
                }
                Err(e) if e == SyscallError::Interrupted as i64 =>
                {}
                Err(e) =>
                {
                    std::os::seraph::log!(warn: "wait failed (err={e})");
                    let _ = syscall::thread_sleep(WAIT_RETRY_MS);
                }
            }
        }
    }

    /// Answer one request. The caps it carries are deleted after, but those
    /// a handler keeps or moves, which it clears from `caps`.
    fn dispatch(&mut self, msg: &IpcMessage) -> IpcMessage
    {
        let mut caps = [0u64; syscall_abi::MSG_CAP_SLOTS_MAX];
        for (slot, &cap) in caps.iter_mut().zip(msg.caps())
        {
            *slot = cap;
        }
        let reply = if msg.badge & stop::STOP_AUTHORITY != 0
        {
            match msg.label
            {
                stop::LIST_CANDIDATES => self.list(msg.word(0)),
                stop::STOP_CANDIDATE => self.stop(msg.word(0)),
                sl::REGISTER_INTERFACE
                | sl::OPEN_SESSION
                | sl::SESSION_STDIO
                | sl::START_SESSION => IpcMessage::new(sl::UNAUTHORIZED),
                _ => IpcMessage::new(sl::UNKNOWN_OPCODE),
            }
        }
        else if msg.badge & sl::OPERATOR_AUTHORITY != 0
        {
            match msg.label
            {
                sl::REGISTER_INTERFACE => self.register(msg, &mut caps),
                sl::OPEN_SESSION => self.open(msg.word(0), &mut caps),
                sl::SESSION_STDIO => self.stdio(msg, &mut caps),
                sl::START_SESSION => self.start_session(msg.word(0), msg.word(1)),
                stop::LIST_CANDIDATES | stop::STOP_CANDIDATE => IpcMessage::new(sl::UNAUTHORIZED),
                _ => IpcMessage::new(sl::UNKNOWN_OPCODE),
            }
        }
        else
        {
            IpcMessage::new(sl::UNAUTHORIZED)
        };
        for cap in caps.into_iter().filter(|&cap| cap != 0)
        {
            let _ = syscall::cap_delete(cap);
        }
        reply
    }

    // ── Interfaces ───────────────────────────────────────────────────────

    /// The key of the interface registered under `nonce`.
    fn interface_of(&self, nonce: u64) -> Option<u64>
    {
        if nonce == 0
        {
            return None;
        }
        self.interfaces.find(|i| i.nonce == nonce)
    }

    /// `REGISTER_INTERFACE`: `data[0]` the nonce, `data[1]` the version,
    /// `caps[0]` the end queue's RECV cap, kept on success.
    #[inline(never)]
    fn register(&mut self, msg: &IpcMessage, caps: &mut [u64]) -> IpcMessage
    {
        if msg.word(1) != u64::from(ipc::SESSIOND_LABELS_VERSION)
        {
            return IpcMessage::new(sl::VERSION_MISMATCH);
        }
        let nonce = msg.word(0);
        let queue = caps.first().copied().unwrap_or(0);
        if nonce == 0
            || !cap_is(
                queue,
                syscall_abi::CAP_TAG_EVENT_QUEUE,
                syscall::RIGHTS_EQ_RECV,
            )
            || self.interface_of(nonce).is_some()
        {
            return IpcMessage::new(sl::INVALID_ARGUMENT);
        }
        let Some(key) = self.interfaces.insert(Interface {
            nonce,
            end_queue: queue,
        })
        else
        {
            return IpcMessage::new(sl::TABLE_FULL);
        };
        let wake = WAKE_INTERFACE.saturating_add(u64::try_from(slot_of_key(key)).unwrap_or(0));
        if syscall::wait_set_add(self.wait_set, queue, wake).is_err()
        {
            // The cap stays in `caps`, so the dispatch deletes it.
            let _ = self.interfaces.remove(key);
            return IpcMessage::new(sl::INVALID_ARGUMENT);
        }
        if let Some(cap) = caps.first_mut()
        {
            *cap = 0;
        }
        std::os::seraph::log!("interface {} registered", slot_of_key(key));
        IpcMessage::new(sl::SUCCESS)
    }

    /// The end queue of the interface in `slot` is ready: an entry is the
    /// interface's end, which ends its sessions.
    fn interface_woke(&mut self, slot: usize)
    {
        let Some(key) = self.interfaces.key_at(slot)
        else
        {
            return;
        };
        let Some(queue) = self.interfaces.get(key).map(|i| i.end_queue)
        else
        {
            return;
        };
        match syscall::event_recv_entry(queue, syscall::WAIT_TRY_ONCE)
        {
            Err(e)
                if e == SyscallError::WouldBlock as i64
                    || e == SyscallError::Interrupted as i64 =>
            {}
            // The end, or a queue sessiond can no longer read, which would
            // wake the set without end.
            _ => self.end_interface(key),
        }
    }

    /// Forget the interface `key` names, and end each of its sessions.
    fn end_interface(&mut self, key: u64)
    {
        let Some(interface) = self.interfaces.remove(key)
        else
        {
            return;
        };
        let _ = syscall::wait_set_remove(self.wait_set, interface.end_queue);
        let _ = syscall::cap_delete(interface.end_queue);
        let mut ended = [0u64; SESSION_MAX];
        for (slot, (session, _)) in ended
            .iter_mut()
            .zip(self.sessions.iter().filter(|(_, s)| s.interface == key))
        {
            *slot = session;
        }
        for session in ended.into_iter().filter(|&k| k != 0)
        {
            self.end_session(session, "its interface ended");
        }
        std::os::seraph::log!("interface {} ended", slot_of_key(key));
    }

    // ── Sessions ─────────────────────────────────────────────────────────

    /// `OPEN_SESSION`: `caps[0]` the relay, moved to procmgr with the
    /// leader's create, or deleted.
    #[inline(never)]
    fn open(&mut self, nonce: u64, caps: &mut [u64]) -> IpcMessage
    {
        let Some(interface) = self.interface_of(nonce)
        else
        {
            return IpcMessage::new(sl::UNKNOWN_INTERFACE);
        };
        let relay = caps.first().copied().unwrap_or(0);
        if !cap_is(
            relay,
            syscall_abi::CAP_TAG_EVENT_QUEUE,
            syscall::RIGHTS_EQ_POST,
        )
        {
            return IpcMessage::new(sl::INVALID_ARGUMENT);
        }
        // A session opened now is a candidate oomd stops before any service,
        // so an interface that reopens a stopped one would undo the stop.
        if std::os::seraph::memory_pressure() == Some(std::os::seraph::MemoryPressure::Critical)
        {
            return IpcMessage::new(sl::MEMORY_CRITICAL);
        }
        if !self.sessions.has_room()
        {
            return IpcMessage::new(sl::TABLE_FULL);
        }
        if let Some(cap) = caps.first_mut()
        {
            *cap = 0;
        }
        match self.create_leader(interface, relay)
        {
            Ok(key) =>
            {
                std::os::seraph::log!("session {} opened", slot_of_key(key));
                IpcMessage::builder(sl::SUCCESS).word(0, key).build()
            }
            Err(code) =>
            {
                std::os::seraph::log!(warn: "session not opened (code {code})");
                IpcMessage::builder(sl::CREATE_FAILED).word(0, code).build()
            }
        }
    }

    /// Make a session's node and create its leader, suspended, with the
    /// death relay `relay`, and enter it in the table; its key, or the code
    /// `CREATE_FAILED` carries, with nothing left made and the relay deleted.
    #[inline(never)]
    fn create_leader(&mut self, interface: u64, relay: u64) -> Result<u64, u64>
    {
        let node = match self.create_node()
        {
            Ok(node) => node,
            Err(code) =>
            {
                let _ = syscall::cap_delete(relay);
                return Err(code);
            }
        };
        let (handle, thread) = match self.create_process(node, relay)
        {
            Ok(caps) => caps,
            Err(code) =>
            {
                self.release_node(node);
                return Err(code);
            }
        };
        let Some(key) = self.sessions.insert(Session {
            interface,
            node,
            handle,
            thread,
            started: false,
        })
        else
        {
            // The table had room when the request was taken.
            destroy_process(handle, self.ipc_buf);
            let _ = syscall::cap_delete(handle);
            let _ = syscall::cap_delete(thread);
            self.release_node(node);
            return Err(0);
        };
        if let Err(code) = self.watch(key, handle, thread)
        {
            self.end_session(key, "its death could not be watched");
            return Err(code);
        }
        Ok(key)
    }

    /// `CREATE_SUB_NODE` with no max: the handle of the session's node, or
    /// the code `CREATE_FAILED` carries.
    #[inline(never)]
    fn create_node(&self) -> Result<u64, u64>
    {
        let req = IpcMessage::builder(memmgr_labels::CREATE_SUB_NODE)
            .word(0, u64::MAX)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe {
            ipc::ipc_call(
                std::os::seraph::startup_info().memmgr_endpoint,
                &req,
                self.ipc_buf,
            )
        }
        .map_err(|_| 0u64)?;
        let node = reply.caps().first().copied().unwrap_or(0);
        if reply.label != memmgr_errors::SUCCESS || node == 0
        {
            for &cap in reply.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            return Err(reply.label);
        }
        Ok(node)
    }

    /// Release the node `node` names and delete its handle.
    #[inline(never)]
    fn release_node(&self, node: u64)
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe {
            ipc::ipc_call(
                node,
                &IpcMessage::new(memmgr_labels::NODE_RELEASE),
                self.ipc_buf,
            )
        };
        let _ = syscall::cap_delete(node);
    }

    /// Create the leader, suspended, contained and charged to `node`, with
    /// the death relay `relay` (moved to procmgr, or deleted): its process
    /// handle and main-thread cap, or the code `CREATE_FAILED` carries.
    #[inline(never)]
    #[expect(
        clippy::large_stack_frames,
        reason = "clippy adds up each 576-byte message of the builder chains and calls without \
                  overlap; this is the open path, which runs only while memory is not critical"
    )]
    fn create_process(&self, node: u64, relay: u64) -> Result<(u64, u64), u64>
    {
        let unmade = |code: u64| {
            let _ = syscall::cap_delete(relay);
            code
        };
        let mut blob = self.leader.clone().into_bytes();
        blob.push(0);
        let Ok(Some(argv)) = std::os::seraph::process::ArgvEnvCap::new(&blob, 1, b"", 0)
        else
        {
            return Err(unmade(0));
        };
        let (file, size) =
            std::os::seraph::namespace_lookup_file(std::os::seraph::root_dir_cap(), &self.leader)
                .map_err(|_| unmade(0))?;
        let Ok(charge) = syscall::cap_derive(node, syscall::RIGHTS_ALL)
        else
        {
            let _ = syscall::cap_delete(file);
            return Err(unmade(0));
        };
        let label = procmgr_labels::CREATE_FROM_FILE
            | procmgr_labels::CREATE_DEATH_RELAY
            | procmgr_labels::CREATE_ARGV_ENV
            | procmgr_labels::CREATE_CHARGE_NODE
            | procmgr_labels::CREATE_CONTAIN
            | procmgr_labels::create_sched_bits(LEADER_PRIORITY, LEADER_PRIORITY);
        let builder = IpcMessage::builder(label)
            .word(0, size)
            .words(procmgr_labels::CREATE_FIRST_WORD, &argv.header_words());
        let Some(builder) =
            procmgr_labels::with_create_name(builder, label, self.leader.as_bytes())
        else
        {
            for cap in [file, charge]
            {
                let _ = syscall::cap_delete(cap);
            }
            return Err(unmade(0));
        };
        // The tail caps in the order procmgr reads them: the file, the
        // charge node's handle, the argv/env cap, the relay last.
        let req = builder
            .cap(file)
            .cap(charge)
            .cap(argv.cap())
            .cap(relay)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe {
            ipc::ipc_call(
                std::os::seraph::startup_info().procmgr_endpoint,
                &req,
                self.ipc_buf,
            )
        };
        argv.settle(reply.as_ref().map_or(0, |r| r.label));
        let Ok(reply) = reply
        else
        {
            // The call moved nothing: delete what it would have.
            for cap in [file, charge]
            {
                let _ = syscall::cap_delete(cap);
            }
            return Err(unmade(0));
        };
        match (reply.label, reply.caps())
        {
            (procmgr_errors::SUCCESS, &[handle, thread, ..]) => Ok((handle, thread)),
            (code, caps) =>
            {
                // procmgr deletes the caps of a refused create, the relay
                // unposted.
                for &cap in caps
                {
                    let _ = syscall::cap_delete(cap);
                }
                Err(code)
            }
        }
    }

    /// Bind the death queue to the leader's main thread and, through procmgr,
    /// to its address space, both with the session's key as the correlator,
    /// so either end of the leader posts the key; the code `CREATE_FAILED`
    /// carries when a binding fails.
    #[inline(never)]
    fn watch(&self, key: u64, handle: u64, thread: u64) -> Result<(), u64>
    {
        syscall::thread_bind_notification(thread, self.death_queue, key).map_err(|_| 0u64)?;
        let post =
            syscall::cap_derive(self.death_queue, syscall::RIGHTS_EQ_POST).map_err(|_| 0u64)?;
        let req = IpcMessage::builder(procmgr_labels::BIND_DEATH_OBSERVER)
            .word(0, key)
            .cap(post)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(handle, &req, self.ipc_buf) };
        match reply
        {
            Ok(reply) if reply.label == procmgr_errors::SUCCESS => Ok(()),
            Ok(reply) => Err(reply.label),
            Err(_) =>
            {
                let _ = syscall::cap_delete(post);
                Err(0)
            }
        }
    }

    /// The leader's handle of the session `key` names when it belongs to the
    /// interface registered under `nonce` and has not started; the label of
    /// the reply refusing it otherwise.
    fn pending(&self, nonce: u64, key: u64) -> Result<u64, u64>
    {
        let interface = self.interface_of(nonce).ok_or(sl::UNKNOWN_INTERFACE)?;
        self.sessions
            .get(key)
            .filter(|s| s.interface == interface && !s.started)
            .map(|s| s.handle)
            .ok_or(sl::NO_SESSION)
    }

    /// `SESSION_STDIO`: `data[0..4]` the nonce, the key, the direction and
    /// the ring capacity, `caps[0..3]` the ring's caps, moved to procmgr. A
    /// session whose stdio is refused is ended, so its relay is posted.
    #[inline(never)]
    #[expect(
        clippy::large_stack_frames,
        reason = "clippy adds up each 576-byte message of the builder chains and calls without \
                  overlap; this is the open path, which runs only while memory is not critical"
    )]
    fn stdio(&mut self, msg: &IpcMessage, caps: &mut [u64]) -> IpcMessage
    {
        let handle = match self.pending(msg.word(0), msg.word(1))
        {
            Ok(handle) => handle,
            Err(label) => return IpcMessage::new(label),
        };
        let key = msg.word(1);
        let direction = msg.word(2);
        let (memory, data, space) = match *caps
        {
            [memory, data, space, ..] => (memory, data, space),
            _ => (0, 0, 0),
        };
        let notification = syscall::RIGHTS_NTF_NOTIFY | syscall::RIGHTS_NTF_WAIT;
        if direction > procmgr_labels::PIPE_DIR_STDERR
            || !cap_is(memory, syscall::CAP_TAG_MEMORY, syscall::RIGHTS_MEM_MAP_RW)
            || !cap_is(data, syscall::CAP_TAG_NOTIFICATION, notification)
            || !cap_is(space, syscall::CAP_TAG_NOTIFICATION, notification)
        {
            self.end_session(key, "its stdio request was malformed");
            return IpcMessage::new(sl::INVALID_ARGUMENT);
        }
        let req = IpcMessage::builder(procmgr_labels::CONFIGURE_PIPE)
            .word(0, direction)
            .word(1, msg.word(3))
            .cap(memory)
            .cap(data)
            .cap(space)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(handle, &req, self.ipc_buf) };
        match reply
        {
            Ok(reply) if reply.label == procmgr_errors::SUCCESS =>
            {
                // The call moved them.
                if let Some(moved) = caps.get_mut(..3)
                {
                    moved.fill(0);
                }
                IpcMessage::new(sl::SUCCESS)
            }
            Ok(reply) =>
            {
                self.end_session(key, "its stdio was refused");
                IpcMessage::builder(sl::CREATE_FAILED)
                    .word(0, reply.label)
                    .build()
            }
            Err(_) =>
            {
                self.end_session(key, "its stdio was refused");
                IpcMessage::builder(sl::CREATE_FAILED).word(0, 0).build()
            }
        }
    }

    /// `START_SESSION`: hand the leader sessiond's namespace root and start
    /// it; a session whose start fails is ended.
    #[inline(never)]
    fn start_session(&mut self, nonce: u64, key: u64) -> IpcMessage
    {
        let handle = match self.pending(nonce, key)
        {
            Ok(handle) => handle,
            Err(label) => return IpcMessage::new(label),
        };
        match self.configure_and_start(handle)
        {
            Ok(()) =>
            {
                if let Some(session) = self.sessions.get_mut(key)
                {
                    session.started = true;
                }
                std::os::seraph::log!("session {} started", slot_of_key(key));
                IpcMessage::new(sl::SUCCESS)
            }
            Err(code) =>
            {
                self.end_session(key, "its start failed");
                IpcMessage::builder(sl::CREATE_FAILED).word(0, code).build()
            }
        }
    }

    /// `CONFIGURE_NAMESPACE` with a copy of sessiond's root and no cwd, then
    /// `START_PROCESS`; the code `CREATE_FAILED` carries on a failure.
    #[inline(never)]
    #[expect(
        clippy::large_stack_frames,
        reason = "clippy adds up each 576-byte message of the builder chains and calls without \
                  overlap; this is the open path, which runs only while memory is not critical"
    )]
    fn configure_and_start(&self, handle: u64) -> Result<(), u64>
    {
        let info = std::os::seraph::startup_info();
        let root = syscall::cap_copy(
            std::os::seraph::root_dir_cap(),
            info.self_cspace,
            syscall::RIGHTS_EP_SEND,
        )
        .map_err(|_| 0u64)?;
        let configure = IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE)
            .cap(root)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page; procmgr consumes
        // the cap whatever it replies.
        let reply = unsafe { ipc::ipc_call(handle, &configure, self.ipc_buf) }.map_err(|_| {
            let _ = syscall::cap_delete(root);
            0u64
        })?;
        if reply.label != procmgr_errors::SUCCESS
        {
            return Err(reply.label);
        }
        let start = IpcMessage::new(procmgr_labels::START_PROCESS);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(handle, &start, self.ipc_buf) }.map_err(|_| 0u64)?;
        if reply.label != procmgr_errors::SUCCESS
        {
            return Err(reply.label);
        }
        Ok(())
    }

    /// End the session `key` names (`why`, for the log): destroy its leader,
    /// whose relay procmgr then posts, with every process the leader started,
    /// and release its node. `false` when no session holds `key`.
    #[inline(never)]
    fn end_session(&mut self, key: u64, why: &str) -> bool
    {
        let Some(session) = self.sessions.remove(key)
        else
        {
            return false;
        };
        destroy_process(session.handle, self.ipc_buf);
        let _ = syscall::cap_delete(session.handle);
        let _ = syscall::cap_delete(session.thread);
        self.release_node(session.node);
        std::os::seraph::log!("session {} ended: {why}", slot_of_key(key));
        true
    }

    /// End the session of each death the queue holds. An entry whose key
    /// names no session is of a leader sessiond ended already.
    fn drain_deaths(&mut self)
    {
        while let Ok(entry) = syscall::event_recv_entry(self.death_queue, syscall::WAIT_TRY_ONCE)
        {
            let death = syscall::DeathEvent::from_entry(entry);
            if self.sessions.get(death.correlator).is_some()
            {
                let why = if death.exit_reason == 0
                {
                    "its leader exited"
                }
                else
                {
                    "its leader ended abnormally"
                };
                self.end_session(death.correlator, why);
            }
        }
    }

    // ── Stop source ──────────────────────────────────────────────────────

    /// The handle and the node of each started session, in slot order, with
    /// its key; unused entries are zero.
    fn started(&self) -> [(u64, u64, u64); SESSION_MAX]
    {
        let mut out = [(0, 0, 0); SESSION_MAX];
        for (slot, (key, session)) in out
            .iter_mut()
            .zip(self.sessions.iter().filter(|(_, s)| s.started))
        {
            *slot = (key, session.handle, session.node);
        }
        out
    }

    /// `LIST_CANDIDATES` from `cursor`: for each started session, in slot
    /// order, the session, then each child of its leader, a job.
    #[inline(never)]
    fn list(&self, cursor: u64) -> IpcMessage
    {
        let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
        let mut page = Page::new(cursor, stop::LIST_CANDIDATES_PAGE);
        'walk: for (key, handle, node) in self.started().into_iter().filter(|&(k, _, _)| k != 0)
        {
            match page.place()
            {
                Place::Skip =>
                {}
                Place::Take(index) =>
                {
                    let Some(pages) = self.node_pages(node)
                    else
                    {
                        return IpcMessage::new(stop::UNAVAILABLE);
                    };
                    let mut name = [0u8; SESSION_NAME_MAX];
                    let slot = u32::try_from(slot_of_key(key)).unwrap_or(u32::MAX);
                    let name = session_name(slot, &mut name);
                    let _ = stop::pack_candidate(
                        &mut words,
                        index,
                        key,
                        stop::RANK_SESSION,
                        pages,
                        name,
                    );
                }
                Place::Full => break 'walk,
            }
            let mut after = None;
            loop
            {
                let Some(reply) = self.children(handle, after)
                else
                {
                    return IpcMessage::new(stop::UNAVAILABLE);
                };
                let count = usize::try_from(reply.word(0)).unwrap_or(0);
                for entry in 0..count
                {
                    let mut name = [0u8; ipc::svcmgr_labels::NAME_MAX];
                    let Some((badge, len, pages)) =
                        procmgr_labels::unpack_child_entry(reply.words(), entry, &mut name)
                    else
                    {
                        break;
                    };
                    after = Some(badge);
                    match page.place()
                    {
                        Place::Skip =>
                        {}
                        Place::Take(index) =>
                        {
                            let name = name.get(..len).filter(|n| !n.is_empty()).unwrap_or(b"job");
                            let _ = stop::pack_candidate(
                                &mut words,
                                index,
                                badge,
                                stop::RANK_JOB,
                                pages,
                                name,
                            );
                        }
                        Place::Full => break 'walk,
                    }
                }
                if count < procmgr_labels::LIST_CHILDREN_PAGE
                {
                    break;
                }
            }
        }
        let count = page.count();
        let next = page.next_cursor().max(cursor.saturating_add(1));
        let [count_word, next_word, ..] = &mut words;
        *count_word = u64::try_from(count).unwrap_or(0);
        *next_word = next;
        let used = stop::HEADER_WORDS.saturating_add(count.saturating_mul(stop::CANDIDATE_WORDS));
        IpcMessage::builder(stop::SUCCESS)
            .words(0, words.get(..used).unwrap_or_default())
            .build()
    }

    /// The pages the subtree of the node `node` names holds; `None` when
    /// memmgr does not answer.
    #[inline(never)]
    fn node_pages(&self, node: u64) -> Option<u64>
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe {
            ipc::ipc_call(
                node,
                &IpcMessage::new(memmgr_labels::NODE_QUERY_USAGE),
                self.ipc_buf,
            )
        }
        .ok()?;
        (reply.label == memmgr_errors::SUCCESS).then(|| reply.word(2))
    }

    /// One `LIST_CHILDREN` page of the leader `handle` names, after the
    /// badge `after`; an empty page for a leader procmgr no longer knows,
    /// whose death the queue holds; `None` when procmgr does not answer.
    #[inline(never)]
    #[expect(
        clippy::large_stack_frames,
        reason = "clippy adds up each 576-byte message of the builder chain and the call without \
                  overlap; the list path's depth is what STACK_TOUCH_BYTES touches at start"
    )]
    fn children(&self, handle: u64, after: Option<u64>) -> Option<IpcMessage>
    {
        let req = match after
        {
            None => IpcMessage::builder(procmgr_labels::LIST_CHILDREN).word(0, 0),
            Some(badge) => IpcMessage::builder(procmgr_labels::LIST_CHILDREN)
                .word(0, 1)
                .word(1, badge),
        }
        .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(handle, &req, self.ipc_buf) }.ok()?;
        match reply.label
        {
            procmgr_errors::SUCCESS => Some(reply),
            procmgr_errors::INVALID_BADGE => Some(
                IpcMessage::builder(procmgr_errors::SUCCESS)
                    .word(0, 0)
                    .build(),
            ),
            _ => None,
        }
    }

    /// `STOP_CANDIDATE` of `key`: a session's key ends the session, a job's
    /// destroys that child of the leader whose child it is.
    #[inline(never)]
    fn stop(&mut self, key: u64) -> IpcMessage
    {
        match Key::of(key)
        {
            Key::Session(key) =>
            {
                if !self.sessions.get(key).is_some_and(|s| s.started)
                {
                    return IpcMessage::new(stop::NO_CANDIDATE);
                }
                self.end_session(key, "stopped for a stop-authority holder");
                IpcMessage::new(stop::SUCCESS)
            }
            Key::Job(badge) =>
            {
                if badge == 0
                {
                    return IpcMessage::new(stop::NO_CANDIDATE);
                }
                for (session, handle, _) in self.started().into_iter().filter(|&(k, _, _)| k != 0)
                {
                    let req = IpcMessage::builder(procmgr_labels::DESTROY_CHILD)
                        .word(0, badge)
                        .build();
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    match unsafe { ipc::ipc_call(handle, &req, self.ipc_buf) }.map(|r| r.label)
                    {
                        Ok(procmgr_errors::SUCCESS) =>
                        {
                            std::os::seraph::log!(
                                "job {badge:#x} of session {} stopped for a stop-authority holder",
                                slot_of_key(session)
                            );
                            return IpcMessage::new(stop::SUCCESS);
                        }
                        Ok(procmgr_errors::INVALID_BADGE) =>
                        {}
                        Ok(_) | Err(_) => return IpcMessage::new(stop::UNAVAILABLE),
                    }
                }
                IpcMessage::new(stop::NO_CANDIDATE)
            }
        }
    }
}

/// Whether `cap` is a capability of type `tag` holding every right in
/// `rights`; `false` for slot 0. sessiond checks each cap an interface hands
/// it this way before keeping or forwarding it: the operator SEND carries
/// `GRANT`, so its holder can pass any cap, and one of another type or with
/// fewer rights would otherwise fail only where sessiond, or procmgr after
/// it, first uses it.
fn cap_is(cap: u64, tag: u8, rights: u64) -> bool
{
    cap != 0
        && syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
            .is_ok_and(|packed| packed >> 32 == u64::from(tag) && packed & rights == rights)
}

/// Send `DESTROY_PROCESS` on `handle`, retrying a call a stop of this
/// thread, or an upcall to it, interrupted.
#[inline(never)]
fn destroy_process(handle: u64, ipc_buf: *mut u64)
{
    let req = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        match unsafe { ipc::ipc_call(handle, &req, ipc_buf) }
        {
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {}
            Ok(_) | Err(_) => return,
        }
    }
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack sessiond uses, written once at start"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}
