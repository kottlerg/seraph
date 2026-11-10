// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/main.rs

//! The GDB stub: debugs one process from a host GDB over the debug port.
//!
//! The service finds the process its argv names in procmgr's process list,
//! attaches to it, binds the exception and upcall classes of each of its
//! threads to its own endpoint, and serves the GDB remote serial protocol
//! (`shared/gdb-rsp`) on the debug port. The protocol coverage, the stop
//! model, and the detach are specified in `services/gdbstub/README.md`.

mod arch;

use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::time::{Duration, Instant};

use arch::{ARCH, BREAKPOINT_PC_ADVANCE, StepUndo};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::command::{BreakpointType, Command, ThreadId, ThreadOp, VContActions};
use gdb_rsp::frame::{AckMode, Event, PacketReader, PacketWriter, unescape};
use gdb_rsp::target::TARGET_XML_ANNEX;
use gdbstub::breakpoints::{self, Breakpoints};
use gdbstub::control::{self, Credit, Named, Plan, Unclaimed};
use gdbstub::{regs, signal, stop_signal};
use ipc::{
    IpcMessage, devmgr_errors, devmgr_labels, procmgr_errors, procmgr_labels, serial_errors,
    serial_labels, svcmgr_labels,
};

/// Logged once the stub is attached and serves the debug port; the batch
/// test connects GDB on seeing it. Kept in sync with
/// `xtask/src/commands/test_gdb.rs`.
const READY_MARKER: &str = "attached; serving the debug port";

/// The most threads one attach binds: a bound on the stub's receiver threads,
/// one per target thread, each of which can hold that thread stopped. Threads
/// listed past it run unbound and unlisted.
const MAX_THREADS: usize = 32;

/// How long, and how often, the stub looks for the debug port, and for its
/// target in procmgr's process list at startup before it serves the port
/// detached.
const FIND_ATTEMPTS: u32 = 600;
const FIND_INTERVAL: Duration = Duration::from_millis(100);

/// How many times a `qSupported` that finds the stub detached looks for the
/// target, [`FIND_INTERVAL`] apart: 5 s, well inside the 30 s remote timeout
/// of the GDB command line xtask prints.
const REATTACH_ATTEMPTS: u32 = 50;

/// How long an all-stop waits for every thread's upcall to arrive.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// How long a detach keeps answering stops that arrive after it, until no
/// stop has come for [`DRAIN_QUIET`].
const DRAIN_WAIT: Duration = Duration::from_millis(500);
const DRAIN_QUIET: Duration = Duration::from_millis(50);

/// How many times a thread-list refresh is tried when a thread of the old
/// list exits during it.
const REFRESH_TRIES: u32 = 3;

/// How long the serve loop waits for the port between looks at the threads'
/// events, in milliseconds.
const POLL_MS: u64 = 10;

/// The most bytes one serial-protocol message carries.
const MAX_MESSAGE_BYTES: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

fn main()
{
    std::os::seraph::log::register_name(b"gdbstub");
    let info = std::os::seraph::startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // A debug-authority holder declares itself undebuggable before it spawns
    // a thread, so no other holder stops it while it stops a target.
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &IpcMessage::new(procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    };
    // The recipe's seed is `devmgr.debug`; `debug_authority = yes` delivers
    // the authority cap in the slot after it.
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok([registry, debug]) =
        (unsafe { ipc::bootstrap::request_slots::<2>(info.creator_endpoint, ipc_buf) })
    else
    {
        std::os::seraph::log!("no bootstrap caps; exiting");
        return;
    };
    let Some(name) = std::env::args().nth(1)
    else
    {
        std::os::seraph::log!("no target name in argv; exiting");
        return;
    };
    if registry == 0 || debug == 0
    {
        std::os::seraph::log!("devmgr.debug or the debug authority missing; exiting");
        return;
    }
    let Some(port) = Port::open(registry, ipc_buf)
    else
    {
        std::os::seraph::log!("no debug port served; exiting");
        return;
    };
    let Some(endpoint) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
    else
    {
        std::os::seraph::log!("no fault endpoint; exiting");
        return;
    };
    let (events_tx, events) = channel();
    let mut stub = Stub {
        port,
        reader: PacketReader::new(),
        acks: AckMode::default(),
        last: Vec::new(),
        name,
        debug,
        self_thread: info.self_thread,
        endpoint,
        ipc_buf,
        events,
        events_tx,
        receivers: Vec::new(),
        target: None,
        breakpoints: Breakpoints::new(),
        current: 0,
        running: false,
        stepping: None,
    };
    stub.attach(FIND_ATTEMPTS);
    stub.serve(ipc_buf);
}

// ── The debug port ───────────────────────────────────────────────────────────

/// The debug port: the serial-protocol cap devmgr hands the debug-port
/// authority, and the notification its driver signals on receive (`0` with
/// none registered).
struct Port
{
    cap: u64,
    rx: u64,
}

impl Port
{
    /// Take the port from devmgr, waiting out its driver's on-disk spawn,
    /// and register an RX notification on it.
    fn open(registry: u64, ipc_buf: *mut u64) -> Option<Self>
    {
        let mut cap = 0;
        for _ in 0..FIND_ATTEMPTS
        {
            let req = IpcMessage::builder(devmgr_labels::QUERY_DEBUG_PORT_DEVICE)
                .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let reply = unsafe { ipc::ipc_call(registry, &req, ipc_buf) }.ok()?;
            match (reply.label, reply.caps().first())
            {
                (devmgr_errors::SUCCESS, Some(&c)) if c != 0 =>
                {
                    cap = c;
                    break;
                }
                (devmgr_errors::NO_DEVICE, _) => std::thread::sleep(FIND_INTERVAL),
                _ => return None,
            }
        }
        if cap == 0
        {
            return None;
        }
        let rx = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        .unwrap_or(0);
        if rx != 0
            && let Ok(copy) = syscall::cap_derive(rx, syscall::RIGHTS_ALL)
        {
            let req = IpcMessage::builder(serial_labels::SERIAL_REGISTER_RX_NOTIFY)
                .cap(copy)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(cap, &req, ipc_buf) };
        }
        Some(Self { cap, rx })
    }

    /// Read the bytes the port holds into `buf`; returns the count.
    fn read(&self, buf: &mut [u8; MAX_MESSAGE_BYTES], ipc_buf: *mut u64) -> usize
    {
        let req = IpcMessage::new(serial_labels::SERIAL_READ_BYTES);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(self.cap, &req, ipc_buf) })
        else
        {
            return 0;
        };
        if reply.label & 0xFFFF != serial_errors::SUCCESS
        {
            return 0;
        }
        let count = usize::try_from((reply.label >> 16) & 0xFFFF).unwrap_or(0);
        let bytes = reply.data_bytes();
        let n = count.min(bytes.len()).min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        n
    }

    /// Write `bytes`, one message's worth per call.
    fn write(&self, bytes: &[u8], ipc_buf: *mut u64)
    {
        for chunk in bytes.chunks(MAX_MESSAGE_BYTES)
        {
            let label = serial_labels::SERIAL_WRITE_BYTES | ((chunk.len() as u64) << 16);
            let req = IpcMessage::builder(label).bytes(0, chunk).build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(self.cap, &req, ipc_buf) };
        }
    }

    /// Wait for received bytes, at most [`POLL_MS`].
    fn wait(&self)
    {
        if self.rx == 0
        {
            std::thread::sleep(Duration::from_millis(POLL_MS));
        }
        else
        {
            let _ = syscall::notification_wait_timeout(self.rx, POLL_MS);
        }
    }
}

// ── Fault receivers ──────────────────────────────────────────────────────────

/// A fault or upcall message one receiver took off the endpoint, which that
/// receiver holds, its thread blocked, until the stub's decision.
#[derive(Clone, Copy, Debug)]
struct Stop
{
    receiver: usize,
    badge: u64,
    kind: u64,
    /// Data word 1: the exception class, or the upcall's cookie.
    detail: u64,
    /// Data word 3: the thread's instruction pointer.
    ip: u64,
}

/// Start receiver `id` on `endpoint`: each message it takes goes to the
/// serve loop on `events`, and it replies with the label the loop sends back
/// on its own channel before it receives again. One receiver holds one
/// thread stopped, since a receive cancels the pending reply.
fn start_receiver(id: usize, endpoint: u64, events: Sender<Stop>) -> Option<Sender<u64>>
{
    let (reply_tx, reply_rx): (Sender<u64>, Receiver<u64>) = channel();
    std::thread::Builder::new()
        .spawn(move || {
            let ipc_buf = std::os::seraph::current_ipc_buf();
            loop
            {
                // SAFETY: ipc_buf is this thread's registered IPC buffer.
                let Ok(msg) = (unsafe { ipc::ipc_recv(endpoint, ipc_buf) })
                else
                {
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    continue;
                };
                let stop = Stop {
                    receiver: id,
                    badge: msg.badge,
                    kind: msg.word(0),
                    detail: msg.word(1),
                    ip: msg.word(3),
                };
                if events.send(stop).is_err()
                {
                    return;
                }
                let Ok(label) = reply_rx.recv()
                else
                {
                    return;
                };
                // SAFETY: ipc_buf is this thread's registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(label), ipc_buf) };
            }
        })
        .ok()?;
    Some(reply_tx)
}

// ── The target ───────────────────────────────────────────────────────────────

/// One thread of the target, at the index of the stub's table it was stored
/// at: the attach stores procmgr's list in order, and a refresh stores each
/// new thread in the slot of an exited one, or after the last.
struct Thread
{
    /// The attach's cap, with `OBSERVE`, `CONTROL`, and `UPCALL`.
    cap: u64,
    /// The thread's classes are bound to the stub's endpoint under
    /// `control::thread_badge` of its index; an unbound thread (its bind
    /// failed) keeps its slot while it lives and is not shown to GDB.
    bound: bool,
    /// The receiver holding the thread's stop, while it is stopped.
    held: Option<Stop>,
    /// An all-stop has posted the thread an upcall it has not taken yet.
    posted: bool,
    /// The thread has exited.
    gone: bool,
}

impl Thread
{
    /// The thread is bound and has not exited: GDB sees it.
    fn live(&self) -> bool
    {
        self.bound && !self.gone
    }
}

/// The attached process.
struct Target
{
    badge: u64,
    bias: u64,
    threads: Vec<Thread>,
    /// The table holds every thread procmgr listed, so a refresh can page on
    /// from the count of threads still alive; `false` once [`MAX_THREADS`]
    /// cut the list short.
    complete: bool,
}

/// A step in flight: the stepped thread and what to undo at its stop.
#[derive(Clone, Copy)]
struct Stepping
{
    thread: usize,
    undo: StepUndo,
}

struct Stub
{
    port: Port,
    reader: PacketReader<PACKET_SIZE>,
    acks: AckMode,
    /// The last packet sent, which a `-` asks for again.
    last: Vec<u8>,
    /// The target's name, as the stub's argv gives it.
    name: String,
    /// The procmgr cap carrying `DEBUG_AUTHORITY`.
    debug: u64,
    self_thread: u64,
    endpoint: u64,
    /// The main thread's IPC buffer, on which every call of the stub is made.
    ipc_buf: *mut u64,
    events: Receiver<Stop>,
    events_tx: Sender<Stop>,
    /// Each receiver's reply channel.
    receivers: Vec<Sender<u64>>,
    target: Option<Target>,
    breakpoints: Breakpoints,
    /// The thread register and memory commands act on, by index.
    current: usize,
    /// The target was resumed and no stop has been reported since.
    running: bool,
    stepping: Option<Stepping>,
}

impl Stub
{
    /// Find the target by name, looking `attempts` times, and attach to it,
    /// stopping every thread. With no such process the stub serves the port
    /// detached, and attaches again at GDB's next connection.
    fn attach(&mut self, attempts: u32)
    {
        // A stop left over from an earlier session is answered, not taken
        // for one of this attach's.
        self.drain_events(Duration::ZERO);
        let mut badge = None;
        for i in 0..attempts
        {
            badge = find_process(self.debug, self.name.as_bytes(), self.ipc_buf);
            if badge.is_some()
            {
                break;
            }
            if i + 1 < attempts
            {
                std::thread::sleep(FIND_INTERVAL);
            }
        }
        let Some(badge) = badge
        else
        {
            std::os::seraph::log!("no process named {} to attach to", self.name);
            return;
        };
        let watch = Some(self.self_thread);
        let Some(page) = attach_process(self.debug, badge, 0, watch, MAX_THREADS, self.ipc_buf)
        else
        {
            std::os::seraph::log!("attach to {} refused", self.name);
            return;
        };
        self.target = Some(Target {
            badge,
            bias: page.bias,
            threads: Vec::new(),
            complete: page.complete,
        });
        for cap in page.caps
        {
            self.add_thread(cap);
        }
        self.current = 0;
        // The target runs until this all-stop holds it; GDB has been told of
        // no stop.
        self.running = true;
        self.stop_all();
        std::os::seraph::log!("{READY_MARKER} ({})", self.name);
    }

    /// Store `cap` in the thread table, in the slot of an exited thread
    /// ([`control::free_slot`]) or after the last, binding it under the
    /// index it is stored at.
    fn add_thread(&mut self, cap: u64)
    {
        let Some((index, reused)) = self.target.as_ref().map(|t| {
            control::free_slot(t.threads.iter().map(|t| (t.gone, t.held.is_some())))
                .map_or((t.threads.len(), false), |i| (i, true))
        })
        else
        {
            let _ = syscall::cap_delete(cap);
            return;
        };
        // A step whose thread exited is undone before its slot is taken.
        if reused && self.stepping.is_some_and(|s| s.thread == index)
        {
            self.finish_stepping();
        }
        let bound = self.ensure_receiver(index) && bind_thread(self.endpoint, cap, index);
        let thread = Thread {
            cap,
            bound,
            held: None,
            posted: false,
            gone: !bound && !thread_alive(cap),
        };
        if let Some(target) = &mut self.target
        {
            if reused
            {
                let old = core::mem::replace(&mut target.threads[index], thread);
                let _ = syscall::cap_delete(old.cap);
            }
            else
            {
                target.threads.push(thread);
            }
        }
    }

    /// Take the threads the target registered since the attach from
    /// procmgr's list and bind them, so their stops stop arriving under the
    /// badge of the thread that spawned them: a bind made while such a
    /// thread's stop is in flight cancels that delivery and delivers it
    /// again under the new badge (docs/fault-handling.md § Delivery, Resume,
    /// and Kill, Rebind). procmgr lists the threads still alive in the
    /// order it listed them before, then the new ones, so the new ones start
    /// at the count of the table's threads still alive. Returns whether a
    /// thread was added.
    fn refresh(&mut self) -> bool
    {
        let Some(target) = &mut self.target
        else
        {
            return false;
        };
        if !target.complete
        {
            return false;
        }
        let badge = target.badge;
        for _ in 0..REFRESH_TRIES
        {
            // Exited threads' slots are taken again, so only the live ones
            // count toward the bound.
            let alive = self.alive_count();
            let room = MAX_THREADS.saturating_sub(alive);
            let Some(page) =
                attach_process(self.debug, badge, alive as u64, None, room, self.ipc_buf)
            else
            {
                return false;
            };
            // A thread of the table that exited during the call shifted
            // procmgr's list under the page: take it again.
            if self.alive_count() != alive || page.count < alive as u64
            {
                for cap in page.caps
                {
                    let _ = syscall::cap_delete(cap);
                }
                continue;
            }
            let added = !page.caps.is_empty();
            if let Some(target) = &mut self.target
            {
                target.complete = page.complete;
            }
            for cap in page.caps
            {
                self.add_thread(cap);
            }
            return added;
        }
        false
    }

    /// Mark the table's exited threads gone; returns how many are alive.
    fn alive_count(&mut self) -> usize
    {
        let Some(target) = &mut self.target
        else
        {
            return 0;
        };
        for t in &mut target.threads
        {
            if !t.gone && !thread_alive(t.cap)
            {
                t.gone = true;
            }
        }
        target.threads.iter().filter(|t| !t.gone).count()
    }

    /// Start receiver `index` when it is not running yet.
    fn ensure_receiver(&mut self, index: usize) -> bool
    {
        while self.receivers.len() <= index
        {
            match start_receiver(self.receivers.len(), self.endpoint, self.events_tx.clone())
            {
                Some(tx) => self.receivers.push(tx),
                None => return false,
            }
        }
        true
    }

    /// Stop every running thread of the target with an upcall and wait,
    /// bounded by [`STOP_WAIT`], for each stop to arrive; then finish a step
    /// still in flight. A breakpoint another thread hits meanwhile is held
    /// unreported and undone ([`Self::cancel_hit`]); a thread found by a
    /// refresh meanwhile is stopped too.
    fn stop_all(&mut self)
    {
        if self.target.is_none()
        {
            return;
        }
        let deadline = Instant::now() + STOP_WAIT;
        loop
        {
            self.post_upcalls();
            let waiting = self.target.as_ref().is_some_and(|t| {
                t.threads
                    .iter()
                    .any(|t| t.live() && t.held.is_none() && t.posted)
            });
            if !waiting || Instant::now() >= deadline
            {
                break;
            }
            match self.events.try_recv()
            {
                Ok(stop) =>
                {
                    if let Some(index) = self.hold(stop)
                    {
                        self.cancel_hit(index);
                    }
                }
                Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(1)),
                Err(TryRecvError::Disconnected) => break,
            }
        }
        if let Some(target) = &mut self.target
        {
            for t in &mut target.threads
            {
                t.posted = false;
            }
        }
        self.finish_stepping();
        self.running = false;
    }

    /// Post an `UPCALL_ANY_INSTRUCTION` upcall to every live thread not held
    /// and not yet posted.
    fn post_upcalls(&mut self)
    {
        let Some(target) = &mut self.target
        else
        {
            return;
        };
        for t in target
            .threads
            .iter_mut()
            .filter(|t| t.live() && t.held.is_none() && !t.posted)
        {
            let posted = syscall::thread_post_upcall(t.cap, 0, syscall_abi::UPCALL_ANY_INSTRUCTION);
            // A refused post to a live thread finds an upcall already
            // pending (an earlier post), which arrives as well.
            if posted.is_err() && !thread_alive(t.cap)
            {
                t.gone = true;
            }
            else
            {
                t.posted = true;
            }
        }
    }

    /// Record `stop` as its thread's held stop; returns the thread's index.
    /// A stop that is not the thread's own ([`control::credit`]) comes from
    /// a thread spawned after the attach under its spawner's badge, or is a
    /// delivery the kernel made again: the stub refreshes its thread list,
    /// whose bind delivers a new thread's stop again under its own badge,
    /// and settles the stop as [`control::settle`] says.
    fn hold(&mut self, stop: Stop) -> Option<usize>
    {
        let index = control::thread_index(stop.badge);
        let Some((i, thread)) =
            index.and_then(|i| Some((i, self.target.as_ref()?.threads.get(i)?)))
        else
        {
            self.reply(stop.receiver, control::decline_label(stop.kind));
            return None;
        };
        let held = thread.held;
        let regs_pc = if held.is_some()
        {
            None
        }
        else
        {
            read_pc(thread.cap)
        };
        if control::credit(held.is_some(), regs_pc, stop.ip) == Credit::Own
        {
            if let Some(t) = self.target.as_mut().and_then(|t| t.threads.get_mut(i))
            {
                t.held = Some(stop);
                t.posted = false;
            }
            return Some(i);
        }
        let added = self.refresh();
        let repeats =
            held.is_some_and(|h| (h.kind, h.detail, h.ip) == (stop.kind, stop.detail, stop.ip));
        let named = match (held, self.running)
        {
            (None, _) => Named::Free,
            (Some(_), true) => Named::Unreported,
            (Some(_), false) => Named::Reported,
        };
        match control::settle(named, added, repeats)
        {
            Unclaimed::Restart => self.restart(i, stop),
            Unclaimed::Replace =>
            {
                if let Some(t) = self.target.as_mut().and_then(|t| t.threads.get_mut(i))
                {
                    t.held = Some(stop);
                }
                // The replaced delivery was cancelled; its reply is ignored.
                if let Some(old) = held
                {
                    self.reply(old.receiver, syscall_abi::FAULT_REPLY_RESUME);
                }
            }
            Unclaimed::Decline => self.reply(stop.receiver, control::decline_label(stop.kind)),
        }
        None
    }

    /// Resume both the held stop of thread `index` and `stop`, a second
    /// delivery under its badge, after rewinding the thread's breakpoint hit:
    /// whichever delivery is live runs the thread's stopping instruction
    /// again, and the thread stops anew under its own badge
    /// ([`control::Unclaimed::Restart`]).
    fn restart(&mut self, index: usize, stop: Stop)
    {
        let Some(t) = self.target.as_mut().and_then(|t| t.threads.get_mut(index))
        else
        {
            return;
        };
        let held = t.held.take();
        t.posted = false;
        let cap = t.cap;
        self.rewind_hit(cap, held.iter().chain([&stop]));
        if let Some(h) = held
        {
            self.reply(h.receiver, syscall_abi::FAULT_REPLY_RESUME);
        }
        self.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
    }

    /// Undo a breakpoint hit of held thread `index` that the stub does not
    /// report ([`Self::rewind_hit`]).
    fn cancel_hit(&mut self, index: usize)
    {
        let Some((cap, stop)) = self
            .target
            .as_ref()
            .and_then(|t| t.threads.get(index))
            .and_then(|t| Some((t.cap, t.held?)))
        else
        {
            return;
        };
        self.rewind_hit(cap, [&stop].into_iter());
    }

    /// Set the pointer of the fault-blocked thread `cap` back to the
    /// breakpoint it took, when one of `stops` is a breakpoint hit and the
    /// architecture reports the pointer past it ([`control::rewound_pc`]),
    /// so its resume runs the breakpoint again, and reports it then, rather
    /// than resuming inside the replaced instruction
    /// (docs/fault-handling.md § Debugging).
    fn rewind_hit<'a>(&self, cap: u64, mut stops: impl Iterator<Item = &'a Stop>)
    {
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        if syscall::thread_read_regs(cap, &mut file[..size]).is_err()
        {
            return;
        }
        let pc = regs::pc(ARCH, &file);
        let planted = |a| self.breakpoints.contains(a);
        let Some(at) = stops.find_map(|s| {
            control::rewound_pc(BREAKPOINT_PC_ADVANCE, s.kind, s.detail, pc, planted)
        })
        else
        {
            return;
        };
        regs::set_pc(ARCH, &mut file[..size], at);
        // SAFETY: the register file was read from this fault-blocked thread
        // just above; only its pointer moved back to the breakpoint it took.
        let _ = unsafe { syscall::thread_write_regs(cap, &file[..size]) };
    }

    /// Undo the step in flight, once its thread is held: its trap flag, or
    /// its planted `c.ebreak`. A thread not held keeps the step pending,
    /// for its next stop.
    fn finish_stepping(&mut self)
    {
        self.undo_step(false);
    }

    /// Undo the step in flight: its text part (riscv64's planted
    /// `c.ebreak`) through any live thread of the target, and its register
    /// part (x86-64's trap flag) when the stepped thread is held. Unless
    /// `force`, a stepped thread that is alive and not held keeps the step
    /// pending; with it (a detach), the text is undone anyway, and a trap
    /// flag left on a thread that never stopped is logged.
    fn undo_step(&mut self, force: bool)
    {
        let Some(step) = self.stepping
        else
        {
            return;
        };
        let stepped = self
            .target
            .as_ref()
            .and_then(|t| t.threads.get(step.thread))
            .map(|t| (t.cap, t.held.is_some(), t.gone));
        if let Some((_, false, false)) = stepped
            && !force
        {
            return;
        }
        let text = match stepped
        {
            Some((cap, _, false)) => Some(cap),
            _ => self.any_thread(),
        };
        if let Some(cap) = text
        {
            arch::finish_step_text(cap, step.undo);
        }
        match stepped
        {
            Some((cap, true, _)) =>
            {
                let mut file = [0u8; 512];
                let size = regs::file_size(ARCH);
                if syscall::thread_read_regs(cap, &mut file[..size]).is_ok()
                {
                    arch::finish_step_regs(step.undo, &mut file[..size]);
                    // SAFETY: read from this held thread just above; only
                    // the step's trap flag changed.
                    let _ = unsafe { syscall::thread_write_regs(cap, &file[..size]) };
                }
            }
            Some((_, false, false)) if ARCH == gdb_rsp::target::Arch::X86_64 =>
            {
                std::os::seraph::log!("a step's thread never stopped; its trap flag stays set");
            }
            _ =>
            {}
        }
        self.stepping = None;
    }

    fn reply(&self, receiver: usize, label: u64)
    {
        if let Some(tx) = self.receivers.get(receiver)
        {
            let _ = tx.send(label);
        }
    }

    /// Answer every stop the receivers hold or pass on within `wait`, until
    /// none has come for [`DRAIN_QUIET`]: with `FAULT_REPLY_RESUME`, which
    /// resumes a thread the stub no longer debugs and fails harmlessly for a
    /// delivery a rebind cancelled. A zero `wait` answers what is queued.
    fn drain_events(&mut self, wait: Duration)
    {
        let deadline = Instant::now() + wait;
        let mut quiet_from = Instant::now();
        loop
        {
            match self.events.try_recv()
            {
                Ok(stop) =>
                {
                    self.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
                    quiet_from = Instant::now();
                }
                Err(TryRecvError::Empty) =>
                {
                    let now = Instant::now();
                    if now >= deadline || now >= quiet_from + DRAIN_QUIET
                    {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TryRecvError::Disconnected) => return,
            }
        }
    }

    /// Resume every held thread: with `FAULT_REPLY_RESUME`, or, for thread
    /// `signalled` when GDB passes it a nonzero `signal` and it is stopped
    /// on a fault, with `FAULT_REPLY_KILL`, so the fault takes the outcome
    /// it has with no handler. Returns how many threads it resumed.
    fn resume_all(&mut self, signal: Option<u8>, signalled: usize) -> usize
    {
        let Some(target) = &mut self.target
        else
        {
            return 0;
        };
        let mut replies = Vec::new();
        for (i, t) in target.threads.iter_mut().enumerate()
        {
            if let Some(stop) = t.held.take()
            {
                let pass = i == signalled && signal.is_some_and(|s| s != 0);
                let label = if pass && stop.kind != syscall_abi::FAULT_KIND_UPCALL
                {
                    syscall_abi::FAULT_REPLY_KILL
                }
                else
                {
                    syscall_abi::FAULT_REPLY_RESUME
                };
                replies.push((stop.receiver, label));
            }
        }
        let resumed = replies.len();
        for (receiver, label) in replies
        {
            self.reply(receiver, label);
        }
        self.running = true;
        resumed
    }

    /// Step thread `index` one instruction, the others held.
    fn step(&mut self, index: usize) -> bool
    {
        let Some(t) = self.target.as_mut().and_then(|t| t.threads.get_mut(index))
        else
        {
            return false;
        };
        let Some(stop) = t.held
        else
        {
            return false;
        };
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        if syscall::thread_read_regs(t.cap, &mut file[..size]).is_err()
        {
            return false;
        }
        let Ok(undo) = arch::prepare_step(t.cap, &mut file[..size])
        else
        {
            return false;
        };
        // SAFETY: the register file was read from this held thread just
        // above; only the trap flag changed.
        if unsafe { syscall::thread_write_regs(t.cap, &file[..size]) }.is_err()
        {
            // The registers were not written; only a planted c.ebreak needs
            // taking back.
            arch::finish_step_text(t.cap, undo);
            return false;
        }
        t.held = None;
        self.stepping = Some(Stepping {
            thread: index,
            undo,
        });
        self.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
        self.running = true;
        true
    }

    /// Carry out a resume packet's `plan`, after moving the planned thread's
    /// pointer to `addr` when the packet gives one.
    fn resume(&mut self, plan: Plan, addr: Option<u64>, ipc_buf: *mut u64)
    {
        if self.target.is_none()
        {
            self.send(ipc_buf, |w| {
                w.exited(0);
            });
            return;
        }
        let thread = match plan
        {
            Plan::Step { thread } | Plan::Continue { thread, .. } => thread,
            Plan::Nothing =>
            {
                self.error(ipc_buf, 1);
                return;
            }
        };
        if let Some(addr) = addr
            && !self.set_pc(thread, addr)
        {
            self.error(ipc_buf, 1);
            return;
        }
        match plan
        {
            Plan::Step { thread } =>
            {
                self.current = thread;
                if !self.step(thread)
                {
                    self.error(ipc_buf, 1);
                }
            }
            Plan::Continue { thread, signal } =>
            {
                self.resume_all(signal, thread);
                // Every thread exited: no stop will come, so the target is
                // reported gone rather than left running.
                if self.alive_count() == 0
                {
                    self.drop_target();
                    self.send(ipc_buf, |w| {
                        w.exited(0);
                    });
                }
            }
            Plan::Nothing =>
            {}
        }
    }

    /// Set held thread `index`'s pointer to `addr`.
    fn set_pc(&self, index: usize, addr: u64) -> bool
    {
        let Some(t) = self.target.as_ref().and_then(|t| t.threads.get(index))
        else
        {
            return false;
        };
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        if syscall::thread_read_regs(t.cap, &mut file[..size]).is_err()
        {
            return false;
        }
        regs::set_pc(ARCH, &mut file[..size], addr);
        // SAFETY: the register file was read from this held thread just
        // above; only its pointer changed, to the address GDB resumes at.
        unsafe { syscall::thread_write_regs(t.cap, &file[..size]) }.is_ok()
    }

    /// Take the stops that arrived while the target ran: the first stops
    /// the target, which the stub reports to GDB.
    fn poll(&mut self, ipc_buf: *mut u64)
    {
        if !self.running
        {
            return;
        }
        let Ok(stop) = self.events.try_recv()
        else
        {
            return;
        };
        // An upcall arrives while the target runs only when it was posted
        // to a thread that stopped on a fault first, and was delivered after
        // that fault resolved: the stop it asked for is over.
        if stop.kind == syscall_abi::FAULT_KIND_UPCALL
        {
            self.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
            return;
        }
        let Some(index) = self.hold(stop)
        else
        {
            return;
        };
        // All-stop: hold every other thread too before GDB sees the stop;
        // the stop_all finishes the step this stop may end.
        self.stop_all();
        // A second delivery under the thread's badge during the all-stop
        // can have restarted it (`Unclaimed::Restart`): the stop reported is
        // then another held thread's, and with none held the target runs on.
        let reported = self.target.as_ref().and_then(|t| {
            let held = |i: usize| t.threads.get(i)?.held.map(|s| (i, s));
            held(index).or_else(|| (0..t.threads.len()).find_map(held))
        });
        let Some((index, stop)) = reported
        else
        {
            self.running = true;
            return;
        };
        self.current = index;
        let sig = stop_signal(stop.kind, stop.detail);
        self.send(ipc_buf, |w| {
            w.stop_thread(sig, index as u64 + 1);
        });
    }

    /// Detach: undo a step in flight, write every breakpoint's bytes back,
    /// resume every thread, have procmgr bind the target back to its crash
    /// endpoint, unbind the upcall class, drop the threads, and answer the
    /// stops that arrive meanwhile. Also run when the stub's session ends
    /// (`k`).
    fn detach(&mut self, ipc_buf: *mut u64)
    {
        let Some(cap) = self.any_thread()
        else
        {
            self.drop_target();
            return;
        };
        // A step whose thread an all-stop left running gets one more
        // all-stop to take its stop; its text is undone whatever comes.
        self.finish_stepping();
        if self.stepping.is_some()
        {
            self.stop_all();
        }
        self.undo_step(true);
        for bp in self.breakpoints.take_all()
        {
            let _ = write_text(cap, bp.addr, bp.original());
        }
        let current = self.current;
        self.resume_all(None, current);
        let Some(target) = self.target.take()
        else
        {
            return;
        };
        // procmgr rebinds the exception class over the stub's binding, so no
        // thread is unbound meanwhile; the upcall class the stub unbinds.
        let req = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
            .word(0, target.badge)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let detached = unsafe { ipc::ipc_call(self.debug, &req, ipc_buf) }
            .is_ok_and(|r| r.label == procmgr_errors::SUCCESS);
        for t in &target.threads
        {
            let _ = syscall::thread_set_fault_handler(t.cap, 0, syscall_abi::FAULT_CLASS_UPCALL);
            let _ = syscall::cap_delete(t.cap);
        }
        self.running = false;
        // A fault or upcall delivered between the resume and the rebind is
        // answered here, not left to a later attach.
        self.drain_events(DRAIN_WAIT);
        std::os::seraph::log!(
            "detached from {} (crash bindings restored: {})",
            self.name,
            detached
        );
    }

    /// Forget a target whose every thread exited: delete the thread caps,
    /// and the breakpoints, whose text went with it.
    fn drop_target(&mut self)
    {
        if let Some(target) = self.target.take()
        {
            for t in &target.threads
            {
                let _ = syscall::cap_delete(t.cap);
            }
        }
        let _ = self.breakpoints.take_all();
        self.stepping = None;
        self.running = false;
    }

    /// The cap of a live thread of the target, for memory access.
    fn any_thread(&self) -> Option<u64>
    {
        let target = self.target.as_ref()?;
        target
            .threads
            .get(self.current)
            .filter(|t| !t.gone)
            .or_else(|| target.threads.iter().find(|t| !t.gone))
            .map(|t| t.cap)
    }

    // ── The serve loop ───────────────────────────────────────────────────

    fn serve(&mut self, ipc_buf: *mut u64) -> !
    {
        let mut buf = [0u8; MAX_MESSAGE_BYTES];
        loop
        {
            let n = self.port.read(&mut buf, ipc_buf);
            for &byte in &buf[..n]
            {
                self.take(byte, ipc_buf);
            }
            self.poll(ipc_buf);
            if n == 0
            {
                self.port.wait();
            }
        }
    }

    /// Take one byte from the port.
    fn take(&mut self, byte: u8, ipc_buf: *mut u64)
    {
        let mut body = [0u8; PACKET_SIZE];
        let (ack, len, event) = {
            let Some(event) = self.reader.push(byte)
            else
            {
                return;
            };
            let ack = self.acks.response(&event);
            let len = match event
            {
                Event::Packet(b) =>
                {
                    body[..b.len()].copy_from_slice(b);
                    b.len()
                }
                _ => 0,
            };
            let kind = match event
            {
                Event::Packet(_) => Some(EventKind::Packet),
                Event::Interrupt => Some(EventKind::Interrupt),
                Event::Nack => Some(EventKind::Nack),
                Event::Overflow => Some(EventKind::Overflow),
                Event::Ack | Event::BadChecksum => None,
            };
            (ack, len, kind)
        };
        if let Some(a) = ack
        {
            self.port.write(&[a], ipc_buf);
        }
        match event
        {
            Some(EventKind::Packet) => self.command(&body[..len], ipc_buf),
            Some(EventKind::Interrupt) if self.running =>
            {
                self.stop_all();
                let thread = self.current as u64 + 1;
                self.send(ipc_buf, |w| {
                    w.stop_thread(signal::INT, thread);
                });
            }
            Some(EventKind::Nack) =>
            {
                let last = self.last.clone();
                self.port.write(&last, ipc_buf);
            }
            Some(EventKind::Overflow) => self.send(ipc_buf, |w| {
                w.error(2);
            }),
            _ =>
            {}
        }
    }

    /// Send one packet whose body `body` writes, and keep it for a `-`.
    fn send(&mut self, ipc_buf: *mut u64, body: impl FnOnce(&mut PacketWriter<'_>))
    {
        let mut buf = vec![0u8; 2 * PACKET_SIZE + 8];
        let mut w = PacketWriter::new(&mut buf);
        body(&mut w);
        let Ok(n) = w.finish()
        else
        {
            return;
        };
        buf.truncate(n);
        self.port.write(&buf, ipc_buf);
        self.last = buf;
    }

    fn ok(&mut self, ipc_buf: *mut u64)
    {
        self.send(ipc_buf, |w| {
            w.ok();
        });
    }

    fn error(&mut self, ipc_buf: *mut u64, code: u8)
    {
        self.send(ipc_buf, |w| {
            w.error(code);
        });
    }

    /// Answer one packet.
    // too_many_lines: one arm per command of the packet set, each a call or
    // two; splitting the match would scatter the protocol's table.
    #[allow(clippy::too_many_lines)]
    fn command(&mut self, body: &[u8], ipc_buf: *mut u64)
    {
        let Ok(command) = Command::parse(body)
        else
        {
            self.error(ipc_buf, 1);
            return;
        };
        if self.target.is_none() && matches!(command, Command::Supported(_))
        {
            self.attach(REATTACH_ATTEMPTS);
        }
        match command
        {
            Command::Supported(_) => self.send(ipc_buf, |w| {
                w.supported();
            }),
            Command::StartNoAckMode =>
            {
                self.ok(ipc_buf);
                self.acks.enter_no_ack();
            }
            Command::HaltReason => match &self.target
            {
                Some(_) =>
                {
                    let thread = self.current as u64 + 1;
                    self.send(ipc_buf, |w| {
                        w.stop_thread(signal::TRAP, thread);
                    });
                }
                None => self.send(ipc_buf, |w| {
                    w.exited(0);
                }),
            },
            Command::Attached => self.send(ipc_buf, |w| {
                w.bytes(b"1");
            }),
            Command::Offsets =>
            {
                let bias = self.target.as_ref().map_or(0, |t| t.bias);
                self.send(ipc_buf, |w| {
                    w.offsets(bias);
                });
            }
            Command::FeaturesRead { annex, offset, len } if annex == TARGET_XML_ANNEX =>
            {
                self.send(ipc_buf, |w| {
                    w.xfer_chunk(ARCH.target_xml(), offset, len);
                });
            }
            Command::FeaturesRead { .. } => self.error(ipc_buf, 0),
            Command::ThreadInfoFirst =>
            {
                let ids: Vec<u64> = self.target.as_ref().map_or_else(Vec::new, |t| {
                    (0..t.threads.len())
                        .filter(|&i| t.threads[i].live())
                        .map(|i| i as u64 + 1)
                        .collect()
                });
                self.send(ipc_buf, |w| {
                    w.thread_list(&ids);
                });
            }
            Command::ThreadInfoNext => self.send(ipc_buf, |w| {
                w.thread_list(&[]);
            }),
            Command::CurrentThread =>
            {
                let thread = self.current as u64 + 1;
                self.send(ipc_buf, |w| {
                    w.current_thread(thread);
                });
            }
            Command::SetThread { op, thread } => match (op, self.select(thread))
            {
                (ThreadOp::General, Some(i)) =>
                {
                    self.current = i;
                    self.ok(ipc_buf);
                }
                (_, Some(_)) | (ThreadOp::Resume, None) => self.ok(ipc_buf),
                (ThreadOp::General, None) => self.error(ipc_buf, 1),
            },
            Command::ThreadAlive(thread) => match self.select(thread)
            {
                Some(_) => self.ok(ipc_buf),
                None => self.error(ipc_buf, 1),
            },
            Command::ReadRegisters => self.read_registers(None, ipc_buf),
            Command::ReadRegister(n) => self.read_registers(usize::try_from(n).ok(), ipc_buf),
            Command::WriteRegisters(hex) => self.write_registers(None, hex, ipc_buf),
            Command::WriteRegister { regnum, value } =>
            {
                self.write_registers(usize::try_from(regnum).ok(), value, ipc_buf);
            }
            Command::ReadMemory { addr, len } => self.read_memory(addr, len, ipc_buf),
            Command::WriteMemory { addr, data } =>
            {
                let mut bytes = vec![0u8; data.len() / 2];
                let ok = gdb_rsp::hex::decode(data, &mut bytes).is_ok()
                    && self.write_memory(addr, &bytes);
                self.reply_ok(ok, ipc_buf);
            }
            Command::WriteMemoryBinary { addr, data } =>
            {
                let mut bytes = vec![0u8; data.len()];
                let ok =
                    unescape(data, &mut bytes).is_ok_and(|n| self.write_memory(addr, &bytes[..n]));
                self.reply_ok(ok, ipc_buf);
            }
            Command::InsertBreakpoint {
                ty: BreakpointType::Software,
                addr,
                kind,
            } =>
            {
                let ok = self.insert_breakpoint(addr, kind);
                self.reply_ok(ok, ipc_buf);
            }
            Command::RemoveBreakpoint {
                ty: BreakpointType::Software,
                addr,
                ..
            } =>
            {
                let ok = self.remove_breakpoint(addr);
                self.reply_ok(ok, ipc_buf);
            }
            Command::Continue { addr, signal } =>
            {
                let plan = control::plan_resume(false, signal, self.current);
                self.resume(plan, addr, ipc_buf);
            }
            Command::Step { addr, signal } =>
            {
                let plan = control::plan_resume(true, signal, self.current);
                self.resume(plan, addr, ipc_buf);
            }
            Command::VContQuery => self.send(ipc_buf, |w| {
                w.vcont_actions();
            }),
            Command::VCont(actions) => self.vcont(actions, ipc_buf),
            Command::Detach =>
            {
                self.detach(ipc_buf);
                self.ok(ipc_buf);
            }
            Command::Kill => self.detach(ipc_buf),
            Command::InsertBreakpoint { .. }
            | Command::RemoveBreakpoint { .. }
            | Command::Attach(_)
            | Command::Unknown(_) => self.send(ipc_buf, |_| {}),
        }
    }

    fn reply_ok(&mut self, ok: bool, ipc_buf: *mut u64)
    {
        if ok
        {
            self.ok(ipc_buf);
        }
        else
        {
            self.error(ipc_buf, 1);
        }
    }

    /// The index of the live thread `thread` names; the current thread for
    /// "any" and "all".
    fn select(&self, thread: ThreadId) -> Option<usize>
    {
        let target = self.target.as_ref()?;
        let index = match thread
        {
            ThreadId::Id(id) => usize::try_from(id).ok()?.checked_sub(1)?,
            ThreadId::Any | ThreadId::All => self.current,
        };
        target
            .threads
            .get(index)
            .filter(|t| t.live())
            .map(|_| index)
    }

    /// `vCont`: as [`control::plan_vcont`] plans it.
    fn vcont(&mut self, actions: VContActions<'_>, ipc_buf: *mut u64)
    {
        let actions: Vec<_> = actions.iter().collect();
        let plan = control::plan_vcont(actions.iter().copied(), self.current, |t| self.select(t));
        self.resume(plan, None, ipc_buf);
    }

    /// The current thread's register file, read; `None` without a target or
    /// when the read fails (the thread exited, or is not held).
    fn read_file(&self) -> Option<(u64, [u8; 512])>
    {
        let t = self.target.as_ref()?.threads.get(self.current)?;
        let mut file = [0u8; 512];
        syscall::thread_read_regs(t.cap, &mut file[..regs::file_size(ARCH)]).ok()?;
        Some((t.cap, file))
    }

    /// `g` (every register, `regnum` `None`) or `p` (one).
    fn read_registers(&mut self, regnum: Option<usize>, ipc_buf: *mut u64)
    {
        let Some((_, file)) = self.read_file()
        else
        {
            self.error(ipc_buf, 1);
            return;
        };
        match regnum
        {
            None => self.send(ipc_buf, |w| regs::encode_registers(ARCH, &file, w)),
            Some(n) if n < ARCH.registers().len() =>
            {
                self.send(ipc_buf, |w| regs::encode_register(ARCH, &file, n, w));
            }
            Some(_) => self.error(ipc_buf, 1),
        }
    }

    /// `G` (every register, `regnum` `None`) or `P` (one).
    fn write_registers(&mut self, regnum: Option<usize>, hex: &[u8], ipc_buf: *mut u64)
    {
        let Some((cap, mut file)) = self.read_file()
        else
        {
            self.error(ipc_buf, 1);
            return;
        };
        let size = regs::file_size(ARCH);
        let applied = match regnum
        {
            None => regs::write_registers(ARCH, hex, &mut file[..size]),
            Some(n) => regs::write_register(ARCH, n, hex, &mut file[..size]),
        };
        // SAFETY: `file` is the held thread's own register file, as read
        // above, with GDB's values in the fields the stub lets it write.
        let ok =
            applied.is_ok() && unsafe { syscall::thread_write_regs(cap, &file[..size]) }.is_ok();
        self.reply_ok(ok, ipc_buf);
    }

    /// `m`: read target memory, in chunks the kernel copies at once.
    fn read_memory(&mut self, addr: u64, len: u64, ipc_buf: *mut u64)
    {
        let Some(cap) = self.any_thread()
        else
        {
            self.error(ipc_buf, 1);
            return;
        };
        let max = (PACKET_SIZE - 4) / 2;
        let len = usize::try_from(len).map_or(max, |l| l.min(max));
        let mut bytes = vec![0u8; len];
        let mut read = 0;
        while read < len
        {
            let n = (len - read).min(syscall_abi::MAX_THREAD_MEM_COPY);
            if syscall::thread_read_mem(cap, addr + read as u64, &mut bytes[read..read + n])
                .is_err()
            {
                break;
            }
            read += n;
        }
        if read == 0 && len != 0
        {
            self.error(ipc_buf, 1);
            return;
        }
        self.send(ipc_buf, |w| {
            w.hex(&bytes[..read]);
        });
    }

    /// Write target memory: a plain write, or through the text route when
    /// the page is read-only text.
    fn write_memory(&self, addr: u64, bytes: &[u8]) -> bool
    {
        let Some(cap) = self.any_thread()
        else
        {
            return false;
        };
        bytes
            .chunks(syscall_abi::MAX_THREAD_MEM_COPY)
            .enumerate()
            .all(|(i, chunk)| {
                let at = addr + (i * syscall_abi::MAX_THREAD_MEM_COPY) as u64;
                // SAFETY: the write lands in the target's address space, not
                // the stub's own; every thread of the target is held.
                unsafe { syscall::thread_write_mem(cap, at, chunk, 0) }.is_ok()
                    || write_text(cap, at, chunk)
            })
    }

    /// `Z0`: plant the breakpoint instruction `kind` asks for, saving the
    /// bytes it replaces.
    fn insert_breakpoint(&mut self, addr: u64, kind: u64) -> bool
    {
        let Some(insn) = breakpoints::instruction(ARCH, kind)
        else
        {
            return false;
        };
        if self.breakpoints.contains(addr)
        {
            return true;
        }
        let Some(cap) = self.any_thread()
        else
        {
            return false;
        };
        let mut saved = [0u8; breakpoints::MAX_BREAKPOINT_BYTES];
        let saved = &mut saved[..insn.len()];
        if syscall::thread_read_mem(cap, addr, saved).is_err() || !write_text(cap, addr, insn)
        {
            return false;
        }
        self.breakpoints.insert(addr, saved);
        true
    }

    /// `z0`: write the saved bytes back.
    fn remove_breakpoint(&mut self, addr: u64) -> bool
    {
        let Some(cap) = self.any_thread()
        else
        {
            return false;
        };
        match self.breakpoints.remove(addr)
        {
            Some(bp) => write_text(cap, bp.addr, bp.original()),
            None => true,
        }
    }
}

/// What a byte from the port completed, copied out of the reader's borrow.
enum EventKind
{
    Packet,
    Interrupt,
    Nack,
    Overflow,
}

/// Write `bytes` at `addr` of the target's text, through the kernel's text
/// route (`THREAD_MEM_TEXT`), with every thread of the target held.
fn write_text(cap: u64, addr: u64, bytes: &[u8]) -> bool
{
    // SAFETY: the write lands in the target's address space, not the stub's
    // own, and every thread of the target is held, as a text write requires
    // (docs/fault-handling.md § Debugging).
    unsafe { syscall::thread_write_mem(cap, addr, bytes, syscall_abi::THREAD_MEM_TEXT) }.is_ok()
}

/// The pointer of a thread that is stopped or fault-blocked; `None` for one
/// that runs, whose register file the kernel refuses to read.
fn read_pc(cap: u64) -> Option<u64>
{
    let mut file = [0u8; 512];
    let size = regs::file_size(ARCH);
    syscall::thread_read_regs(cap, &mut file[..size]).ok()?;
    Some(regs::pc(ARCH, &file))
}

/// Whether `cap` names a thread that has not exited.
fn thread_alive(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall_abi::CAP_INFO_THREAD_STATE)
        .is_ok_and(|packed| (packed >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED)
}

/// Bind the exception and upcall classes of the thread stored at table
/// index `index` to `endpoint` under that index's badge.
fn bind_thread(endpoint: u64, cap: u64, index: usize) -> bool
{
    let badge = control::thread_badge(index);
    let Ok(send) = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND, badge)
    else
    {
        return false;
    };
    let bound = syscall::thread_set_fault_handler(
        cap,
        send,
        syscall_abi::FAULT_CLASS_EXCEPTION | syscall_abi::FAULT_CLASS_UPCALL,
    )
    .is_ok();
    let _ = syscall::cap_delete(send);
    bound
}

/// The badge of the live process named `name` in procmgr's list
/// (`LIST_PROCESSES`), the first in badge order when several share it.
fn find_process(debug: u64, name: &[u8], ipc_buf: *mut u64) -> Option<u64>
{
    let mut cursor = None;
    loop
    {
        let req = IpcMessage::builder(procmgr_labels::LIST_PROCESSES)
            .word(0, u64::from(cursor.is_some()))
            .word(1, cursor.unwrap_or(0))
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(debug, &req, ipc_buf) }.ok()?;
        if reply.label != procmgr_errors::SUCCESS
        {
            return None;
        }
        let words = reply.words();
        let count = usize::try_from(words.first().copied().unwrap_or(0)).ok()?;
        let mut entry_name = [0u8; svcmgr_labels::NAME_MAX];
        for i in 0..count
        {
            let (badge, len) = procmgr_labels::unpack_list_entry(words, i, &mut entry_name)?;
            if &entry_name[..len] == name
            {
                return Some(badge);
            }
            cursor = Some(badge);
        }
        if count < procmgr_labels::LIST_PROCESSES_PAGE
        {
            return None;
        }
    }
}

/// What [`attach_process`] took from procmgr.
struct AttachPage
{
    /// The image's load bias.
    bias: u64,
    /// The length of procmgr's thread list for the target.
    count: u64,
    /// The caps of the threads from the first index asked for, at most the
    /// room given.
    caps: Vec<u64>,
    /// The caps reach the end of procmgr's list.
    complete: bool,
}

/// Attach to the process `badge` names (`ATTACH_PROCESS`), paging its
/// thread list from index `first`, at most `room` threads. With `watch`, the
/// stub's own main thread goes to procmgr as the debugger watch, so the
/// target's crash bindings come back if the stub dies attached. A refusal
/// or a failed call on any page deletes the caps already taken, and, when
/// the watch was given, has procmgr drop it again (`DETACH_PROCESS`).
fn attach_process(
    debug: u64,
    badge: u64,
    first: u64,
    watch: Option<u64>,
    room: usize,
    ipc_buf: *mut u64,
) -> Option<AttachPage>
{
    let mut caps = Vec::new();
    let mut next = first;
    let mut watched = false;
    let fail = |caps: &[u64], watched: bool| {
        for &cap in caps
        {
            let _ = syscall::cap_delete(cap);
        }
        if watched
        {
            let req = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
                .word(0, badge)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(debug, &req, ipc_buf) };
        }
    };
    loop
    {
        let mut req = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
            .word(0, badge)
            .word(1, next);
        // The watch carries `OBSERVE` alone: procmgr only reads the thread's
        // state, which takes no right.
        if !watched
            && let Some(thread) = watch
            && let Ok(cap) = syscall::cap_derive(thread, syscall_abi::RIGHTS_THREAD_OBSERVE)
        {
            req = req.cap(cap);
        }
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = match unsafe { ipc::ipc_call(debug, &req.build(), ipc_buf) }
        {
            Ok(reply) if reply.label == procmgr_errors::SUCCESS => reply,
            _ =>
            {
                fail(&caps, watched);
                return None;
            }
        };
        watched |= watch.is_some();
        let count = reply.word(0);
        let page = reply.caps();
        for &cap in page
        {
            if caps.len() < room
            {
                caps.push(cap);
            }
            else
            {
                let _ = syscall::cap_delete(cap);
            }
        }
        next += page.len() as u64;
        if page.is_empty() || next >= count || caps.len() >= room
        {
            return Some(AttachPage {
                bias: reply.word(1),
                count,
                complete: first + caps.len() as u64 >= count,
                caps,
            });
        }
    }
}
