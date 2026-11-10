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

use arch::current::{ARCH, StepUndo};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::command::{BreakpointType, Command, Resume, ThreadId, ThreadOp, VContActions};
use gdb_rsp::frame::{AckMode, Event, PacketReader, PacketWriter, unescape};
use gdb_rsp::target::TARGET_XML_ANNEX;
use gdbstub::breakpoints::{self, Breakpoints};
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

/// How long, and how often, the stub looks for its target in procmgr's
/// process list before it serves the port detached.
const FIND_ATTEMPTS: u32 = 600;
const FIND_INTERVAL: Duration = Duration::from_millis(100);

/// How long an all-stop waits for every thread's upcall to arrive.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// How long the serve loop waits for the port between looks at the threads'
/// events, in milliseconds.
const POLL_MS: u64 = 10;

/// The most bytes one serial-protocol message carries.
const MAX_MESSAGE_BYTES: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// The badge a target thread's bindings carry: a verb bit (bit 62, which no
/// process badge carries) with the thread's index plus one, and bit 63
/// clear, so it is neither the target's process badge nor a crash badge, as
/// procmgr requires of a debugger's binding (§ `REGISTER_THREAD`).
const THREAD_BADGE_TAG: u64 = 1 << 62;

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
        events,
        events_tx,
        receivers: Vec::new(),
        target: None,
        breakpoints: Breakpoints::new(),
        current: 0,
        running: false,
        stepping: None,
    };
    stub.attach(ipc_buf);
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

/// One thread of the target.
struct Thread
{
    /// The attach's cap, with `OBSERVE`, `CONTROL`, and `UPCALL`.
    cap: u64,
    /// The receiver holding the thread's stop, while it is stopped.
    held: Option<Stop>,
    /// The thread has exited.
    gone: bool,
}

/// The attached process.
struct Target
{
    badge: u64,
    bias: u64,
    threads: Vec<Thread>,
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
    /// Find the target by name and attach to it, stopping every thread. With
    /// no such process the stub serves the port detached, and attaches again
    /// at GDB's next connection.
    fn attach(&mut self, ipc_buf: *mut u64)
    {
        let mut badge = None;
        for _ in 0..FIND_ATTEMPTS
        {
            badge = find_process(self.debug, self.name.as_bytes(), ipc_buf);
            if badge.is_some()
            {
                break;
            }
            std::thread::sleep(FIND_INTERVAL);
        }
        let Some(badge) = badge
        else
        {
            std::os::seraph::log!("no process named {} to attach to", self.name);
            return;
        };
        let Some((bias, caps)) = attach_process(self.debug, badge, self.self_thread, ipc_buf)
        else
        {
            std::os::seraph::log!("attach to {} refused", self.name);
            return;
        };
        let mut threads = Vec::new();
        for (i, cap) in caps.into_iter().enumerate()
        {
            if !self.ensure_receiver(i) || !bind_thread(self.endpoint, cap, i)
            {
                let _ = syscall::cap_delete(cap);
                continue;
            }
            threads.push(Thread {
                cap,
                held: None,
                gone: false,
            });
        }
        self.target = Some(Target {
            badge,
            bias,
            threads,
        });
        self.current = 0;
        self.stop_all();
        std::os::seraph::log!("{READY_MARKER} ({})", self.name);
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
    /// bounded, for each stop to arrive.
    fn stop_all(&mut self)
    {
        let Some(target) = &mut self.target
        else
        {
            return;
        };
        let mut waiting = 0;
        for t in target
            .threads
            .iter_mut()
            .filter(|t| !t.gone && t.held.is_none())
        {
            match syscall::thread_post_upcall(t.cap, 0, syscall_abi::UPCALL_ANY_INSTRUCTION)
            {
                Ok(()) => waiting += 1,
                Err(_) if !thread_alive(t.cap) => t.gone = true,
                Err(_) =>
                {}
            }
        }
        let deadline = Instant::now() + STOP_WAIT;
        while waiting > 0 && Instant::now() < deadline
        {
            match self.events.try_recv()
            {
                Ok(stop) =>
                {
                    if self.hold(stop).is_some()
                    {
                        waiting -= 1;
                    }
                }
                Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(1)),
                Err(TryRecvError::Disconnected) => break,
            }
        }
        self.running = false;
    }

    /// Record `stop` as its thread's held stop; returns the thread's index.
    /// A stop whose thread already holds one (a thread spawned after the
    /// attach, which copied its spawner's binding) is resumed at once.
    fn hold(&mut self, stop: Stop) -> Option<usize>
    {
        let index = thread_index(stop.badge);
        let Some(thread) = index.and_then(|i| self.target.as_mut()?.threads.get_mut(i))
        else
        {
            self.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
            return None;
        };
        if thread.held.is_some()
        {
            self.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
            return None;
        }
        thread.held = Some(stop);
        index
    }

    fn reply(&self, receiver: usize, label: u64)
    {
        if let Some(tx) = self.receivers.get(receiver)
        {
            let _ = tx.send(label);
        }
    }

    /// Resume every held thread: with `FAULT_REPLY_RESUME`, or, for the
    /// thread the last stop named when GDB passes it a signal, with
    /// `FAULT_REPLY_KILL`, so the fault takes the outcome it has with no
    /// handler.
    fn resume_all(&mut self, signal: Option<u8>)
    {
        let current = self.current;
        let Some(target) = &mut self.target
        else
        {
            return;
        };
        let mut replies = Vec::new();
        for (i, t) in target.threads.iter_mut().enumerate()
        {
            if let Some(stop) = t.held.take()
            {
                let pass = i == current && signal.is_some_and(|s| s != 0);
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
        for (receiver, label) in replies
        {
            self.reply(receiver, label);
        }
        self.running = true;
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
        let Ok(undo) = arch::current::prepare_step(t.cap, &mut file[..size])
        else
        {
            return false;
        };
        // SAFETY: the register file was read from this held thread just
        // above; only the trap flag changed.
        if unsafe { syscall::thread_write_regs(t.cap, &file[..size]) }.is_err()
        {
            arch::current::finish_step(t.cap, undo, &mut file[..size]);
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
        if let Some(step) = self.stepping.take()
            && let Some(t) = self
                .target
                .as_ref()
                .and_then(|t| t.threads.get(step.thread))
        {
            let mut file = [0u8; 512];
            let size = regs::file_size(ARCH);
            if syscall::thread_read_regs(t.cap, &mut file[..size]).is_ok()
            {
                arch::current::finish_step(t.cap, step.undo, &mut file[..size]);
                // SAFETY: read from this held thread just above.
                let _ = unsafe { syscall::thread_write_regs(t.cap, &file[..size]) };
            }
        }
        // All-stop: hold every other thread too before GDB sees the stop.
        self.stop_all();
        self.current = index;
        let sig = stop_signal(stop.kind, stop.detail);
        self.send(ipc_buf, |w| {
            w.stop_thread(sig, index as u64 + 1);
        });
    }

    /// Detach: write every breakpoint's bytes back, resume every thread,
    /// have procmgr bind the target back to its crash endpoint, and drop the
    /// threads. Also run when the stub's session ends (`k`).
    fn detach(&mut self, ipc_buf: *mut u64)
    {
        let Some(cap) = self.any_thread()
        else
        {
            self.target = None;
            return;
        };
        for bp in self.breakpoints.take_all()
        {
            let _ = write_text(cap, bp.addr, bp.original());
        }
        if let Some(step) = self.stepping.take()
            && let Some(t) = self
                .target
                .as_ref()
                .and_then(|t| t.threads.get(step.thread))
        {
            let mut file = [0u8; 512];
            let size = regs::file_size(ARCH);
            if syscall::thread_read_regs(t.cap, &mut file[..size]).is_ok()
            {
                arch::current::finish_step(t.cap, step.undo, &mut file[..size]);
                // SAFETY: read from this thread just above; only the step's
                // trap flag changed.
                let _ = unsafe { syscall::thread_write_regs(t.cap, &file[..size]) };
            }
        }
        self.resume_all(None);
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
        std::os::seraph::log!(
            "detached from {} (crash bindings restored: {})",
            self.name,
            detached
        );
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
            self.attach(ipc_buf);
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
                        .filter(|&i| !t.threads[i].gone)
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
            Command::Continue { signal, .. } => self.resume_all(signal),
            Command::Step { .. } =>
            {
                let current = self.current;
                if !self.step(current)
                {
                    self.error(ipc_buf, 1);
                }
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
        target.threads.get(index).filter(|t| !t.gone).map(|_| index)
    }

    /// `vCont`: a step action steps its thread, the others held; otherwise
    /// a continue action resumes every thread, passing its signal to the
    /// current one.
    fn vcont(&mut self, actions: VContActions<'_>, ipc_buf: *mut u64)
    {
        let step = actions.iter().find(|a| a.resume == Resume::Step);
        if let Some(action) = step
        {
            let index = action
                .thread
                .and_then(|t| self.select(t))
                .unwrap_or(self.current);
            self.current = index;
            if !self.step(index)
            {
                self.error(ipc_buf, 1);
            }
            return;
        }
        if let Some(action) = actions.iter().find(|a| a.resume == Resume::Continue)
        {
            self.resume_all(action.signal);
        }
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

/// The thread index a binding's badge names.
fn thread_index(badge: u64) -> Option<usize>
{
    if badge & THREAD_BADGE_TAG == 0
    {
        return None;
    }
    usize::try_from(badge & !THREAD_BADGE_TAG)
        .ok()?
        .checked_sub(1)
}

/// Whether `cap` names a thread that has not exited.
fn thread_alive(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall_abi::CAP_INFO_THREAD_STATE)
        .is_ok_and(|packed| (packed >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED)
}

/// Bind thread `index`'s exception and upcall classes to `endpoint` under
/// its badge.
fn bind_thread(endpoint: u64, cap: u64, index: usize) -> bool
{
    let badge = THREAD_BADGE_TAG | (index as u64 + 1);
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

/// Attach to the process `badge` names (`ATTACH_PROCESS`), paging its
/// thread list, at most [`MAX_THREADS`] threads, with the stub's own main
/// thread as procmgr's watch, so the target's crash bindings come back if
/// the stub dies attached. Returns the image's load bias and the threads'
/// caps.
fn attach_process(
    debug: u64,
    badge: u64,
    self_thread: u64,
    ipc_buf: *mut u64,
) -> Option<(u64, Vec<u64>)>
{
    let mut caps = Vec::new();
    let mut first = 0u64;
    loop
    {
        let mut req = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
            .word(0, badge)
            .word(1, first);
        // The watch carries `OBSERVE` alone: procmgr only reads the thread's
        // state, which takes no right.
        if first == 0
            && let Ok(watch) = syscall::cap_derive(self_thread, syscall_abi::RIGHTS_THREAD_OBSERVE)
        {
            req = req.cap(watch);
        }
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(debug, &req.build(), ipc_buf) }.ok()?;
        if reply.label != procmgr_errors::SUCCESS
        {
            return None;
        }
        let count = reply.word(0);
        let bias = reply.word(1);
        let page = reply.caps();
        for &cap in page
        {
            if caps.len() < MAX_THREADS
            {
                caps.push(cap);
            }
            else
            {
                let _ = syscall::cap_delete(cap);
            }
        }
        first += page.len() as u64;
        if page.is_empty() || first >= count || caps.len() >= MAX_THREADS
        {
            return Some((bias, caps));
        }
    }
}
