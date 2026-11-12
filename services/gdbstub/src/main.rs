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
//!
//! # The target is never the stub
//!
//! The stub writes memory only through a thread cap procmgr's
//! `ATTACH_PROCESS` listed, and serves only once its own
//! `DECLARE_NO_DEBUG` was accepted. From then on procmgr refuses an attach
//! to the stub, under its process badge or a crash badge, and refuses the
//! registration of every thread it spawns, so no list holds a thread of the
//! stub's through the stub's own entry (`services/procmgr/docs/ipc-interface.md`
//! § Label 21). Another process's list could hold one only if a holder of
//! `CONTROL` on that thread registered it there: the stub hands out no
//! thread cap of its own but the watch, which procmgr keeps and never lists,
//! and its creator, svcmgr, which holds its main thread's, registers only its
//! own threads. So a `SYS_THREAD_WRITE_MEM` of the stub's writes another
//! address space, which its `# Safety` contract does not constrain.

mod arch;

use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::time::{Duration, Instant};

use arch::{ARCH, BREAKPOINT_PC_ADVANCE, StepUndo};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::command::{BreakpointType, Command, ThreadId, ThreadOp, VContActions};
use gdb_rsp::frame::{AckMode, Event, PacketReader, PacketWriter, unescape};
use gdb_rsp::target::TARGET_XML_ANNEX;
use gdbstub::breakpoints;
use gdbstub::control::{self, Plan};
use gdbstub::session::{self, Kernel, Page, Resumed, Session, Stop};
use gdbstub::{regs, signal, stop_signal};
use ipc::{
    ClassCallError, IpcMessage, devmgr_errors, procmgr_errors, procmgr_labels, serial_errors,
    serial_labels, svcmgr_labels,
};

/// Logged once the stub is attached and serves the debug port; the batch
/// test connects GDB on seeing it. Kept in sync with
/// `xtask/src/commands/test_gdb.rs`.
const READY_MARKER: &str = "attached; serving the debug port";

/// How long, and how often, the stub looks for the debug port, and for its
/// target in procmgr's process list at startup before it serves the port
/// detached.
const FIND_ATTEMPTS: u32 = 600;
const FIND_INTERVAL: Duration = Duration::from_millis(100);

/// How many times a `qSupported` that finds the stub detached looks for the
/// target, [`FIND_INTERVAL`] apart: 5 s, well inside the 30 s remote timeout
/// of the GDB command line xtask prints.
const REATTACH_ATTEMPTS: u32 = 50;

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
    // a thread, so no other holder stops it while it stops a target. The
    // declaration is also what keeps the stub's own address space out of
    // its target: procmgr refuses an attach to a declared process
    // (`NOT_ATTACHABLE`), so a stub whose declaration failed does not serve.
    // SAFETY: ipc_buf is the registered IPC buffer.
    let declared = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &IpcMessage::new(procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    }
    .is_ok_and(|r| r.label == procmgr_errors::SUCCESS);
    if !declared
    {
        std::os::seraph::log!(error: "DECLARE_NO_DEBUG not accepted; exiting");
        return;
    }
    // The recipe's seed is `devmgr.class.debug-port`; `debug_authority = yes`
    // delivers the authority cap in the slot after it.
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok([debug_port_class, debug]) =
        (unsafe { ipc::bootstrap::request_slots::<2>(info.creator_endpoint, ipc_buf) })
    else
    {
        std::os::seraph::log!(error: "no bootstrap caps; exiting");
        return;
    };
    let Some(name) = std::env::args().nth(1)
    else
    {
        std::os::seraph::log!(error: "no target name in argv; exiting");
        return;
    };
    if debug_port_class == 0 || debug == 0
    {
        std::os::seraph::log!(
            error: "devmgr.class.debug-port or the debug authority missing; exiting"
        );
        return;
    }
    let Some(port) = Port::open(debug_port_class, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "no debug port served; exiting");
        return;
    };
    let Some(endpoint) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
    else
    {
        std::os::seraph::log!(error: "no fault endpoint; exiting");
        return;
    };
    let (events_tx, events) = channel();
    let mut stub = Stub {
        port,
        reader: PacketReader::new(),
        acks: AckMode::default(),
        last: Vec::new(),
        name,
        self_thread: info.self_thread,
        sys: Sys {
            debug,
            endpoint,
            ipc_buf,
            target: 0,
            events,
            events_tx,
            receivers: Vec::new(),
            step: None,
            receiver_short: false,
            start: Instant::now(),
        },
        session: None,
        bias: 0,
    };
    stub.attach(FIND_ATTEMPTS);
    stub.serve(ipc_buf);
}

// ── The debug port ───────────────────────────────────────────────────────────

/// The debug port: the serial-protocol cap devmgr serves through the
/// `debug-port` class SEND, and the notification its driver signals on receive (`0` with
/// none registered).
struct Port
{
    cap: u64,
    rx: u64,
}

impl Port
{
    /// Take the port from devmgr through `debug_port_class`, the
    /// `debug-port` class SEND (`QUERY_DEVICE` at ordinal 0), waiting out
    /// its driver's on-disk spawn, and register an RX notification on it.
    fn open(debug_port_class: u64, ipc_buf: *mut u64) -> Option<Self>
    {
        let mut cap = 0;
        for _ in 0..FIND_ATTEMPTS
        {
            // SAFETY: ipc_buf is the registered IPC buffer.
            match unsafe { ipc::query_device(debug_port_class, 0, ipc_buf) }
            {
                Ok(c) =>
                {
                    cap = c;
                    break;
                }
                Err(ClassCallError::Refused(devmgr_errors::NO_DEVICE)) =>
                {
                    std::thread::sleep(FIND_INTERVAL);
                }
                Err(_) => return None,
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
        let (Some(dst), Some(src)) = (buf.get_mut(..n), bytes.get(..n))
        else
        {
            return 0;
        };
        dst.copy_from_slice(src);
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

// ── The kernel the session drives ────────────────────────────────────────────

/// The syscalls and procmgr calls that carry the session's decisions out
/// ([`Kernel`]), and the fault receivers that pass its stops on.
struct Sys
{
    /// The procmgr cap carrying `DEBUG_AUTHORITY`.
    debug: u64,
    /// The stub's fault endpoint, which every bound thread's classes send to.
    endpoint: u64,
    /// The main thread's IPC buffer, on which every call of the stub is made.
    ipc_buf: *mut u64,
    /// The attached process's badge, for the refresh's `ATTACH_PROCESS` and
    /// the detach's `DETACH_PROCESS`.
    target: u64,
    events: Receiver<Stop>,
    events_tx: Sender<Stop>,
    /// Each receiver's reply channel.
    receivers: Vec<Sender<u64>>,
    /// What the step in flight changed, to undo.
    step: Option<StepUndo>,
    /// The last ask for receivers fell short.
    receiver_short: bool,
    start: Instant,
}

impl Sys
{
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
}

impl Kernel for Sys
{
    fn now(&mut self) -> u64
    {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn next_stop(&mut self, until: u64) -> Option<Stop>
    {
        loop
        {
            match self.events.try_recv()
            {
                Ok(stop) => return Some(stop),
                Err(TryRecvError::Empty) if self.now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return None,
            }
        }
    }

    fn receivers(&mut self, count: usize)
    {
        // `count` is nonzero where it is used, so the subtraction cannot saturate.
        let started = count == 0 || self.ensure_receiver(count.saturating_sub(1));
        // Logged once per shortfall: a stop waits on the endpoint until a
        // held one is answered, and the serve loop asks again at each wait.
        if !started && !self.receiver_short
        {
            std::os::seraph::log!(
                warn: "a fault receiver could not be started; a stop waits for one"
            );
        }
        self.receiver_short = !started;
    }

    fn reply(&mut self, receiver: usize, label: u64)
    {
        if let Some(tx) = self.receivers.get(receiver)
        {
            let _ = tx.send(label);
        }
    }

    fn pc(&mut self, cap: u64) -> Option<u64>
    {
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        let part = file.get_mut(..size)?;
        syscall::thread_read_regs(cap, part).ok()?;
        Some(regs::pc(ARCH, part))
    }

    fn set_pc(&mut self, cap: u64, pc: u64) -> bool
    {
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        let Some(part) = file.get_mut(..size)
        else
        {
            return false;
        };
        if syscall::thread_read_regs(cap, part).is_err()
        {
            return false;
        }
        regs::set_pc(ARCH, part, pc);
        // SAFETY: the register file was read from this stopped thread just
        // above; only its pointer changed.
        unsafe { syscall::thread_write_regs(cap, part) }.is_ok()
    }

    fn alive(&mut self, cap: u64) -> bool
    {
        syscall::cap_info(cap, syscall_abi::CAP_INFO_THREAD_STATE)
            .is_ok_and(|packed| (packed >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED)
    }

    fn post_upcall(&mut self, cap: u64) -> bool
    {
        syscall::thread_post_upcall(cap, 0, syscall_abi::UPCALL_ANY_INSTRUCTION).is_ok()
    }

    fn bind(&mut self, slot: usize, cap: u64) -> bool
    {
        if !self.ensure_receiver(slot)
        {
            std::os::seraph::log!(
                warn: "a fault receiver could not be started; thread {} is left unbound",
                slot.saturating_add(1)
            );
            return false;
        }
        let badge = control::thread_badge(slot);
        let Ok(send) = syscall::cap_derive_badge(self.endpoint, syscall::RIGHTS_EP_SEND, badge)
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

    fn unbind_upcall(&mut self, cap: u64)
    {
        let _ = syscall::thread_set_fault_handler(cap, 0, syscall_abi::FAULT_CLASS_UPCALL);
    }

    fn delete(&mut self, cap: u64)
    {
        let _ = syscall::cap_delete(cap);
    }

    fn list(&mut self, first: u64, room: usize) -> Option<Page>
    {
        attach_process(self.debug, self.target, first, None, room, self.ipc_buf).map(|a| a.page)
    }

    fn prepare_step(&mut self, cap: u64) -> bool
    {
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        let Some(part) = file.get_mut(..size)
        else
        {
            return false;
        };
        if syscall::thread_read_regs(cap, part).is_err()
        {
            return false;
        }
        let Ok(undo) = arch::prepare_step(cap, part)
        else
        {
            return false;
        };
        // SAFETY: the register file was read from this held thread just
        // above; only the trap flag changed.
        if unsafe { syscall::thread_write_regs(cap, part) }.is_err()
        {
            // The registers were not written; only a planted c.ebreak needs
            // taking back.
            arch::finish_step_text(cap, undo);
            return false;
        }
        self.step = Some(undo);
        true
    }

    fn undo_step_text(&mut self, cap: u64)
    {
        if let Some(undo) = self.step
        {
            arch::finish_step_text(cap, undo);
        }
    }

    fn undo_step_regs(&mut self, cap: u64)
    {
        let Some(undo) = self.step.take()
        else
        {
            return;
        };
        let mut file = [0u8; 512];
        let size = regs::file_size(ARCH);
        if let Some(part) = file.get_mut(..size)
            && syscall::thread_read_regs(cap, part).is_ok()
        {
            arch::finish_step_regs(undo, part);
            // SAFETY: read from this held thread just above; only the step's
            // trap flag changed.
            let _ = unsafe { syscall::thread_write_regs(cap, part) };
        }
    }

    fn step_abandoned(&mut self, _cap: u64)
    {
        self.step = None;
        if ARCH == gdb_rsp::target::Arch::X86_64
        {
            std::os::seraph::log!(warn: "a step's thread never stopped; its trap flag stays set");
        }
    }

    fn write_text(&mut self, cap: u64, addr: u64, bytes: &[u8]) -> bool
    {
        write_text(cap, addr, bytes)
    }

    fn breakpoint_at(&mut self, cap: u64, addr: u64) -> bool
    {
        // A hit leaves the pointer past x86-64's `int3`, GDB's breakpoint
        // kind 1. RISC-V reports the pointer at its `ebreak`, so nothing is
        // set back there and this is not asked.
        let kind = match ARCH
        {
            gdb_rsp::target::Arch::X86_64 => 1,
            gdb_rsp::target::Arch::Riscv64 => return false,
        };
        let Some(insn) = breakpoints::instruction(ARCH, kind)
        else
        {
            return false;
        };
        let mut bytes = [0u8; breakpoints::MAX_BREAKPOINT_BYTES];
        let Some(bytes) = bytes.get_mut(..insn.len())
        else
        {
            return false;
        };
        syscall::thread_read_mem(cap, addr, bytes).is_ok() && bytes == insn
    }

    fn detach_process(&mut self) -> bool
    {
        let req = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
            .word(0, self.target)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        unsafe { ipc::ipc_call(self.debug, &req, self.ipc_buf) }
            .is_ok_and(|r| r.label == procmgr_errors::SUCCESS)
    }
}

// ── The stub ─────────────────────────────────────────────────────────────────

struct Stub
{
    port: Port,
    reader: PacketReader<PACKET_SIZE>,
    acks: AckMode,
    /// The last packet sent, which a `-` asks for again.
    last: Vec<u8>,
    /// The target's name, as the stub's argv gives it.
    name: String,
    self_thread: u64,
    sys: Sys,
    /// The attached session; `None` while the stub serves the port detached.
    session: Option<Session>,
    /// The attached image's load bias.
    bias: u64,
}

impl Stub
{
    /// Find the target by name, looking `attempts` times, and attach to it,
    /// stopping every thread. With no such process the stub serves the port
    /// detached, and attaches again at GDB's next connection.
    fn attach(&mut self, attempts: u32)
    {
        // A stop left over from an earlier session is declined, not taken
        // for one of this attach's.
        let now = self.sys.now();
        while session::decline_detached(&mut self.sys, now)
        {}
        let mut badge = None;
        for i in 0..attempts
        {
            badge = find_process(self.sys.debug, self.name.as_bytes(), self.sys.ipc_buf);
            if badge.is_some()
            {
                break;
            }
            if i.saturating_add(1) < attempts
            {
                std::thread::sleep(FIND_INTERVAL);
            }
        }
        let Some(badge) = badge
        else
        {
            std::os::seraph::log!(warn: "no process named {} to attach to", self.name);
            return;
        };
        let watch = Some(self.self_thread);
        let Some(attached) = attach_process(
            self.sys.debug,
            badge,
            0,
            watch,
            session::MAX_THREADS,
            self.sys.ipc_buf,
        )
        else
        {
            std::os::seraph::log!(warn: "attach to {} refused", self.name);
            return;
        };
        self.sys.target = badge;
        self.bias = attached.bias;
        self.session = Some(Session::attach(
            &mut self.sys,
            BREAKPOINT_PC_ADVANCE,
            attached.page,
        ));
        std::os::seraph::log!("{READY_MARKER} ({})", self.name);
    }

    /// Carry out a resume packet's `plan`, after moving the planned thread's
    /// pointer to `addr` when the packet gives one.
    fn resume(&mut self, plan: Plan, addr: Option<u64>, ipc_buf: *mut u64)
    {
        let Some(session) = &mut self.session
        else
        {
            self.send(ipc_buf, |w| {
                w.exited(0);
            });
            return;
        };
        match session.resume(&mut self.sys, plan, addr)
        {
            Resumed::Running =>
            {}
            Resumed::Refused => self.error(ipc_buf, 1),
            Resumed::Exited =>
            {
                // Every thread exited: no stop will come, so the target is
                // reported gone rather than left running.
                if let Some(session) = self.session.take()
                {
                    session.drop_all(&mut self.sys);
                }
                self.send(ipc_buf, |w| {
                    w.exited(0);
                });
            }
        }
    }

    /// Take the stops that arrived while the target ran, and report the one
    /// that stops it; detached, decline what arrives.
    fn poll(&mut self, ipc_buf: *mut u64)
    {
        let Some(session) = &mut self.session
        else
        {
            let now = self.sys.now();
            while session::decline_detached(&mut self.sys, now)
            {}
            return;
        };
        if let Some((index, stop)) = session.poll(&mut self.sys)
        {
            let sig = stop_signal(stop.kind, stop.detail);
            self.send(ipc_buf, |w| {
                w.stop_thread(sig, (index as u64).saturating_add(1));
            });
        }
    }

    /// Detach ([`Session::detach`]); also run when the stub's session ends
    /// (`k`).
    fn detach(&mut self)
    {
        let Some(session) = self.session.take()
        else
        {
            return;
        };
        let detached = session.detach(&mut self.sys);
        std::os::seraph::log!(
            "detached from {} (crash bindings restored: {})",
            self.name,
            detached
        );
    }

    /// The cap of a live thread of the target, for memory access.
    fn any_thread(&self) -> Option<u64>
    {
        self.session.as_ref()?.any_cap()
    }

    // ── The serve loop ───────────────────────────────────────────────────

    fn serve(&mut self, ipc_buf: *mut u64) -> !
    {
        let mut buf = [0u8; MAX_MESSAGE_BYTES];
        loop
        {
            let n = self.port.read(&mut buf, ipc_buf);
            for &byte in buf.iter().take(n)
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
                Event::Packet(b) => match body.get_mut(..b.len())
                {
                    Some(dst) =>
                    {
                        dst.copy_from_slice(b);
                        b.len()
                    }
                    None => 0,
                },
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
            Some(EventKind::Packet) => self.command(body.get(..len).unwrap_or_default(), ipc_buf),
            Some(EventKind::Interrupt)
                if self
                    .session
                    .as_mut()
                    .is_some_and(|s| s.interrupt(&mut self.sys)) =>
            {
                let thread = (self.current() as u64).saturating_add(1);
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
        if self.session.is_none() && matches!(command, Command::Supported(_))
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
            Command::HaltReason => match &self.session
            {
                Some(_) =>
                {
                    let thread = (self.current() as u64).saturating_add(1);
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
                let bias = self.bias;
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
                let ids = self
                    .session
                    .as_ref()
                    .map_or_else(Vec::new, Session::live_ids);
                self.send(ipc_buf, |w| {
                    w.thread_list(&ids);
                });
            }
            Command::ThreadInfoNext => self.send(ipc_buf, |w| {
                w.thread_list(&[]);
            }),
            Command::CurrentThread =>
            {
                let thread = (self.current() as u64).saturating_add(1);
                self.send(ipc_buf, |w| {
                    w.current_thread(thread);
                });
            }
            Command::SetThread { op, thread } => match (op, self.select(thread))
            {
                (ThreadOp::General, Some(i)) =>
                {
                    if let Some(s) = &mut self.session
                    {
                        s.current = i;
                    }
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
                let ok = unescape(data, &mut bytes)
                    .is_ok_and(|n| bytes.get(..n).is_some_and(|b| self.write_memory(addr, b)));
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
                let plan = control::plan_resume(false, signal, self.current());
                self.resume(plan, addr, ipc_buf);
            }
            Command::Step { addr, signal } =>
            {
                let plan = control::plan_resume(true, signal, self.current());
                self.resume(plan, addr, ipc_buf);
            }
            Command::VContQuery => self.send(ipc_buf, |w| {
                w.vcont_actions();
            }),
            Command::VCont(actions) => self.vcont(actions, ipc_buf),
            Command::Detach =>
            {
                self.detach();
                self.ok(ipc_buf);
            }
            Command::Kill => self.detach(),
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

    /// The slot of the live thread `thread` names ([`Session::select`]).
    fn select(&self, thread: ThreadId) -> Option<usize>
    {
        self.session.as_ref()?.select(thread)
    }

    /// The slot of the thread register and memory commands act on.
    fn current(&self) -> usize
    {
        self.session.as_ref().map_or(0, |s| s.current)
    }

    /// `vCont`: as [`control::plan_vcont`] plans it.
    fn vcont(&mut self, actions: VContActions<'_>, ipc_buf: *mut u64)
    {
        let actions: Vec<_> = actions.iter().collect();
        let plan = control::plan_vcont(actions.iter().copied(), self.current(), |t| self.select(t));
        self.resume(plan, None, ipc_buf);
    }

    /// The current thread's register file, read; `None` without a target or
    /// when the read fails (the thread exited, or is not held).
    fn read_file(&self) -> Option<(u64, [u8; 512])>
    {
        let session = self.session.as_ref()?;
        let cap = session.cap(session.current)?;
        let mut file = [0u8; 512];
        let part = file.get_mut(..regs::file_size(ARCH))?;
        syscall::thread_read_regs(cap, part).ok()?;
        Some((cap, file))
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
        let Some(part) = file.get_mut(..regs::file_size(ARCH))
        else
        {
            self.error(ipc_buf, 1);
            return;
        };
        let applied = match regnum
        {
            None => regs::write_registers(ARCH, hex, part),
            Some(n) => regs::write_register(ARCH, n, hex, part),
        };
        // SAFETY: `file` is the held thread's own register file, as read
        // above, with GDB's values in the fields the stub lets it write.
        let ok = applied.is_ok() && unsafe { syscall::thread_write_regs(cap, part) }.is_ok();
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
        let mut read = 0usize;
        for chunk in bytes.chunks_mut(syscall_abi::MAX_THREAD_MEM_COPY)
        {
            let Some(at) = addr.checked_add(read as u64)
            else
            {
                break;
            };
            if syscall::thread_read_mem(cap, at, chunk).is_err()
            {
                break;
            }
            // `chunk` is part of `bytes`, so `read` stays at most `len`.
            read = read.saturating_add(chunk.len());
        }
        if read == 0 && len != 0
        {
            self.error(ipc_buf, 1);
            return;
        }
        self.send(ipc_buf, |w| {
            w.hex(bytes.get(..read).unwrap_or_default());
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
                let Some(at) =
                    addr.checked_add(i.saturating_mul(syscall_abi::MAX_THREAD_MEM_COPY) as u64)
                else
                {
                    return false;
                };
                // SAFETY: the write lands in the target's address space, not
                // the stub's own (module doc, § The target is never the
                // stub); every thread of the target is held.
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
        let Some(session) = &mut self.session
        else
        {
            return false;
        };
        if session.breakpoints.contains(addr)
        {
            return true;
        }
        let Some(cap) = session.any_cap()
        else
        {
            return false;
        };
        let mut saved = [0u8; breakpoints::MAX_BREAKPOINT_BYTES];
        let Some(saved) = saved.get_mut(..insn.len())
        else
        {
            return false;
        };
        if syscall::thread_read_mem(cap, addr, saved).is_err() || !write_text(cap, addr, insn)
        {
            return false;
        }
        session.breakpoints.insert(addr, saved);
        true
    }

    /// `z0`: write the saved bytes back.
    fn remove_breakpoint(&mut self, addr: u64) -> bool
    {
        let Some(session) = &mut self.session
        else
        {
            return false;
        };
        let Some(cap) = session.any_cap()
        else
        {
            return false;
        };
        match session.breakpoints.remove(addr)
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
    // own (module doc, § The target is never the stub), and every thread of
    // the target is held, as a text write requires
    // (docs/fault-handling.md § Debugging).
    unsafe { syscall::thread_write_mem(cap, addr, bytes, syscall_abi::THREAD_MEM_TEXT) }.is_ok()
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
            if entry_name.get(..len) == Some(name)
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
    /// The page of the thread list, at most the room given.
    page: Page,
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
        next = next.saturating_add(page.len() as u64);
        if page.is_empty() || next >= count || caps.len() >= room
        {
            return Some(AttachPage {
                bias: reply.word(1),
                page: Page {
                    count,
                    complete: first.saturating_add(caps.len() as u64) >= count,
                    caps,
                },
            });
        }
    }
}
