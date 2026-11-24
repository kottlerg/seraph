// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/debug-echo/src/main.rs

//! Debug-port fixture: answers fixed GDB remote serial protocol packets on
//! the debug port, so the `debug-port` case proves the transport from
//! the host to a guest service and back without a debugger stub.
//!
//! It follows the debug port across devmgr's restart of its driver
//! (`device_tracker`), so the test's kill of the driver proves the follow
//! too.
//!
//! The packets it answers, and the markers it logs, are specified in
//! `services/fixtures/debug-echo/README.md`.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use device_tracker::Device;

use gdb_rsp::command::Command;
use gdb_rsp::frame::{AckMode, Event, PacketReader, PacketWriter, unescape};
use gdb_rsp::{Error, PACKET_SIZE};
use ipc::{IpcMessage, serial_errors, serial_labels};

/// Logged once the fixture holds the debug port and waits for packets: the
/// host test connects on seeing it. Kept in sync with
/// `xtask/src/commands/test/debug_port/echo.rs`.
const READY_MARKER: &str = "READY on the debug port";

/// The vendor query the fixture echoes: `qSeraph.Echo:<data>` is answered
/// with `<data>`, unescaped and escaped again.
const ECHO_QUERY: &[u8] = b"qSeraph.Echo:";

/// The bounded wait between reads, in milliseconds: the driver signals the
/// RX notification on each interrupt, and the timeout recovers a lost one.
const RX_WAIT_MS: u64 = 20;

/// The most bytes one serial-protocol message carries.
const MAX_MESSAGE_BYTES: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

fn main()
{
    std::os::seraph::log::register_name(b"debug-echo");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(debug_port_class) = bootstrap_seed(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("no devmgr.class.debug-port seed; exiting");
        return;
    };
    let Some(port) = Port::open(debug_port_class, ipc_buf)
    else
    {
        std::os::seraph::log!("no debug port served; exiting");
        return;
    };
    std::os::seraph::log!("{READY_MARKER}");
    // The guard, a temporary of this statement, lives as long as `serve`,
    // which never returns.
    serve(
        &mut BUFFERS.lock().unwrap_or_else(PoisonError::into_inner),
        port,
        ipc_buf,
    );
}

/// Pull the bootstrap round; slot 0 is the recipe's
/// `seed = devmgr.class.debug-port`.
fn bootstrap_seed(creator_ep: u64, ipc_buf: *mut u64) -> Option<u64>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let [cap] = unsafe { ipc::bootstrap::request_slots::<1>(creator_ep, ipc_buf) }.ok()?;
    (cap != 0).then_some(cap)
}

/// The debug port: the `debug-port` class's current driver, followed across
/// devmgr's restart of it, and the RX notification registered with each new
/// instance.
struct Port
{
    device: Device,
    /// The notification the driver signals on receive; `0` when none could
    /// be made, and the reads then poll on the bounded wait.
    rx: u64,
    /// The generation of the driver `rx` was last registered with.
    registered: Option<u64>,
}

impl Port
{
    /// Follow the debug port through `debug_port_class`, the `debug-port`
    /// class SEND, and take its first live driver, waited for without a bound
    /// while devmgr serves none. `None` when the class cannot be followed
    /// and serves none.
    fn open(debug_port_class: u64, ipc_buf: *mut u64) -> Option<Self>
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        let device = unsafe { Device::start(debug_port_class, "debug port", ipc_buf) };
        device.await_first("debug port")?;
        let rx = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        .unwrap_or(0);
        Some(Self {
            device,
            rx,
            registered: None,
        })
    }

    /// The current driver's SEND, after registering the RX notification with
    /// it when it is an instance the notification was not registered with.
    /// `None` while the class serves none.
    fn driver(&mut self, ipc_buf: *mut u64) -> Option<u64>
    {
        let driver = self.device.current()?;
        if self.registered != Some(driver.generation)
        {
            self.registered = Some(driver.generation);
            if self.rx != 0
            {
                register_rx_notify(driver.cap, self.rx, ipc_buf);
            }
        }
        Some(driver.cap)
    }

    /// Wait for received bytes, at most [`RX_WAIT_MS`].
    fn wait(&self)
    {
        if self.rx == 0
        {
            std::thread::sleep(Duration::from_millis(RX_WAIT_MS));
        }
        else
        {
            let _ = syscall::notification_wait_timeout(self.rx, RX_WAIT_MS);
        }
    }
}

/// Register `notif` as the notification `port`'s driver signals on receive,
/// sending a derived copy, since IPC moves caps; a refusal is logged, and the
/// reads then find the bytes on the bounded wait.
fn register_rx_notify(port: u64, notif: u64, ipc_buf: *mut u64)
{
    let Ok(copy) = syscall::cap_derive(notif, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!("RX notification not registered; polling");
        return;
    };
    let req = IpcMessage::builder(serial_labels::SERIAL_REGISTER_RX_NOTIFY)
        .cap(copy)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    match unsafe { ipc::ipc_call(port, &req, ipc_buf) }
    {
        Ok(reply) if reply.label == serial_errors::SUCCESS =>
        {}
        _ => std::os::seraph::log!("RX notification not registered; polling"),
    }
}

/// Read the bytes the port holds into `buf`; returns the count, 0 when none.
fn read(port: &mut Port, buf: &mut [u8; MAX_MESSAGE_BYTES], ipc_buf: *mut u64) -> usize
{
    let Some(cap) = port.driver(ipc_buf)
    else
    {
        return 0;
    };
    let req = IpcMessage::new(serial_labels::SERIAL_READ_BYTES);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(cap, &req, ipc_buf) })
    else
    {
        return 0;
    };
    if reply.label & 0xFFFF != serial_errors::SUCCESS
    {
        return 0;
    }
    // The count rides the label's bits 16-31; clamp it to the bytes carried.
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

/// Write `bytes` to the port, one message's worth per call; dropped while
/// the class serves no driver.
fn write(port: &mut Port, bytes: &[u8], ipc_buf: *mut u64)
{
    let Some(cap) = port.driver(ipc_buf)
    else
    {
        return;
    };
    for chunk in bytes.chunks(MAX_MESSAGE_BYTES)
    {
        let req =
            IpcMessage::builder(serial_labels::SERIAL_WRITE_BYTES | ((chunk.len() as u64) << 16))
                .bytes(0, chunk)
                .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(cap, &req, ipc_buf) };
    }
}

/// The fixture's packet buffers: the reader's, the last reply, which a `-`
/// asks for again, the reply being built, and an echo query's unescaped data.
struct Buffers
{
    reader: PacketReader<PACKET_SIZE>,
    last: [u8; PACKET_SIZE],
    reply: [u8; PACKET_SIZE],
    data: [u8; PACKET_SIZE],
}

/// The packet buffers, 16 KiB, in the image rather than on the 32 KiB
/// main-thread stack the serve loop runs on. The serve loop holds the lock
/// for the process's life; nothing else takes it.
static BUFFERS: Mutex<Buffers> = Mutex::new(Buffers {
    reader: PacketReader::new(),
    last: [0; PACKET_SIZE],
    reply: [0; PACKET_SIZE],
    data: [0; PACKET_SIZE],
});

/// The fixture's connection state: its buffers, the acknowledgement mode, and
/// the length of the last reply.
struct Session<'a>
{
    buffers: &'a mut Buffers,
    acks: AckMode,
    last_len: usize,
}

/// Serve packets on the port forever, with the packet buffers `buffers`.
fn serve(buffers: &mut Buffers, mut port: Port, ipc_buf: *mut u64) -> !
{
    let mut session = Session {
        buffers,
        acks: AckMode::default(),
        last_len: 0,
    };
    let mut buf = [0u8; MAX_MESSAGE_BYTES];
    loop
    {
        let n = read(&mut port, &mut buf, ipc_buf);
        if n == 0
        {
            port.wait();
            continue;
        }
        for &byte in buf.iter().take(n)
        {
            session.take(byte, &mut port, ipc_buf);
        }
    }
}

impl Session<'_>
{
    /// Take one received byte; acknowledge and answer what it completes.
    fn take(&mut self, byte: u8, port: &mut Port, ipc_buf: *mut u64)
    {
        let Buffers {
            reader,
            last,
            reply,
            data,
        } = &mut *self.buffers;
        let (ack, answer) = {
            let Some(event) = reader.push(byte)
            else
            {
                return;
            };
            let ack = self.acks.response(&event);
            let answer = match event
            {
                Event::Packet(body) => answer(body, reply, data),
                Event::Overflow => error_reply(2, reply),
                Event::Interrupt => stop_reply(2, reply),
                Event::Nack =>
                {
                    if let Some(last) = last.get(..self.last_len)
                    {
                        write(port, last, ipc_buf);
                    }
                    Answer::None
                }
                Event::Ack | Event::BadChecksum => Answer::None,
            };
            (ack, answer)
        };
        if let Some(a) = ack
        {
            write(port, &[a], ipc_buf);
        }
        let (len, no_ack_after) = match answer
        {
            Answer::None => return,
            Answer::Packet(len) => (len, false),
            Answer::NoAckOk(len) => (len, true),
        };
        let (Some(sent), Some(kept)) = (reply.get(..len), last.get_mut(..len))
        else
        {
            return;
        };
        write(port, sent, ipc_buf);
        kept.copy_from_slice(sent);
        self.last_len = len;
        if no_ack_after
        {
            self.acks.enter_no_ack();
            std::os::seraph::log!("no-ack mode");
        }
    }
}

/// What a received event is answered with: nothing, or a packet of the
/// given length in the reply buffer, after which `NoAckOk` enters no-ack
/// mode.
enum Answer
{
    None,
    Packet(usize),
    NoAckOk(usize),
}

/// Answer one packet body into `out`; `data` takes an echo query's
/// unescaped data.
fn answer(body: &[u8], out: &mut [u8], data: &mut [u8]) -> Answer
{
    if let Some(escaped) = body.strip_prefix(ECHO_QUERY)
    {
        return echo_reply(escaped, out, data);
    }
    match Command::parse(body)
    {
        Ok(Command::Supported(_)) => packet(out, |w| {
            w.supported();
        }),
        Ok(Command::StartNoAckMode) => match packet(out, |w| {
            w.ok();
        })
        {
            Answer::Packet(len) | Answer::NoAckOk(len) => Answer::NoAckOk(len),
            Answer::None => Answer::None,
        },
        Ok(Command::HaltReason) => stop_reply(5, out),
        Ok(_) => packet(out, |_| {}),
        Err(Error::Malformed | Error::Overflow) => error_reply(1, out),
    }
}

/// The echo of `qSeraph.Echo:<data>`: the data, unescaped into `data`, then
/// escaped again by the writer.
fn echo_reply(escaped: &[u8], out: &mut [u8], data: &mut [u8]) -> Answer
{
    match unescape(escaped, data)
    {
        Ok(n) => packet(out, |w| {
            w.bytes(data.get(..n).unwrap_or_default());
        }),
        Err(_) => error_reply(1, out),
    }
}

fn stop_reply(signal: u8, out: &mut [u8]) -> Answer
{
    packet(out, |w| {
        w.stop_signal(signal);
    })
}

fn error_reply(code: u8, out: &mut [u8]) -> Answer
{
    packet(out, |w| {
        w.error(code);
    })
}

/// Write one packet whose body `body` fills into `out`.
fn packet(out: &mut [u8], body: impl FnOnce(&mut PacketWriter<'_>)) -> Answer
{
    let mut w = PacketWriter::new(out);
    body(&mut w);
    if let Ok(len) = w.finish()
    {
        Answer::Packet(len)
    }
    else
    {
        std::os::seraph::log!("reply past the packet buffer; not sent");
        Answer::None
    }
}
