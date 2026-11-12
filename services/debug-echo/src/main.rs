// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/debug-echo/src/main.rs

//! Debug-port fixture: answers fixed GDB remote serial protocol packets on
//! the debug port, so `cargo xtask test-debug-port` proves the transport from
//! the host to a guest service and back without a debugger stub.
//!
//! The packets it answers, and the markers it logs, are specified in
//! `services/debug-echo/README.md`.

use std::time::Duration;

use gdb_rsp::command::Command;
use gdb_rsp::frame::{AckMode, Event, PacketReader, PacketWriter, unescape};
use gdb_rsp::{Error, PACKET_SIZE};
use ipc::{ClassCallError, IpcMessage, devmgr_errors, serial_errors, serial_labels};

/// Logged once the fixture holds the debug port and waits for packets: the
/// host test connects on seeing it. Kept in sync with
/// `xtask/src/commands/test_debug_port.rs`.
const READY_MARKER: &str = "READY on the debug port";

/// The vendor query the fixture echoes: `qSeraph.Echo:<data>` is answered
/// with `<data>`, unescaped and escaped again.
const ECHO_QUERY: &[u8] = b"qSeraph.Echo:";

/// How often, and how long apart, the fixture asks devmgr for the debug port
/// while devmgr has not yet received the drivers directory its driver loads
/// from.
const QUERY_ATTEMPTS: u32 = 200;
const QUERY_INTERVAL: Duration = Duration::from_millis(50);

/// The bounded wait between reads, in milliseconds: the driver signals the
/// RX notification on each interrupt, and the timeout recovers a lost one.
const RX_WAIT_MS: u64 = 20;

/// The most bytes one serial-protocol message carries.
const MAX_MESSAGE_BYTES: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

fn main()
{
    std::os::seraph::log::register_name(b"debug-echo");
    let info = std::os::seraph::startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(debug_port_class) = bootstrap_seed(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("no devmgr.class.debug-port seed; exiting");
        return;
    };
    let Some(port) = query_debug_port(debug_port_class, ipc_buf)
    else
    {
        std::os::seraph::log!("no debug port served; exiting");
        return;
    };
    let rx_notify = register_rx_notify(port, ipc_buf);
    std::os::seraph::log!("{READY_MARKER}");
    serve(port, rx_notify, ipc_buf);
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

/// Ask devmgr for the debug port through `debug_port_class`, the
/// `debug-port` class SEND (`QUERY_DEVICE` at ordinal 0), waiting out its
/// driver's on-disk spawn: devmgr replies `NO_DEVICE` until
/// `SET_DRIVERS_DIR` arrives, and a query received after that waits in
/// devmgr until the on-disk batch has settled.
fn query_debug_port(debug_port_class: u64, ipc_buf: *mut u64) -> Option<u64>
{
    for _ in 0..QUERY_ATTEMPTS
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        match unsafe { ipc::query_device(debug_port_class, 0, ipc_buf) }
        {
            Ok(cap) => return Some(cap),
            Err(ClassCallError::Refused(devmgr_errors::NO_DEVICE)) =>
            {
                std::thread::sleep(QUERY_INTERVAL);
            }
            Err(e) =>
            {
                std::os::seraph::log!("QUERY_DEVICE on the debug-port class refused ({e:?})");
                return None;
            }
        }
    }
    None
}

/// Register a notification the port's driver signals on receive; `0` when
/// none could be registered, and the reads then poll on the bounded wait.
fn register_rx_notify(port: u64, ipc_buf: *mut u64) -> u64
{
    let Some(notif) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
    else
    {
        return 0;
    };
    // IPC moves caps: send a derived copy and keep the original to wait on.
    let Ok(copy) = syscall::cap_derive(notif, syscall::RIGHTS_ALL)
    else
    {
        return notif;
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
    notif
}

/// Read the bytes the port holds into `buf`; returns the count, 0 when none.
fn read(port: u64, buf: &mut [u8; MAX_MESSAGE_BYTES], ipc_buf: *mut u64) -> usize
{
    let req = IpcMessage::new(serial_labels::SERIAL_READ_BYTES);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(port, &req, ipc_buf) })
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

/// Write `bytes` to the port, one message's worth per call.
fn write(port: u64, bytes: &[u8], ipc_buf: *mut u64)
{
    for chunk in bytes.chunks(MAX_MESSAGE_BYTES)
    {
        let req =
            IpcMessage::builder(serial_labels::SERIAL_WRITE_BYTES | ((chunk.len() as u64) << 16))
                .bytes(0, chunk)
                .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(port, &req, ipc_buf) };
    }
}

/// The fixture's connection state: the reader, the acknowledgement mode, and
/// the last reply, which a `-` asks for again.
struct Session
{
    reader: PacketReader<PACKET_SIZE>,
    acks: AckMode,
    last: [u8; PACKET_SIZE],
    last_len: usize,
}

/// Serve packets on the port forever.
fn serve(port: u64, rx_notify: u64, ipc_buf: *mut u64) -> !
{
    let mut session = Session {
        reader: PacketReader::new(),
        acks: AckMode::default(),
        last: [0; PACKET_SIZE],
        last_len: 0,
    };
    let mut buf = [0u8; MAX_MESSAGE_BYTES];
    loop
    {
        let n = read(port, &mut buf, ipc_buf);
        if n == 0
        {
            if rx_notify == 0
            {
                std::thread::sleep(Duration::from_millis(RX_WAIT_MS));
            }
            else
            {
                let _ = syscall::notification_wait_timeout(rx_notify, RX_WAIT_MS);
            }
            continue;
        }
        for &byte in buf.iter().take(n)
        {
            session.take(byte, port, ipc_buf);
        }
    }
}

impl Session
{
    /// Take one received byte; acknowledge and answer what it completes.
    fn take(&mut self, byte: u8, port: u64, ipc_buf: *mut u64)
    {
        let mut reply = [0u8; PACKET_SIZE];
        let (ack, answer) = {
            let Some(event) = self.reader.push(byte)
            else
            {
                return;
            };
            let ack = self.acks.response(&event);
            let answer = match event
            {
                Event::Packet(body) => answer(body, &mut reply),
                Event::Overflow => error_reply(2, &mut reply),
                Event::Interrupt => stop_reply(2, &mut reply),
                Event::Nack =>
                {
                    if let Some(last) = self.last.get(..self.last_len)
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
        let (Some(sent), Some(kept)) = (reply.get(..len), self.last.get_mut(..len))
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

/// Answer one packet body.
fn answer(body: &[u8], out: &mut [u8]) -> Answer
{
    if let Some(data) = body.strip_prefix(ECHO_QUERY)
    {
        return echo_reply(data, out);
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
            Answer::Packet(len) => Answer::NoAckOk(len),
            other => other,
        },
        Ok(Command::HaltReason) => stop_reply(5, out),
        Ok(_) => packet(out, |_| {}),
        Err(Error::Malformed | Error::Overflow) => error_reply(1, out),
    }
}

/// The echo of `qSeraph.Echo:<data>`: the data, unescaped, then escaped
/// again by the writer.
fn echo_reply(escaped: &[u8], out: &mut [u8]) -> Answer
{
    let mut data = [0u8; PACKET_SIZE];
    match unescape(escaped, &mut data)
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
