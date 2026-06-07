// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/output.rs

//! Output sink: mirror a byte run to both the framebuffer (primary) and serial
//! TX (debug). One sink instance is owned by the single consumer thread, so no
//! locking is needed; each call issues IPC on the calling thread's own buffer.
//!
//! The two paths diverge on ANSI: the framebuffer path runs the bytes through
//! an SGR parser ([`ansi::AnsiParser`]) that turns `ESC[…m` colour sequences
//! into `FB_SET_ATTRS` attribute changes (the driver never sees `ESC`), while
//! the serial mirror receives the raw bytes so ANSI-capable serial consumers
//! still see colour.

use ansi::{AnsiParser, Event};
use ipc::{IpcMessage, fb_errors, fb_labels, serial_errors, serial_labels};

/// Maximum payload bytes per `*_WRITE_BYTES` call (label bits 16-31, 0..=512).
const PAYLOAD_MAX: usize = 512;

/// Holds the framebuffer and serial driver write caps plus the SGR parser for
/// the framebuffer path. The framebuffer is optional: a headless boot has none,
/// and the terminal then mirrors to serial only. Cap handles are process-wide;
/// the per-thread IPC buffer is fetched per write. The parser carries colour
/// and partial-sequence state across writes, so the sink is `&mut`.
pub struct Sink
{
    framebuffer: Option<u32>,
    serial: u32,
    parser: AnsiParser,
}

impl Sink
{
    pub fn new(framebuffer: Option<u32>, serial: u32) -> Self
    {
        Self {
            framebuffer,
            serial,
            parser: AnsiParser::new(),
        }
    }

    /// Write `bytes` to each available sink. Driver/IPC errors are logged and
    /// abandon that sink for this run only; the relay keeps going.
    pub fn write(&mut self, bytes: &[u8])
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return;
        }
        // Framebuffer (primary): SGR is parsed into FB_SET_ATTRS colour
        // changes; only literal text reaches FB_WRITE_BYTES.
        if let Some(fb) = self.framebuffer
        {
            self.parser.feed(bytes, |ev| match ev
            {
                Event::Attrs(fg, bg) => fb_set_attrs(fb, fg, bg, ipc_buf),
                Event::Text(text) => write_chunked(
                    fb,
                    fb_labels::FB_WRITE_BYTES,
                    fb_errors::SUCCESS,
                    text,
                    ipc_buf,
                    "framebuffer",
                ),
            });
        }
        // Serial mirror (debug): raw bytes, ESC sequences intact so
        // ANSI-capable serial consumers still see colour.
        write_chunked(
            self.serial,
            serial_labels::SERIAL_WRITE_BYTES,
            serial_errors::SUCCESS,
            bytes,
            ipc_buf,
            "serial",
        );
    }
}

/// Send an `FB_SET_ATTRS` colour change (six-byte RGB payload) to the
/// framebuffer driver. Errors are logged and abandon the attribute for this
/// call; subsequent writes proceed.
fn fb_set_attrs(cap: u32, fg: [u8; 3], bg: [u8; 3], ipc_buf: *mut u64)
{
    let payload = [fg[0], fg[1], fg[2], bg[0], bg[1], bg[2]];
    let msg = IpcMessage::builder(fb_labels::FB_SET_ATTRS | (6u64 << 16))
        .bytes(0, &payload)
        .build();
    // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
    match unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == fb_errors::SUCCESS =>
        {}
        Ok(reply) =>
        {
            std::os::seraph::log!(
                "terminal: framebuffer FB_SET_ATTRS returned label={:#x}",
                reply.label
            );
        }
        Err(_) =>
        {
            std::os::seraph::log!("terminal: framebuffer FB_SET_ATTRS ipc_call failed");
        }
    }
}

/// Submit `bytes` as `*_WRITE_BYTES` calls, chunking to [`PAYLOAD_MAX`]. The
/// framebuffer and serial drivers share this wire format (`label = opcode |
/// (len << 16)`, payload via `.bytes(0, …)`); only the opcode/success code and
/// the cap differ.
fn write_chunked(cap: u32, opcode: u64, success: u64, bytes: &[u8], ipc_buf: *mut u64, label: &str)
{
    let mut rest = bytes;
    while !rest.is_empty()
    {
        let n = rest.len().min(PAYLOAD_MAX);
        let msg = IpcMessage::builder(opcode | ((n as u64) << 16))
            .bytes(0, &rest[..n])
            .build();
        // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
        match unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
        {
            Ok(reply) if reply.label == success =>
            {}
            Ok(reply) =>
            {
                std::os::seraph::log!("terminal: {label} driver returned label={:#x}", reply.label);
                return;
            }
            Err(_) =>
            {
                std::os::seraph::log!("terminal: {label} ipc_call failed mid-write");
                return;
            }
        }
        rest = &rest[n..];
    }
}
