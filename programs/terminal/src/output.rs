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
//!
//! Each write takes the current framebuffer and serial drivers from their
//! [`Device`]s, so output reaches the instance devmgr serves after a driver's
//! restart. A new framebuffer instance starts at the driver's default
//! attributes, so the parser starts again with it.

use ansi::{AnsiParser, Event};
use ipc::{IpcMessage, fb_errors, fb_labels, serial_errors, serial_labels};

use device_tracker::Device;

/// Maximum payload bytes per `*_WRITE_BYTES` call (label bits 16-31, 0..=512).
const PAYLOAD_MAX: usize = 512;

/// Holds the framebuffer and serial drivers plus the SGR parser for the
/// framebuffer path. The framebuffer is optional: a headless boot has none,
/// and the terminal then mirrors to serial only. Cap handles are process-wide;
/// the per-thread IPC buffer is fetched per write. The parser carries colour
/// and partial-sequence state across writes, so the sink is `&mut`.
pub struct Sink
{
    framebuffer: Device,
    serial: Device,
    parser: AnsiParser,
    /// The generation of the framebuffer driver the parser's state is for.
    fb_generation: Option<u64>,
    /// The generation of a framebuffer driver no write has reached yet, after
    /// the first: the terminal logs the first write that reaches it.
    fb_unconfirmed: Option<u64>,
}

impl Sink
{
    pub fn new(framebuffer: Device, serial: Device) -> Self
    {
        let fb_generation = framebuffer.current().map(|d| d.generation);
        Self {
            framebuffer,
            serial,
            parser: AnsiParser::new(),
            fb_generation,
            fb_unconfirmed: None,
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
        if let Some(fb) = self.framebuffer.current()
        {
            if self.fb_generation != Some(fb.generation)
            {
                // A new instance, at the driver's default attributes.
                if self.fb_generation.is_some()
                {
                    self.fb_unconfirmed = Some(fb.generation);
                }
                self.fb_generation = Some(fb.generation);
                self.parser = AnsiParser::new();
            }
            let mut reached = false;
            self.parser.feed(bytes, |ev| match ev
            {
                Event::Attrs(fg, bg) => fb_set_attrs(fb.cap, fg, bg, ipc_buf),
                Event::Text(text) =>
                {
                    reached |= write_chunked(
                        fb.cap,
                        fb_labels::FB_WRITE_BYTES,
                        fb_errors::SUCCESS,
                        text,
                        ipc_buf,
                        "framebuffer",
                    );
                    true // text is not deduped; the sink result is for attrs
                }
            });
            if reached && self.fb_unconfirmed == Some(fb.generation)
            {
                self.fb_unconfirmed = None;
                std::os::seraph::log!(
                    "terminal: framebuffer output reaches the driver at ordinal {}",
                    fb.ordinal
                );
            }
        }
        // Serial mirror (debug): raw bytes, ESC sequences intact so
        // ANSI-capable serial consumers still see colour.
        if let Some(serial) = self.serial.current()
        {
            write_chunked(
                serial.cap,
                serial_labels::SERIAL_WRITE_BYTES,
                serial_errors::SUCCESS,
                bytes,
                ipc_buf,
                "serial",
            );
        }
    }
}

/// Send an `FB_SET_ATTRS` colour change (six-byte RGB payload) to the
/// framebuffer driver. Returns whether the driver acknowledged with `SUCCESS`;
/// the parser advances its dedup only on success, so a failed set is retried on
/// the next change rather than masked.
fn fb_set_attrs(cap: u64, fg: [u8; 3], bg: [u8; 3], ipc_buf: *mut u64) -> bool
{
    let payload = [fg[0], fg[1], fg[2], bg[0], bg[1], bg[2]];
    let msg = IpcMessage::builder(fb_labels::FB_SET_ATTRS | (6u64 << 16))
        .bytes(0, &payload)
        .build();
    // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
    match unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == fb_errors::SUCCESS => true,
        Ok(reply) =>
        {
            std::os::seraph::log!(
                warn: "terminal: framebuffer FB_SET_ATTRS returned label={:#x}",
                reply.label
            );
            false
        }
        Err(_) =>
        {
            std::os::seraph::log!(warn: "terminal: framebuffer FB_SET_ATTRS ipc_call failed");
            false
        }
    }
}

/// Submit `bytes` as `*_WRITE_BYTES` calls, chunking to [`PAYLOAD_MAX`]. The
/// framebuffer and serial drivers share this wire format (`label = opcode |
/// (len << 16)`, payload via `.bytes(0, …)`); only the opcode/success code and
/// the cap differ. Returns whether the driver answered every call `success`.
fn write_chunked(
    cap: u64,
    opcode: u64,
    success: u64,
    bytes: &[u8],
    ipc_buf: *mut u64,
    label: &str,
) -> bool
{
    for chunk in bytes.chunks(PAYLOAD_MAX)
    {
        let msg = IpcMessage::builder(opcode | ((chunk.len() as u64) << 16))
            .bytes(0, chunk)
            .build();
        // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
        match unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
        {
            Ok(reply) if reply.label == success =>
            {}
            Ok(reply) =>
            {
                std::os::seraph::log!(
                    warn: "terminal: {label} driver returned label={:#x}",
                    reply.label
                );
                return false;
            }
            Err(_) =>
            {
                std::os::seraph::log!(warn: "terminal: {label} ipc_call failed mid-write");
                return false;
            }
        }
    }
    true
}
