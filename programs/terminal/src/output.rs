// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/output.rs

//! Output sink: mirror a byte run to both the framebuffer (primary) and serial
//! TX (debug). One sink instance is owned by the single consumer thread, so no
//! locking is needed; each call issues IPC on the calling thread's own buffer.

use ipc::{IpcMessage, fb_errors, fb_labels, serial_errors, serial_labels};

/// Maximum payload bytes per `*_WRITE_BYTES` call (label bits 16-31, 0..=512).
const PAYLOAD_MAX: usize = 512;

/// Holds the framebuffer and serial driver write caps. The framebuffer is
/// optional: a headless boot has none, and the terminal then mirrors to serial
/// only. Cap handles are process-wide; the per-thread IPC buffer is fetched per
/// write.
pub struct Sink
{
    framebuffer: Option<u32>,
    serial: u32,
}

impl Sink
{
    pub fn new(framebuffer: Option<u32>, serial: u32) -> Self
    {
        Self {
            framebuffer,
            serial,
        }
    }

    /// Write `bytes` to each available sink. Driver/IPC errors are logged and
    /// abandon that sink for this run only; the relay keeps going.
    pub fn write(&self, bytes: &[u8])
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return;
        }
        if let Some(fb) = self.framebuffer
        {
            write_chunked(
                fb,
                fb_labels::FB_WRITE_BYTES,
                fb_errors::SUCCESS,
                bytes,
                ipc_buf,
                "framebuffer",
            );
        }
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
