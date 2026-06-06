// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/input.rs

//! Keyboard input source: block on the virtio-input keysym stream, decode
//! key-down events into a byte stream, and forward it to the consumer.
//!
//! Decoding to bytes happens here so the consumer is source-agnostic: a future
//! serial-RX source (#66 RX is unimplemented today) becomes another producer
//! feeding the same channel with raw bytes, with no change to the line
//! discipline.

use std::sync::mpsc::Sender;

use ipc::{IpcMessage, input_errors, input_labels, keysym};

use crate::Msg;

/// Block reading the keysym stream and forward decoded bytes as [`Msg::Input`].
/// Returns (ending the thread) only on a fatal IPC error or a closed channel.
pub fn keyboard_loop(input_cap: u32, tx: &Sender<Msg>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("terminal: keyboard thread has no IPC buffer");
        return;
    }
    loop
    {
        let req = IpcMessage::new(input_labels::INPUT_READ_EVENTS);
        // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(input_cap, &req, ipc_buf) })
        else
        {
            std::os::seraph::log!("terminal: INPUT_READ_EVENTS ipc_call failed");
            return;
        };
        if reply.label != input_errors::SUCCESS
        {
            std::os::seraph::log!("terminal: INPUT_READ_EVENTS error label={:#x}", reply.label);
            return;
        }
        let count = reply.word(0) as usize;
        let mut bytes = Vec::new();
        for i in 0..count
        {
            let (ks, _mods, pressed) = keysym::unpack_event(reply.word(1 + i));
            // Act on key-down only; the matching release would double every key.
            if !pressed || is_modifier(ks)
            {
                continue;
            }
            decode_keysym(ks, &mut bytes);
        }
        if !bytes.is_empty() && tx.send(Msg::Input(bytes)).is_err()
        {
            return;
        }
    }
}

/// Modifier keys arrive as their own keysym events; they carry no byte.
fn is_modifier(ks: u32) -> bool
{
    (keysym::SHIFT_L..=keysym::ALT_R).contains(&ks)
}

/// Map one keysym to its byte(s). Printable keysyms are Unicode codepoints;
/// Return becomes CR (the consumer translates CR→LF), Backspace becomes BS.
/// Other named keys (arrows, Home/End/Delete, Tab, Escape) are dropped in
/// v0.0.1.
fn decode_keysym(ks: u32, out: &mut Vec<u8>)
{
    match ks
    {
        keysym::RETURN => out.push(b'\r'),
        keysym::BACKSPACE => out.push(0x08),
        printable if printable < 0xFF00 =>
        {
            if let Some(c) = char::from_u32(printable)
            {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
        _ =>
        {}
    }
}
