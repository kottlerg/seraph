// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/input.rs

//! Input sources, one producer thread each, all feeding the consumer's channel
//! as raw [`Msg::Input`] byte runs:
//! - [`keyboard_loop`]: block on the virtio-input keysym stream and decode
//!   key-down events to bytes.
//! - [`serial_loop`]: wake on serial receive interrupts and forward the UART's
//!   received bytes verbatim.
//!
//! Decoding to bytes happens in each source, so the consumer's line discipline
//! is source-agnostic — keyboard and serial bytes flow through the same path.

use std::sync::mpsc::Sender;

use ipc::{IpcMessage, input_errors, input_labels, keysym, serial_errors, serial_labels};

use crate::Msg;

/// Bounded wait between serial RX drains. Backstops the x86 IOAPIC's
/// edge-triggered delivery (a byte racing the driver's interrupt re-arm is
/// recovered on the next tick) and degrades to plain polling when the serial
/// driver holds no IRQ cap. Matches the virtio-input driver's poll interval.
const SERIAL_RX_POLL_MS: u64 = 20;

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
        // The count is an external (wire) value; clamp it to the ABI maximum so
        // a misbehaving driver cannot drive an out-of-bounds word index.
        let count = usize::try_from(reply.word(0))
            .unwrap_or(0)
            .min(keysym::INPUT_MAX_EVENTS_PER_READ);
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

/// Wake on serial receive interrupts and forward incoming UART bytes as
/// [`Msg::Input`]. Registers a notification with the serial driver, then loops:
/// drain everything available via `SERIAL_READ_BYTES`, then wait on the
/// notification with a bounded timeout (see [`SERIAL_RX_POLL_MS`]). Received
/// bytes are raw — the consumer's line discipline already handles CR, DEL/BS,
/// and printables, so no decoding is needed here. Returns (ending the thread)
/// only on a fatal IPC error or a closed channel.
pub fn serial_loop(serial_cap: u32, tx: &Sender<Msg>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("terminal: serial RX thread has no IPC buffer");
        return;
    }

    // Notification the driver kicks on receive-data-ready. Keep `notif` to wait
    // on; send a derived copy to the driver — IPC moves caps, so sending the
    // original would forfeit our wait handle.
    let Some(notif) = std::os::seraph::object_slab_acquire(120)
        .and_then(|slab| syscall::cap_create_notification(slab).ok())
    else
    {
        std::os::seraph::log!("terminal: serial RX notification create failed");
        return;
    };
    if let Ok(notif_send) = syscall::cap_derive(notif, syscall::RIGHTS_ALL)
    {
        let req = IpcMessage::builder(serial_labels::SERIAL_REGISTER_RX_NOTIFY)
            .cap(notif_send)
            .build();
        // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer. A
        // REGISTER_FAILED reply (driver holds no IRQ) is non-fatal — the bounded
        // wait below then degrades to timed polling.
        let _ = unsafe { ipc::ipc_call(serial_cap, &req, ipc_buf) };
    }

    loop
    {
        // Drain everything currently buffered before sleeping.
        loop
        {
            let req = IpcMessage::new(serial_labels::SERIAL_READ_BYTES);
            // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
            let Ok(reply) = (unsafe { ipc::ipc_call(serial_cap, &req, ipc_buf) })
            else
            {
                std::os::seraph::log!("terminal: SERIAL_READ_BYTES ipc_call failed");
                return;
            };
            if reply.label & 0xFFFF != serial_errors::SUCCESS
            {
                std::os::seraph::log!("terminal: SERIAL_READ_BYTES error label={:#x}", reply.label);
                return;
            }
            // Count rides bits 16-31 of the reply label; bytes are packed in the
            // data words. Clamp to the byte view so a misbehaving driver cannot
            // over-read.
            let count = ((reply.label >> 16) & 0xFFFF) as usize;
            let bytes = reply.data_bytes();
            let n = count.min(bytes.len());
            if n == 0
            {
                break;
            }
            if tx.send(Msg::Input(bytes[..n].to_vec())).is_err()
            {
                return;
            }
        }
        // Block until the next RX interrupt, bounded so an edge-triggered miss
        // (or a missing IRQ) is recovered by the next drain.
        let _ = syscall::notification_wait_timeout(notif, SERIAL_RX_POLL_MS);
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
