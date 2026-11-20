// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/input.rs

//! Input sources, one producer thread each, all feeding the consumer's channel
//! as raw [`Msg::Input`] byte runs. Each calls the current driver of its
//! class ([`Device`]); a failed call waits for a newer driver, the restarted
//! instance devmgr serves, for at most [`RETRY_WAIT`], and calls again:
//! - [`keyboard_loop`]: block on the virtio-input keysym stream and decode
//!   key-down events to bytes.
//! - [`serial_loop`]: wake on serial receive interrupts and forward the UART's
//!   received bytes verbatim.
//!
//! Decoding to bytes happens in each source, so the consumer's line discipline
//! is source-agnostic — keyboard and serial bytes flow through the same path.

use std::sync::mpsc::Sender;
use std::time::Duration;

use ipc::{IpcMessage, input_errors, input_labels, keysym, serial_errors, serial_labels};

use crate::Msg;
use device_tracker::{Device, Driver};

/// Bounded wait between serial RX drains. Backstops the edge-triggered
/// delivery the serial driver registers the x86 UART line with (mode 0; a
/// byte racing the driver's interrupt re-arm is recovered on the next tick)
/// and degrades to plain polling when the serial driver holds no IRQ cap.
/// Matches the virtio-input driver's poll interval.
const SERIAL_RX_POLL_MS: u64 = 20;

/// How long a thread whose call on its driver failed waits for a newer
/// driver before it calls the one it holds again: long enough that a driver
/// failing at once is not called in a loop, short enough that a failure
/// devmgr follows with no withdrawal costs one second of input.
const RETRY_WAIT: Duration = Duration::from_secs(1);

/// After a failed call on `held`, the driver to call next: a newer one, or
/// `held` again once [`RETRY_WAIT`] has passed. Logs the first failure on
/// each driver, `what` naming the call.
fn after_failure(device: &Device, held: Driver, what: &str, logged: &mut Option<u64>) -> Driver
{
    if *logged != Some(held.generation)
    {
        *logged = Some(held.generation);
        std::os::seraph::log!(
            warn: "terminal: {what} failed on the driver at ordinal {}; waiting for another",
            held.ordinal
        );
    }
    device.await_newer(held, RETRY_WAIT).unwrap_or(held)
}

/// Block reading the keysym stream of the current input driver, `first` at
/// the start, and forward decoded bytes as [`Msg::Input`]. Returns (ending
/// the thread) only on a closed channel.
pub fn keyboard_loop(device: &Device, first: Driver, tx: &Sender<Msg>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "terminal: keyboard thread has no IPC buffer");
        return;
    }
    let mut driver = first;
    let mut logged = None;
    loop
    {
        let req = IpcMessage::new(input_labels::INPUT_READ_EVENTS);
        // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
        let reply = match unsafe { ipc::ipc_call(driver.cap, &req, ipc_buf) }
        {
            Ok(reply) if reply.label == input_errors::SUCCESS => reply,
            _ =>
            {
                driver = after_failure(device, driver, "INPUT_READ_EVENTS", &mut logged);
                continue;
            }
        };
        // The count is an external (wire) value; clamp it to the ABI maximum so
        // a misbehaving driver cannot drive an out-of-bounds word index.
        let count = usize::try_from(reply.word(0))
            .unwrap_or(0)
            .min(keysym::INPUT_MAX_EVENTS_PER_READ);
        let mut bytes = Vec::new();
        // The events ride words 1..=count, after the count in word 0.
        for word in 1..=count
        {
            let (ks, _mods, pressed) = keysym::unpack_event(reply.word(word));
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
/// [`Msg::Input`]. Registers a notification with the current serial driver,
/// `first` at the start, and again with each driver that replaces it, then
/// loops: drain everything available via `SERIAL_READ_BYTES`, then wait on
/// the notification with a bounded timeout (see [`SERIAL_RX_POLL_MS`]).
/// Received bytes are raw — the consumer's line discipline already handles CR,
/// DEL/BS, and printables, so no decoding is needed here. Returns (ending the
/// thread) only on a failure to create the notification or a closed channel.
pub fn serial_loop(device: &Device, first: Driver, tx: &Sender<Msg>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "terminal: serial RX thread has no IPC buffer");
        return;
    }

    // Notification the driver kicks on receive-data-ready; each driver is sent
    // a copy (`register_rx_notify`).
    let Some(notif) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
    else
    {
        std::os::seraph::log!(error: "terminal: serial RX notification create failed");
        return;
    };
    let mut driver = first;
    register_rx_notify(driver.cap, notif, ipc_buf);
    let mut logged = None;
    loop
    {
        // Drain everything currently buffered before sleeping.
        loop
        {
            let req = IpcMessage::new(serial_labels::SERIAL_READ_BYTES);
            // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
            let reply = match unsafe { ipc::ipc_call(driver.cap, &req, ipc_buf) }
            {
                Ok(reply) if reply.label & 0xFFFF == serial_errors::SUCCESS => reply,
                _ =>
                {
                    let next = after_failure(device, driver, "SERIAL_READ_BYTES", &mut logged);
                    if next.generation != driver.generation
                    {
                        // The new instance holds no registration of the dead one's.
                        register_rx_notify(next.cap, notif, ipc_buf);
                    }
                    driver = next;
                    continue;
                }
            };
            // Count rides bits 16-31 of the reply label; bytes are packed in the
            // data words. Clamp to the byte view so a misbehaving driver cannot
            // over-read.
            let count = ((reply.label >> 16) & 0xFFFF) as usize;
            let bytes = reply.data_bytes();
            let run = bytes.get(..count).unwrap_or(bytes);
            if run.is_empty()
            {
                break;
            }
            if tx.send(Msg::Input(run.to_vec())).is_err()
            {
                return;
            }
        }
        // Block until the next RX interrupt, bounded so an edge-triggered miss
        // (or a missing IRQ) is recovered by the next drain.
        let _ = syscall::notification_wait_timeout(notif, SERIAL_RX_POLL_MS);
    }
}

/// Register a copy of `notif` with the serial driver `cap` as its receive
/// notification. A refusal (`REGISTER_FAILED`: the driver holds no IRQ) or a
/// failed call is not fatal: the bounded wait of [`serial_loop`] then
/// degrades to timed polling.
fn register_rx_notify(cap: u64, notif: u64, ipc_buf: *mut u64)
{
    // IPC moves caps, so a derived copy is sent and `notif` kept to wait on.
    if let Ok(notif_send) = syscall::cap_derive(notif, syscall::RIGHTS_ALL)
    {
        let req = IpcMessage::builder(serial_labels::SERIAL_REGISTER_RX_NOTIFY)
            .cap(notif_send)
            .build();
        // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(cap, &req, ipc_buf) };
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
