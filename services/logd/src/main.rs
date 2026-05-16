// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// logd/src/main.rs

//! Seraph system log daemon — post-mount owner of the master log
//! endpoint.
//!
//! Spawned by init at the end of Phase 2, real-logd:
//!
//! 1. Receives via bootstrap protocol a RECV cap on the master log
//!    endpoint, a SEND cap on the same endpoint (single-use, for the
//!    `HANDOVER_PULL` IPC to init-logd), a SEND cap on procmgr
//!    carrying `DEATH_EQ_AUTHORITY` (for `REGISTER_DEATH_EQ`), and
//!    an arch-specific serial-authority cap (`IoPortRange` on
//!    x86-64, `SbiControl` on RISC-V) for direct UART output.
//! 2. Drains init-logd's captured state via `HANDOVER_PULL` until
//!    `DONE`. Init-logd self-terminates immediately after replying
//!    `DONE`.
//! 3. Creates an `EventQueue` for procmgr-routed death notifications.
//! 4. Registers the EQ with procmgr via `REGISTER_DEATH_EQ`. Procmgr
//!    retroactively binds it on every existing thread and on every
//!    future spawn (correlator = process token, equal to the log
//!    token logd sees on `STREAM_BYTES`).
//! 5. Enters the main wait loop, draining death notifications first
//!    then servicing log endpoint messages.
//!
//! Logd does NOT use `seraph::log!` for its own diagnostics — it IS
//! the log receiver, so a `log!` call would self-IPC into the
//! endpoint it serves and deadlock once init-logd has terminated.
//! Diagnostics + received log lines are emitted directly to serial
//! via `arch::current::serial_write_byte`, mirroring init-logd's
//! `flush_synthetic_logd_line` pattern.
//!
//! The pre-existing tokened SEND caps held by memmgr, procmgr,
//! tier-1 services, and every Phase-3 child remain valid across the
//! handover — same kernel endpoint object, only the RECV-holder
//! changes.

// The `seraph` target is not in rustc's recognised-OS list, so `std`
// is `restricted_std`-gated for downstream bins.
#![feature(restricted_std)]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod handover;
mod slot;

use core::fmt::Write;

use ipc::stream_labels::{STREAM_BYTES, STREAM_REGISTER_NAME};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use std::os::seraph::startup_info;

use crate::slot::{LINE_BUF_SIZE, MAX_NAME_LEN, SlotTable};

/// `WaitSet` token for the master log endpoint.
const WS_TOKEN_LOG: u64 = 0;
/// `WaitSet` token for the death-notification event queue.
const WS_TOKEN_DEATH: u64 = 1;

/// Caps real-logd receives from init's bootstrap round.
struct BootCaps
{
    /// RECV cap on the master log endpoint. Real-logd is now the
    /// RECV-holder; init-logd has already terminated by the time
    /// this cap is in use.
    log_ep_recv: u32,
    /// SEND cap on the master log endpoint, used only for the
    /// `HANDOVER_PULL` IPC to init-logd. Deleted after handover.
    log_ep_handover_send: u32,
    /// SEND cap on procmgr carrying `DEATH_EQ_AUTHORITY`, used to
    /// call `REGISTER_DEATH_EQ`. Kept across the lifetime of
    /// real-logd in case re-registration is ever needed.
    procmgr_death_auth_send: u32,
    /// Arch-specific serial-authority cap. `IoPortRange` on x86-64
    /// (bound to logd's main thread for COM1 access);
    /// `SbiControl` on RISC-V (used for SBI legacy
    /// `console_putchar`). Zero disables serial output (logd then
    /// buffers received log lines in memory only).
    arch_serial_cap: u32,
}

fn bootstrap_caps(creator_endpoint: u32, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 4 || !round.done
    {
        return None;
    }
    Some(BootCaps {
        log_ep_recv: round.caps[0],
        log_ep_handover_send: round.caps[1],
        procmgr_death_auth_send: round.caps[2],
        arch_serial_cap: round.caps[3],
    })
}

fn main() -> !
{
    let startup = startup_info();

    // IPC buffer is registered by `_start`; reinterpret as `*mut u64`.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // Wire serial output BEFORE handover, so logd's own diagnostics
    // are visible. On x86-64 this binds the IoPortRange cap to
    // logd's main thread; on RISC-V it stashes the SbiControl cap
    // for SBI calls.
    arch::current::serial_init(startup.self_thread, caps.arch_serial_cap);

    self_log("started; pulling init-logd handover state");

    let mut table = SlotTable::default();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    unsafe { handover::pull_all(caps.log_ep_handover_send, ipc_buf, &mut table) };

    // Handover send cap is single-use; drop it now so we don't carry a
    // SEND cap to the log endpoint around (the only legitimate path
    // for that cap was the handover IPC).
    let _ = syscall::cap_delete(caps.log_ep_handover_send);

    {
        let mut buf = SerialFmt::new();
        let _ = write!(
            buf,
            "handover complete: {} slots, {} history lines",
            table.slots.len(),
            table.slots.values().map(|s| s.history.len()).sum::<usize>(),
        );
        buf.flush_self_log();
    }

    let Some(death_eq) = create_death_eq()
    else
    {
        self_log("FATAL: death-EQ create failed; halting");
        syscall::thread_exit();
    };

    register_with_procmgr(caps.procmgr_death_auth_send, death_eq, ipc_buf);

    let Some(ws_cap) = create_wait_set(caps.log_ep_recv, death_eq)
    else
    {
        self_log("FATAL: wait_set create failed; halting");
        syscall::thread_exit();
    };

    event_loop(ws_cap, death_eq, caps.log_ep_recv, ipc_buf, &mut table);
}

/// Allocate the slab and create the death-notification `EventQueue`.
/// Capacity sized so a burst of simultaneous child deaths fits before
/// logd's next drain (`MAX_DEATHS_PER_BURST`).
fn create_death_eq() -> Option<u32>
{
    const MAX_DEATHS_PER_BURST: u32 = 64;
    // Bytes: 24 wrapper + 56 state + (capacity + 1) * 8 ring.
    let slab_bytes: u64 = 24 + 56 + (u64::from(MAX_DEATHS_PER_BURST) + 1) * 8;
    let slab = std::os::seraph::object_slab_acquire(slab_bytes)?;
    syscall::event_queue_create(slab, MAX_DEATHS_PER_BURST).ok()
}

/// Build a 2-member wait set: the log endpoint (`WS_TOKEN_LOG`) and
/// the death event queue (`WS_TOKEN_DEATH`).
fn create_wait_set(log_ep_recv: u32, death_eq: u32) -> Option<u32>
{
    let slab = std::os::seraph::object_slab_acquire(4096)?;
    let ws = match syscall::wait_set_create(slab)
    {
        Ok(c) => c,
        Err(e) =>
        {
            let mut buf = SerialFmt::new();
            let _ = write!(buf, "wait_set_create err={e} slab={slab}");
            buf.flush_self_log();
            return None;
        }
    };
    if let Err(e) = syscall::wait_set_add(ws, log_ep_recv, WS_TOKEN_LOG)
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_add(log) err={e}");
        buf.flush_self_log();
        return None;
    }
    if let Err(e) = syscall::wait_set_add(ws, death_eq, WS_TOKEN_DEATH)
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_add(death) err={e}");
        buf.flush_self_log();
        return None;
    }
    Some(ws)
}

/// POST = bit 9 (matches `core::cap::slot::Rights::POST` =
/// `1 << 9`). Construct directly; `shared/syscall` does not expose
/// a `RIGHTS_POST` helper yet.
const RIGHTS_POST: u64 = 1 << 9;

/// Send `REGISTER_DEATH_EQ` to procmgr.
///
/// `ipc_call` on a message carrying a cap MOVES the cap into the
/// receiver's `CSpace` and clears the sender's slot. logd needs to
/// retain `RECV` on the original event queue so `wait_set_add` and
/// `event_try_recv` keep working, so it first derives a POST-only
/// copy and transfers that. Procmgr's `REGISTER_DEATH_EQ` handler
/// gates on the POST right (`sys_thread_bind_notification`'s lookup
/// already requires it).
fn register_with_procmgr(procmgr_send: u32, death_eq: u32, ipc_buf: *mut u64)
{
    if procmgr_send == 0
    {
        self_log("REGISTER_DEATH_EQ skipped: no procmgr cap");
        return;
    }
    let Ok(post_cap) = syscall::cap_derive(death_eq, RIGHTS_POST)
    else
    {
        self_log("REGISTER_DEATH_EQ: cap_derive POST failed");
        return;
    };
    let msg = IpcMessage::builder(procmgr_labels::REGISTER_DEATH_EQ)
        .cap(post_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page; the cap
    // transfer moves `post_cap` into procmgr's CSpace.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_send, &msg, ipc_buf) })
    else
    {
        self_log("REGISTER_DEATH_EQ: IPC call failed");
        let _ = syscall::cap_delete(post_cap);
        return;
    };
    if reply.label == procmgr_errors::SUCCESS
    {
        self_log("REGISTER_DEATH_EQ: bound on procmgr");
    }
    else
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "REGISTER_DEATH_EQ: error code {}", reply.label);
        buf.flush_self_log();
    }
}

/// Main wait loop. Drains death notifications before each log-EP
/// dispatch so a recently-died sender's slot is evicted before we
/// process its in-flight messages (matches procmgr's drain-deaths-
/// first pattern).
fn event_loop(
    ws_cap: u32,
    death_eq: u32,
    log_ep_recv: u32,
    ipc_buf: *mut u64,
    table: &mut SlotTable,
) -> !
{
    loop
    {
        let Ok(token) = syscall::wait_set_wait(ws_cap)
        else
        {
            continue;
        };
        drain_deaths(death_eq, table);
        // Only WS_TOKEN_LOG warrants service action; deaths were
        // already drained above. WS_TOKEN_DEATH and unknown tokens
        // fall through silently.
        if token == WS_TOKEN_LOG
        {
            dispatch_log(log_ep_recv, ipc_buf, table);
        }
    }
}

/// Non-blocking drain of the death event queue. Each payload encodes
/// `(process_token as u32) << 32 | exit_reason`. We evict the
/// matching slot from the token table.
fn drain_deaths(death_eq: u32, table: &mut SlotTable)
{
    loop
    {
        let Ok(payload) = syscall::event_try_recv(death_eq)
        else
        {
            return;
        };
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload as u32;
        // Token in logd's slot map is the full u64; the correlator
        // procmgr binds is `process_token as u32`. Match against the
        // low 32 bits.
        let dead: Vec<u64> = table
            .slots
            .keys()
            .copied()
            .filter(|&t| (t as u32) == correlator)
            .collect();
        for token in dead
        {
            if table.evict(token)
            {
                let mut buf = SerialFmt::new();
                let _ = write!(buf, "reclaim: token={token} exit_reason=0x{exit_reason:x}");
                buf.flush_self_log();
            }
        }
    }
}

fn dispatch_log(log_ep_recv: u32, ipc_buf: *mut u64, table: &mut SlotTable)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(recv) = (unsafe { ipc::ipc_recv(log_ep_recv, ipc_buf) })
    else
    {
        return;
    };
    let label_id = recv.label & 0xFFFF;
    let byte_len = ((recv.label >> 16) & 0xFFFF) as usize;
    if label_id == STREAM_BYTES
    {
        consume_bytes(table, recv.token, &recv, byte_len);
        reply_ack(ipc_buf);
    }
    else if label_id == STREAM_REGISTER_NAME
    {
        register_name(table, recv.token, &recv, byte_len);
        reply_ack(ipc_buf);
    }
    else
    {
        // Unknown / legacy label (e.g. GET_LOG_CAP from a hypothetical
        // pre-pivot caller). Reply empty so the sender unblocks.
        reply_ack(ipc_buf);
    }
}

fn reply_ack(ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(0), ipc_buf) };
}

/// Append `byte_len` bytes from the IPC payload onto the slot for
/// `token`, flushing complete lines (`\n`-terminated) to the serial
/// port AND recording them into the per-slot history ring.
///
/// Accepts up to `STREAM_CHUNK_SIZE = MSG_DATA_WORDS_MAX * 8` bytes
/// per call (the maximum a single `STREAM_BYTES` IPC can carry); the
/// per-line buffer is `LINE_BUF_SIZE` and force-flushes when full,
/// so a chunk longer than `LINE_BUF_SIZE` produces multiple emitted
/// lines rather than truncated output (matches init-logd's behaviour).
fn consume_bytes(table: &mut SlotTable, token: u64, msg: &IpcMessage, byte_len: usize)
{
    const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(STREAM_CHUNK_SIZE);
    // Stage the bytes in a stack buffer so we can borrow the slot
    // mutably without aliasing the IPC buffer.
    let mut staged = [0u8; STREAM_CHUNK_SIZE];
    staged[..n].copy_from_slice(&bytes[..n]);
    let slot = table.get_or_create(token);
    for &b in &staged[..n]
    {
        if b == b'\n'
        {
            flush_partial(token, slot);
        }
        else if slot.partial.len() < LINE_BUF_SIZE
        {
            slot.partial.push(b);
            if slot.partial.len() == LINE_BUF_SIZE
            {
                flush_partial(token, slot);
            }
        }
    }
}

/// Snapshot the slot's in-progress line, emit it to serial, append
/// it to the history ring, clear the partial buffer. Separated so
/// the `&slot.name`/`&slot.partial` borrows don't alias the
/// subsequent `&mut slot` calls.
fn flush_partial(token: u64, slot: &mut crate::slot::Slot)
{
    let name = slot.name.clone();
    let line: Vec<u8> = slot.partial.drain(..).collect();
    emit_line(token, &name, &line);
    let us = elapsed_us();
    slot.push_history(us, &line);
}

/// Record / update the display name for `token`. Lines emitted with
/// the old name remain attributed to the old name in history (those
/// are immutable); subsequent emissions render under the new name.
/// Long names truncated. No collision-suffix policy (procmgr's
/// process token is unique, so name collisions only happen if two
/// processes intentionally pick the same display name).
fn register_name(table: &mut SlotTable, token: u64, msg: &IpcMessage, byte_len: usize)
{
    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(MAX_NAME_LEN);
    let slot = table.get_or_create(token);
    slot.name.clear();
    slot.name.extend_from_slice(&bytes[..n]);
}

/// Emit `[sec.usfrac] [name] <bytes>\r\n` directly to the serial
/// port. Mirrors init-logd's `flush_line` shape so the post-handover
/// output stream looks identical to the pre-handover output.
fn emit_line(_token: u64, name: &[u8], line: &[u8])
{
    let us = elapsed_us();
    let sec = us / 1_000_000;
    let usfrac = (us % 1_000_000) as u32;

    arch::current::serial_write_byte(b'[');
    write_decimal(sec);
    arch::current::serial_write_byte(b'.');
    write_decimal_padded(u64::from(usfrac), 6);
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    arch::current::serial_write_byte(b'[');
    if name.is_empty()
    {
        arch::current::serial_write_byte(b'?');
    }
    else
    {
        for &b in name
        {
            arch::current::serial_write_byte(b);
        }
    }
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    for &b in line
    {
        if b == b'\n'
        {
            arch::current::serial_write_byte(b'\r');
        }
        arch::current::serial_write_byte(b);
    }
    arch::current::serial_write_byte(b'\r');
    arch::current::serial_write_byte(b'\n');
}

/// Emit `[sec.usfrac] [logd] <payload>\r\n` directly to the serial
/// port. Used for logd's own internal diagnostics, replacing every
/// `seraph::log!` call (which would self-IPC into the log endpoint
/// logd serves).
fn self_log(payload: &str)
{
    let us = elapsed_us();
    let sec = us / 1_000_000;
    let usfrac = (us % 1_000_000) as u32;

    arch::current::serial_write_byte(b'[');
    write_decimal(sec);
    arch::current::serial_write_byte(b'.');
    write_decimal_padded(u64::from(usfrac), 6);
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    arch::current::serial_write_byte(b'[');
    for &b in b"logd"
    {
        arch::current::serial_write_byte(b);
    }
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    for b in payload.bytes()
    {
        if b == b'\n'
        {
            arch::current::serial_write_byte(b'\r');
        }
        arch::current::serial_write_byte(b);
    }
    arch::current::serial_write_byte(b'\r');
    arch::current::serial_write_byte(b'\n');
}

/// Stack-buffer `fmt::Write` adapter for one-shot formatted
/// diagnostics. 256-byte cap matches `LINE_BUF_SIZE`; over-long
/// formatted output truncates.
struct SerialFmt
{
    buf: [u8; 256],
    used: usize,
}

impl SerialFmt
{
    fn new() -> Self
    {
        Self {
            buf: [0u8; 256],
            used: 0,
        }
    }

    fn flush_self_log(&self)
    {
        // SAFETY: SerialFmt only ever receives UTF-8 from
        // `core::fmt::write`.
        let s = unsafe { core::str::from_utf8_unchecked(&self.buf[..self.used]) };
        self_log(s);
    }
}

impl Write for SerialFmt
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        let bytes = s.as_bytes();
        let cap = self.buf.len() - self.used;
        let n = bytes.len().min(cap);
        self.buf[self.used..self.used + n].copy_from_slice(&bytes[..n]);
        self.used += n;
        Ok(())
    }
}

fn write_decimal(value: u64)
{
    let mut buf = [0u8; 20];
    let mut n = value;
    let mut idx = buf.len();
    if n == 0
    {
        idx -= 1;
        buf[idx] = b'0';
    }
    else
    {
        while n > 0
        {
            idx -= 1;
            buf[idx] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    for &b in &buf[idx..]
    {
        arch::current::serial_write_byte(b);
    }
}

fn write_decimal_padded(value: u64, width: usize)
{
    let mut buf = [b'0'; 20];
    let mut n = value;
    let mut idx = buf.len();
    while n > 0 && idx > 0
    {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let start = buf.len().saturating_sub(width);
    for &b in &buf[start..]
    {
        arch::current::serial_write_byte(b);
    }
}

fn elapsed_us() -> u64
{
    syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0)
}
