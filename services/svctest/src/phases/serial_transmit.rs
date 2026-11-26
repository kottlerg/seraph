// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/serial_transmit.rs

//! The serial driver answers a write once its bytes are in its transmit ring,
//! and a read while a write is in flight
//! (`services/drivers/serial/README.md` § Transmit and receive).
//!
//! Through the debug authority, the phase attaches to the serial driver and
//! stops its transmitter, the driver's main thread, the one thread that
//! touches the UART; its service threads keep serving. On a granted serial
//! SEND (`devmgr.class.serial`) it then:
//!
//! - writes [`BURST_LINES`] numbered console lines, one `SERIAL_WRITE_BYTES`
//!   call each, every call to be answered `SUCCESS` within [`CALL_BOUND`]:
//!   the stopped transmitter takes no byte, so each answer comes from the
//!   ring;
//! - starts a zero-length `SERIAL_WRITE_SENT` write on a thread of its own,
//!   which must stay unanswered while the transmitter is stopped: the burst's
//!   bytes have not left the UART;
//! - reads (`SERIAL_READ_BYTES`) while that write is in flight, to be
//!   answered `SUCCESS` within [`CALL_BOUND`];
//! - starts the transmitter again, and requires the `SERIAL_WRITE_SENT`
//!   write to be answered `SUCCESS` after it, once the ring has drained.
//!
//! The burst is bracketed by the lines `serial-burst begin` and
//! `serial-burst end senders=1 lines=<n>`, which the phase writes to the
//! driver itself, before the stop and after the restart, so they reach the
//! ring in order with the burst; the boot's
//! `cargo xtask run --whole-lines serial-burst` check requires every line
//! between them to be one console line and the burst's numbered lines to
//! arrive whole, in order, none missing (`xtask/README.md` § `--whole-lines`).
//! No assertion panics while the transmitter is stopped: a panic's message
//! goes through logd to this driver and would wait behind it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ipc::serial_labels::{SERIAL_READ_BYTES, SERIAL_WRITE_BYTES, SERIAL_WRITE_SENT};
use ipc::stream_labels::LEVEL_INFO;
use ipc::{IpcMessage, procmgr_errors, procmgr_labels, serial_errors};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "serial_transmit",
        run: serial_transmit_phase,
    }]
}

/// The serial driver's process name, as `logd_sinks` finds it.
const SERIAL_NAME: &[u8] = b"/services/drivers/serial";

/// The tag of the burst's lines and of the window that brackets them.
const TAG: &str = "serial-burst";

/// Lines the burst writes: about 1.5 KiB, well inside the driver's transmit
/// ring (`TX_RING_BYTES`, 4 KiB) with logd's lines beside it.
const BURST_LINES: u64 = 16;

/// The shortest numbered line's payload, in letters.
const PAYLOAD_MIN: u64 = 40;

/// The payload lengths' spread above [`PAYLOAD_MIN`].
const PAYLOAD_SPREAD: u64 = 40;

/// The bound on a write or a read the stopped transmitter must not hold. A
/// write that waited on the transmitter would wait for the driver's stall
/// bound (`TX_STALL_MS`, 1 s) and be answered `STALLED`.
const CALL_BOUND: Duration = Duration::from_millis(500);

/// How long the `SERIAL_WRITE_SENT` write is in flight before the read, so
/// it has reached a service thread.
const SENT_SETTLE: Duration = Duration::from_millis(50);

/// The bound on the `SERIAL_WRITE_SENT` write's call: past the driver's
/// stall bound, so a write the driver refuses is answered, not cut off.
const SENT_CALL_MS: u32 = 5000;

fn serial_transmit_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "serial_transmit: no debug authority");
    assert_ne!(
        caps.serial_class, 0,
        "serial_transmit: no devmgr.class.serial seed"
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let serial = unsafe { ipc::first_device(caps.serial_class, ipc_buf) }
        .unwrap_or_else(|e| panic!("serial_transmit: QUERY_DEVICE on the serial class ({e:?})"));
    let process = super::crash::badge_named(authority, SERIAL_NAME)
        .expect("serial_transmit: LIST_PROCESSES lists no serial driver");
    let lines = burst_lines();

    let begin = console_line(&format!("{TAG} begin"));
    let begin_reply = write(serial, 0, &begin, u32::MAX)
        .unwrap_or_else(|e| panic!("serial_transmit: the begin line's write failed ({e})"));
    assert_eq!(
        begin_reply,
        serial_errors::SUCCESS,
        "serial_transmit: the begin line's write refused"
    );
    let threads = attach(authority, process);
    let transmitter = *threads
        .first()
        .expect("serial_transmit: the serial attach returned no thread");
    syscall::thread_stop(transmitter)
        .unwrap_or_else(|e| panic!("serial_transmit: stopping the transmitter ({e})"));
    let outcome = with_transmitter_stopped(serial, &lines, transmitter);
    detach(authority, process, threads);
    let lines_written = outcome.unwrap_or_else(|e| panic!("{e}"));
    let end = console_line(&format!("{TAG} end senders=1 lines={lines_written}"));
    let end_reply = write(serial, 0, &end, u32::MAX)
        .unwrap_or_else(|e| panic!("serial_transmit: the end line's write failed ({e})"));
    assert_eq!(
        end_reply,
        serial_errors::SUCCESS,
        "serial_transmit: the end line's write refused"
    );
    let _ = syscall::cap_delete(serial);
    std::os::seraph::log!(
        "serial_transmit: {lines_written} writes and a read answered with the transmitter stopped"
    );
}

/// The checks made while the transmitter, `transmitter`, is stopped, which
/// start it again before they return: the lines written, or the first
/// failure.
fn with_transmitter_stopped(serial: u64, lines: &[Vec<u8>], transmitter: u64)
-> Result<u64, String>
{
    let stopped_at = Instant::now();
    let burst = write_burst(serial, lines);
    let answered = Arc::new(AtomicBool::new(false));
    let sent_write = {
        let answered = Arc::clone(&answered);
        std::thread::spawn(move || {
            let reply = write(serial, SERIAL_WRITE_SENT, &[], SENT_CALL_MS);
            answered.store(true, Ordering::SeqCst);
            reply
        })
    };
    std::thread::sleep(SENT_SETTLE);
    let read = read(serial);
    let early = answered.load(Ordering::SeqCst);
    let stopped_ms = stopped_at.elapsed().as_millis();
    let restarted = syscall::thread_start(transmitter)
        .map_err(|e| format!("serial_transmit: starting the transmitter ({e})"));
    let sent = sent_write
        .join()
        .map_err(|_| "serial_transmit: the SERIAL_WRITE_SENT thread panicked".to_string())?;
    restarted?;
    let written = burst?;
    read?;
    if early
    {
        return Err(format!(
            "serial_transmit: a SERIAL_WRITE_SENT write was answered ({sent:?}) while the \
             transmitter was stopped, {stopped_ms} ms after the stop, with the burst's bytes in \
             its ring"
        ));
    }
    match sent
    {
        Ok(serial_errors::SUCCESS) => Ok(written),
        Ok(label) => Err(format!(
            "serial_transmit: the SERIAL_WRITE_SENT write was refused ({label:#x})"
        )),
        Err(e) => Err(format!(
            "serial_transmit: the SERIAL_WRITE_SENT write failed ({e})"
        )),
    }
}

/// Write each of `lines` with one plain `SERIAL_WRITE_BYTES` call, each to
/// be answered `SUCCESS` within [`CALL_BOUND`]; the lines written.
fn write_burst(serial: u64, lines: &[Vec<u8>]) -> Result<u64, String>
{
    let bound = u32::try_from(CALL_BOUND.as_millis()).unwrap_or(u32::MAX);
    let mut written = 0u64;
    for line in lines
    {
        let start = Instant::now();
        let label = write(serial, 0, line, bound)
            .map_err(|e| format!("serial_transmit: write {written} not answered ({e})"))?;
        if label != serial_errors::SUCCESS
        {
            return Err(format!(
                "serial_transmit: write {written} refused ({label:#x})"
            ));
        }
        if start.elapsed() >= CALL_BOUND
        {
            return Err(format!(
                "serial_transmit: write {written} took {} ms with the transmitter stopped",
                start.elapsed().as_millis()
            ));
        }
        written = written.saturating_add(1);
    }
    Ok(written)
}

/// One `SERIAL_WRITE_BYTES` call of `bytes` with `flags` on `serial`,
/// bounded by `timeout_ms`: its reply label, or the call's error.
fn write(serial: u64, flags: u64, bytes: &[u8], timeout_ms: u32) -> Result<u64, String>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let label = SERIAL_WRITE_BYTES | flags | ((bytes.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, bytes).build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call_timeout(serial, &msg, ipc_buf, timeout_ms) }
        .map(|reply| reply.label & 0xFFFF)
        .map_err(|e| format!("{e:?}"))
}

/// One `SERIAL_READ_BYTES` call, to be answered `SUCCESS` within
/// [`CALL_BOUND`].
fn read(serial: u64) -> Result<(), String>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let bound = u32::try_from(CALL_BOUND.as_millis()).unwrap_or(u32::MAX);
    let start = Instant::now();
    let msg = IpcMessage::new(SERIAL_READ_BYTES);
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call_timeout(serial, &msg, ipc_buf, bound) }.map_err(|e| {
        format!("serial_transmit: a read with a write in flight not answered ({e:?})")
    })?;
    if reply.label & 0xFFFF != serial_errors::SUCCESS
    {
        return Err(format!(
            "serial_transmit: a read with a write in flight refused ({:#x})",
            reply.label
        ));
    }
    if start.elapsed() >= CALL_BOUND
    {
        return Err(format!(
            "serial_transmit: a read with a write in flight took {} ms",
            start.elapsed().as_millis()
        ));
    }
    Ok(())
}

/// The burst's lines, each a whole console line ([`console_line`]): `serial-burst t=0 n=<n> len=<len> <payload>`,
/// its payload `len` lowercase letters that depend on `n`, so a line cut or
/// joined with another fails the check.
fn burst_lines() -> Vec<Vec<u8>>
{
    (0..BURST_LINES)
        .map(|n| {
            // Every term stays far below `u64::MAX`; the wrapping forms only
            // spell that out.
            let len = PAYLOAD_MIN
                .wrapping_add(n.wrapping_mul(7).checked_rem(PAYLOAD_SPREAD).unwrap_or(0));
            let payload: String = (0..len).map(|i| letter(n.wrapping_add(i))).collect();
            console_line(&format!("{TAG} t=0 n={n} len={len} {payload}"))
        })
        .collect()
}

/// `text` as one whole console line as logd writes one: its prefix,
/// stamped now, then `text` and `\r\n`.
fn console_line(text: &str) -> Vec<u8>
{
    let us = syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let mut line = Vec::new();
    logd_codec::prefix::write(us, LEVEL_INFO, b"svctest", |b| line.push(b));
    line.extend_from_slice(text.as_bytes());
    line.extend_from_slice(b"\r\n");
    line
}

/// The lowercase letter `i` places past `a`, cycling.
fn letter(i: u64) -> char
{
    let past_a = i
        .checked_rem(26)
        .and_then(|r| u8::try_from(r).ok())
        .unwrap_or(0);
    // `past_a` is below 26, so the byte stays a lowercase letter.
    char::from(b'a'.wrapping_add(past_a))
}

/// Attach to the serial driver `process`; the caps of its threads, main
/// thread first.
fn attach(authority: u64, process: u64) -> Vec<u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("serial_transmit: ATTACH_PROCESS failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "serial_transmit: ATTACH_PROCESS of the serial driver refused ({:#x})",
        reply.label
    );
    reply.caps().to_vec()
}

/// Let go of `process` (`DETACH_PROCESS`) and delete its thread caps.
fn detach(authority: u64, process: u64, threads: Vec<u64>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
        .word(0, process)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("serial_transmit: DETACH_PROCESS failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "serial_transmit: DETACH_PROCESS of the serial driver refused ({:#x})",
        reply.label
    );
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}
