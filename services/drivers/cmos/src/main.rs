// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/cmos/src/main.rs

//! Seraph x86-64 CMOS / MC146818-compatible RTC driver.
//!
//! Spawned by devmgr with a narrow `IoPortRange` cap covering CMOS
//! index/data ports `0x70`–`0x71` plus a RECV cap on the driver's
//! service endpoint. Implements the one-label RTC driver contract
//! ([`rtc_labels::RTC_GET_EPOCH_TIME`]) by re-reading hardware on
//! every request.

#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

use ipc::{IpcMessage, rtc_errors, rtc_labels};
use std::os::seraph::startup_info;

// ── CMOS port and register layout (MC146818) ───────────────────────────────

const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;
const REG_CENTURY: u8 = 0x32;

const STATUS_A_UIP: u8 = 0x80;
const STATUS_B_BINARY: u8 = 0x04;
const STATUS_B_24H: u8 = 0x02;
const HOUR_PM_BIT: u8 = 0x80;

// ── Bootstrap ──────────────────────────────────────────────────────────────

struct BootCaps
{
    service_ep: u32,
    ioport_cap: u32,
}

fn bootstrap_caps(creator_endpoint: u32, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 2 || !round.done
    {
        return None;
    }
    Some(BootCaps {
        service_ep: round.caps[0],
        ioport_cap: round.caps[1],
    })
}

// ── Port I/O ───────────────────────────────────────────────────────────────

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port is bound to this thread.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val,
            options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: caller guarantees port is bound to this thread.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val,
            options(nomem, nostack, preserves_flags));
    }
    val
}

fn cmos_read(reg: u8) -> u8
{
    // SAFETY: CMOS_INDEX / CMOS_DATA are in the bound IoPortRange.
    unsafe {
        outb(CMOS_INDEX, reg);
        inb(CMOS_DATA)
    }
}

fn cmos_uip() -> bool
{
    cmos_read(REG_STATUS_A) & STATUS_A_UIP != 0
}

// ── Raw → calendar fields ───────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
struct CmosFields
{
    sec: u8,
    min: u8,
    hour: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

fn read_cmos_fields() -> CmosFields
{
    CmosFields {
        sec: cmos_read(REG_SECONDS),
        min: cmos_read(REG_MINUTES),
        hour: cmos_read(REG_HOURS),
        day: cmos_read(REG_DAY),
        month: cmos_read(REG_MONTH),
        year: cmos_read(REG_YEAR),
        century: cmos_read(REG_CENTURY),
    }
}

fn bcd_to_bin(v: u8) -> u8
{
    (v & 0x0F) + (v >> 4) * 10
}

#[derive(Clone, Copy)]
struct Calendar
{
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
}

fn decode(raw: CmosFields, status_b: u8) -> Calendar
{
    let binary = status_b & STATUS_B_BINARY != 0;
    let h24 = status_b & STATUS_B_24H != 0;

    let conv = |v: u8| -> u8 { if binary { v } else { bcd_to_bin(v) } };

    let sec = conv(raw.sec);
    let min = conv(raw.min);

    // Hour needs PM-bit handling for 12-hour mode; the PM bit lives in
    // the raw byte and must be masked off before BCD conversion.
    let mut hour_raw = raw.hour;
    let pm = !h24 && (hour_raw & HOUR_PM_BIT != 0);
    hour_raw &= !HOUR_PM_BIT;
    let mut hour = conv(hour_raw);
    if !h24
    {
        if hour == 12
        {
            hour = 0;
        }
        if pm
        {
            hour += 12;
        }
    }

    let day = conv(raw.day);
    let month = conv(raw.month);
    let year_lo = conv(raw.year);
    let century_raw = conv(raw.century);

    // QEMU CMOS leaves register 0x32 at zero; treat a missing/implausible
    // century as 20 (year 2000–2099). Real hardware writes 19, 20, or 21.
    let century: u32 = match century_raw
    {
        19..=21 => u32::from(century_raw),
        _ => 20,
    };
    let year: u32 = century * 100 + u32::from(year_lo);

    Calendar {
        year,
        month: u32::from(month),
        day: u32::from(day),
        hour: u32::from(hour),
        min: u32::from(min),
        sec: u32::from(sec),
    }
}

/// Snapshot CMOS, retrying if the update-in-progress bit fires
/// mid-read or if two consecutive snapshots disagree. Bounded retry
/// loop — if hardware never settles within `MAX_ATTEMPTS` the call
/// returns `None` and the caller replies `READ_FAILED`.
fn snapshot_cmos() -> Option<Calendar>
{
    const MAX_ATTEMPTS: u32 = 16;

    for _ in 0..MAX_ATTEMPTS
    {
        while cmos_uip()
        {
            core::hint::spin_loop();
        }
        let first = read_cmos_fields();
        if cmos_uip()
        {
            continue;
        }
        let second = read_cmos_fields();
        if first == second
        {
            let status_b = cmos_read(REG_STATUS_B);
            return Some(decode(first, status_b));
        }
    }
    None
}

// ── Civil-date arithmetic ─────────────────────────────────────────────────

/// Days from 1970-01-01 to `(year, month, day)`. Howard Hinnant's
/// algorithm; valid for the full proleptic Gregorian range. Inputs are
/// constrained to year >= 1970 by the caller, so all intermediate
/// values are non-negative and the unsigned arithmetic below cannot
/// underflow.
fn days_from_civil(y: u32, m: u32, d: u32) -> u64
{
    let y: u64 = if m <= 2
    {
        u64::from(y) - 1
    }
    else
    {
        u64::from(y)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let m_adj = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * u64::from(m_adj) + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn epoch_us(c: Calendar) -> Option<u64>
{
    if c.month == 0 || c.month > 12 || c.day == 0 || c.day > 31 || c.year < 1970
    {
        return None;
    }
    let days = days_from_civil(c.year, c.month, c.day);
    let secs = days * 86_400 + u64::from(c.hour) * 3600 + u64::from(c.min) * 60 + u64::from(c.sec);
    secs.checked_mul(1_000_000)
}

// ── Service loop ───────────────────────────────────────────────────────────

fn handle_request(msg: &IpcMessage, ipc_buf: *mut u64)
{
    let reply = match msg.label
    {
        rtc_labels::RTC_GET_EPOCH_TIME => match snapshot_cmos().and_then(epoch_us)
        {
            Some(us) => IpcMessage::builder(rtc_errors::SUCCESS).word(0, us).build(),
            None => IpcMessage::new(rtc_errors::READ_FAILED),
        },
        _ => IpcMessage::new(rtc_errors::UNKNOWN_OPCODE),
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn service_loop(service_ep: u32, ipc_buf: *mut u64) -> !
{
    std::os::seraph::log!("ready");
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
        else
        {
            continue;
        };
        handle_request(&msg, ipc_buf);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"cmos-rtc");
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("bootstrap caps missing");
        syscall::thread_exit();
    };

    if syscall::ioport_bind(info.self_thread, caps.ioport_cap).is_err()
    {
        std::os::seraph::log!("ioport_bind failed");
        syscall::thread_exit();
    }

    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint");
        syscall::thread_exit();
    }

    service_loop(caps.service_ep, ipc_buf);
}
