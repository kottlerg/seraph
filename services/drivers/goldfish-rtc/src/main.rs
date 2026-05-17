// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/goldfish-rtc/src/main.rs

//! Seraph Goldfish RTC driver (QEMU `virt` RISC-V).
//!
//! Spawned by devmgr with a one-page `MmioRegion` cap covering the
//! Goldfish RTC register page (`0x101000` on QEMU virt) plus a RECV
//! cap on the driver's service endpoint. Implements the one-label
//! RTC driver contract ([`rtc_labels::RTC_GET_EPOCH_TIME`]).

#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_ptr_alignment)]

use ipc::{IpcMessage, rtc_errors, rtc_labels};
use std::os::seraph::{reserve_pages, startup_info};

// ── Register offsets (Goldfish RTC) ────────────────────────────────────────

const REG_TIME_LOW: u64 = 0x00;
const REG_TIME_HIGH: u64 = 0x04;

// ── Bootstrap ──────────────────────────────────────────────────────────────

struct BootCaps
{
    service_ep: u32,
    mmio_cap: u32,
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
        mmio_cap: round.caps[1],
    })
}

// ── MMIO read sequence ─────────────────────────────────────────────────────

fn read_epoch_ns(base_va: u64) -> u64
{
    let low_addr = (base_va + REG_TIME_LOW) as *const u32;
    let high_addr = (base_va + REG_TIME_HIGH) as *const u32;

    // Read order: LOW first latches the 64-bit value; subsequent HIGH
    // read returns the latched upper half. Per the Goldfish RTC model
    // in QEMU (hw/rtc/goldfish_rtc.c).
    // SAFETY: base_va was mapped via mmio_map; addresses are within
    // the mapped page and naturally aligned.
    let low = unsafe { core::ptr::read_volatile(low_addr) };
    // SAFETY: same.
    let high = unsafe { core::ptr::read_volatile(high_addr) };

    u64::from(low) | (u64::from(high) << 32)
}

// ── Service loop ───────────────────────────────────────────────────────────

fn handle_request(msg: &IpcMessage, ipc_buf: *mut u64, base_va: u64)
{
    let reply = match msg.label
    {
        rtc_labels::RTC_GET_EPOCH_TIME =>
        {
            let ns = read_epoch_ns(base_va);
            IpcMessage::builder(rtc_errors::SUCCESS)
                .word(0, ns / 1000)
                .build()
        }
        _ => IpcMessage::new(rtc_errors::UNKNOWN_OPCODE),
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn service_loop(service_ep: u32, ipc_buf: *mut u64, base_va: u64) -> !
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
        handle_request(&msg, ipc_buf, base_va);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"goldfish-rtc");
    let info = startup_info();

    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("bootstrap caps missing");
        syscall::thread_exit();
    };

    if caps.mmio_cap == 0
    {
        std::os::seraph::log!("no MMIO cap");
        syscall::thread_exit();
    }

    // Reserve one page of VA for the MMIO mapping. The reservation
    // lives for the driver process's lifetime; ReservedRange has no
    // Drop impl, so falling out of scope is a no-op.
    let Ok(range) = reserve_pages(1)
    else
    {
        std::os::seraph::log!("reserve_pages failed");
        syscall::thread_exit();
    };
    let base_va = range.va_start();

    if syscall::mmio_map(info.self_aspace, caps.mmio_cap, base_va, 0).is_err()
    {
        std::os::seraph::log!("mmio_map failed");
        syscall::thread_exit();
    }

    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint");
        syscall::thread_exit();
    }

    service_loop(caps.service_ep, ipc_buf, base_va);
}
