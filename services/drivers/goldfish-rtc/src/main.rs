// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/goldfish-rtc/src/main.rs

//! Seraph Goldfish RTC driver (QEMU `virt` RISC-V).
//!
//! devmgr binds it to the platform device record a platform description
//! table names `google,goldfish-rtc` (`0x101000` on QEMU virt) and delivers
//! the record's register page as an `Mmio` range, with the driver's service
//! endpoint and its devmgr query cap, in a resource list
//! (`driver_binding::resources`). Once the page is mapped it
//! reports ready (`devmgr_labels::DRIVER_READY`) on the query cap,
//! immediately before its service loop: devmgr serves the driver's endpoint
//! only after that report. Implements the one-label RTC driver contract
//! ([`rtc_labels::RTC_GET_EPOCH_TIME`]).

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_ptr_alignment)]

use driver_binding::resources::{self, PlatformDelivery, Resource};
use ipc::{IpcMessage, rtc_errors, rtc_labels};
use std::os::seraph::{reserve_pages, startup_info};
use syscall_abi::PAGE_SIZE;

// ── Register offsets (Goldfish RTC) ────────────────────────────────────────

const REG_TIME_LOW: u64 = 0x00;
const REG_TIME_HIGH: u64 = 0x04;

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations).
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "goldfish-rtc",
    class: Some("rtc"),
    matches: &[driver_binding::decl::Match::Platform("google,goldfish-rtc")],
    instance_limit: Some(1),
    interrupt: driver_binding::decl::Interrupt::NONE,
    dma: false,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::None,
    tier: driver_binding::decl::Tier::Auxiliary,
});

// ── Bootstrap ──────────────────────────────────────────────────────────────

/// Receive the resource list (`driver_binding::resources`): the RTC's
/// register page as an `Mmio` range, and the endpoints. `None` unless the
/// range is page-aligned, holds the time registers, and spans at most one
/// page, so its cap maps into a one-page reservation.
fn bootstrap(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<(u64, PlatformDelivery)>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { resources::receive(creator_endpoint, ipc_buf) }.ok()?;
    let device = PlatformDelivery::from_list(&list)?;
    let Resource::Mmio {
        cap, phys, bytes, ..
    } = device.registers
    else
    {
        return None;
    };
    let fits = phys % PAGE_SIZE == 0 && (REG_TIME_HIGH + 4..=PAGE_SIZE).contains(&bytes);
    fits.then_some((cap, device))
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
            if msg.badge & rtc_labels::READ_AUTHORITY == 0
            {
                IpcMessage::new(rtc_errors::UNAUTHORIZED)
            }
            else
            {
                let ns = read_epoch_ns(base_va);
                IpcMessage::builder(rtc_errors::SUCCESS)
                    .word(0, ns / 1000)
                    .build()
            }
        }
        _ => IpcMessage::new(rtc_errors::UNKNOWN_OPCODE),
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn service_loop(service_ep: u64, ipc_buf: *mut u64, base_va: u64) -> !
{
    std::os::seraph::log!("ready");
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
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

    let Some((mmio_cap, device)) = bootstrap(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("resource list missing or without a one-page register range");
        syscall::thread_exit();
    };

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

    if !std::os::seraph::fund_aspace_pt_budget(info.self_aspace, 1)
    {
        std::os::seraph::log!("PT-budget funding failed");
        syscall::thread_exit();
    }
    // SAFETY: `range` is a fresh one-page reservation from the per-process
    // arena, owned for the process's lifetime, and `bootstrap` admits only a
    // page-aligned range of at most one page, whose cap devmgr carves to the
    // page end, so the whole-region mapping stays inside it: VA no Rust
    // object or IPC page occupies. `read_epoch_ns` reaches the mapping only
    // through raw `read_volatile`, never a reference, and the reservation
    // stays held for the process's lifetime (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(info.self_aspace, mmio_cap, base_va, 0) }.is_err()
    {
        std::os::seraph::log!("mmio_map failed");
        syscall::thread_exit();
    }

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { ipc::report_driver_ready(device.endpoints.devmgr_query, ipc_buf) }
    {
        std::os::seraph::log!("DRIVER_READY failed ({:?}); exiting", e);
        syscall::thread_exit();
    }
    service_loop(device.endpoints.service, ipc_buf, base_va);
}
