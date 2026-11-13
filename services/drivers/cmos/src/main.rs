// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/cmos/src/main.rs

//! Seraph x86-64 CMOS / MC146818-compatible RTC driver.
//!
//! Bound by devmgr to the ACPI namespace device whose `_HID` or a `_CID` is
//! `PNP0B00`, `PNP0B01` or `PNP0B02`, it receives the resource list
//! (`driver_binding::resources`): an `IoPort` cap on the range the device's `_CRS` names, which holds the CMOS
//! index/data ports `0x70`–`0x71`, a RECV cap on the driver's service
//! endpoint, and its devmgr query cap. It reads the century register's
//! index, which devmgr attaches to the record from the FADT `CENTURY` field,
//! with `QUERY_DEVICE_INFO`. Once its ports are bound it reports ready
//! (`devmgr_labels::DRIVER_READY`) on the query cap, immediately before its
//! service loop: devmgr serves the driver's endpoint only after that report.
//! Implements the one-label RTC driver contract
//! ([`rtc_labels::RTC_GET_EPOCH_TIME`]) by re-reading hardware on
//! every request.

use cmos_rtc::{Calendar, CmosRegs, epoch_us};
use driver_binding::resources::{self, PlatformDelivery, Resource};
use ipc::{IpcMessage, devmgr_labels, rtc_errors, rtc_labels};
use std::os::seraph::startup_info;

// ── CMOS port and register layout (MC146818) ───────────────────────────────

const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// Register numbers, the snapshot protocol and the decode live in the crate's
// library (`cmos_rtc`).

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations): every ACPI identifier of a
// CMOS-compatible RTC, as `_HID` or `_CID`, the set devmgr attaches the
// FADT's century index to.
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "cmos-rtc",
    class: Some("rtc"),
    matches: &[
        driver_binding::decl::Match::AcpiHid("PNP0B00"),
        driver_binding::decl::Match::AcpiHid("PNP0B01"),
        driver_binding::decl::Match::AcpiHid("PNP0B02"),
        driver_binding::decl::Match::AcpiCid("PNP0B00"),
        driver_binding::decl::Match::AcpiCid("PNP0B01"),
        driver_binding::decl::Match::AcpiCid("PNP0B02"),
    ],
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
/// `IoPort` range, and the endpoints. `None` unless the range holds the
/// index and data ports.
fn bootstrap(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<(u64, PlatformDelivery)>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { resources::receive(creator_endpoint, ipc_buf) }.ok()?;
    let device = PlatformDelivery::from_list(&list)?;
    let Resource::IoPort { cap, base, count } = device.registers
    else
    {
        return None;
    };
    let covers = base <= u64::from(CMOS_INDEX) && base.checked_add(count)? > u64::from(CMOS_DATA);
    covers.then_some((cap, device))
}

/// The CMOS RAM index of the century register, from the FADT `CENTURY`
/// field devmgr attaches to the RTC's record as device info
/// (`QUERY_DEVICE_INFO`, `ipc::device_info_kind::RTC_CENTURY`); `None` when
/// the record carries none, or names a register the driver cannot read
/// ([`cmos_rtc::century_from_payload`]).
fn query_century(devmgr_ep: u64, ipc_buf: *mut u64) -> Option<u8>
{
    let request = IpcMessage::builder(devmgr_labels::QUERY_DEVICE_INFO)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(devmgr_ep, &request, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        return None;
    }
    let words = reply.words();
    let (&[kind, version, byte_len, first], _) = words.split_first_chunk::<4>()?;
    if kind != u64::from(ipc::device_info_kind::RTC_CENTURY)
        || version != u64::from(ipc::device_info_kind::RTC_CENTURY_VERSION)
    {
        return None;
    }
    cmos_rtc::century_from_payload(byte_len, first)
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
    // SAFETY: CMOS_INDEX is in the IoPort range bound to this thread.
    unsafe { outb(CMOS_INDEX, reg) };
    // SAFETY: CMOS_DATA is in the IoPort range bound to this thread.
    unsafe { inb(CMOS_DATA) }
}

/// [`CmosRegs`] over the CMOS index/data ports bound to this thread.
struct PortRegs;

impl CmosRegs for PortRegs
{
    fn read(&mut self, reg: u8) -> u8
    {
        cmos_read(reg)
    }
}

// ── Read ─────────────────────────────────────────────────────────────────

/// Read and decode the CMOS clock, with the century from `century_reg` when
/// the platform names one. `None` when [`cmos_rtc::snapshot`] finds no
/// consistent reading within its bounded attempts (a stuck
/// update-in-progress bit included); the caller replies `READ_FAILED`.
fn snapshot_cmos(century_reg: Option<u8>) -> Option<Calendar>
{
    let (fields, status_b) = cmos_rtc::snapshot(&mut PortRegs, century_reg)?;
    Some(cmos_rtc::decode(fields, status_b))
}

// ── Service loop ───────────────────────────────────────────────────────────

fn handle_request(msg: &IpcMessage, century_reg: Option<u8>, ipc_buf: *mut u64)
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
                match snapshot_cmos(century_reg).and_then(epoch_us)
                {
                    Some(us) => IpcMessage::builder(rtc_errors::SUCCESS).word(0, us).build(),
                    None => IpcMessage::new(rtc_errors::READ_FAILED),
                }
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
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn service_loop(service_ep: u64, century_reg: Option<u8>, ipc_buf: *mut u64) -> !
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
        handle_request(&msg, century_reg, ipc_buf);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"cmos-rtc");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some((ioport_cap, device)) = bootstrap(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "resource list missing or without the CMOS ports");
        syscall::thread_exit();
    };

    if syscall::ioport_bind(info.self_thread, ioport_cap).is_err()
    {
        std::os::seraph::log!(error: "ioport_bind failed");
        syscall::thread_exit();
    }

    let century_reg = query_century(device.endpoints.devmgr_query, ipc_buf);

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { ipc::report_driver_ready(device.endpoints.devmgr_query, ipc_buf) }
    {
        std::os::seraph::log!(error: "DRIVER_READY failed ({:?}); exiting", e);
        syscall::thread_exit();
    }
    service_loop(device.endpoints.service, century_reg, ipc_buf);
}
