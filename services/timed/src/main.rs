// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/timed/src/main.rs

//! Seraph wall-clock service.
//!
//! Resolves the platform RTC via [`devmgr_labels::QUERY_DEVICE`] on the
//! `rtc` class SEND its definition seeds, reads the current wall-clock
//! time once, computes a fixed offset against the kernel monotonic
//! clock, and serves [`timed_labels::GET_WALL_TIME`] from `offset +
//! system_info(ElapsedUs)` thereafter.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]

use ipc::{IpcMessage, rtc_errors, rtc_labels, timed_errors, timed_labels};
use std::os::seraph::startup_info;
use syscall_abi::SystemInfoType;

// ── Bootstrap ──────────────────────────────────────────────────────────────

struct BootCaps
{
    service_ep: u64,
    rtc_class: u64,
}

fn bootstrap_caps(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`. Both slots are required.
    let [service_ep, rtc_class] =
        unsafe { ipc::bootstrap::request_slots::<2>(creator_endpoint, ipc_buf) }.ok()?;
    if service_ep == 0 || rtc_class == 0
    {
        return None;
    }
    Some(BootCaps {
        service_ep,
        rtc_class,
    })
}

// ── RTC query ──────────────────────────────────────────────────────────────

fn query_rtc(rtc_cap: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let request = IpcMessage::new(rtc_labels::RTC_GET_EPOCH_TIME);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(rtc_cap, &request, ipc_buf) }.ok()?;
    if reply.label != rtc_errors::SUCCESS
    {
        return None;
    }
    Some(reply.word(0))
}

// ── Service loop ───────────────────────────────────────────────────────────

fn kernel_elapsed_us() -> u64
{
    syscall::system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0)
}

/// Reply to a single request. `offset` is `Some` once the RTC has been
/// successfully sampled; `None` means the boot-time lookup failed.
fn handle_request(msg: &IpcMessage, ipc_buf: *mut u64, offset: Option<u64>)
{
    let reply = match (msg.label, offset)
    {
        (timed_labels::GET_WALL_TIME, Some(off)) =>
        {
            // `GET_WALL_TIME` replies one `u64` of microseconds since the
            // Unix epoch, which spans about 584 000 years.
            let now = off.wrapping_add(kernel_elapsed_us());
            IpcMessage::builder(timed_errors::SUCCESS)
                .word(0, now)
                .build()
        }
        (timed_labels::GET_WALL_TIME, None) =>
        {
            IpcMessage::new(timed_errors::WALL_CLOCK_UNAVAILABLE)
        }
        _ => IpcMessage::new(timed_errors::UNKNOWN_OPCODE),
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn service_loop(service_ep: u64, ipc_buf: *mut u64, offset: Option<u64>) -> !
{
    if offset.is_some()
    {
        std::os::seraph::log!("ready, offset computed");
    }
    else
    {
        std::os::seraph::log!("ready, no RTC — replies WALL_CLOCK_UNAVAILABLE");
    }
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
        handle_request(&msg, ipc_buf, offset);
    }
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

// ── Entry ──────────────────────────────────────────────────────────────────

/// Resolve the first RTC driver's SEND through `rtc_class`, the `rtc` class
/// SEND (`QUERY_DEVICE` at ordinal 0). Returns `0` when devmgr replies
/// anything other than success (label-version mismatch, no RTC driver
/// served).
fn resolve_rtc_cap(rtc_class: u64, ipc_buf: *mut u64) -> u64
{
    if rtc_class == 0
    {
        return 0;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    unsafe { ipc::query_device(rtc_class, 0, ipc_buf) }.unwrap_or(0)
}

/// Resolve the RTC via devmgr and compute the wall-clock offset.
/// Returns `None` if any step fails (devmgr unreachable, no RTC, RTC
/// read error); the service then runs in `WALL_CLOCK_UNAVAILABLE` mode.
///
/// Brackets the RTC IPC with two `ElapsedUs` reads so the kernel-side
/// moment of the RTC sample is approximated as the midpoint of the
/// roundtrip; subtracting that midpoint from the RTC value removes
/// most of the IPC-roundtrip bias from the resulting offset.
fn compute_offset(rtc_class: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let rtc_cap = resolve_rtc_cap(rtc_class, ipc_buf);
    if rtc_cap == 0
    {
        return None;
    }
    let kernel_pre = kernel_elapsed_us();
    let rtc_us = query_rtc(rtc_cap, ipc_buf);
    let kernel_post = kernel_elapsed_us();
    let _ = syscall::cap_delete(rtc_cap);
    let rtc_us = rtc_us?;
    let kernel_mid = kernel_pre.wrapping_add(kernel_post.wrapping_sub(kernel_pre) / 2);
    Some(rtc_us.wrapping_sub(kernel_mid))
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"timed");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "bootstrap missing caps");
        syscall::thread_exit();
    };

    let offset = compute_offset(caps.rtc_class, ipc_buf);

    service_loop(caps.service_ep, ipc_buf, offset);
}
