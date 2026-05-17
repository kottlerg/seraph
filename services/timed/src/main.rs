// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// timed/src/main.rs

//! Seraph wall-clock service.
//!
//! Discovers `rtc.primary` via the service registry, reads the
//! current wall-clock time once, computes a fixed offset against the
//! kernel monotonic clock, and serves
//! [`timed_labels::GET_WALL_TIME`] from `offset +
//! system_info(ElapsedUs)` thereafter.

#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

use ipc::{IpcMessage, rtc_errors, rtc_labels, timed_errors, timed_labels};
use std::os::seraph::startup_info;
use syscall_abi::SystemInfoType;

// ── Bootstrap ──────────────────────────────────────────────────────────────

fn bootstrap_service_ep(creator_endpoint: u32, ipc_buf: *mut u64) -> Option<u32>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 1 || !round.done
    {
        return None;
    }
    Some(round.caps[0])
}

// ── RTC query ──────────────────────────────────────────────────────────────

fn query_rtc(rtc_cap: u32, ipc_buf: *mut u64) -> Option<u64>
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

fn service_loop(service_ep: u32, ipc_buf: *mut u64, offset: Option<u64>) -> !
{
    if offset.is_some()
    {
        std::os::seraph::log!("ready, offset computed");
    }
    else
    {
        std::os::seraph::log!("ready, no RTC — replies WALL_CLOCK_UNAVAILABLE");
    }
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
        else
        {
            continue;
        };
        handle_request(&msg, ipc_buf, offset);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

/// Look up `rtc.primary` and compute the wall-clock offset. Returns
/// `None` if any step fails (no registry, no RTC, RTC read error); the
/// service then runs in `WALL_CLOCK_UNAVAILABLE` mode.
///
/// Brackets the RTC IPC with two `ElapsedUs` reads so the kernel-side
/// moment of the RTC sample is approximated as the midpoint of the
/// roundtrip; subtracting that midpoint from the RTC value removes
/// most of the IPC-roundtrip bias from the resulting offset.
fn compute_offset(ipc_buf: *mut u64) -> Option<u64>
{
    let rtc_cap = std::os::seraph::registry::lookup(b"rtc.primary")?;
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

    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(service_ep) = bootstrap_service_ep(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("bootstrap missing service endpoint");
        syscall::thread_exit();
    };

    // std's `_start` already installed the per-process registry cap into
    // the registry-client cache; just query via std's wrapper to avoid
    // pulling in a second registry-client instance with its own static
    // (cargo unifies features per workspace, not across the std mirror's
    // workspace and ours).
    let offset = compute_offset(ipc_buf);

    service_loop(service_ep, ipc_buf, offset);
}
