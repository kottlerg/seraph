// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// inputtest/src/main.rs

//! inputtest — virtio-input keyboard driver smoke test.
//!
//! A services-surface test staged only for the `cargo xtask test-input` cell
//! (it is not in svcmgr's default scan set). It resolves the input endpoint
//! from devmgr, prints a READY marker, then blocks reading the keysym stream
//! while the host injects a known key sequence (`a`, Shift+`a`, Return) via
//! QMP, and asserts the decoded events. Emits the
//! `[inputtest] ALL TESTS PASSED` / `SOME TESTS FAILED` marker (testing.md) and
//! requests pwrmgr shutdown.

#![allow(clippy::cast_possible_truncation)]

use ipc::{IpcMessage, devmgr_labels, input_errors, input_labels, keysym, pwrmgr_labels};
use std::os::seraph::startup_info;

/// Printed once the input cap is held and the test is about to block on its
/// first read; the host harness injects keys on seeing it. Kept in sync with
/// `xtask/src/commands/test_input.rs`.
const READY_MARKER: &str = "inputtest: READY for injection";

/// Expected decoded events after the host injects `a` / Shift+`a` / Return,
/// with modifier-key events (`Shift_L`, …) filtered out:
/// `(keysym, modifiers, pressed)`.
const EXPECTED: &[(u32, u32, bool)] = &[
    (0x61, 0, true),                  // 'a' down
    (0x61, 0, false),                 // 'a' up
    (0x41, keysym::MOD_SHIFT, true),  // 'A' down (Shift held)
    (0x41, keysym::MOD_SHIFT, false), // 'A' up
    (keysym::RETURN, 0, true),        // Return down
    (keysym::RETURN, 0, false),       // Return up
];

struct Caps
{
    devmgr_registry: u32,
    pwrmgr_auth: u32,
}

/// Decode the creator bootstrap round. Seed order in `inputtest.svc` is
/// `devmgr.registry pwrmgr.shutdown`, so `caps[0]` is the
/// `REGISTRY_QUERY_AUTHORITY` SEND on devmgr's registry and `caps[1]` the
/// `SHUTDOWN_AUTHORITY` SEND on pwrmgr.
fn bootstrap(ipc_buf: *mut u64) -> Caps
{
    let mut caps = Caps {
        devmgr_registry: 0,
        pwrmgr_auth: 0,
    };
    let info = startup_info();
    if info.creator_endpoint == 0
    {
        return caps;
    }
    // SAFETY: IPC buffer registered by `_start`, page-aligned by the boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) })
    else
    {
        return caps;
    };
    if round.cap_count >= 1
    {
        caps.devmgr_registry = round.caps[0];
    }
    if round.cap_count >= 2
    {
        caps.pwrmgr_auth = round.caps[1];
    }
    caps
}

/// Query devmgr for the input device endpoint, retrying briefly on a transient
/// failure in case the driver's on-disk spawn has not completed yet.
fn query_input_cap(devmgr_registry: u32, ipc_buf: *mut u64) -> Option<u32>
{
    for _ in 0..100
    {
        let req = IpcMessage::builder(devmgr_labels::QUERY_INPUT_DEVICE)
            .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(devmgr_registry, &req, ipc_buf) };
        if let Ok(reply) = reply
            && reply.label == ipc::devmgr_errors::SUCCESS
            && let Some(cap) = reply.caps().first().copied()
        {
            return Some(cap);
        }
        let _ = syscall::thread_yield();
    }
    None
}

/// Modifier keys (`Shift_L` … `Alt_R`) are delivered as their own keysym
/// events; the assertion filters them and checks only the character/named keys.
fn is_modifier_keysym(ks: u32) -> bool
{
    (keysym::SHIFT_L..=keysym::ALT_R).contains(&ks)
}

/// Read the keysym stream and assert it matches [`EXPECTED`] in order. Blocks
/// on each read until events arrive (the host injects after READY); returns
/// `true` on a full match.
fn run_assertions(input_cap: u32, ipc_buf: *mut u64) -> bool
{
    let mut idx = 0usize;
    while idx < EXPECTED.len()
    {
        let req = IpcMessage::new(input_labels::INPUT_READ_EVENTS);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(input_cap, &req, ipc_buf) })
        else
        {
            std::os::seraph::log!("INPUT_READ_EVENTS ipc_call failed");
            return false;
        };
        if reply.label != input_errors::SUCCESS
        {
            std::os::seraph::log!("INPUT_READ_EVENTS error label={:#x}", reply.label);
            return false;
        }
        let count = reply.word(0) as usize;
        for i in 0..count
        {
            let (ks, mods, pressed) = keysym::unpack_event(reply.word(1 + i));
            if is_modifier_keysym(ks)
            {
                continue;
            }
            let (eks, emods, epressed) = EXPECTED[idx];
            if ks != eks || mods != emods || pressed != epressed
            {
                std::os::seraph::log!(
                    "event {} mismatch: got ks={:#x} mods={:#x} pressed={}; want ks={:#x} mods={:#x} pressed={}",
                    idx,
                    ks,
                    mods,
                    u64::from(pressed),
                    eks,
                    emods,
                    u64::from(epressed)
                );
                return false;
            }
            idx += 1;
            if idx == EXPECTED.len()
            {
                return true;
            }
        }
    }
    true
}

fn shutdown(pwrmgr_auth: u32, ipc_buf: *mut u64)
{
    if pwrmgr_auth == 0
    {
        return;
    }
    let msg = IpcMessage::new(pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer. On success the platform
    // powers off and QEMU exits; a reply arrives only on failure.
    let _ = unsafe { ipc::ipc_call(pwrmgr_auth, &msg, ipc_buf) };
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"inputtest");
    let info = startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let caps = bootstrap(ipc_buf);

    let passed = if caps.devmgr_registry == 0
    {
        std::os::seraph::log!("no devmgr.registry seed");
        false
    }
    else if let Some(input_cap) = query_input_cap(caps.devmgr_registry, ipc_buf)
    {
        std::os::seraph::log!("{}", READY_MARKER);
        run_assertions(input_cap, ipc_buf)
    }
    else
    {
        std::os::seraph::log!("QUERY_INPUT_DEVICE failed (driver not bound?)");
        false
    };

    if passed
    {
        std::os::seraph::log!("ALL TESTS PASSED");
    }
    else
    {
        std::os::seraph::log!("SOME TESTS FAILED");
    }

    shutdown(caps.pwrmgr_auth, ipc_buf);
    syscall::thread_exit();
}
