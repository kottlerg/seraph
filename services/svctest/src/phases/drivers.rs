// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/drivers.rs

//! Device-driver verb-bit gates: the serial, virtio-input, and framebuffer
//! drivers refuse a label whose verb bit the caller's badge lacks.
//!
//! devmgr mints every client SEND on these endpoints with the verb bits set,
//! and a holder cannot strip a bit from a badged cap, so the phase takes its
//! no-authority SENDs from devmgr's test-only `TEST_QUERY_DENY_DEVICE` label
//! on `devmgr.test`. Each SEND carries `TEST_DENY_BADGE`, which holds none of
//! the driver's verb bits; every gated label sent on it must reply the
//! driver's `UNAUTHORIZED` at once, without blocking for input or consuming
//! a byte. The serial and input drivers are part of every boot's device set;
//! the framebuffer case skips on a headless boot (CI's), where devmgr runs no
//! framebuffer driver. The input case also skips when the `terminal` recipe
//! is staged: the input driver serves one request at a time, and the
//! terminal keeps a blocking `INPUT_READ_EVENTS` pending, so svctest's call
//! would wait behind it for a keypress. TODO(#165): retire with the devmgr
//! test labels.

use std::time::Duration;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "drivers_verb_bit_deny",
        run: verb_bit_deny_phase,
    }]
}

/// Attempts at an input query while devmgr reports `NO_DEVICE`: the input
/// driver is spawned from disk after devmgr's `SET_DRIVERS_DIR`, so its
/// endpoint can lag svctest's start (the bounded wait the `NO_DEVICE`
/// contract allows). 500 attempts 10 ms apart bound the wait at about 5 s.
/// devmgr spawns the serial and framebuffer drivers before it serves any
/// query, so one attempt settles those. Shared with the devmgr ordinal phase.
pub(crate) const INPUT_ATTEMPTS: u32 = 500;

/// The recipe that starts the terminal, the system's other input reader
/// (programs/terminal/README.md), when it is staged for this boot.
const TERMINAL_RECIPE: &str = "/config/svcmgr/services/terminal.svc";

/// A no-authority SEND on the driver `query_label` names, from devmgr's
/// `TEST_QUERY_DENY_DEVICE`, or `None` when devmgr still reports
/// `NO_DEVICE` after `attempts` tries.
fn deny_send(devmgr_test: u32, query_label: u64, name: &str, attempts: u32) -> Option<u32>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let req = ipc::IpcMessage::builder(ipc::devmgr_labels::TEST_QUERY_DENY_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .word(1, query_label)
        .build();
    for _ in 0..attempts
    {
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(devmgr_test, &req, ipc_buf) }
            .unwrap_or_else(|_| panic!("TEST_QUERY_DENY_DEVICE ({name}) ipc_call failed"));
        if reply.label == ipc::devmgr_errors::NO_DEVICE
        {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        assert_eq!(
            reply.label,
            ipc::devmgr_errors::SUCCESS,
            "TEST_QUERY_DENY_DEVICE ({name}) status"
        );
        let cap = reply.caps().first().copied().unwrap_or(0);
        assert!(cap != 0, "TEST_QUERY_DENY_DEVICE ({name}) carried no cap");
        return Some(cap);
    }
    None
}

/// `msg` sent on the no-authority `cap` replies `unauthorized` and carries
/// no cap.
fn assert_denied(cap: u32, msg: &ipc::IpcMessage, unauthorized: u64, what: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(cap, msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("{what} on a no-authority SEND: ipc_call failed"));
    assert_eq!(
        reply.label, unauthorized,
        "{what} without its verb bit must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    assert!(reply.caps().is_empty(), "{what} deny must carry no cap");
}

fn verb_bit_deny_phase(caps: &Caps)
{
    let devmgr = caps.devmgr_test;
    assert!(devmgr != 0, "drivers deny: no devmgr.test cap seeded");

    let serial = deny_send(devmgr, ipc::devmgr_labels::QUERY_SERIAL_DEVICE, "serial", 1)
        .expect("drivers deny: no serial driver");
    let unauth = ipc::serial_errors::UNAUTHORIZED;
    // A one-byte write; a granted write would emit it on the console.
    let write = ipc::IpcMessage::builder(ipc::serial_labels::SERIAL_WRITE_BYTES | (1 << 16))
        .word(0, u64::from(b'!'))
        .build();
    assert_denied(serial, &write, unauth, "SERIAL_WRITE_BYTES");
    let read = ipc::IpcMessage::new(ipc::serial_labels::SERIAL_READ_BYTES);
    assert_denied(serial, &read, unauth, "SERIAL_READ_BYTES");
    let notify = ipc::IpcMessage::new(ipc::serial_labels::SERIAL_REGISTER_RX_NOTIFY);
    assert_denied(serial, &notify, unauth, "SERIAL_REGISTER_RX_NOTIFY");
    let _ = syscall::cap_delete(serial);

    if std::fs::metadata(TERMINAL_RECIPE).is_ok()
    {
        std::os::seraph::log!("drivers deny: input case skipped: terminal staged as a reader");
    }
    else
    {
        let input = deny_send(
            devmgr,
            ipc::devmgr_labels::QUERY_INPUT_DEVICE,
            "input",
            INPUT_ATTEMPTS,
        )
        .expect("drivers deny: no input driver");
        // A granted read blocks until a key arrives; the deny must not.
        let read = ipc::IpcMessage::new(ipc::input_labels::INPUT_READ_EVENTS);
        assert_denied(
            input,
            &read,
            ipc::input_errors::UNAUTHORIZED,
            "INPUT_READ_EVENTS",
        );
        let _ = syscall::cap_delete(input);
    }

    let Some(fb) = deny_send(
        devmgr,
        ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE,
        "fb",
        1,
    )
    else
    {
        std::os::seraph::log!("drivers deny: framebuffer case skipped: no framebuffer driver");
        return;
    };
    let unauth = ipc::fb_errors::UNAUTHORIZED;
    let write = ipc::IpcMessage::builder(ipc::fb_labels::FB_WRITE_BYTES | (1 << 16))
        .word(0, u64::from(b'!'))
        .build();
    assert_denied(fb, &write, unauth, "FB_WRITE_BYTES");
    let attrs = ipc::IpcMessage::new(ipc::fb_labels::FB_SET_ATTRS);
    assert_denied(fb, &attrs, unauth, "FB_SET_ATTRS");
    let _ = syscall::cap_delete(fb);
}
