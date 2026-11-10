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
//! would wait behind it for a keypress. TODO(#165): retire the deny phase
//! with the devmgr test labels.
//!
//! The stray-cap flood phase checks the serial and input drivers' cap
//! hygiene: a cap a request carries that the driver does not keep is
//! deleted, not left in the driver's `CSpace`, and an accepted serial RX
//! registration deletes the notification it replaces. It takes granted SENDs
//! from `devmgr.registry`. Under a staged terminal its input case skips, as
//! the deny phase's does, and so do its serial cases that read the UART or
//! rebind its interrupt, which would take the terminal's input.

use std::time::Duration;

use syscall_abi::MSG_CAP_SLOTS_MAX;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "drivers_verb_bit_deny",
            run: verb_bit_deny_phase,
        },
        Phase {
            name: "drivers_stray_cap_flood",
            run: stray_cap_flood_phase,
        },
    ]
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

/// Whether the terminal is staged for this boot: it then reads the input
/// driver and the UART, so a case that would wait behind its read, take its
/// bytes, or rebind its UART notification skips.
fn terminal_staged() -> bool
{
    std::fs::metadata(TERMINAL_RECIPE).is_ok()
}

/// A no-authority SEND on the driver `query_label` names, from devmgr's
/// `TEST_QUERY_DENY_DEVICE`, or `None` when devmgr still reports
/// `NO_DEVICE` after `attempts` tries.
fn deny_send(devmgr_test: u64, query_label: u64, name: &str, attempts: u32) -> Option<u64>
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
fn assert_denied(cap: u64, msg: &ipc::IpcMessage, unauthorized: u64, what: &str)
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

    if terminal_staged()
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

/// Calls of one flood case. Each call leaves at least one cap with a driver
/// that keeps what it should delete, so the calls outnumber the slots of a
/// spawned driver's `CSpace` (procmgr seeds a child's with 335 usable slots,
/// `CSPACE_RETYPE_PAGES`, and a driver grows it only when it spawns a
/// thread), with margin.
const FLOOD_CALLS: usize = 512;

/// The first cap of a flood call; the others are always stray SENDs.
#[derive(Clone, Copy)]
enum FirstCap
{
    /// A stray SEND on the driver's own endpoint.
    Stray,
    /// A fresh notification, which an accepted `SERIAL_REGISTER_RX_NOTIFY`
    /// keeps in place of the one it bound before.
    Notification,
}

/// A request sent with `MSG_CAP_SLOTS_MAX` caps, and the low 16 bits of the
/// reply label it must get (a read's byte count rides above them).
struct StrayCapCase
{
    label: u64,
    first: FirstCap,
    expected: u64,
    /// Whether the case reads the UART or rebinds its interrupt, so it skips
    /// under a staged terminal ([`terminal_staged`]).
    uart: bool,
    what: &'static str,
}

/// A label neither driver serves.
const UNKNOWN_LABEL: u64 = 0x7FFF;

/// The serial driver's cases. A granted label keeps no cap but the
/// notification of an accepted `SERIAL_REGISTER_RX_NOTIFY`, which replaces
/// (and deletes) the one bound before. The rejected registration carries a
/// stray SEND as its notification, which `SYS_IRQ_REGISTER` refuses, so the
/// line's binding stays as it was; the accepted one rebinds the line to a
/// fresh notification on each call.
const SERIAL_CASES: [StrayCapCase; 5] = [
    StrayCapCase {
        label: UNKNOWN_LABEL,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::UNKNOWN_OPCODE,
        uart: false,
        what: "serial unknown label",
    },
    // A zero-byte write: it emits nothing.
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_WRITE_BYTES,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::SUCCESS,
        uart: false,
        what: "SERIAL_WRITE_BYTES",
    },
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_READ_BYTES,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::SUCCESS,
        uart: true,
        what: "SERIAL_READ_BYTES",
    },
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_REGISTER_RX_NOTIFY,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::REGISTER_FAILED,
        uart: false,
        what: "SERIAL_REGISTER_RX_NOTIFY rejected",
    },
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_REGISTER_RX_NOTIFY,
        first: FirstCap::Notification,
        expected: ipc::serial_errors::SUCCESS,
        uart: true,
        what: "SERIAL_REGISTER_RX_NOTIFY accepted",
    },
];

/// The virtio-input driver's case: no input label keeps a cap, and a granted
/// `INPUT_READ_EVENTS` would block for a key, so the unknown label stands for
/// every label.
const INPUT_CASE: StrayCapCase = StrayCapCase {
    label: UNKNOWN_LABEL,
    first: FirstCap::Stray,
    expected: ipc::input_errors::UNKNOWN_OPCODE,
    uart: false,
    what: "input unknown label",
};

/// A granted SEND on the driver `query_label` names, from `devmgr.registry`,
/// or `None` when devmgr still reports `NO_DEVICE` after `attempts` tries.
fn granted_send(devmgr: u64, query_label: u64, name: &str, attempts: u32) -> Option<u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let req = ipc::IpcMessage::builder(query_label)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    for _ in 0..attempts
    {
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(devmgr, &req, ipc_buf) }
            .unwrap_or_else(|_| panic!("{name} device query ipc_call failed"));
        if reply.label == ipc::devmgr_errors::NO_DEVICE
        {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        assert_eq!(
            reply.label,
            ipc::devmgr_errors::SUCCESS,
            "{name} device query status"
        );
        let cap = reply.caps().first().copied().unwrap_or(0);
        assert!(cap != 0, "{name} device query carried no cap");
        return Some(cap);
    }
    None
}

/// The first cap of a flood call on `driver`, as `first` names it.
fn first_cap(driver: u64, first: FirstCap) -> u64
{
    match first
    {
        FirstCap::Stray =>
        {
            syscall::cap_derive(driver, syscall::RIGHTS_EP_SEND).expect("cap_derive of a stray cap")
        }
        FirstCap::Notification => std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        .expect("notification for a registration"),
    }
}

/// Send `case` on `driver` [`FLOOD_CALLS`] times, each call carrying
/// `MSG_CAP_SLOTS_MAX` caps, and check that each call gets the case's reply
/// and moves every cap out of svctest's `CSpace`.
///
/// A driver that kept a cap it should delete runs out of `CSpace` slots
/// within one case. Its receive then fails before it parks (`SYS_IPC_RECV`'s
/// `OutOfMemory`), and its `RecvGuard` ends it with `EXIT_RECV_WEDGE`
/// (docs/ipc-design.md § Receive-Failure Policy). devmgr then withdraws it
/// and revokes its service endpoint, so the call in flight returns an error
/// and the `ipc_call` check below fails the phase
/// (docs/device-management.md): the input case's outcome. The serial driver
/// also carries logd's writes, which stall on it before then, and devmgr
/// logs the withdrawal through logd, so the boot stalls instead, and its run
/// timeout classifies it as a `HANG`.
fn flood(driver: u64, case: &StrayCapCase)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let what = case.what;
    for call in 0..FLOOD_CALLS
    {
        let mut sent = [0u64; MSG_CAP_SLOTS_MAX];
        sent[0] = first_cap(driver, case.first);
        for stray in &mut sent[1..]
        {
            *stray = syscall::cap_derive(driver, syscall::RIGHTS_EP_SEND)
                .expect("cap_derive of a stray cap");
        }
        let mut builder = ipc::IpcMessage::builder(case.label);
        for &cap in &sent
        {
            builder = builder.cap(cap);
        }
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(driver, &builder.build(), ipc_buf) }
            .unwrap_or_else(|_| panic!("{what} call {call}: ipc_call failed"));
        assert_eq!(
            reply.label & 0xFFFF,
            case.expected,
            "{what} call {call}: reply label"
        );
        assert!(
            reply.caps().is_empty(),
            "{what} call {call}: reply carried a cap"
        );
        // No cap is created between the call and this check, so an empty
        // slot is the moved cap, not a reused slot.
        for &cap in &sent
        {
            assert!(
                syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).is_err(),
                "{what} call {call}: a cap it carried stayed with svctest"
            );
        }
    }
}

fn stray_cap_flood_phase(caps: &Caps)
{
    let devmgr = caps.devmgr_registry;
    assert!(
        devmgr != 0,
        "drivers stray caps: no devmgr.registry cap seeded"
    );
    let staged = terminal_staged();

    let serial = granted_send(devmgr, ipc::devmgr_labels::QUERY_SERIAL_DEVICE, "serial", 1)
        .expect("drivers stray caps: no serial driver");
    for case in &SERIAL_CASES
    {
        if staged && case.uart
        {
            std::os::seraph::log!(
                "drivers stray caps: {} case skipped: terminal staged as a reader",
                case.what
            );
            continue;
        }
        flood(serial, case);
    }
    let _ = syscall::cap_delete(serial);

    if staged
    {
        std::os::seraph::log!(
            "drivers stray caps: input case skipped: terminal staged as a reader"
        );
        return;
    }
    let input = granted_send(
        devmgr,
        ipc::devmgr_labels::QUERY_INPUT_DEVICE,
        "input",
        INPUT_ATTEMPTS,
    )
    .expect("drivers stray caps: no input driver");
    flood(input, &INPUT_CASE);
    let _ = syscall::cap_delete(input);
}
