// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/drivers.rs

//! Device-driver verb-bit gates: the serial, virtio-input, framebuffer, and
//! virtio-rng drivers refuse a label whose verb bit the caller's badge lacks.
//!
//! devmgr mints a client SEND on these endpoints with the verb bits of the
//! class SEND it is asked through, and a holder cannot strip a bit from a
//! badged cap, so the phase takes its no-authority SENDs through the
//! test-only `devmgr.class.serial-deny`, `input-deny`, `framebuffer-deny`,
//! and `hwrng-deny` class SENDs, whose verb mask holds only bit 58, which
//! none of these drivers checks. Every gated label sent on such a SEND must
//! reply the driver's `UNAUTHORIZED` at once, without blocking for input or
//! consuming a byte. The serial, input, and entropy drivers are part of every
//! boot's device set; the framebuffer case skips on a headless boot (CI's debug
//! svctest cells), where devmgr runs no framebuffer driver. The svctest image
//! stages no program, so no terminal reads the input driver or the UART beside
//! the phases.
//!
//! The stray-cap flood phase checks the serial, input, entropy, RTC, and
//! framebuffer drivers' cap hygiene: a cap a request carries that the driver
//! does not keep is deleted, not left in the driver's `CSpace`, and an
//! accepted serial RX registration deletes the notification it replaces. It
//! takes granted SENDs through the `devmgr.class.serial`,
//! `devmgr.class.input`, `devmgr.class.hwrng`, and `devmgr.class.rtc` class
//! SENDs, and the framebuffer driver's through `devmgr.class.framebuffer-deny`,
//! whose refused badge stands for every label, since the driver checks the
//! badge first. The framebuffer case skips on a headless boot, as the deny
//! phase's does.
//!
//! The hwrng read phase reads the entropy driver through a granted SEND on
//! the `devmgr.class.hwrng` class SEND: a `READ` of the most bytes one reply
//! carries answers with at least one byte and no more than asked, two such
//! reads differ, and a `READ` of no bytes answers with none.
//!
//! The hwrng restart phase kills the entropy driver, through the debug
//! authority, with a fault at an unmapped address, and requires devmgr to
//! restart it (services/devmgr/docs/responsibilities.md § Driver Restart):
//! the killed driver's ordinal answers `WITHDRAWN`, the class's next ordinal
//! answers with a new instance, started from the driver's installed path,
//! and a `READ` through it answers with bytes, so the new instance was given
//! its device's registers, interrupt and DMA again.

use std::time::{Duration, Instant};

use hwrng_protocol::{MAX_READ_BYTES, errors as hwrng_errors};
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
        Phase {
            name: "drivers_hwrng_read",
            run: hwrng_read_phase,
        },
        Phase {
            name: "drivers_hwrng_restart",
            run: hwrng_restart_phase,
        },
    ]
}

/// A test wait bound, in milliseconds: how long svctest waits on a
/// `WATCH_CLASS` watch for devmgr to serve the input, the entropy, or the
/// `test-dma` driver (`ipc::await_device`) before it fails. Each is spawned from disk
/// by the drivers-directory pass `SET_DRIVERS_DIR` posts, and a query devmgr
/// receives after that waits for the pass's settle, so the watch only
/// covers a query that reaches devmgr first. devmgr spawns the serial and
/// framebuffer drivers before it serves any query, so their queries do not
/// wait. Shared with the devmgr phases.
pub(crate) const DEVICE_WAIT_MS: u64 = 5_000;

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

/// The entropy driver's deny case, through the `hwrng-deny` class SEND
/// `deny_class`: `READ` replies `UNAUTHORIZED`. A function of its own, so its
/// message does not add to the deny phase's frame.
fn hwrng_denied(deny_class: u64)
{
    let hwrng = granted_send(deny_class, "hwrng-deny", Some(DEVICE_WAIT_MS))
        .expect("drivers deny: no hwrng driver");
    // A granted READ would post a buffer to the device; the deny must not.
    let read = ipc::IpcMessage::builder(hwrng_protocol::READ)
        .word(0, 8)
        .build();
    assert_denied(hwrng, &read, hwrng_errors::UNAUTHORIZED, "hwrng READ");
    let _ = syscall::cap_delete(hwrng);
}

fn verb_bit_deny_phase(caps: &Caps)
{
    use crate::phases::devmgr::TEST_DEVICES_HINT;

    for (cap, shown) in [
        (caps.serial_deny_class, "devmgr.class.serial-deny"),
        (caps.input_deny_class, "devmgr.class.input-deny"),
        (caps.framebuffer_deny_class, "devmgr.class.framebuffer-deny"),
        (caps.hwrng_deny_class, "devmgr.class.hwrng-deny"),
    ]
    {
        assert!(
            cap != 0,
            "drivers deny: no {shown} cap seeded: {TEST_DEVICES_HINT}"
        );
    }

    hwrng_denied(caps.hwrng_deny_class);

    let serial = granted_send(caps.serial_deny_class, "serial-deny", None)
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

    let input = granted_send(caps.input_deny_class, "input-deny", Some(DEVICE_WAIT_MS))
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

    let Some(fb) = granted_send(caps.framebuffer_deny_class, "framebuffer-deny", None)
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
    what: &'static str,
}

/// A label none of the flooded drivers serves.
const UNKNOWN_LABEL: u64 = 0x7FFF;

/// The serial driver's cases. A granted label keeps no cap but the
/// notification of an accepted `SERIAL_REGISTER_RX_NOTIFY`, which replaces
/// (and deletes) the one kept before. The rejected registration carries a
/// stray SEND as its notification, which is not a notification the driver
/// may signal, so the driver deletes it and keeps the one registered before;
/// the accepted one replaces that with a fresh notification on each call.
const SERIAL_CASES: [StrayCapCase; 5] = [
    StrayCapCase {
        label: UNKNOWN_LABEL,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::UNKNOWN_OPCODE,
        what: "serial unknown label",
    },
    // A zero-byte write: it emits nothing.
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_WRITE_BYTES,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::SUCCESS,
        what: "SERIAL_WRITE_BYTES",
    },
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_READ_BYTES,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::SUCCESS,
        what: "SERIAL_READ_BYTES",
    },
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_REGISTER_RX_NOTIFY,
        first: FirstCap::Stray,
        expected: ipc::serial_errors::REGISTER_FAILED,
        what: "SERIAL_REGISTER_RX_NOTIFY rejected",
    },
    StrayCapCase {
        label: ipc::serial_labels::SERIAL_REGISTER_RX_NOTIFY,
        first: FirstCap::Notification,
        expected: ipc::serial_errors::SUCCESS,
        what: "SERIAL_REGISTER_RX_NOTIFY accepted",
    },
];

/// The fewest bytes each of the hwrng read phase's two reads must answer:
/// enough that two reads of a working source agreeing on them is negligible.
const HWRNG_COMPARE_BYTES: usize = 16;

/// The entropy driver's cases: no hwrng label keeps a cap. A `READ` with no
/// data word asks for no bytes, so it posts nothing to the device.
const HWRNG_CASES: [StrayCapCase; 2] = [
    StrayCapCase {
        label: UNKNOWN_LABEL,
        first: FirstCap::Stray,
        expected: hwrng_errors::UNKNOWN_OPCODE,
        what: "hwrng unknown label",
    },
    StrayCapCase {
        label: hwrng_protocol::READ,
        first: FirstCap::Stray,
        expected: hwrng_errors::SUCCESS,
        what: "hwrng READ(0)",
    },
];

/// The RTC driver's cases (cmos-rtc on x86-64, goldfish-rtc on RISC-V): no
/// RTC label keeps a cap. The class SEND carries `READ_AUTHORITY`, so a
/// `RTC_GET_EPOCH_TIME` is served and reads the clock.
const RTC_CASES: [StrayCapCase; 2] = [
    StrayCapCase {
        label: UNKNOWN_LABEL,
        first: FirstCap::Stray,
        expected: ipc::rtc_errors::UNKNOWN_OPCODE,
        what: "rtc unknown label",
    },
    StrayCapCase {
        label: ipc::rtc_labels::RTC_GET_EPOCH_TIME,
        first: FirstCap::Stray,
        expected: ipc::rtc_errors::SUCCESS,
        what: "RTC_GET_EPOCH_TIME",
    },
];

/// The framebuffer driver's case, through a SEND without its verb bits: the
/// driver refuses the badge before it reads the label, so a write that
/// would draw stands for every label.
const FRAMEBUFFER_CASE: StrayCapCase = StrayCapCase {
    label: ipc::fb_labels::FB_WRITE_BYTES,
    first: FirstCap::Stray,
    expected: ipc::fb_errors::UNAUTHORIZED,
    what: "framebuffer refused FB_WRITE_BYTES",
};

/// The virtio-input driver's case: no input label keeps a cap, and a granted
/// `INPUT_READ_EVENTS` would block for a key, so the unknown label stands for
/// every label.
const INPUT_CASE: StrayCapCase = StrayCapCase {
    label: UNKNOWN_LABEL,
    first: FirstCap::Stray,
    expected: ipc::input_errors::UNKNOWN_OPCODE,
    what: "input unknown label",
};

/// The SEND on the first live driver of the class whose class SEND is
/// `class_send` (`ipc::first_device`), carrying that class SEND's verb bits,
/// or `None` when devmgr reports `NO_DEVICE`: at once with no `wait_ms`, or
/// once a `WATCH_CLASS` wait of `wait_ms` milliseconds ends with no driver
/// (`ipc::await_device`).
fn granted_send(class_send: u64, name: &str, wait_ms: Option<u64>) -> Option<u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let found = match wait_ms
    {
        None =>
        {
            // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
            unsafe { ipc::first_device(class_send, ipc_buf) }
        }
        Some(ms) =>
        {
            // SAFETY: as above.
            unsafe { ipc::await_device(class_send, ms, ipc_buf, || {}) }
        }
    };
    match found
    {
        Ok(cap) => Some(cap),
        Err(ipc::ClassCallError::Refused(ipc::devmgr_errors::NO_DEVICE)) => None,
        Err(e) => panic!("{name} QUERY_DEVICE failed: {e:?}"),
    }
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
/// and the `ipc_call` check below fails the phase (docs/device-management.md
/// § Relationship to Other Services): the outcome of every driver's cases but
/// the serial driver's. The serial driver also carries logd's writes, which
/// stall on it before then, and devmgr logs the withdrawal through logd, so
/// the boot stalls instead, and its run timeout classifies it as a `HANG`.
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
    assert!(
        caps.serial_class != 0
            && caps.input_class != 0
            && caps.hwrng_class != 0
            && caps.rtc_class != 0
            && caps.framebuffer_deny_class != 0,
        "drivers stray caps: no devmgr.class.serial, devmgr.class.input, \
         devmgr.class.hwrng, devmgr.class.rtc, or devmgr.class.framebuffer-deny cap seeded"
    );

    let hwrng = granted_send(caps.hwrng_class, "hwrng", Some(DEVICE_WAIT_MS))
        .expect("drivers stray caps: no hwrng driver");
    for case in &HWRNG_CASES
    {
        flood(hwrng, case);
    }
    let _ = syscall::cap_delete(hwrng);

    let rtc = granted_send(caps.rtc_class, "rtc", Some(DEVICE_WAIT_MS))
        .expect("drivers stray caps: no rtc driver");
    for case in &RTC_CASES
    {
        flood(rtc, case);
    }
    let _ = syscall::cap_delete(rtc);

    if let Some(fb) = granted_send(caps.framebuffer_deny_class, "framebuffer-deny", None)
    {
        flood(fb, &FRAMEBUFFER_CASE);
        let _ = syscall::cap_delete(fb);
    }
    else
    {
        std::os::seraph::log!(
            "drivers stray caps: framebuffer case skipped: no framebuffer driver"
        );
    }

    let serial = granted_send(caps.serial_class, "serial", None)
        .expect("drivers stray caps: no serial driver");
    for case in &SERIAL_CASES
    {
        flood(serial, case);
    }
    let _ = syscall::cap_delete(serial);

    let input = granted_send(caps.input_class, "input", Some(DEVICE_WAIT_MS))
        .expect("drivers stray caps: no input driver");
    flood(input, &INPUT_CASE);
    let _ = syscall::cap_delete(input);
}

/// One `READ` of `out.len()` bytes on the entropy driver's SEND `driver`:
/// the bytes it answered with, into the front of `out`, and their count. A
/// `NOT_READY` reply, which a device that produced nothing within the
/// driver's wait bound earns, fails the phase: QEMU's device answers at once.
fn hwrng_read(driver: u64, out: &mut [u8]) -> usize
{
    let asked = out.len();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(hwrng_protocol::READ)
        .word(0, asked as u64)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(driver, &msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("hwrng READ({asked}): ipc_call failed"));
    assert_eq!(
        reply.label,
        hwrng_errors::SUCCESS,
        "hwrng READ({asked}) must succeed (got {:#x})",
        reply.label
    );
    assert!(
        reply.caps().is_empty(),
        "hwrng READ({asked}) reply carried a cap"
    );
    let n = hwrng_protocol::decode_reply(reply.words(), out)
        .unwrap_or_else(|| panic!("hwrng READ({asked}): reply does not decode"));
    assert!(n <= asked, "hwrng READ({asked}) answered {n} bytes");
    n
}

fn hwrng_read_phase(caps: &Caps)
{
    assert!(
        caps.hwrng_class != 0,
        "drivers hwrng read: no devmgr.class.hwrng cap seeded"
    );
    let driver = granted_send(caps.hwrng_class, "hwrng", Some(DEVICE_WAIT_MS))
        .expect("drivers hwrng read: no hwrng driver");

    let mut first = [0u8; MAX_READ_BYTES];
    let n1 = hwrng_read(driver, &mut first);
    let mut second = [0u8; MAX_READ_BYTES];
    let n2 = hwrng_read(driver, &mut second);
    // The contract allows a short answer; QEMU's device fills each buffer it
    // is given, so a read this short is a driver that lost the device's bytes,
    // and the comparison below needs enough bytes to mean anything.
    let shorter = n1.min(n2);
    assert!(
        shorter >= HWRNG_COMPARE_BYTES,
        "hwrng READ({MAX_READ_BYTES}) answered {n1} and {n2} bytes"
    );
    // Two reads of a working source agree on HWRNG_COMPARE_BYTES bytes with
    // probability 2^-128; a driver handing out a stale or zeroed buffer
    // repeats itself.
    assert_ne!(
        first.get(..shorter),
        second.get(..shorter),
        "two hwrng READs answered the same {shorter} bytes"
    );
    assert_eq!(
        hwrng_read(driver, &mut []),
        0,
        "hwrng READ(0) must answer no bytes"
    );
    let _ = syscall::cap_delete(driver);
    std::os::seraph::log!("drivers hwrng read phase passed ({n1} and {n2} bytes)");
}

/// The entropy driver's process name: its install path, which devmgr creates
/// it with as its `argv[0]`.
const HWRNG_NAME: &[u8] = b"/services/drivers/virtio-rng";

/// How long the restart phase waits, at most, for the killed driver to be
/// gone and its ordinal withdrawn.
const RESTART_DEATH_TIMEOUT: Duration = Duration::from_secs(30);

/// Kill the entropy driver and require devmgr to restart it (see the module
/// documentation).
fn hwrng_restart_phase(caps: &Caps)
{
    assert!(
        caps.hwrng_class != 0,
        "drivers hwrng restart: no devmgr.class.hwrng cap seeded"
    );
    assert_ne!(
        caps.debug_authority, 0,
        "drivers hwrng restart: no debug authority"
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let (ordinal, served) = unsafe { ipc::first_device_from(caps.hwrng_class, 0, ipc_buf) }
        .unwrap_or_else(|e| panic!("drivers hwrng restart: no hwrng driver ({e:?})"));
    let _ = syscall::cap_delete(served);
    let process = super::crash::badge_named(caps.debug_authority, HWRNG_NAME)
        .expect("drivers hwrng restart: LIST_PROCESSES lists no entropy driver");

    super::logd_sinks::kill(caps.debug_authority, process, "virtio-rng");
    super::logd_sinks::await_gone(caps.debug_authority, process, HWRNG_NAME, "virtio-rng");
    let start_at = Instant::now();
    loop
    {
        // SAFETY: as above.
        match unsafe { ipc::query_device(caps.hwrng_class, ordinal, ipc_buf) }
        {
            Ok(copy) =>
            {
                let _ = syscall::cap_delete(copy);
            }
            Err(ipc::ClassCallError::Refused(ipc::devmgr_errors::WITHDRAWN)) => break,
            Err(e) => panic!("drivers hwrng restart: querying ordinal {ordinal} ({e:?})"),
        }
        assert!(
            start_at.elapsed() < RESTART_DEATH_TIMEOUT,
            "drivers hwrng restart: devmgr has not withdrawn the killed driver"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // devmgr posts the restart in the hold that withdraws the dead driver, so
    // this query waits for the restart's settle.
    let next = ordinal.saturating_add(1);
    // SAFETY: as above.
    let driver =
        unsafe { ipc::query_device(caps.hwrng_class, next, ipc_buf) }.unwrap_or_else(|e| {
            panic!("drivers hwrng restart: no driver restarted at ordinal {next} ({e:?})")
        });
    let restarted = super::crash::badge_named(caps.debug_authority, HWRNG_NAME)
        .expect("drivers hwrng restart: LIST_PROCESSES lists no restarted entropy driver");
    assert_ne!(
        restarted, process,
        "drivers hwrng restart: the killed driver is listed"
    );
    let mut bytes = [0u8; MAX_READ_BYTES];
    let n = hwrng_read(driver, &mut bytes);
    assert!(
        n >= HWRNG_COMPARE_BYTES,
        "drivers hwrng restart: the restarted driver answered READ({MAX_READ_BYTES}) with {n} \
         bytes"
    );
    let _ = syscall::cap_delete(driver);
    std::os::seraph::log!(
        "drivers hwrng restart phase passed (ordinal {ordinal} withdrawn, ordinal {next} served, \
         {n} bytes read)"
    );
}
