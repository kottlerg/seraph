// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/devmgr.rs

//! devmgr surface — the `QUERY_BLOCK_DEVICE`, `QUERY_SHUTDOWN_DEVICE`, and
//! test-label authority gates, the instance ordinal of `QUERY_INPUT_DEVICE`,
//! and driver-spawn orphan teardown (#176).
//!
//! The deny phases send the gated labels on `devmgr.registry`, a cap
//! carrying `REGISTRY_QUERY_AUTHORITY` but none of `BLOCK_DEVICE_AUTHORITY`,
//! `SHUTDOWN_DEVICE_AUTHORITY`, and `TEST_LABEL_AUTHORITY`, and assert
//! `UNAUTHORIZED`: such a holder cannot acquire the whole-disk block cap or
//! the platform shutdown actuators, or drive devmgr's test labels (the
//! `TEST_SPAWN_ORPHAN` shim and `TEST_QUERY_DENY_DEVICE`).
//!
//! The ordinal phase asks `devmgr.registry` for the input driver at ordinal 0,
//! absent and explicit, and past the one keyboard every boot's device set
//! carries, and asserts a cap for the first and `NO_DEVICE` for the second.
//!
//! The teardown phase drives devmgr's temporary `TEST_SPAWN_ORPHAN` shim to
//! force a round-2 bootstrap failure in a fault-injection driver that hangs
//! (never exits), then asserts both that devmgr reports the spawn failed and
//! that the child's reserved pages return to memmgr's free pool. Free-pool
//! recovery is the observable that distinguishes #176's `DESTROY_PROCESS`
//! teardown from a leak: a hung child is never reaped by procmgr's exit
//! path, so without teardown its pages stay pinned and `free` never
//! recovers.
//!
//! The withdrawal phase drives devmgr's `TEST_SPAWN_FAULT_DRIVERS` shim: one
//! settle batch of three `test-fault` fixtures, two that report ready and one
//! that never does. It asserts the settle ends at the batch's bound with the
//! two ready fixtures served at ordinals 0 and 1 and the hung one not served,
//! then makes the fixture at ordinal 0 exit with a call queued on its
//! endpoint, and asserts that the queued call returns, that ordinal 0 then
//! replies `WITHDRAWN`, that ordinal 1 still names its live fixture, and,
//! once every fixture is gone, that memmgr's free pool recovers the memory
//! the hung fixture held, which only its destruction returns.
//! TODO(#165): retire the teardown, withdrawal, and test-label deny phases
//! with the devmgr enumeration redesign and its shims.

use std::os::seraph::startup_info;
use std::time::Duration;

use crate::bootstrap::Caps;
use crate::phases::drivers::INPUT_ATTEMPTS;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "devmgr_block_device_deny",
            run: block_device_deny_phase,
        },
        Phase {
            name: "devmgr_shutdown_device_deny",
            run: shutdown_device_deny_phase,
        },
        Phase {
            name: "devmgr_input_instance_ordinal",
            run: input_instance_ordinal_phase,
        },
        Phase {
            name: "devmgr_orphan_teardown",
            run: orphan_teardown_phase,
        },
        Phase {
            name: "devmgr_driver_withdrawal",
            run: driver_withdrawal_phase,
        },
        Phase {
            name: "devmgr_test_label_deny",
            run: test_label_deny_phase,
        },
    ]
}

/// A version-current request with the right label.
fn versioned(label: u64) -> ipc::IpcMessage
{
    ipc::IpcMessage::builder(label)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build()
}

/// `label` sent on `devmgr.registry`, whose badge lacks the label's
/// authority bit (`bit_name`), replies `UNAUTHORIZED` and carries no cap.
fn assert_registry_denies(caps: &Caps, label: u64, label_name: &str, bit_name: &str)
{
    let devmgr = caps.devmgr_registry;
    assert!(
        devmgr != 0,
        "{label_name} deny: no devmgr.registry cap seeded"
    );

    let ipc_buf = std::os::seraph::current_ipc_buf();

    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(devmgr, &versioned(label), ipc_buf) }
        .unwrap_or_else(|_| panic!("{label_name} ipc_call failed"));
    assert_eq!(
        reply.label,
        ipc::devmgr_errors::UNAUTHORIZED,
        "{label_name} without {bit_name} must reply UNAUTHORIZED"
    );
    assert!(
        reply.caps().is_empty(),
        "{label_name} deny must carry no cap"
    );
}

fn block_device_deny_phase(caps: &Caps)
{
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::QUERY_BLOCK_DEVICE,
        "QUERY_BLOCK_DEVICE",
        "BLOCK_DEVICE_AUTHORITY",
    );
}

fn shutdown_device_deny_phase(caps: &Caps)
{
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::QUERY_SHUTDOWN_DEVICE,
        "QUERY_SHUTDOWN_DEVICE",
        "SHUTDOWN_DEVICE_AUTHORITY",
    );
}

/// `QUERY_INPUT_DEVICE` on `devmgr.registry` selecting `ordinal` in
/// `data[1]`, or sending no `data[1]` for `None`.
fn query_input(devmgr: u32, ordinal: Option<u64>) -> ipc::IpcMessage
{
    let mut req = ipc::IpcMessage::builder(ipc::devmgr_labels::QUERY_INPUT_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION));
    if let Some(o) = ordinal
    {
        req = req.word(1, o);
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(devmgr, &req.build(), ipc_buf) }
        .unwrap_or_else(|_| panic!("QUERY_INPUT_DEVICE ordinal {ordinal:?} ipc_call failed"))
}

/// `reply` is a `SUCCESS` carrying one cap, which is released.
fn assert_granted(reply: &ipc::IpcMessage, what: &str)
{
    assert_eq!(reply.label, ipc::devmgr_errors::SUCCESS, "{what} status");
    let cap = reply.caps().first().copied().unwrap_or(0);
    assert!(cap != 0, "{what} carried no cap");
    let _ = syscall::cap_delete(cap);
}

fn input_instance_ordinal_phase(caps: &Caps)
{
    let devmgr = caps.devmgr_registry;
    assert!(devmgr != 0, "input ordinal: no devmgr.registry cap seeded");

    let mut first = query_input(devmgr, None);
    for _ in 1..INPUT_ATTEMPTS
    {
        if first.label != ipc::devmgr_errors::NO_DEVICE
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        first = query_input(devmgr, None);
    }
    assert_granted(&first, "QUERY_INPUT_DEVICE without an ordinal");
    assert_granted(
        &query_input(devmgr, Some(0)),
        "QUERY_INPUT_DEVICE ordinal 0",
    );
    for ordinal in [1, u64::MAX]
    {
        let reply = query_input(devmgr, Some(ordinal));
        assert_eq!(
            reply.label,
            ipc::devmgr_errors::NO_DEVICE,
            "QUERY_INPUT_DEVICE ordinal {ordinal} past the one keyboard must reply NO_DEVICE"
        );
        assert!(
            reply.caps().is_empty(),
            "ordinal {ordinal} reply must carry no cap"
        );
    }
}

/// Read memmgr's current free-pool total (`QUERY_POOL_STATUS` `data[3]`).
fn free_bytes(memmgr_ep: u32, ipc_buf: *mut u64) -> u64
{
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }
        .expect("memmgr QUERY_POOL_STATUS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status"
    );
    reply.word(3)
}

fn orphan_teardown_phase(caps: &Caps)
{
    // The child reserves ~1 MiB before hanging; the margin absorbs unrelated
    // allocator noise in the sampling window.
    const MARGIN_BYTES: u64 = 128 * 1024;
    // A test wait bound: it limits only how long the phase polls before it
    // fails.
    const MAX_POLL: u32 = 4096;
    // `free_bytes` samples memmgr's *whole-pool* free total, so the
    // before/after delta folds in any allocation other services perform in the
    // sampling window (and first-cycle page-cache warming of the on-disk
    // `test-orphan` ELF). Under SMP oversubscription that concurrent activity
    // can exceed `MARGIN_BYTES` for a single spawn, failing the recovery check
    // even though the orphan's pages were reclaimed (#285). Retry the whole
    // spawn→teardown→measure cycle: a genuine leak pins ~1 MiB *every* cycle so
    // the pool never recovers, whereas transient perturbation clears on a
    // re-baselined cycle. Passing on any clean cycle therefore tolerates the
    // noise without masking a real leak.
    const CYCLES: u32 = 8;

    let devmgr = caps.devmgr_test;
    assert!(devmgr != 0, "devmgr_orphan: no devmgr.test cap seeded");

    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let memmgr = info.memmgr_endpoint;

    let mut last_before = 0u64;
    let mut last_after = 0u64;
    let mut reclaimed = false;

    for cycle in 0..CYCLES
    {
        // Re-baseline each cycle so a prior cycle's incidental allocation does
        // not accumulate into this cycle's comparison.
        let free_before = free_bytes(memmgr, ipc_buf);

        // Trigger the forced-failure spawn. devmgr acks immediately, then runs
        // the spawn (which fails, unwinds, and DESTROYs the child) before it
        // services the result query below.
        let trigger = versioned(ipc::devmgr_labels::TEST_SPAWN_ORPHAN);
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let ack = unsafe { ipc::ipc_call(devmgr, &trigger, ipc_buf) }
            .expect("TEST_SPAWN_ORPHAN ipc_call failed");
        assert_eq!(
            ack.label,
            ipc::devmgr_errors::SUCCESS,
            "TEST_SPAWN_ORPHAN ack"
        );

        // Serviced only after devmgr returns to its loop — i.e. after the spawn
        // and its synchronous teardown completed.
        let query = versioned(ipc::devmgr_labels::TEST_ORPHAN_RESULT);
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let res = unsafe { ipc::ipc_call(devmgr, &query, ipc_buf) }
            .expect("TEST_ORPHAN_RESULT ipc_call failed");
        assert_eq!(
            res.label,
            ipc::devmgr_errors::SUCCESS,
            "TEST_ORPHAN_RESULT status"
        );
        let outcome = res.word(0);
        assert_eq!(
            outcome, 1,
            "devmgr_orphan: expected spawn-failed/unwind (1), got outcome={outcome} \
             (2=unexpected success, 3=shim setup error)"
        );

        // With #176's teardown the child's reserved pages are reclaimed
        // synchronously, so `free` returns to baseline; without it the hung
        // child stays pinned and `free` stays ~1 MiB low. Poll to bound any
        // incidental lag.
        let mut free_after = free_bytes(memmgr, ipc_buf);
        for _ in 0..MAX_POLL
        {
            if free_after + MARGIN_BYTES >= free_before
            {
                break;
            }
            let _ = syscall::thread_yield();
            free_after = free_bytes(memmgr, ipc_buf);
        }

        last_before = free_before;
        last_after = free_after;
        if free_after + MARGIN_BYTES >= free_before
        {
            reclaimed = true;
            break;
        }

        std::os::seraph::log!(
            "devmgr_orphan: cycle {cycle} reclaim short (before={free_before} after={free_after}); retrying"
        );
    }

    assert!(
        reclaimed,
        "devmgr_orphan: orphan pages not reclaimed across {CYCLES} cycles \
         (genuine leak pins memory every cycle): last free_before={last_before} free_after={last_after}"
    );

    std::os::seraph::log!(
        "devmgr_orphan_teardown passed: spawn unwound, free reclaimed (before={last_before} after={last_after})"
    );
}

/// `TEST_QUERY_FAULT_DEVICE` at `ordinal` on `devmgr.test`.
fn query_fault(devmgr: u32, ordinal: u64) -> ipc::IpcMessage
{
    let req = ipc::IpcMessage::builder(ipc::devmgr_labels::TEST_QUERY_FAULT_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .word(1, ordinal)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(devmgr, &req, ipc_buf) }
        .unwrap_or_else(|_| panic!("TEST_QUERY_FAULT_DEVICE ordinal {ordinal} ipc_call failed"))
}

/// The SEND a `SUCCESS` reply to `TEST_QUERY_FAULT_DEVICE` carries.
fn fault_cap(reply: &ipc::IpcMessage, what: &str) -> u32
{
    assert_eq!(reply.label, ipc::devmgr_errors::SUCCESS, "{what}: status");
    let cap = reply.caps().first().copied().unwrap_or(0);
    assert!(cap != 0, "{what}: SUCCESS carried no cap");
    cap
}

/// Call a fault fixture with `label` and no data.
fn call_fixture(cap: u32, label: u64) -> Result<ipc::IpcMessage, i64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, &ipc::IpcMessage::new(label), ipc_buf) }
}

/// devmgr's settle ends at its bound and withdraws a driver that never
/// reports ready; a served driver's death withdraws its endpoint (a call
/// queued on it returns) and leaves a tombstone at its ordinal while the
/// later ordinal keeps its driver.
fn driver_withdrawal_phase(caps: &Caps)
{
    use ipc::test_fault_labels::{FAULT_EXIT, FAULT_PING};

    // A test wait bound: it limits only how long the phase polls for the
    // fixtures' pages to return before it fails.
    const RECLAIM_POLLS: u32 = 300;

    let devmgr = caps.devmgr_test;
    assert!(devmgr != 0, "devmgr_withdrawal: no devmgr.test cap seeded");
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let memmgr = startup_info().memmgr_endpoint;
    let free_before = free_bytes(memmgr, ipc_buf);

    let start = std::time::Instant::now();
    let trigger = versioned(ipc::devmgr_labels::TEST_SPAWN_FAULT_DRIVERS);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let ack = unsafe { ipc::ipc_call(devmgr, &trigger, ipc_buf) }
        .expect("TEST_SPAWN_FAULT_DRIVERS ipc_call failed");
    assert_eq!(
        ack.label,
        ipc::devmgr_errors::SUCCESS,
        "TEST_SPAWN_FAULT_DRIVERS ack"
    );

    // Served once devmgr returns to its registry loop, after the batch's
    // settle: the never-ready fixture holds it until the bound.
    let first = fault_cap(&query_fault(devmgr, 0), "fault ordinal 0");
    let settle = start.elapsed();
    let bound = Duration::from_millis(ipc::devmgr_labels::TEST_FAULT_SETTLE_TIMEOUT_MS);
    assert!(
        settle >= bound,
        "devmgr_withdrawal: the settle ended after {settle:?}, before its bound {bound:?}, \
         with a fixture that never reports ready"
    );
    let second = fault_cap(&query_fault(devmgr, 1), "fault ordinal 1");
    assert_eq!(
        query_fault(devmgr, 2).label,
        ipc::devmgr_errors::NO_DEVICE,
        "the never-ready fixture must not be served"
    );

    // The fixture at ordinal 0 replies, then dies without receiving again, so
    // the PING sent after the reply is queued on its endpoint until devmgr
    // withdraws it.
    let exit = call_fixture(first, FAULT_EXIT).expect("FAULT_EXIT call failed");
    assert_eq!(exit.label, ipc::devmgr_errors::SUCCESS, "FAULT_EXIT reply");
    assert!(
        call_fixture(first, FAULT_PING).is_err(),
        "a call queued on a dead served driver's endpoint must return an error"
    );
    assert_eq!(
        query_fault(devmgr, 0).label,
        ipc::devmgr_errors::WITHDRAWN,
        "the dead fixture's ordinal must reply WITHDRAWN"
    );

    // The ordinal after the tombstone keeps its live fixture.
    let again = fault_cap(
        &query_fault(devmgr, 1),
        "fault ordinal 1 after the withdrawal",
    );
    let ping = call_fixture(again, FAULT_PING).expect("FAULT_PING on ordinal 1 failed");
    assert_eq!(ping.label, ipc::devmgr_errors::SUCCESS, "FAULT_PING reply");

    // Retire the last fixture; its own withdrawal is not observed here.
    let _ = call_fixture(second, FAULT_EXIT);
    for cap in [first, second, again]
    {
        let _ = syscall::cap_delete(cap);
    }

    // With every fixture gone, memmgr's free pool returns to its baseline
    // only if devmgr destroyed the never-ready fixture, which holds
    // NEVER_READY_RESERVE_BYTES until it is destroyed; the two ready
    // fixtures exited and are reaped. Half the reservation absorbs the
    // pool's incidental movement (the fixture ELF's file-cache warming
    // included).
    let margin = (ipc::test_fault_labels::NEVER_READY_RESERVE_BYTES / 2) as u64;
    let mut free_after = free_bytes(memmgr, ipc_buf);
    for _ in 0..RECLAIM_POLLS
    {
        if free_after + margin >= free_before
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        free_after = free_bytes(memmgr, ipc_buf);
    }
    assert!(
        free_after + margin >= free_before,
        "devmgr_withdrawal: the never-ready fixture's pages did not return \
         (free_before={free_before} free_after={free_after}); it was not destroyed"
    );

    std::os::seraph::log!(
        "devmgr_driver_withdrawal passed: settle ended at its bound after {settle:?}, \
         never-ready fixture destroyed, dead driver withdrawn, later ordinal kept"
    );
}

/// The test labels on `devmgr.registry` (no `TEST_LABEL_AUTHORITY`) reply
/// `UNAUTHORIZED`.
fn test_label_deny_phase(caps: &Caps)
{
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::TEST_SPAWN_FAULT_DRIVERS,
        "TEST_SPAWN_FAULT_DRIVERS",
        "TEST_LABEL_AUTHORITY",
    );
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::TEST_QUERY_FAULT_DEVICE,
        "TEST_QUERY_FAULT_DEVICE",
        "TEST_LABEL_AUTHORITY",
    );
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::TEST_SPAWN_ORPHAN,
        "TEST_SPAWN_ORPHAN",
        "TEST_LABEL_AUTHORITY",
    );
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::TEST_ORPHAN_RESULT,
        "TEST_ORPHAN_RESULT",
        "TEST_LABEL_AUTHORITY",
    );
    assert_registry_denies(
        caps,
        ipc::devmgr_labels::TEST_QUERY_DENY_DEVICE,
        "TEST_QUERY_DENY_DEVICE",
        "TEST_LABEL_AUTHORITY",
    );
}
