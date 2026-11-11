// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/log_client.rs

//! The `shared/log` client against a log receiver that stops answering.
//!
//! Every log call is bounded (`log::LOG_CALL_TIMEOUT_MS`), and once one times
//! out the process's later calls are bounded by
//! `log::LOG_CALL_UNANSWERED_TIMEOUT_MS` until a call is answered again, so a
//! wedged or dead logd costs a sender one long bound and then a short one per
//! line, and the sender keeps running. The receiver here is an endpoint of
//! svctest's own: one thread receives a call on it and never answers, and
//! nothing receives on it after that, so the first call times out waiting for
//! its reply and the later ones waiting for a receiver. The calls go through
//! this binary's own copy of the `log` crate with the endpoint's cap passed
//! explicitly, so svctest's real log stream (std's copy, on logd) is
//! untouched.

use std::os::seraph::current_ipc_buf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ipc::stream_labels::LEVEL_INFO;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// Log calls made after the first has timed out; together they must take
/// less than the one bound the first call waited out.
const LATER_CALLS: u32 = 20;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "log_wedged_receiver",
        run: wedged_receiver_phase,
    }]
}

fn wedged_receiver_phase(_: &Caps)
{
    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("log_wedged_receiver: an endpoint");

    let (received_tx, received_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let wedged = std::thread::spawn(move || {
        let ipc_buf = current_ipc_buf();
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        unsafe { ipc::ipc_recv(endpoint, ipc_buf) }
            .expect("log_wedged_receiver: the receiver's ipc_recv");
        let _ = received_tx.send(());
        // Leave the call unanswered, and receive nothing more, until the
        // phase is done; the thread's exit then releases the binding.
        let _ = release_rx.recv();
    });

    let ipc_buf = current_ipc_buf();
    let line = b"svctest: a line to a receiver that never answers\n";

    let start = Instant::now();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { log::write_bytes(endpoint, ipc_buf, LEVEL_INFO, line) };
    let first = start.elapsed();
    let bound = Duration::from_millis(u64::from(log::LOG_CALL_TIMEOUT_MS));
    assert!(
        first >= bound * 9 / 10,
        "log_wedged_receiver: the first call returned after {first:?}, before its {bound:?} bound"
    );

    let start = Instant::now();
    for _ in 0..LATER_CALLS
    {
        // SAFETY: as above.
        unsafe { log::write_bytes(endpoint, ipc_buf, LEVEL_INFO, line) };
    }
    let later = start.elapsed();
    std::os::seraph::log!(
        "log_wedged_receiver: first call {first:?}, {LATER_CALLS} later calls {later:?}"
    );
    assert!(
        later < bound,
        "log_wedged_receiver: {LATER_CALLS} calls after a timeout took {later:?}, not under one \
         {bound:?} bound"
    );

    assert!(
        received_rx.recv_timeout(bound).is_ok(),
        "log_wedged_receiver: the receiver never received a call"
    );
    let _ = release_tx.send(());
    wedged
        .join()
        .expect("log_wedged_receiver: the receiver thread");
    syscall::cap_delete(endpoint).expect("log_wedged_receiver: deleting the endpoint");
}
