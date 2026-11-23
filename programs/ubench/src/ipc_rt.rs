// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/ubench/src/ipc_rt.rs

//! `ipc_rt`: the round trip of a synchronous call from one thread of a
//! process to another on the same CPU, through the userspace IPC library a
//! service uses (`shared/ipc`'s `ipc_call`, `ipc_recv` and `ipc_reply`).
//!
//! The server thread echoes each call's data words in its reply, so a sample
//! of `words=N` carries N words each way. Both threads are pinned to
//! [`BENCH_CPU`]: every call wakes the server on the caller's CPU, and every
//! reply wakes the caller there, so no sample crosses a CPU.

use bench::{Counters, Value};
use ipc::IpcMessage;
use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::harness::{BENCH_CPU, Outcome, pin_to, report};

/// The data-word counts measured: none, the most that may travel in
/// registers (`MSG_REGS_DATA_MAX`, 6), the first count past it, and the
/// most a message holds (`MSG_DATA_WORDS_MAX`, 64).
const WORDS: [usize; 4] = [0, 6, 7, MSG_DATA_WORDS_MAX];

/// Untimed round trips before each count's timed ones.
const WARMUP: usize = 64;

/// Timed round trips per word count.
const ITERS: usize = 1024;

/// The label of a measured call.
const CALL: u64 = 0;

/// The label of the call that ends the server thread.
const STOP: u64 = 1;

/// Bound on the stopping call, in milliseconds: a server thread that ended
/// early leaves no receiver, and the harness reports that rather than hang.
const STOP_TIMEOUT_MS: u32 = 10_000;

/// Run the benchmark: one result line per word count.
pub fn run(counters: &Counters, cpus: u32) -> Outcome
{
    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .ok_or_else(|| "create the endpoint".to_string())?;
    let server = std::thread::Builder::new()
        .name("ubench-ipc-server".into())
        .spawn(move || serve(ep))
        .map_err(|e| format!("spawn the server thread: {e}"));
    let outcome = server.and_then(|server| {
        let measured = measure_all(ep, counters, cpus);
        let stopped = stop(ep);
        let server_outcome = server
            .join()
            .map_err(|_| "the server thread panicked".to_string())
            .and_then(|r| r);
        measured.and(stopped).and(server_outcome)
    });
    // The endpoint is this function's alone; a failed delete leaks one slot
    // of a process that exits after the suite.
    let _ = syscall::cap_delete(ep);
    outcome
}

/// Time every word count's round trips and log their result lines.
fn measure_all(ep: u64, counters: &Counters, cpus: u32) -> Outcome
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let payload = [0x5a5a_5a5a_5a5a_5a5au64; MSG_DATA_WORDS_MAX];
    let mut samples = Vec::with_capacity(ITERS);
    for words in WORDS
    {
        let sent = payload
            .get(..words)
            .ok_or_else(|| format!("words={words} exceeds the payload"))?;
        let msg = IpcMessage::builder(CALL).words(0, sent).build();
        samples.clear();
        for i in 0..WARMUP + ITERS
        {
            let start = counters.read();
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            let reply = unsafe { ipc::ipc_call(ep, &msg, ipc_buf) };
            let cycles = counters.read().since(&start).cycles;
            let reply = reply.map_err(|e| format!("words={words}: call failed: error {e}"))?;
            if reply.word_count() != words
            {
                return Err(format!(
                    "words={words}: the reply carried {} words",
                    reply.word_count()
                ));
            }
            if i >= WARMUP
            {
                samples.push(cycles);
            }
        }
        report(
            "ipc_rt",
            &[("words", Value::Num(words as u64))],
            cpus,
            &mut samples,
            &[],
        )?;
    }
    Ok(())
}

/// End the server thread: a call with the [`STOP`] label, which it answers
/// before it returns.
fn stop(ep: u64) -> Outcome
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(STOP).build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call_timeout(ep, &msg, ipc_buf, STOP_TIMEOUT_MS) }
        .map(|_| ())
        .map_err(|e| format!("stop the server thread: error {e}"))
}

/// The server thread: pinned to [`BENCH_CPU`], it answers every call with
/// the call's data words until a call carries [`STOP`].
///
/// It serves even when its pin fails, so the caller's calls are answered and
/// the failure is reported once the run ends rather than hanging it.
fn serve(ep: u64) -> Outcome
{
    let pinned = pin_to(BENCH_CPU);
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let call = unsafe { ipc::ipc_recv(ep, ipc_buf) }
            .map_err(|e| format!("server receive failed: error {e}"))?;
        let reply = IpcMessage::builder(0).words(0, call.words()).build();
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        unsafe { ipc::ipc_reply(&reply, ipc_buf) }
            .map_err(|e| format!("server reply failed: error {e}"))?;
        if call.label == STOP
        {
            return pinned.map_err(|e| format!("server thread: {e}"));
        }
    }
}
