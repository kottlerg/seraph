// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/recv_pool.rs

//! The worker-pool receive helper under concurrent nested IPC, and concurrent
//! logging through logd.
//!
//! `recv_pool` serves an endpoint of svctest's own through a four-worker
//! `RecvPool`. Each handler makes a nested `ipc_call` to an echo server on
//! its own IPC buffer page while it serves, and the reply it builds from the
//! copied-out request must be whole. A gather request holds every worker
//! inside its handler until four requests are in flight at once, which
//! completes only when four workers receive concurrently. `logd_concurrent`
//! logs from several threads at once, times it, and checks every retained
//! record of svctest's own slot whole through `logd.query`.

use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ipc::IpcMessage;
use ipc::log_query::{
    ENTRY_RECORD, QUERY_OK, SLOT_LIVE, reply_more, reply_status, slot_entry, slots_request,
};
use ipc::log_record::Record;
use ipc::recv_guard::RecvFailureStage;
use recv_pool::{IpcBuf, RecvPool};

use crate::bootstrap::Caps;
use crate::phases::procmgr::{logd_history, logd_query_call};
use crate::runner::Phase;

/// Request label: a nested-call echo round.
const RP_ECHO: u64 = 1;
/// Request label: hold the handler until four requests are in flight.
const RP_GATHER: u64 = 2;
/// Reply label: the request was served and every check held.
const RP_OK: u64 = 0;
/// Reply label: a check in the handler failed.
const RP_FAIL: u64 = 0xBAD;

/// Workers of the pool: three spawned, one the serving thread.
const WORKERS: usize = 4;
/// Client threads.
const CLIENTS: u64 = 4;
/// `RP_ECHO` calls per client.
const ROUNDS: u64 = 32;
/// Words of an echo request and its reply.
const ECHO_WORDS: usize = 16;
/// The mask the handler applies to the words it forwards to the echo server.
const FORWARD_MASK: u64 = 0x5A5A_5A5A_5A5A_5A5A;
/// Total time a gather handler waits for the other workers.
const GATHER_BUDGET: Duration = Duration::from_secs(10);

/// Buffer pages of the workers currently held in a gather handler.
static GATHER: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static GATHER_CHANGED: Condvar = Condvar::new();

/// Threads of the `logd_concurrent` burst.
const THREADS: usize = 4;
/// Records each burst thread logs.
const LINES: usize = 50;
/// The message of every burst record.
const BURST_MESSAGE: &[u8] = b"logd_concurrent burst";

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "recv_pool",
            run: recv_pool_phase,
        },
        Phase {
            name: "logd_concurrent",
            run: logd_concurrent_phase,
        },
    ]
}

/// The pool's `RecvGuard` hook.
fn diag(stage: RecvFailureStage, err: i64)
{
    let stage = match stage
    {
        RecvFailureStage::First => "first failure",
        RecvFailureStage::Fatal => "fatal",
    };
    std::os::seraph::log!("recv_pool: worker receive {stage}: error {err}");
}

fn fail_reply() -> IpcMessage
{
    IpcMessage::new(RP_FAIL)
}

/// Serve one request; the returned message is the reply.
fn serve(msg: &IpcMessage, buf: IpcBuf, echo: u64) -> IpcMessage
{
    if buf.as_ptr() != std::os::seraph::current_ipc_buf()
    {
        return fail_reply();
    }
    match msg.label
    {
        RP_ECHO => serve_echo(msg, buf, echo),
        RP_GATHER => serve_gather(buf),
        _ => fail_reply(),
    }
}

fn serve_echo(msg: &IpcMessage, buf: IpcBuf, echo: u64) -> IpcMessage
{
    let mut sent = [0u64; ECHO_WORDS];
    for (k, w) in sent.iter_mut().enumerate()
    {
        *w = msg.word(k) ^ FORWARD_MASK;
    }
    let nested = IpcMessage::builder(RP_ECHO).words(0, &sent).build();
    // SAFETY: `buf` is this worker thread's registered IPC buffer page.
    let Ok(echoed) = (unsafe { ipc::ipc_call(echo, &nested, buf.as_ptr()) })
    else
    {
        return fail_reply();
    };
    if echoed.label != RP_ECHO
        || echoed.word_count() != ECHO_WORDS
        || sent.iter().enumerate().any(|(k, &w)| echoed.word(k) != !w)
    {
        return fail_reply();
    }
    let mut out = [0u64; ECHO_WORDS];
    for (k, w) in out.iter_mut().enumerate()
    {
        *w = msg
            .word(k)
            .wrapping_add((k as u64).checked_add(1).expect("echo word index"));
    }
    IpcMessage::builder(RP_OK).words(0, &out).build()
}

fn serve_gather(buf: IpcBuf) -> IpcMessage
{
    let deadline = Instant::now()
        .checked_add(GATHER_BUDGET)
        .expect("gather deadline overflowed");
    let mut held = GATHER.lock().unwrap_or_else(PoisonError::into_inner);
    held.push(buf.as_ptr() as usize);
    GATHER_CHANGED.notify_all();
    while held.len() < WORKERS
    {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero()
        {
            return fail_reply();
        }
        held = GATHER_CHANGED
            .wait_timeout(held, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
    let mut pages = held.clone();
    drop(held);
    pages.sort_unstable();
    pages.dedup();
    if pages.len() == WORKERS
    {
        IpcMessage::builder(RP_OK).word(0, 1).build()
    }
    else
    {
        fail_reply()
    }
}

/// The request word `k` of client `client`'s round `round`.
fn request_word(client: u64, round: u64, k: usize) -> u64
{
    match k
    {
        0 => client,
        1 => round,
        _ =>
        {
            (client << 48)
                | (round << 32)
                | ((k as u64)
                    .checked_sub(2)
                    .and_then(|extra| extra.checked_mul(0x1111))
                    .expect("request word index"))
        }
    }
}

/// One client: the gather call, then [`ROUNDS`] echo calls. Returns a
/// description of each failure.
#[expect(
    clippy::large_stack_frames,
    reason = "the `gather` and `req` `IpcMessage`s (568 B each), the `reply` of each call and the \
              `words` array (`ECHO_WORDS`, 128 B); on the stack of a spawned client thread, 64 KiB \
              at the least"
)]
fn run_client(client: u64, send: u64) -> Vec<String>
{
    let buf = std::os::seraph::current_ipc_buf();
    let mut failures = Vec::new();

    let gather = IpcMessage::new(RP_GATHER);
    // SAFETY: `buf` is this thread's registered IPC buffer page.
    match unsafe { ipc::ipc_call(send, &gather, buf) }
    {
        Ok(reply) if reply.label == RP_OK && reply.word(0) == 1 =>
        {}
        Ok(reply) => failures.push(format!(
            "client {client}: gather reply label {:#x} word0 {}",
            reply.label,
            reply.word(0)
        )),
        Err(e) => failures.push(format!("client {client}: gather call failed ({e})")),
    }

    for round in 0..ROUNDS
    {
        let mut words = [0u64; ECHO_WORDS];
        for (k, w) in words.iter_mut().enumerate()
        {
            *w = request_word(client, round, k);
        }
        let req = IpcMessage::builder(RP_ECHO).words(0, &words).build();
        // SAFETY: as above.
        let reply = match unsafe { ipc::ipc_call(send, &req, buf) }
        {
            Ok(reply) => reply,
            Err(e) =>
            {
                failures.push(format!("client {client} round {round}: call failed ({e})"));
                continue;
            }
        };
        if reply.label != RP_OK
        {
            failures.push(format!(
                "client {client} round {round}: reply label {:#x}",
                reply.label
            ));
            continue;
        }
        for (k, &w) in words.iter().enumerate()
        {
            let want = w.wrapping_add((k as u64).checked_add(1).expect("echo word index"));
            if reply.word(k) != want
            {
                failures.push(format!(
                    "client {client} round {round} word {k}: got {:#x}, want {want:#x}",
                    reply.word(k)
                ));
                break;
            }
        }
    }
    failures
}

fn recv_pool_phase(_: &Caps)
{
    let new_endpoint = |what: &str| {
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or_else(|| panic!("recv_pool: {what} endpoint"))
    };
    // Neither endpoint is deleted: a pool worker whose endpoint is deleted
    // fails its receives, and its `RecvGuard` exits the whole process. The
    // echo thread and the workers stay blocked in receive for the life of
    // the process.
    let served = new_endpoint("served");
    let echo = new_endpoint("echo");
    let served_send =
        syscall::cap_derive(served, syscall::RIGHTS_EP_SEND).expect("recv_pool: served SEND");
    let echo_send =
        syscall::cap_derive(echo, syscall::RIGHTS_EP_SEND).expect("recv_pool: echo SEND");

    std::thread::Builder::new()
        .name("svctest-rp-echo".into())
        .spawn(move || {
            let buf = std::os::seraph::current_ipc_buf();
            loop
            {
                // SAFETY: `buf` is this thread's registered IPC buffer page.
                let Ok(msg) = (unsafe { ipc::ipc_recv(echo, buf) })
                else
                {
                    return;
                };
                let mut out = [0u64; ECHO_WORDS];
                for (k, w) in out.iter_mut().enumerate()
                {
                    *w = !msg.word(k);
                }
                let reply = IpcMessage::builder(msg.label).words(0, &out).build();
                // SAFETY: as above.
                let _ = unsafe { ipc::ipc_reply(&reply, buf) };
            }
        })
        .expect("recv_pool: spawn echo thread");

    std::thread::Builder::new()
        .name("svctest-rp-serve".into())
        .spawn(move || {
            let pool = RecvPool::new(served, diag, move |msg: &IpcMessage, buf: IpcBuf| {
                let reply = serve(msg, buf, echo_send);
                // SAFETY: `buf` is this worker's registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, buf.as_ptr()) };
            });
            match pool.spawn("svctest-rp", WORKERS - 1)
            {
                Ok(n) if n == WORKERS - 1 =>
                {}
                _ => panic!("recv_pool: spawning the pool workers failed"),
            }
            pool.serve_on_current()
        })
        .expect("recv_pool: spawn serving thread");

    let clients: Vec<_> = (0..CLIENTS)
        .map(|client| std::thread::spawn(move || run_client(client, served_send)))
        .collect();
    let mut failures = Vec::new();
    for (client, handle) in clients.into_iter().enumerate()
    {
        match handle.join()
        {
            Ok(mut f) => failures.append(&mut f),
            Err(_) => failures.push(format!("client {client}: thread panicked")),
        }
    }
    assert!(
        failures.is_empty(),
        "recv_pool: {} failures: {failures:?}",
        failures.len()
    );
    std::os::seraph::log!(
        "recv_pool phase passed ({WORKERS} workers, {CLIENTS} clients, {ROUNDS} rounds each)"
    );
}

/// The live slots named `svctest`, as badges, across every `QUERY_SLOTS`
/// page.
fn own_live_badges(query: u64) -> Vec<u64>
{
    let mut found = Vec::new();
    let mut after = None;
    loop
    {
        let reply = logd_query_call(query, &slots_request(after));
        assert_eq!(
            reply_status(reply.label),
            QUERY_OK,
            "logd_concurrent: QUERY_SLOTS refused ({:#x})",
            reply.label
        );
        let mut index = 0;
        while let Some(entry) = slot_entry(&reply, index)
        {
            if entry.name() == b"svctest" && entry.state == SLOT_LIVE
            {
                found.push(entry.badge);
            }
            after = Some(entry.cursor());
            index = index.checked_add(1).expect("slot index");
        }
        if !reply_more(reply.label)
        {
            return found;
        }
        assert!(
            index > 0,
            "logd_concurrent: QUERY_SLOTS page empty but more"
        );
    }
}

/// Parse the decimal value of a record field.
fn field_number(value: &[u8]) -> Option<usize>
{
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn logd_concurrent_phase(caps: &Caps)
{
    assert_ne!(caps.logd_query, 0, "logd_concurrent: no logd.query seed");

    let start = Instant::now();
    let burst: Vec<_> = (0..THREADS)
        .map(|i| {
            std::thread::spawn(move || {
                for j in 0..LINES
                {
                    std::os::seraph::log!("logd_concurrent burst"; t = i, n = j);
                }
            })
        })
        .collect();
    for handle in burst
    {
        handle.join().expect("logd_concurrent: burst thread");
    }
    let elapsed = start.elapsed();
    std::os::seraph::log!(
        "logd_concurrent: {} records from {THREADS} threads in {}.{:03} ms",
        THREADS * LINES,
        elapsed.as_millis(),
        elapsed.as_micros() % 1000
    );

    // svctest's slot is the live slot named `svctest` whose history holds the
    // burst; its children's slots carry the same name.
    let mut records = None;
    for badge in own_live_badges(caps.logd_query)
    {
        let found: Vec<Vec<u8>> = logd_history(caps.logd_query, badge)
            .into_iter()
            .filter(|(kind, bytes)| {
                *kind == ENTRY_RECORD
                    && Record::decode(bytes).is_ok_and(|r| r.message() == BURST_MESSAGE)
            })
            .map(|(_, bytes)| bytes)
            .collect();
        if !found.is_empty()
        {
            records = Some(found);
            break;
        }
    }
    let records = records.expect("logd_concurrent: no burst record in svctest's history");

    // Newest first: per thread, `n` strictly decreases.
    let mut last = [usize::MAX; THREADS];
    for bytes in &records
    {
        let record = Record::decode(bytes).expect("logd_concurrent: a retained record decodes");
        let fields: Vec<_> = record.fields().collect();
        let [t, n] = &fields[..]
        else
        {
            panic!("logd_concurrent: record has {} fields, not 2", fields.len());
        };
        assert_eq!(t.key, b"t", "logd_concurrent: first field is not `t`");
        assert_eq!(n.key, b"n", "logd_concurrent: second field is not `n`");
        let t = field_number(t.value)
            .filter(|&t| t < THREADS)
            .expect("logd_concurrent: field `t` out of range");
        let n = field_number(n.value)
            .filter(|&n| n < LINES)
            .expect("logd_concurrent: field `n` out of range");
        let prev = last
            .get_mut(t)
            .expect("logd_concurrent: thread index out of range");
        assert!(
            n < *prev,
            "logd_concurrent: thread {t} retained out of order (n {n} after {})",
            *prev
        );
        *prev = n;
    }
    std::os::seraph::log!(
        "logd_concurrent phase passed ({} burst records retained whole and in order)",
        records.len()
    );
}
