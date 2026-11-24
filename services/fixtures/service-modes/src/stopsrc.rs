// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/service-modes/src/stopsrc.rs

//! The stop-source test fixture: a supervised stop source of the program
//! class (`stop_source = program`), staged only with svctest
//! (services/fixtures/service-modes/README.md#stopsrc).
//!
//! On request it starts one job, a child process of its own binary that
//! touches a given number of pages and waits, and lists it through the
//! shared stop labels (`ipc::stop_labels`) at the program class's job rank,
//! with the pages its subtree holds beyond its own. A stop of the job's key
//! destroys the child through the process handle the fixture holds as its
//! creator. It serves `ipc::stopsrc_labels` on any badge on the endpoint of
//! the name its recipe provides, which svcmgr delivers in bootstrap slot 0,
//! and the stop labels there as well on a badge carrying
//! `stop_labels::STOP_AUTHORITY`, which only the SEND svcmgr hands a
//! stop-authority holder carries; on any other badge they reply
//! `stop_labels::UNAUTHORIZED`.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, stop_labels as stop, stopsrc_labels as src};

/// The mode of this fixture in its binary (`crate::PATH`), the first argument
/// of the job it starts.
const MODE: &str = "stopsrc";

/// Bytes of stack the fixture touches at start, below its loop's frame, so
/// its list and stop paths fault no new stack page while memory is critical.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

/// How long `START_JOB` waits for the job to hold its pages.
const JOB_READY_MS: u64 = 10_000;

/// How often `START_JOB` reads the subtree while it waits.
const JOB_POLL_MS: u64 = 20;

/// The page size the job touches its heap at.
const PAGE_BYTES: usize = 4096;

/// The job this instance started: its child, its key, whether a stop
/// destroyed it.
struct Job
{
    child: Option<Child>,
    key: u64,
    stopped: bool,
}

pub fn main() -> !
{
    let mut args = std::env::args().skip(2);
    if args.next().as_deref() == Some("job")
    {
        let pages = args
            .next()
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(0);
        job(pages);
    }
    std::os::seraph::log::register_name(b"stopsrc");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let service = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
        .map_or(0, |[cap]| cap);
    let nonce = syscall::random_u64().unwrap_or(0);
    if service == 0 || nonce == 0
    {
        std::os::seraph::log!(error: "no service endpoint or nonce");
        syscall::thread_exit();
    }
    touch_stack();
    std::os::seraph::log!("serving");
    serve(service, nonce, ipc_buf)
}

/// The job's role: touch `pages` pages of heap, then wait to be destroyed.
fn job(pages: usize) -> !
{
    let mut held = vec![0u8; pages.saturating_mul(PAGE_BYTES)];
    for page in held.chunks_mut(PAGE_BYTES)
    {
        if let Some(byte) = page.first_mut()
        {
            *byte = 1;
        }
    }
    std::hint::black_box(&mut held);
    loop
    {
        let _ = syscall::thread_sleep(60_000);
    }
}

/// Serve `src`'s labels on `service` on any badge, and the stop labels as
/// well on a badge carrying the stop bit.
fn serve(service: u64, nonce: u64, ipc_buf: *mut u64) -> !
{
    let mut job = Job {
        child: None,
        key: 0,
        stopped: false,
    };
    // Job keys start at the instance's nonce, so a key an earlier instance
    // handed out names none of this one's jobs but by chance
    // (`ipc::stop_labels`).
    let mut next_key = nonce;
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(service, ipc_buf) }
        {
            Ok(msg) =>
            {
                guard.on_success();
                msg
            }
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let authorized = msg.badge & stop::STOP_AUTHORITY != 0;
        let reply = match msg.label
        {
            stop::LIST_CANDIDATES | stop::STOP_CANDIDATE if !authorized =>
            {
                IpcMessage::new(stop::UNAUTHORIZED)
            }
            stop::LIST_CANDIDATES => list(&mut job, msg.word(0)),
            stop::STOP_CANDIDATE => stop_job(&mut job, msg.word(0)),
            src::PROBE => IpcMessage::builder(src::SUCCESS)
                .word(0, nonce)
                .word(1, state(&mut job))
                .word(2, if running(&mut job) { job.key } else { 0 })
                .build(),
            src::START_JOB => start_job(&mut job, &mut next_key, msg.word(0)),
            src::EXIT =>
            {
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(src::SUCCESS), ipc_buf) };
                // The job is left running: svcmgr creates the fixture
                // contained, so procmgr destroys it with this instance.
                std::os::seraph::log!("exiting on request");
                std::process::exit(0);
            }
            _ => IpcMessage::new(src::UNKNOWN_OPCODE),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// [`ipc::recv_guard::RecvGuard`] hook of stopsrc's receive loop: log the first
/// failure of a streak and the fatal one.
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

/// Whether the job runs: a child that has not ended.
fn running(job: &mut Job) -> bool
{
    job.child
        .as_mut()
        .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
}

/// The job's state as `PROBE` reports it.
fn state(job: &mut Job) -> u64
{
    if job.stopped
    {
        src::JOB_STOPPED
    }
    else if running(job)
    {
        src::JOB_RUNNING
    }
    else
    {
        src::JOB_NONE
    }
}

/// The pages the fixture's budget subtree holds beyond its own node: the
/// job's. `None` when memmgr does not answer.
fn job_pages() -> Option<u64>
{
    let req = IpcMessage::new(ipc::memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: current_ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &req,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .ok()?;
    (reply.label == ipc::memmgr_errors::SUCCESS)
        .then(|| reply.word(2).saturating_sub(reply.word(0)))
}

/// `START_JOB` of `pages` pages under the next key.
fn start_job(job: &mut Job, next_key: &mut u64, pages: u64) -> IpcMessage
{
    if running(job)
    {
        return IpcMessage::new(src::BUSY);
    }
    let Ok(mut child) = Command::new(crate::PATH)
        .args([MODE, "job"])
        .arg(pages.to_string())
        .spawn()
    else
    {
        std::os::seraph::log!(warn: "job not created");
        return IpcMessage::new(src::JOB_FAILED);
    };
    let start = Instant::now();
    while job_pages().is_none_or(|held| held < pages)
    {
        if start.elapsed() >= Duration::from_millis(JOB_READY_MS)
        {
            let _ = child.kill();
            let _ = child.wait();
            std::os::seraph::log!(warn: "job did not hold {pages} pages");
            return IpcMessage::new(src::JOB_FAILED);
        }
        std::thread::sleep(Duration::from_millis(JOB_POLL_MS));
    }
    job.child = Some(child);
    job.key = *next_key;
    job.stopped = false;
    *next_key = next_key.wrapping_add(1).max(1);
    std::os::seraph::log!("job {} holds {pages} pages", job.key);
    IpcMessage::builder(src::SUCCESS).word(0, job.key).build()
}

/// `LIST_CANDIDATES` from `cursor`: the job, while it runs, at cursor 0;
/// the list is one entry long, so every page is short.
fn list(job: &mut Job, cursor: u64) -> IpcMessage
{
    let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
    let mut count = 0u64;
    if cursor == 0
        && running(job)
        && let Some(pages) = job_pages()
        && stop::pack_candidate(&mut words, 0, job.key, stop::RANK_JOB, pages, src::JOB_NAME)
    {
        count = 1;
    }
    words[0] = count;
    words[1] = 1;
    let used = if count == 1
    {
        stop::HEADER_WORDS.saturating_add(stop::CANDIDATE_WORDS)
    }
    else
    {
        stop::HEADER_WORDS
    };
    IpcMessage::builder(stop::SUCCESS)
        .words(0, words.get(..used).unwrap_or_default())
        .build()
}

/// `STOP_CANDIDATE` of `key`: destroy the job when `key` names it and it
/// runs.
fn stop_job(job: &mut Job, key: u64) -> IpcMessage
{
    if key != job.key || !running(job)
    {
        std::os::seraph::log!("stop of key {key} refused: no such job");
        return IpcMessage::new(stop::NO_CANDIDATE);
    }
    let Some(child) = job.child.as_mut()
    else
    {
        return IpcMessage::new(stop::NO_CANDIDATE);
    };
    if child.kill().is_err()
    {
        std::os::seraph::log!(warn: "stop of job {key} failed");
        return IpcMessage::new(stop::UNAVAILABLE);
    }
    let _ = child.wait();
    job.stopped = true;
    std::os::seraph::log!("job {key} stopped for a stop-authority holder");
    IpcMessage::new(stop::SUCCESS)
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the fixture uses, written once at start"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}
