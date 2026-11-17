// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/src/oom.rs

//! The two modes of the crash service's hold of a fault memmgr declined for
//! want of memory (services/crashd/docs/operation.md § Hold), which the tester
//! runs together.
//!
//! `crashme oom-fill <ms>` commits what memmgr can still promise a process
//! outside the system reserve until its pressure level reads `CRITICAL`,
//! prints `full`, keeps it there for `<ms>` milliseconds, taking back what
//! other processes free meanwhile, and exits, which gives it all back.
//! `crashme oom-touch` registers a demand page before that, and on its second
//! line of stdin writes the page: memmgr declines the fault, the crash service
//! holds it, and the write either completes once the filler exits, printing
//! how long it took, or the hold times out and the process dies of the fault.
//! Neither allocates while the level is `CRITICAL`.

use std::io::{BufRead, Write};
use std::process::exit;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::PAGE_SIZE;

/// Exit code: a `QUERY_POOL_STATUS` call to memmgr failed or was refused.
const FILL_STATUS_FAILED: i32 = 2;
/// Exit code: the level did not read `CRITICAL`, with nothing left to
/// commit, for [`FILL_SETTLE`] within [`FILL_TIMEOUT`].
const FILL_NOT_CRITICAL: i32 = 3;
/// Exit code: the ballast's allocation failed.
const FILL_BALLAST_FAILED: i32 = 4;
/// Exit code: the mode's argument is not a number of milliseconds.
const FILL_USAGE: i32 = 5;
/// Exit code: `oom-touch` could not register its page or read its stdin.
const TOUCH_SETUP_FAILED: i32 = 6;

/// How long the level must read `CRITICAL`, with nothing left to commit,
/// before the filler prints `full`: a file system gives back its cache when
/// the level rises to `LOW` or `CRITICAL`, and the filler takes it.
const FILL_SETTLE: Duration = Duration::from_millis(500);
/// How long the filler tries to reach `CRITICAL`. A test wait bound.
const FILL_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the filler takes back what other processes freed.
const FILL_TICK: Duration = Duration::from_millis(10);
/// Blocks the filler commits at most: each failure halves the next attempt,
/// and each success commits at least half of what is left.
const FILL_MAX_BLOCKS: usize = 256;
/// Attempts of one top-up.
const FILL_ROUNDS: usize = 64;
/// Pages a heap commitment grows by at least (the runtime's heap grows in
/// 16-page steps); less than this is taken by one-page grants.
const COMMIT_MIN_PAGES: u64 = 16;
/// Bytes of the filler's ballast: the size of the heap's floor, an
/// uncommitted demand region whose untouched pages memmgr backs only while it
/// has pages to spare, so every block the filler commits after lies above it.
const BALLAST_BYTES: usize = 2 << 20;
/// Bytes of stack each mode touches before the window, below its frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

/// `crashme oom-fill <ms>`: fill memmgr's pool up to the system reserve, print
/// `full`, hold it there for `<ms>`, and exit 0.
pub fn fill(arg: Option<&str>) -> !
{
    let Some(full_for) = arg
        .and_then(|ms| ms.parse().ok())
        .map(Duration::from_millis)
    else
    {
        println!("usage: crashme oom-fill <ms>");
        exit(FILL_USAGE);
    };
    let mut ballast: Vec<u8> = Vec::new();
    if ballast.try_reserve_exact(BALLAST_BYTES).is_err()
    {
        exit(FILL_BALLAST_FAILED);
    }
    ballast.resize(BALLAST_BYTES, 1);
    let mut held: Vec<Vec<u8>> = Vec::with_capacity(FILL_MAX_BLOCKS);
    touch_stack();
    say("filling");

    let start = Instant::now();
    let mut critical_since: Option<Instant> = None;
    loop
    {
        top_up(&mut held);
        let full = available() == 0
            && std::os::seraph::memory_pressure()
                == Some(std::os::seraph::MemoryPressure::Critical);
        match (full, critical_since)
        {
            (true, Some(since)) if since.elapsed() >= FILL_SETTLE => break,
            (true, None) => critical_since = Some(Instant::now()),
            (false, _) => critical_since = None,
            (true, Some(_)) =>
            {}
        }
        if start.elapsed() > FILL_TIMEOUT
        {
            exit(FILL_NOT_CRITICAL);
        }
        std::thread::sleep(FILL_TICK);
    }
    say("full");
    let until = Instant::now();
    while until.elapsed() < full_for
    {
        top_up(&mut held);
        std::thread::sleep(FILL_TICK);
    }
    // The exit gives memmgr back every commitment and grant.
    exit(0);
}

/// `crashme oom-touch`: register one demand page, read a first line of stdin
/// and print `ready`, then, on the second line, write the page and print how
/// long the write took.
pub fn touch() -> !
{
    let Ok(page) = std::os::seraph::register_demand_paged(1)
    else
    {
        exit(TOUCH_SETUP_FAILED);
    };
    let stdin = std::io::stdin();
    let mut line = String::with_capacity(64);
    // The first line and `ready` make stdin's and stdout's buffers before the
    // window.
    if stdin.lock().read_line(&mut line).is_err()
    {
        exit(TOUCH_SETUP_FAILED);
    }
    touch_stack();
    say("ready");
    line.clear();
    if stdin.lock().read_line(&mut line).is_err()
    {
        exit(TOUCH_SETUP_FAILED);
    }
    let start = Instant::now();
    // SAFETY: `page` is a page this process registered as a demand region
    // and nothing else uses; the write is volatile so that it is made, and
    // faults, here.
    unsafe { std::ptr::write_volatile(page.va_start() as *mut u8, 1) };
    let held = start.elapsed().as_millis();
    println!("touched held_ms={held}");
    exit(0);
}

/// Print `line` and flush it, so the tester reads it at once.
fn say(line: &str)
{
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the window may use, written once before it"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}

/// What memmgr can still promise a process outside the reserve, in pages:
/// its free pages less `promised` and the reserve (`QUERY_POOL_STATUS`'s
/// `data[3]`, `data[8]` and `data[6]`). Allocates nothing.
fn available() -> u64
{
    let req = IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &req,
            std::os::seraph::current_ipc_buf(),
        )
    };
    match reply
    {
        Ok(r) if r.label == memmgr_errors::SUCCESS => (r.word(3) / PAGE_SIZE)
            .saturating_sub(r.word(8) / PAGE_SIZE)
            .saturating_sub(r.word(6) / PAGE_SIZE),
        _ => exit(FILL_STATUS_FAILED),
    }
}

/// Take what memmgr can still promise: commit it through the heap, halving
/// an attempt memmgr refuses, while [`COMMIT_MIN_PAGES`] or more are left and
/// `held` has room, then take what is left a page at a time by grants,
/// whose caps the filler keeps until it exits.
fn top_up(held: &mut Vec<Vec<u8>>)
{
    let mut ask = u64::MAX;
    for _ in 0..FILL_ROUNDS
    {
        let left = available();
        if left == 0
        {
            return;
        }
        ask = ask.min(left);
        if ask >= COMMIT_MIN_PAGES && held.len() < held.capacity()
        {
            let bytes = usize::try_from(ask.saturating_mul(PAGE_SIZE)).unwrap_or(usize::MAX);
            let mut block: Vec<u8> = Vec::new();
            if block.try_reserve_exact(bytes).is_ok()
            {
                held.push(block);
            }
            else
            {
                ask /= 2;
            }
        }
        else if !grant_one()
        {
            return;
        }
    }
}

/// Take one page by a `REQUEST_MEMORY_CAPS` grant, keeping its cap; `false`
/// when memmgr refuses it.
fn grant_one() -> bool
{
    let grant = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &grant,
            std::os::seraph::current_ipc_buf(),
        )
    };
    reply.is_ok_and(|r| r.label == memmgr_errors::SUCCESS)
}
