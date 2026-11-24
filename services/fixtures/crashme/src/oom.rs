// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/crashme/src/oom.rs

//! The two modes of the crash service's hold of a fault memmgr declined for
//! want of memory (services/crashd/docs/operation.md § Hold), which the tester
//! runs together.
//!
//! `crashme oom-fill <ms>` commits what memmgr can still promise a process
//! outside the system reserve until its pressure level reads `CRITICAL`,
//! prints `full`, keeps it there for `<ms>` milliseconds, taking back what
//! other processes free meanwhile, and exits, which gives it all back.
//! `crashme oom-touch <pages>` registers a demand region of `<pages>` pages
//! before that, and on its second line of stdin writes each page in turn:
//! memmgr declines the first write past the free pages above its growth floor,
//! the crash service holds it, and the write either completes once the filler
//! exits, the process printing how long its longest write took, or the hold
//! times out and the process dies of the fault.
//! Neither allocates while the level is `CRITICAL`. The fill is
//! `mem_fill`'s, shared with the `memhog` fixture.
//!
//! `crashme oom-hold <pages>` touches `<pages>` pages of heap, prints
//! `holding <pages>` and waits to be destroyed: a program of an operator
//! session that svctest's `oom_policy` phase starts through the session's
//! shell, for oomd to stop as a job (docs/session-supervision.md).

use std::io::{BufRead, Write};
use std::process::exit;
use std::time::{Duration, Instant};

use mem_fill::Fill;

/// Exit code: a `QUERY_POOL_STATUS` call to memmgr failed or was refused.
const FILL_STATUS_FAILED: i32 = 2;
/// Exit code: the level did not read `CRITICAL`, with nothing left to
/// commit, for `mem_fill::SETTLE_MS` within `mem_fill::TIMEOUT_MS`.
const FILL_NOT_CRITICAL: i32 = 3;
/// Exit code: the ballast's allocation failed.
const FILL_BALLAST_FAILED: i32 = 4;
/// Exit code: the mode's argument is not a number of milliseconds.
const FILL_USAGE: i32 = 5;
/// Exit code: `oom-touch` could not register its region or read its stdin.
const TOUCH_SETUP_FAILED: i32 = 6;
/// Exit code: `oom-hold`'s argument is not a number of pages.
const HOLD_USAGE: i32 = 7;
/// Exit code: `oom-touch`'s argument is not a non-zero number of pages.
const TOUCH_USAGE: i32 = 8;

/// The page size `oom-hold` touches its heap at, and `oom-touch` writes its
/// region at.
const PAGE_BYTES: usize = 4096;

/// Bytes of stack each mode touches before the window, below its frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

/// `crashme oom-fill <ms>`: fill memmgr's pool down to its growth floor, print
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
    let Some(mut fill) = Fill::new()
    else
    {
        exit(FILL_BALLAST_FAILED);
    };
    touch_stack();
    say("filling");
    match fill.to_critical()
    {
        Ok(()) =>
        {}
        Err(mem_fill::Failed::Status) => exit(FILL_STATUS_FAILED),
        Err(mem_fill::Failed::NotCritical) => exit(FILL_NOT_CRITICAL),
    }
    say("full");
    let until = Instant::now();
    while until.elapsed() < full_for
    {
        fill.top_up();
        std::thread::sleep(Duration::from_millis(mem_fill::TICK_MS));
    }
    // The exit gives memmgr back every commitment and grant.
    exit(0);
}

/// `crashme oom-touch <pages>`: register a demand region of `<pages>` pages,
/// read a first line of stdin and print `ready`, then, on the second line,
/// write each page of the region in turn and print how long the longest write
/// took.
///
/// The writes after the first spend whatever free pages lie above the growth
/// floor when the window opens (a stop's frees, until the filler's next
/// top-up takes them back), so a region larger than those makes the write
/// that memmgr declines, and the crash service holds, certain.
pub fn touch(arg: Option<&str>) -> !
{
    let Some(pages) = arg
        .and_then(|p| p.parse::<usize>().ok())
        .filter(|&p| p != 0)
    else
    {
        println!("usage: crashme oom-touch <pages>");
        exit(TOUCH_USAGE);
    };
    let Some(region) = u64::try_from(pages)
        .ok()
        .and_then(|count| std::os::seraph::register_demand_paged(count).ok())
    else
    {
        exit(TOUCH_SETUP_FAILED);
    };
    let Ok(base) = usize::try_from(region.va_start())
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
    let mut held = 0;
    for addr in (base..).step_by(PAGE_BYTES).take(pages)
    {
        let start = Instant::now();
        // SAFETY: `addr` is the start of one of the `pages` pages of this
        // process's demand region, which nothing else uses; the write is
        // volatile so that it is made, and faults, here.
        unsafe { std::ptr::write_volatile(addr as *mut u8, 1) };
        held = held.max(start.elapsed().as_millis());
    }
    println!("touched held_ms={held}");
    exit(0);
}

/// `crashme oom-hold <pages>`: touch `<pages>` pages of heap, print
/// `holding <pages>`, and wait to be destroyed.
pub fn hold(arg: Option<&str>) -> !
{
    let Some(pages) = arg.and_then(|p| p.parse::<usize>().ok())
    else
    {
        println!("usage: crashme oom-hold <pages>");
        exit(HOLD_USAGE);
    };
    let mut held = vec![0u8; pages.saturating_mul(PAGE_BYTES)];
    for page in held.chunks_mut(PAGE_BYTES)
    {
        if let Some(byte) = page.first_mut()
        {
            *byte = 1;
        }
    }
    std::hint::black_box(&mut held);
    say(&format!("holding {pages}"));
    loop
    {
        let _ = syscall::thread_sleep(60_000);
    }
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
