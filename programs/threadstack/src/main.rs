// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadstack/src/main.rs

//! Guarded demand-stack fixture for the usertest `threadstack` tester.
//!
//! Spawned demand-paged (`CommandExt::demand_paged(true)`), so threads this
//! process spawns get a guarded demand-paged stack: a large lazily-grown
//! usable region with an unregistered guard page below it. Two modes, by argv:
//!
//!   * `grow` — spawn a worker that recurses deep enough to fault in many
//!     demand-paged stack pages (but stays inside the usable region), `join`
//!     it, and print `PASS`. Exercises the real `Thread::new`/`join` demand
//!     path and join-time `UNREGISTER_REGION` reclamation. Exits `SUCCESS`.
//!   * `guard` — spawn a worker that recurses unbounded, past the usable
//!     region into the guard page. The pager declines the unregistered fault,
//!     the kernel kills the worker, and (via the address-space death-observer)
//!     procmgr tears the whole process down — so this process never exits
//!     cleanly. If the overflow somehow survives, print `SURVIVED (BUG)` and
//!     exit `SUCCESS` so the tester's "must be killed" assertion fails loudly
//!     rather than the run hanging.
//!
//! Idiomatic `std` only — no direct Seraph cap awareness. The demand-paged
//! stack machinery lives entirely in `std::sys::thread` / `std::os::seraph`.

use std::io::Write;
use std::process::ExitCode;

/// Bytes of stack each recursion frame consumes, forcing demand faults as the
/// worker descends. One page per frame keeps the fault count proportional to
/// depth.
const FRAME_BYTES: usize = 4096;

/// `grow` recursion depth. 200 frames ≈ 820 KiB — many demand faults, well
/// inside the default 2 MiB usable demand stack.
const GROW_DEPTH: u64 = 200;

fn main() -> ExitCode
{
    if std::env::args().any(|a| a == "guard")
    {
        guard()
    }
    else
    {
        grow()
    }
}

/// Sum a per-frame stack buffer through a `black_box`, so a write into it
/// cannot be elided.
#[inline(never)]
fn touch(buf: &[u8; FRAME_BYTES]) -> u64
{
    std::hint::black_box(buf)
        .iter()
        .fold(0u64, |a, &x| a.wrapping_add(u64::from(x)))
}

/// Recurse, consuming one per-frame stack buffer per level so the stack grows
/// page by page (each frame faults in its demand page on first touch).
///
/// `down` selects the direction: false counts `depth` down to a real base case
/// (bounded, used by `grow`); true counts *up*, never reaching the base case at
/// runtime (used by `guard` to overflow into the guard page).
///
/// The recursive call goes through a `black_box`'d function pointer, so the
/// optimiser cannot recognise the self-recursion and collapse it into a
/// single-frame loop (a per-frame buffer alone does not stop that — its content
/// is constant, so the compiler proves every frame identical). The indirect
/// call forces a genuine, stack-growing call chain.
#[inline(never)]
fn recurse(depth: u64, down: bool) -> u64
{
    let mut buf = [0u8; FRAME_BYTES];
    buf.fill(0xAB);
    let sum = touch(&buf);
    if std::hint::black_box(depth) == 0
    {
        return sum;
    }
    let next = if down
    {
        depth - 1
    }
    else
    {
        depth.wrapping_add(1)
    };
    // Coerce to a fn pointer first, THEN black_box the pointer value — a
    // black_box of the fn item (a ZST) leaves the callee statically known.
    let f: fn(u64, bool) -> u64 = recurse;
    let f = std::hint::black_box(f);
    sum.wrapping_add(f(next, down))
}

fn grow() -> ExitCode
{
    let worker = std::thread::spawn(|| recurse(GROW_DEPTH, true));
    let Ok(checksum) = worker.join()
    else
    {
        println!("grow worker panicked");
        return ExitCode::from(3);
    };
    // Use the checksum so the recursion is not dead code.
    println!("grow checksum {}", std::hint::black_box(checksum));
    println!("PASS");
    ExitCode::SUCCESS
}

fn guard() -> ExitCode
{
    // Flush the marker before the worker faults, so the tester sees the fixture
    // reached the overflow point even though the process is about to die.
    println!("about to overflow");
    let _ = std::io::stdout().flush();

    // Count up from 1; the `depth == 0` base case is never reached before the
    // stack overflows into the guard page.
    let worker = std::thread::spawn(|| recurse(1, false));
    // The worker recurses into the guard page and faults; the kernel kills it
    // and procmgr tears this process down, so `join` never returns. Reaching
    // past it means the guard failed to fault — report it loudly.
    let _ = worker.join();
    println!("SURVIVED (BUG)");
    ExitCode::SUCCESS
}
