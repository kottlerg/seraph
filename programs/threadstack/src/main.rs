// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadstack/src/main.rs

//! Guarded demand-stack fixture for the usertest `threadstack` tester.
//!
//! Spawned demand-paged (the system default; no opt-in needed), so threads this
//! process spawns get a guarded demand-paged stack: a large lazily-grown
//! usable region with an unregistered guard page below it. Three modes, by argv:
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
//!   * `bigframe` — spawn a worker that runs and then parks, then a second
//!     worker, whose stack the reservation arena places directly above the
//!     first's, that calls a function whose single frame is larger than its
//!     whole usable stack and writes only the frame's lowest byte. That byte
//!     lies past the guard page, near the top of the first worker's
//!     registered stack, so only the target's stack probes, touching each
//!     page of the frame in turn, fault on the guard. Same verdict as
//!     `guard`: the process must be killed.
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

/// `bigframe` frame size: the default 2 MiB (512-page) usable demand stack plus
/// 4 pages, so the frame's lowest byte lies at least 3 pages below the one
/// guard page, near the top of the stack reserved just below.
const BIG_FRAME_BYTES: usize = (512 + 4) * 4096;

fn main() -> ExitCode
{
    if std::env::args().any(|a| a == "guard")
    {
        guard()
    }
    else if std::env::args().any(|a| a == "bigframe")
    {
        bigframe()
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
/// `down` selects the direction: true counts `depth` down to a real base case
/// (bounded, used by `grow`); false counts *up*, never reaching the base case at
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

/// Write and read back the lowest byte of a `BIG_FRAME_BYTES` stack frame,
/// leaving the rest of it untouched, so only stack probes touch the pages in
/// between. The buffer's address escapes through `black_box`, so the compiler
/// must allocate the whole frame rather than the one byte used.
#[inline(never)]
fn big_frame() -> u8
{
    let mut buf = std::mem::MaybeUninit::<[u8; BIG_FRAME_BYTES]>::uninit();
    let low = std::hint::black_box(buf.as_mut_ptr()).cast::<u8>();
    // SAFETY: `low` points to the first byte of this frame's own buffer, valid
    // for writes and, once written, for reads.
    unsafe {
        low.write_volatile(0x5A);
        low.read_volatile()
    }
}

fn bigframe() -> ExitCode
{
    println!("about to overflow");
    let _ = std::io::stdout().flush();

    // The parked worker's stack is reserved first, so the arena places the
    // big-frame worker's stack (guard page lowest) directly above it. Waiting
    // until the parked worker runs maps the top of its stack, and the page
    // table covering it, so the big frame's write lands on a page memmgr backs
    // without a fault rather than on a page table this address space has not
    // funded.
    let (ready_tx, ready) = std::sync::mpsc::channel::<()>();
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let below = std::thread::spawn(move || {
        let _ = ready_tx.send(());
        let _ = parked.recv();
    });
    let _ = ready.recv();
    let worker = std::thread::spawn(big_frame);
    // The probes fault on the guard page and procmgr tears this process down,
    // so `join` never returns. Reaching past it means the frame skipped the
    // guard — report it loudly.
    let _ = worker.join();
    let _ = release.send(());
    let _ = below.join();
    println!("SURVIVED (BUG)");
    ExitCode::SUCCESS
}
