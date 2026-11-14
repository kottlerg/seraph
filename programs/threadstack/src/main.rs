// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadstack/src/main.rs

//! Guarded demand-stack fixture for the usertest `threadstack` tester.
//!
//! Spawned demand-paged (the system default; no opt-in needed), so threads this
//! process spawns get a guarded demand-paged stack: a large lazily-grown
//! usable region with an unregistered guard of `process_abi::STACK_GUARD_PAGES`
//! (4) pages below it, and its main thread's stack grows on demand below the
//! pages the loader mapped, above a guard of its own. Spawned pinned (no
//! pager), its threads get an eager stack instead: the requested pages mapped
//! at spawn above an unmapped guard of the same four pages. Ten modes, by argv:
//!
//!   * `grow` — spawn a worker that recurses deep enough to fault in many
//!     demand-paged stack pages (but stays inside the usable region), `join`
//!     it, and print `PASS`. Exercises the real `Thread::new`/`join` demand
//!     path and join-time `UNREGISTER_REGION` reclamation. Exits `SUCCESS`.
//!   * `nested-grow` — as `grow`, but the recursing thread is spawned by a
//!     spawned thread, so its spawn runs the runtime's copy of the spawning
//!     thread's bindings from a spawned thread. The middle and main threads
//!     carry the same pager binding, so a pass shows the grandchild's demand
//!     stack is served, not which thread's binding was copied. Exits
//!     `SUCCESS`.
//!   * `guard` — spawn a worker that recurses unbounded, past the usable
//!     region into the guard. The pager declines the unregistered fault,
//!     the kernel kills the worker, and (via the address-space death-observer)
//!     procmgr tears the whole process down — so this process never exits
//!     cleanly. If the overflow somehow survives, print `SURVIVED (BUG)` and
//!     exit `SUCCESS` so the tester's "must be killed" assertion fails loudly
//!     rather than the run hanging.
//!   * `bigframe` — spawn a worker that runs and then parks, then a second
//!     worker, whose stack the reservation arena places directly above the
//!     first worker's one-page IPC buffer, itself directly above the first
//!     worker's stack, that calls a function whose single frame is larger
//!     than its whole usable stack and writes only the frame's lowest byte.
//!     That byte lies past the guard and that IPC buffer, near the top of the
//!     first worker's registered stack, so only the target's stack probes,
//!     touching each page of the frame in turn, fault on the guard. Same
//!     verdict as `guard`: the process must be killed.
//!   * `splitframe` — the same two workers; the second descends its stack,
//!     writing every page, to within a page of its usable base, and there
//!     calls `split_frame`, a frame of 6128 bytes with a return-address save,
//!     which calls `page_leaf`, a leaf of 4080 bytes of locals that writes
//!     only its lowest byte. On riscv64 the split prologue and the leaf leave
//!     about 10 KiB between the save and that byte unwritten, so a guard of
//!     two pages or fewer lets the byte land on a mapped page of the first
//!     worker: its IPC buffer, or its stack below.
//!     Same verdict as `guard`.
//!   * `span` — the same descent, then two stores 14312 bytes apart, the
//!     largest distance between two consecutive stack stores of the std
//!     target (`process_abi::STACK_GUARD_PAGES`), so a guard of three pages
//!     or fewer lets the second land on a mapped page of the first worker:
//!     its IPC buffer, or its stack below. Same verdict as `guard`.
//!   * `main-grow` — the main thread itself recurses as deep as `grow`'s
//!     worker, far past the pages the loader mapped for it, and prints `PASS`.
//!     Exits `SUCCESS`.
//!   * `main-guard` — the main thread recurses unbounded, past its demand
//!     growth range into the guard below it. Same verdict as `guard`.
//!   * `eager-grow` — for a pinned run: a worker asking for 16 pages of stack
//!     recurses about 41 KiB into the eager stack it gets, is joined, and the
//!     process prints `PASS`. Exits `SUCCESS`.
//!   * `eager-bigframe` — for a pinned run: `bigframe` with workers asking for
//!     16 pages of stack and a frame of 23 pages, the eager stack, its guard,
//!     and 3 pages, whose lowest byte lies in the parked worker's mapped eager
//!     stack. Same verdict as `guard`; a stack with no guard below it, over
//!     mapped memory, lets the frame return and the process print
//!     `SURVIVED (BUG)`.
//!
//! Idiomatic `std` only — no direct Seraph cap awareness. The stack
//! machinery lives entirely in `std::sys::thread` / `std::os::seraph`.

use std::io::Write;
use std::process::ExitCode;

/// Bytes of stack each recursion frame consumes, forcing demand faults as the
/// recursing thread descends. One page per frame keeps the fault count proportional to
/// depth.
const FRAME_BYTES: usize = 4096;

/// `grow`, `nested-grow`, and `main-grow` recursion depth. 200 frames ≈ 820 KiB — many demand
/// faults, well inside the default 2 MiB usable demand stack, and 25 times the
/// main thread's default 8 committed pages.
const GROW_DEPTH: u64 = 200;

/// Usable pages of a spawned thread's demand stack: std's default 2 MiB
/// (`DEFAULT_DEMAND_STACK_PAGES`), which every worker here gets.
const USABLE_STACK_PAGES: usize = 512;

/// Guard pages below a spawned thread's demand stack
/// (`process_abi::STACK_GUARD_PAGES`).
const GUARD_PAGES: usize = 4;

/// `bigframe` frame size: the usable demand stack, its guard, and 3 pages,
/// so the frame's lowest byte lies 3 pages below the guard, past the
/// one-page IPC buffer reserved just below it and near the top of the stack
/// below that.
const BIG_FRAME_BYTES: usize = (USABLE_STACK_PAGES + GUARD_PAGES + 3) * 4096;

/// Stack size every `guard`, `bigframe`, `eager-grow`, and `eager-bigframe` worker
/// asks for: std's default minimum (`DEFAULT_MIN_STACK_SIZE`), 16 pages. A
/// demand-paged process raises it to its 512-page demand stack; a process with
/// no pager maps exactly these pages at spawn, above the same guard.
const EAGER_STACK_PAGES: usize = 16;

/// `EAGER_STACK_PAGES` in bytes, the size `spawn_worker` asks for.
const EAGER_STACK_BYTES: usize = EAGER_STACK_PAGES * 4096;

/// `eager-grow` recursion depth: 10 frames of a little over a page, about
/// 41 KiB, inside the 16-page eager stack with room for the frames above.
const EAGER_GROW_DEPTH: u64 = 10;

/// `eager-bigframe` frame size: the eager stack, its guard, and 3 pages, so
/// the frame's lowest byte lies 3 pages below the guard, past the one-page
/// IPC buffer reserved just below it and near the top of the eager stack
/// below that.
const EAGER_BIG_FRAME_BYTES: usize = (EAGER_STACK_PAGES + GUARD_PAGES + 3) * 4096;

/// Locals of `split_frame`: with its return-address save, a frame of 6128
/// bytes, which riscv64 LLVM allocates as 2032 bytes and then 4096, writing
/// only the save and probing neither part.
const SPLIT_FRAME_LOCALS: usize = 6112;

/// Locals of `page_leaf`: a leaf frame of 4080 bytes, which riscv64 LLVM
/// allocates in one adjustment with no probe.
const LEAF_LOCALS: usize = 4080;

/// The std target's bound on the distance between two consecutive stack
/// stores: 6120 bytes below a return-address save (a split frame's first
/// 2032-byte part less the save, and its unprobed 4096), then 8192 below the
/// callee's entry (a vector frame's probe one page below a page of fixed
/// locals).
const STD_STORE_SPAN: usize = 6120 + 8192;

/// Bytes of each frame's buffer in the coarse descent (`descend_pages`).
const DESCENT_PAGE_BYTES: usize = 4096;

/// Bytes of each frame's buffer in the fine descent (`descend_fine`).
const DESCENT_FINE_BYTES: usize = 256;

/// The coarse descent hands over to the fine one once its frame's buffer is
/// less than this far above the usable base: more than a coarse step above
/// the fine descent's stop.
const FINE_FROM: usize = 3 * 4096;

/// The fine descent calls the overflow once its frame's buffer is less than
/// this far above the usable base. Each fine step is less than 512 bytes, so
/// the overflow's caller sits between about 500 and 1024 bytes above the base:
/// low enough that each overflow's deeper store passes a guard one page
/// smaller than the one it needs, and high enough that the overflow's first
/// writes land in the usable stack, which the dry run checks.
const FINE_STOP: usize = 1024;

fn main() -> ExitCode
{
    if std::env::args().any(|a| a == "main-guard")
    {
        main_guard()
    }
    else if std::env::args().any(|a| a == "main-grow")
    {
        main_grow()
    }
    else if std::env::args().any(|a| a == "guard")
    {
        guard()
    }
    else if std::env::args().any(|a| a == "eager-bigframe")
    {
        bigframe(eager_big_frame)
    }
    else if std::env::args().any(|a| a == "eager-grow")
    {
        eager_grow()
    }
    else if std::env::args().any(|a| a == "bigframe")
    {
        bigframe(big_frame)
    }
    else if std::env::args().any(|a| a == "splitframe")
    {
        over_the_guard(split_frame)
    }
    else if std::env::args().any(|a| a == "span")
    {
        over_the_guard(span_overflow)
    }
    else if std::env::args().any(|a| a == "nested-grow")
    {
        nested_grow()
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

/// Which way `recurse` moves `depth` at each level.
#[derive(Clone, Copy)]
enum Direction
{
    /// Count `depth` down to the real base case at 0 (bounded, used by `grow`,
    /// `nested-grow`, and `main-grow`).
    Down,
    /// Count `depth` up, never reaching the base case at runtime (used by
    /// `guard` and `main-guard` to overflow into the guard).
    Up,
}

/// Recurse, consuming one per-frame stack buffer per level so the stack grows
/// page by page (each frame faults in its demand page on first touch).
///
/// `direction` selects whether the recursion ends (see [`Direction`]).
///
/// The recursive call goes through a `black_box`'d function pointer, so the
/// optimiser cannot recognise the self-recursion and collapse it into a
/// single-frame loop (a per-frame buffer alone does not stop that — its content
/// is constant, so the compiler proves every frame identical). The indirect
/// call forces a genuine, stack-growing call chain.
#[inline(never)]
fn recurse(depth: u64, direction: Direction) -> u64
{
    let mut buf = [0u8; FRAME_BYTES];
    buf.fill(0xAB);
    let sum = touch(&buf);
    if std::hint::black_box(depth) == 0
    {
        return sum;
    }
    let next = match direction
    {
        Direction::Down => depth.saturating_sub(1),
        Direction::Up => depth.wrapping_add(1),
    };
    // Coerce to a fn pointer first, THEN black_box the pointer value — a
    // black_box of the fn item (a ZST) leaves the callee statically known.
    let f: fn(u64, Direction) -> u64 = recurse;
    let f = std::hint::black_box(f);
    sum.wrapping_add(f(next, direction))
}

fn grow() -> ExitCode
{
    let worker = std::thread::spawn(|| recurse(GROW_DEPTH, Direction::Down));
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

/// Spawn `f` on a worker asking for `EAGER_STACK_BYTES` of stack. A refused
/// spawn prints `spawn failed` and exits with code 4, which no tester
/// verdict accepts.
fn spawn_worker<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T>
{
    match std::thread::Builder::new()
        .stack_size(EAGER_STACK_BYTES)
        .spawn(f)
    {
        Ok(handle) => handle,
        Err(e) =>
        {
            println!("spawn failed: {e}");
            let _ = std::io::stdout().flush();
            std::process::exit(4);
        }
    }
}

fn eager_grow() -> ExitCode
{
    let worker = spawn_worker(|| recurse(EAGER_GROW_DEPTH, Direction::Down));
    let Ok(checksum) = worker.join()
    else
    {
        println!("eager-grow worker panicked");
        return ExitCode::from(3);
    };
    println!("eager-grow checksum {}", std::hint::black_box(checksum));
    println!("PASS");
    ExitCode::SUCCESS
}

fn nested_grow() -> ExitCode
{
    // The middle thread spawns the recursing one: the grandchild's binding is
    // the middle thread's copy, not the main thread's.
    let middle =
        std::thread::spawn(|| std::thread::spawn(|| recurse(GROW_DEPTH, Direction::Down)).join());
    let Ok(Ok(checksum)) = middle.join()
    else
    {
        println!("nested-grow worker panicked");
        return ExitCode::from(3);
    };
    println!("nested-grow checksum {}", std::hint::black_box(checksum));
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
    // stack overflows into the guard. The marker is already out, so a refused
    // spawn must not end the process with a fault, as the panic of a plain
    // `std::thread::spawn` would: `spawn_worker` exits with code 4 instead.
    let worker = spawn_worker(|| recurse(1, Direction::Up));
    // The worker recurses into the guard and faults; the kernel kills it
    // and procmgr tears this process down, so `join` never returns. Reaching
    // past it means the guard failed to fault — report it loudly.
    let _ = worker.join();
    println!("SURVIVED (BUG)");
    ExitCode::SUCCESS
}

fn main_grow() -> ExitCode
{
    let checksum = recurse(GROW_DEPTH, Direction::Down);
    println!("main-grow checksum {}", std::hint::black_box(checksum));
    println!("PASS");
    ExitCode::SUCCESS
}

fn main_guard() -> ExitCode
{
    println!("about to overflow");
    let _ = std::io::stdout().flush();

    // The guard fault kills the main thread and procmgr tears this process
    // down, so `recurse` never returns. Reaching past it means the guard failed
    // to fault — report it loudly.
    let _ = std::hint::black_box(recurse(1, Direction::Up));
    println!("SURVIVED (BUG)");
    ExitCode::SUCCESS
}

/// Write and read back the lowest byte of a `BIG_FRAME_BYTES` stack frame,
/// leaving the rest of it untouched, so only stack probes touch the pages in
/// between. The buffer's address escapes through `black_box`, so the compiler
/// must allocate the whole frame rather than the one byte used.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the fixture: `buf`, `BIG_FRAME_BYTES` (2 MiB and 7 pages), is larger \
              than the spawned thread's 2 MiB demand stack and its guard, so its stack probes \
              reach the guard"
)]
fn big_frame() -> u8
{
    let mut buf = std::mem::MaybeUninit::<[u8; BIG_FRAME_BYTES]>::uninit();
    let low = std::hint::black_box(buf.as_mut_ptr()).cast::<u8>();
    // SAFETY: `low` points to the first byte of this frame's own buffer, valid
    // for writes.
    unsafe { low.write_volatile(0x5A) };
    // SAFETY: `low` points to the first byte of this frame's own buffer, which
    // the write above initialised, so it is valid for reads.
    unsafe { low.read_volatile() }
}

/// [`big_frame`] for the eager stack of a process with no pager: write and
/// read back the lowest byte of an `EAGER_BIG_FRAME_BYTES` frame, leaving the
/// rest untouched.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the fixture: `buf`, `EAGER_BIG_FRAME_BYTES` (23 pages), is larger \
              than a pinned process's 16-page eager thread stack and its guard, so its stack \
              probes reach the guard"
)]
fn eager_big_frame() -> u8
{
    let mut buf = std::mem::MaybeUninit::<[u8; EAGER_BIG_FRAME_BYTES]>::uninit();
    let low = std::hint::black_box(buf.as_mut_ptr()).cast::<u8>();
    // SAFETY: `low` points to the first byte of this frame's own buffer, valid
    // for writes.
    unsafe { low.write_volatile(0x5A) };
    // SAFETY: `low` points to the first byte of this frame's own buffer, which
    // the write above initialised, so it is valid for reads.
    unsafe { low.read_volatile() }
}

/// Run `frame`, a frame larger than its worker's stack and guard that writes
/// only its lowest byte, on a worker whose stack the reservation arena places
/// directly above a parked worker's IPC buffer and stack: `bigframe` with
/// [`big_frame`], `eager-bigframe` with [`eager_big_frame`].
fn bigframe(frame: fn() -> u8) -> ExitCode
{
    println!("about to overflow");
    let _ = std::io::stdout().flush();

    // The parked worker's stack and then its one-page IPC buffer are reserved
    // first, so the arena places the big-frame worker's stack (guard lowest)
    // directly above that buffer, which lies directly above the parked
    // worker's stack. Waiting until the parked worker runs maps the top of its
    // stack, and the page table covering it, so the big frame's write lands on
    // a page memmgr backs without a fault rather than on a page table this
    // address space has not funded. An eager stack is mapped whole at spawn,
    // so for it the wait changes nothing.
    let (ready_tx, ready) = std::sync::mpsc::channel::<()>();
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let below = spawn_worker(move || {
        let _ = ready_tx.send(());
        let _ = parked.recv();
    });
    let _ = ready.recv();
    let worker = spawn_worker(frame);
    // The probes fault on the guard and procmgr tears this process down,
    // so `join` never returns. Reaching past it means the frame skipped the
    // guard — report it loudly.
    let _ = worker.join();
    let _ = release.send(());
    let _ = below.join();
    println!("SURVIVED (BUG)");
    ExitCode::SUCCESS
}

/// Run `overflow` on a worker whose stack the reservation arena places
/// directly above a parked worker's IPC buffer and stack, as `bigframe` does,
/// from a stack pointer within a page of the worker's usable base. A dry run
/// first descends to the same depth and writes just below it, then returns:
/// it shows the overflow starts inside the usable stack, so only the
/// overflow's deeper store can reach the guard.
fn over_the_guard(overflow: fn() -> u8) -> ExitCode
{
    // As in `bigframe`: the parked worker runs first, so the top of its stack
    // and the page table covering it are mapped.
    let (ready_tx, ready) = std::sync::mpsc::channel::<()>();
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let below = std::thread::spawn(move || {
        let _ = ready_tx.send(());
        let _ = parked.recv();
    });
    let _ = ready.recv();
    let worker = std::thread::spawn(move || {
        let floor = usable_base();
        let dry = descend_pages(floor, dry_bottom);
        // The dry run returned, so the descent and the overflow's first
        // writes stay inside the usable stack.
        println!("dry run {}", std::hint::black_box(dry));
        println!("about to overflow");
        let _ = std::io::stdout().flush();
        descend_pages(floor, overflow)
    });
    // The overflow's deeper store faults on the guard and procmgr tears this
    // process down, so `join` never returns. Reaching past it means the store
    // passed the guard — report it loudly.
    let _ = worker.join();
    let _ = release.send(());
    let _ = below.join();
    println!("SURVIVED (BUG)");
    ExitCode::SUCCESS
}

/// The calling thread's usable stack base: its top is the page boundary at or
/// above this frame, and the stack is `USABLE_STACK_PAGES` pages. A top
/// misjudged by a page or more (entry frames above this one larger than a
/// page) puts the computed base below the real one; the dry run's descent
/// then faults on the guard before `about to overflow` is printed, which
/// fails the tester.
#[inline(never)]
fn usable_base() -> usize
{
    let here = 0u8;
    let here = std::ptr::from_ref(std::hint::black_box(&here)).addr();
    let top = here.next_multiple_of(4096);
    top.saturating_sub(USABLE_STACK_PAGES * 4096)
}

/// Descend the stack one written page per frame until this frame's buffer is
/// less than `FINE_FROM` above `floor`, then continue with [`descend_fine`].
#[inline(never)]
fn descend_pages(floor: usize, at_bottom: fn() -> u8) -> u8
{
    let mut buf = [0u8; DESCENT_PAGE_BYTES];
    buf.fill(0xAB);
    let buf = std::hint::black_box(&buf);
    let next = if std::ptr::from_ref(buf).addr().saturating_sub(floor) >= FINE_FROM
    {
        // Through a `black_box`'d pointer, as in `recurse`, so the descent is a
        // real call chain.
        let f: fn(usize, fn() -> u8) -> u8 = descend_pages;
        std::hint::black_box(f)(floor, at_bottom)
    }
    else
    {
        descend_fine(floor, at_bottom)
    };
    next.wrapping_add(buf[0])
}

/// Descend the stack in written frames of `DESCENT_FINE_BYTES` until this
/// frame's buffer is less than `FINE_STOP` above `floor`, then call
/// `at_bottom`.
#[inline(never)]
fn descend_fine(floor: usize, at_bottom: fn() -> u8) -> u8
{
    let mut buf = [0u8; DESCENT_FINE_BYTES];
    buf.fill(0xCD);
    let buf = std::hint::black_box(&buf);
    let next = if std::ptr::from_ref(buf).addr().saturating_sub(floor) >= FINE_STOP
    {
        let f: fn(usize, fn() -> u8) -> u8 = descend_fine;
        std::hint::black_box(f)(floor, at_bottom)
    }
    else
    {
        at_bottom()
    };
    next.wrapping_add(buf[0])
}

/// The dry run's bottom: a written frame reaching deeper than the first
/// writes of either overflow (the return-address save, or the first store),
/// each within 16 bytes of the caller's stack pointer.
#[inline(never)]
fn dry_bottom() -> u8
{
    let mut buf = [0u8; 64];
    buf.fill(0xEF);
    std::hint::black_box(&buf)[0]
}

/// Let a pointer escape to code the compiler cannot see, so a frame holds the
/// whole buffer it points into, without writing anything:
/// `std::hint::black_box` would store the pointer in the frame, a write the
/// overflows must not make, and a call would make a leaf save its return
/// address.
macro_rules! escape {
    ($p:expr) => {
        // SAFETY: the template is empty, so the asm reads, writes, and changes
        // nothing; without `nomem` the compiler assumes it may access memory
        // through the pointer.
        unsafe { core::arch::asm!("/* {0} */", in(reg) $p, options(nostack, preserves_flags)) }
    };
}

/// `splitframe`'s overflow: a frame of 6128 bytes that saves its return
/// address and calls [`page_leaf`], writing none of its locals. riscv64 LLVM
/// allocates it as 2032 bytes, with the save at the top, and then 4096
/// unprobed.
#[inline(never)]
fn split_frame() -> u8
{
    let mut buf = std::mem::MaybeUninit::<[u8; SPLIT_FRAME_LOCALS]>::uninit();
    // The address escapes, so the frame holds the whole buffer and the leaf is
    // not a tail call.
    escape!(buf.as_mut_ptr());
    page_leaf().wrapping_add(1)
}

/// A leaf of 4080 bytes of locals that writes and reads back only its lowest
/// byte. riscv64 LLVM allocates its frame in one unprobed adjustment, so the
/// byte lies 4080 bytes below its entry with nothing written in between.
#[inline(never)]
fn page_leaf() -> u8
{
    let mut buf = std::mem::MaybeUninit::<[u8; LEAF_LOCALS]>::uninit();
    let low = buf.as_mut_ptr().cast::<u8>();
    escape!(low);
    // SAFETY: `low` points to the first byte of this frame's own buffer, valid
    // for writes.
    unsafe { low.write_volatile(0x5A) };
    // SAFETY: `low` points to the first byte of this frame's own buffer, which
    // the write above initialised, so it is valid for reads.
    unsafe { low.read_volatile() }
}

/// `span`'s overflow: a store just below the stack pointer, then one
/// `STD_STORE_SPAN` bytes below that, with nothing written in between, as the
/// std target's deepest compiled chain leaves them.
#[inline(never)]
fn span_overflow() -> u8
{
    // SAFETY: both stores are to the stack below the stack pointer, which holds
    // no live value: the first to the usable stack, which the dry run wrote,
    // and the second to the guard, whose fault ends the process, or, past a
    // guard too small for it, to the parked worker's stack, which this test
    // reports. Neither changes a register but the scratch one declared.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "sb zero, -16(sp)",
            "sub {t}, sp, {d}",
            "sb zero, 0({t})",
            d = in(reg) STD_STORE_SPAN + 16,
            t = out(reg) _,
        );
    }
    // SAFETY: as above.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov byte ptr [rsp - 16], 0",
            "mov {t}, rsp",
            "sub {t}, {d}",
            "mov byte ptr [{t}], 0",
            d = in(reg) STD_STORE_SPAN + 16,
            t = out(reg) _,
        );
    }
    0
}
