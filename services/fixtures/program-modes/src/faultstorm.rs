// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/program-modes/src/faultstorm.rs

//! `faultstorm`: demand faults on fresh chunks of a region of this process's
//! own, taken by one or more threads at once in rounds its spawner starts.
//!
//! Argv: `faultstorm <cpu> <chunks> <threads> <touch|verify>`. The main thread
//! pins itself to CPU `<cpu>`, and helper thread t to CPU `(<cpu> + t)` modulo
//! the CPUs online; each thread owns `<chunks>` chunks of the process's region,
//! a chunk being `DEMAND_CHUNK_PAGES` (16) pages, the run memmgr backs on one
//! fault. The spawner drives it over stdin and stdout one byte at a time
//! (services/fixtures/program-modes/README.md § faultstorm): `g` faults every
//! thread's chunks and answers `d`; `n` replaces the region with a fresh one
//! and answers `r`, as the start does; `x` exits, the process dying with the
//! region and whatever it backed. `touch` makes one store per chunk, the fault
//! alone; `verify` also checks that every page of a chunk reads zero before its
//! tag store and that every tag reads back once all threads finished.
//!
//! Driven by svctest's `demand_fault_concurrent` phase and by ubench's
//! `fault_rate` benchmark.

use std::io::{Read, Write};
use std::os::seraph::{register_demand_paged, unregister_demand_paged};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use syscall_abi::PAGE_SIZE;

/// Pages of one chunk: `DEMAND_CHUNK_PAGES`.
const CHUNK_PAGES: u64 = 16;

/// Bytes of one chunk.
const CHUNK_BYTES: u64 = CHUNK_PAGES * PAGE_SIZE;

/// Exit code: an argument is missing or does not parse.
const EXIT_ARGS: u8 = 2;
/// Exit code: a thread could not be pinned to its CPU.
const EXIT_PIN: u8 = 3;
/// Exit code: a region could not be registered.
const EXIT_REGISTER: u8 = 4;
/// Exit code: a region could not be unregistered.
const EXIT_UNREGISTER: u8 = 5;
/// Exit code (`verify`): a page of a freshly backed chunk did not read zero.
const EXIT_NOT_ZERO: u8 = 6;
/// Exit code (`verify`): a tag did not read back after the round.
const EXIT_TAG: u8 = 7;
/// Exit code: stdin carried a byte the protocol does not define, or ended.
const EXIT_PROTOCOL: u8 = 8;
/// Exit code: an answer could not be written to stdout.
const EXIT_STDOUT: u8 = 9;
/// Exit code: a helper thread could not be spawned.
const EXIT_SPAWN: u8 = 10;

/// What each fault store does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Check
{
    /// One store per chunk.
    Touch,
    /// The zero check and a tag on every page, read back after the round.
    Verify,
}

/// The arguments after the mode name.
#[derive(Clone, Copy)]
struct Args
{
    cpu: u32,
    chunks: u64,
    threads: u32,
    check: Check,
}

/// What the threads share: the region's base for the round, the barriers that
/// start and end a round, and the first failure a thread met.
struct Shared
{
    base: AtomicU64,
    round: AtomicU64,
    start: Barrier,
    end: Barrier,
    failed: AtomicU8,
}

impl Shared
{
    /// Record `code` as the failure unless an earlier one is recorded.
    fn fail(&self, code: u8)
    {
        let _ = self
            .failed
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }
}

pub fn main() -> ExitCode
{
    let Some(args) = parse()
    else
    {
        return ExitCode::from(EXIT_ARGS);
    };
    match run(args)
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

/// The arguments, or `None` when one is missing or does not parse.
fn parse() -> Option<Args>
{
    let mut args = std::env::args().skip(2);
    let cpu = args.next()?.parse().ok()?;
    let chunks = args.next()?.parse().ok().filter(|&c| c > 0)?;
    let threads = args.next()?.parse().ok().filter(|&t| t > 0)?;
    let check = match args.next()?.as_str()
    {
        "touch" => Check::Touch,
        "verify" => Check::Verify,
        _ => return None,
    };
    Some(Args {
        cpu,
        chunks,
        threads,
        check,
    })
}

/// Pin the threads, serve the protocol until `x`, and return the exit code
/// of the first failure.
fn run(args: Args) -> Result<(), u8>
{
    let online = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| n > 0)
        .ok_or(EXIT_PIN)?;
    pin(args.cpu.checked_rem(online).ok_or(EXIT_PIN)?)?;
    let threads = usize::try_from(args.threads).map_err(|_| EXIT_ARGS)?;
    let shared = Arc::new(Shared {
        base: AtomicU64::new(0),
        round: AtomicU64::new(0),
        start: Barrier::new(threads),
        end: Barrier::new(threads),
        failed: AtomicU8::new(0),
    });
    for t in 1..args.threads
    {
        let cpu = args
            .cpu
            .wrapping_add(t)
            .checked_rem(online)
            .ok_or(EXIT_PIN)?;
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .spawn(move || {
                helper(cpu, t, args, &shared);
            })
            .map_err(|_| EXIT_SPAWN)?;
    }
    let pages = args
        .chunks
        .checked_mul(u64::from(args.threads))
        .and_then(|c| c.checked_mul(CHUNK_PAGES))
        .ok_or(EXIT_ARGS)?;
    serve(args, pages, &shared)
}

/// The main thread's loop over the bytes of stdin.
fn serve(args: Args, pages: u64, shared: &Shared) -> Result<(), u8>
{
    let mut region = register_demand_paged(pages).map_err(|_| EXIT_REGISTER)?;
    answer(b'r')?;
    let mut stdin = std::io::stdin();
    loop
    {
        let mut byte = [0u8; 1];
        stdin.read_exact(&mut byte).map_err(|_| EXIT_PROTOCOL)?;
        match byte
        {
            [b'g'] =>
            {
                round(args, region.va_start(), shared)?;
                answer(b'd')?;
            }
            [b'n'] =>
            {
                // SAFETY: no reference into the region outlives the stores of
                // the rounds, and the IPC buffer lies outside it.
                unsafe { unregister_demand_paged(region) }.map_err(|_| EXIT_UNREGISTER)?;
                region = register_demand_paged(pages).map_err(|_| EXIT_REGISTER)?;
                answer(b'r')?;
            }
            [b'x'] => return Ok(()),
            _ => return Err(EXIT_PROTOCOL),
        }
    }
}

/// One round: every thread faults its own chunks of the region at `base`, the
/// main thread its slice 0; in `verify`, every tag of the region is then read
/// back.
fn round(args: Args, base: u64, shared: &Shared) -> Result<(), u8>
{
    let round = shared.round.fetch_add(1, Ordering::Relaxed);
    shared.base.store(base, Ordering::Release);
    shared.start.wait();
    if let Err(code) = fault_slice(args, base, 0, round)
    {
        shared.fail(code);
    }
    shared.end.wait();
    match shared.failed.load(Ordering::Acquire)
    {
        0 =>
        {}
        code => return Err(code),
    }
    if args.check == Check::Verify
    {
        for thread in 0..args.threads
        {
            read_back(args, base, thread, round)?;
        }
    }
    Ok(())
}

/// A helper thread: pinned to `cpu`, it faults slice `thread` of each round's
/// region.
fn helper(cpu: u32, thread: u32, args: Args, shared: &Shared) -> !
{
    if pin(cpu).is_err()
    {
        shared.fail(EXIT_PIN);
    }
    loop
    {
        shared.start.wait();
        let base = shared.base.load(Ordering::Acquire);
        let round = shared.round.load(Ordering::Relaxed).wrapping_sub(1);
        if let Err(code) = fault_slice(args, base, thread, round)
        {
            shared.fail(code);
        }
        shared.end.wait();
    }
}

/// Pin the calling thread to `cpu` and move it there.
fn pin(cpu: u32) -> Result<(), u8>
{
    let thread = std::os::seraph::thread::current_thread_cap();
    syscall::thread_set_affinity(thread, cpu).map_err(|_| EXIT_PIN)?;
    syscall::thread_yield().map_err(|_| EXIT_PIN)
}

/// The address of page `page` of chunk `chunk` of slice `thread`.
fn page_va(args: Args, base: u64, thread: u32, chunk: u64, page: u64) -> u64
{
    let index = u64::from(thread)
        .wrapping_mul(args.chunks)
        .wrapping_add(chunk);
    base.wrapping_add(index.wrapping_mul(CHUNK_BYTES))
        .wrapping_add(page.wrapping_mul(PAGE_SIZE))
}

/// The tag `verify` stores at the first word of a page: its slice, chunk and
/// page, the round and the main thread's CPU, so that a page another slice,
/// round or process wrote does not match.
fn tag(args: Args, thread: u32, chunk: u64, page: u64, round: u64) -> u64
{
    let place = u64::from(thread)
        .wrapping_shl(40)
        .wrapping_add(chunk.wrapping_mul(CHUNK_PAGES))
        .wrapping_add(page);
    place ^ round.wrapping_shl(24) ^ u64::from(args.cpu).wrapping_shl(52)
}

/// Fault every chunk of slice `thread`: the first store into each is its
/// fault; in `verify`, every page then reads zero before its own tag.
fn fault_slice(args: Args, base: u64, thread: u32, round: u64) -> Result<(), u8>
{
    for chunk in 0..args.chunks
    {
        let first = page_va(args, base, thread, chunk, 0);
        // SAFETY: `first` starts a chunk of a read-write demand region this
        // process registered, which holds no Rust object; the store's fault is
        // backed by the pager.
        unsafe { core::ptr::write_volatile(first as *mut u64, tag(args, thread, chunk, 0, round)) };
        if args.check == Check::Verify
        {
            verify_fresh(args, base, thread, chunk, round)?;
        }
    }
    Ok(())
}

/// Check that every page of a chunk just backed reads zero, but the tag of
/// its first page, and store each page's tag.
fn verify_fresh(args: Args, base: u64, thread: u32, chunk: u64, round: u64) -> Result<(), u8>
{
    let last_word = PAGE_SIZE.saturating_sub(8);
    for page in 0..CHUNK_PAGES
    {
        let va = page_va(args, base, thread, chunk, page);
        // SAFETY: `va` is a page of a chunk of this process's demand region
        // that the store before this call backed, and holds no Rust object.
        let tail = unsafe { core::ptr::read_volatile(va.wrapping_add(last_word) as *const u64) };
        if tail != 0
        {
            return Err(EXIT_NOT_ZERO);
        }
        if page == 0
        {
            continue;
        }
        // SAFETY: as above.
        let head = unsafe { core::ptr::read_volatile(va as *const u64) };
        if head != 0
        {
            return Err(EXIT_NOT_ZERO);
        }
        // SAFETY: as above; the page is read-write.
        unsafe { core::ptr::write_volatile(va as *mut u64, tag(args, thread, chunk, page, round)) };
    }
    Ok(())
}

/// Check that every page of slice `thread` still holds its tag.
fn read_back(args: Args, base: u64, thread: u32, round: u64) -> Result<(), u8>
{
    for chunk in 0..args.chunks
    {
        for page in 0..CHUNK_PAGES
        {
            let va = page_va(args, base, thread, chunk, page);
            // SAFETY: `va` is a page of this process's demand region that the
            // round backed, and holds no Rust object.
            let word = unsafe { core::ptr::read_volatile(va as *const u64) };
            if word != tag(args, thread, chunk, page, round)
            {
                return Err(EXIT_TAG);
            }
        }
    }
    Ok(())
}

/// Write `byte` to stdout and flush it.
fn answer(byte: u8) -> Result<(), u8>
{
    let mut out = std::io::stdout().lock();
    out.write_all(&[byte])
        .and_then(|()| out.flush())
        .map_err(|_| EXIT_STDOUT)
}
