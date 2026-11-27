// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/ubench/src/fault.rs

//! `fault_fill` and `fault_scaling`: what backing a chunk of fresh memory
//! costs a process, through a demand fault to memmgr or through a grant it
//! maps itself, and how the fault path's cost grows when several CPUs fault at
//! once (services/ubench/README.md § Benchmarks).
//!
//! A chunk is `DEMAND_CHUNK_PAGES` (16) pages, the run memmgr backs on a
//! demand fault when a free run covers it
//! (services/memmgr/docs/memory-pool.md § Demand faults). A sample is the
//! first store into one chunk.

use std::os::seraph::{
    register_demand_paged, reserve_pages, startup_info, unregister_demand_paged,
};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use bench::{Counters, HALTED, MOVED, Value, WINDOW_OPS_KEY, WindowEnd, WindowShape, WindowTally};
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

use crate::harness::{BENCH_CPU, IdleSpan, Outcome, cpu_count, pin_to, report, skip};

/// Pages in one chunk: `DEMAND_CHUNK_PAGES`.
const CHUNK_PAGES: u64 = 16;

/// Bytes in one chunk.
const CHUNK_BYTES: u64 = CHUNK_PAGES * PAGE_SIZE;

/// Timed chunks per path, and per thread of `fault_scaling`.
const CHUNKS: u64 = CHUNKS_LEN as u64;

/// Untimed chunks before the timed ones.
const WARMUP_CHUNKS: u64 = 4;

/// Chunks each path touches, warm-up included.
const TOTAL_CHUNKS: u64 = WARMUP_CHUNKS + CHUNKS;

/// The thread counts `fault_scaling` measures.
const SCALING_THREADS: [u32; 4] = [1, 2, 4, 8];

/// [`CHUNKS`] as a length.
const CHUNKS_LEN: usize = 64;

/// The variant of every line of this module after its own parameter.
const PAGES: (&str, Value<'static>) = ("pages", Value::Num(CHUNK_PAGES));

/// The address of chunk `chunk` of a region or reservation starting at
/// `base`. The region spans [`TOTAL_CHUNKS`] chunks and `chunk` is below that,
/// so the address lies inside it and the arithmetic does not wrap.
const fn chunk_va(base: u64, chunk: u64) -> u64
{
    base.wrapping_add(chunk.wrapping_mul(CHUNK_BYTES))
}

/// Timed grants of the `path=grant affinity=any` row, split into windows
/// ([`WindowShape::for_ops`]).
const ANY_GRANTS: u32 = 128;

/// `SYS_THREAD_SET_AFFINITY`'s value for no affinity (`AFFINITY_ANY`).
const AFFINITY_ANY: u32 = u32::MAX;

/// The extra counting the measuring thread's wakes linked on another CPU than
/// its waker's over the counted windows (`CAP_INFO_THREAD_PLACEMENT`).
const REMOTE_WAKES: &str = "remote_wakes";

/// `fault_fill`: one result line per path, `path=fault` and `path=grant`,
/// and, at more than one CPU, the window row `path=grant affinity=any`.
pub fn fill(counters: &Counters, cpus: u32) -> Outcome
{
    fill_by_fault(counters, cpus)?;
    fill_by_grant(counters, cpus)?;
    if cpus < 2
    {
        skip(
            "fault_fill",
            &format!("path=grant affinity=any: needs 2 CPUs, {cpus} online"),
        );
        return Ok(());
    }
    fill_by_grant_unpinned(counters, cpus)
}

/// The fault path: the first store into each chunk of a fresh demand region.
///
/// Its line carries two extras memmgr's backing of a fault is judged by:
/// `faults=`, the timed stores memmgr backed pages for, and `backed_pages=`,
/// the pages it backed for them, both read from the caller's own charge
/// (`QUERY_MEMORY_USAGE`) before and after each store, outside the timed
/// window. A store whose page an earlier fault already backed adds to neither.
fn fill_by_fault(counters: &Counters, cpus: u32) -> Outcome
{
    let region = register_demand_paged(TOTAL_CHUNKS * CHUNK_PAGES)
        .map_err(|e| format!("path=fault: register the demand region: {e}"))?;
    let base = region.va_start();
    let mut samples = Vec::with_capacity(CHUNKS_LEN);
    let mut faults = 0u64;
    let mut backed_pages = 0u64;
    let mut charged = charged_pages();
    let idle = IdleSpan::open();
    for chunk in 0..TOTAL_CHUNKS
    {
        let va = chunk_va(base, chunk);
        let start = counters.read();
        // SAFETY: `va` starts a chunk of a read-write demand region this
        // process registered, which holds no Rust object; the store's fault
        // is backed by the pager.
        unsafe { core::ptr::write_volatile(va as *mut u64, 1) };
        let cycles = counters.read().since(&start).cycles;
        let before = charged;
        charged = charged_pages();
        if chunk >= WARMUP_CHUNKS
        {
            samples.push(cycles);
            if let (Ok(before), Ok(after)) = (&before, &charged)
            {
                let backed = after.saturating_sub(*before);
                faults = faults.saturating_add(u64::from(backed > 0));
                backed_pages = backed_pages.saturating_add(backed);
            }
        }
    }
    let idle_halts = idle.close();
    // SAFETY: no reference into the region outlives the stores above, and the
    // IPC buffer lies outside it.
    let released = unsafe { unregister_demand_paged(region) }
        .map_err(|e| format!("path=fault: unregister the demand region: {e}"));
    charged.map_err(|e| format!("path=fault: {e}"))?;
    report(
        "fault_fill",
        &[("path", Value::Word("fault")), PAGES],
        cpus,
        &mut samples,
        &[("faults", faults), ("backed_pages", backed_pages)],
        idle_halts,
    )?;
    released
}

/// The pages charged to this process's budget node (`QUERY_MEMORY_USAGE`
/// `data[0]`).
fn charged_pages() -> Result<u64, String>
{
    let memmgr = startup_info().memmgr_endpoint;
    let msg = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_MEMORY_USAGE);
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }
        .map_err(|e| format!("QUERY_MEMORY_USAGE call failed: error {e}"))?;
    if reply.label != ipc::memmgr_errors::SUCCESS
    {
        return Err(format!(
            "QUERY_MEMORY_USAGE answered label={:#x}",
            reply.label
        ));
    }
    Ok(reply.word(0))
}

/// The grant path: `REQUEST_MEMORY_CAPS` for one chunk's pages with
/// `REQUIRE_CONTIGUOUS`, the cap's map into a reservation with
/// `mem_map_funded`, which funds page tables when the map is refused for want
/// of them, and the first store into it, which then faults on nothing.
///
/// The granted chunks stay mapped until ubench exits, when memmgr reclaims
/// them with the process.
fn fill_by_grant(counters: &Counters, cpus: u32) -> Outcome
{
    let info = startup_info();
    let reservation = reserve_pages(TOTAL_CHUNKS * CHUNK_PAGES)
        .map_err(|e| format!("path=grant: reserve the chunks' pages: {e:?}"))?;
    let base = reservation.va_start();
    let mut samples = Vec::with_capacity(CHUNKS_LEN);
    let idle = IdleSpan::open();
    for chunk in 0..TOTAL_CHUNKS
    {
        let va = chunk_va(base, chunk);
        let start = counters.read();
        let cap = request_contiguous(info.memmgr_endpoint, CHUNK_PAGES)
            .ok_or_else(|| format!("path=grant: chunk {chunk}: memmgr granted no chunk"))?;
        // SAFETY: the chunk lies in this process's own reservation, which
        // nothing else maps and where no Rust object or IPC page lies.
        let mapped = unsafe {
            std::os::seraph::mem_map_funded(cap, info.self_aspace, va, 0, CHUNK_PAGES, MAP_WRITABLE)
        };
        mapped.map_err(|e| format!("path=grant: chunk {chunk}: map: error {e}"))?;
        // SAFETY: the chunk was just mapped read-write in this process's own
        // reservation and holds no Rust object.
        unsafe { core::ptr::write_volatile(va as *mut u64, 1) };
        let cycles = counters.read().since(&start).cycles;
        if chunk >= WARMUP_CHUNKS
        {
            samples.push(cycles);
        }
    }
    let idle_halts = idle.close();
    report(
        "fault_fill",
        &[("path", Value::Word("grant")), PAGES],
        cpus,
        &mut samples,
        &[],
        idle_halts,
    )
}

/// The grant path from a thread with no affinity, in the window form
/// (shared/bench/README.md § Window rows): what memmgr's placement beside an
/// unpinned caller saves, which the pinned `path=grant` row, kept apart from
/// memmgr by the synchronous wake rule, cannot show
/// (core/kernel/docs/scheduler.md § Thread Assignment).
///
/// Each window, pinned to [`BENCH_CPU`], the thread makes one untimed grant,
/// whose call blocks and so leaves it on that CPU, opens its idle-halt span,
/// reads the counters, and clears its affinity; it makes the window's grants,
/// reads again, closes the span and pins itself once more. Clearing an
/// affinity, and naming the CPU the thread is on, move nothing, and no
/// blocking call falls between the closing read and the span's close, so a
/// window counts when the span closes with no halt ([`WindowEnd::from_close`]).
/// The line carries `remote_wakes=`, the thread's wakes linked on another CPU
/// than its waker's over the counted windows: one per grant's reply when
/// memmgr stays apart from the thread, none when it runs beside it.
fn fill_by_grant_unpinned(counters: &Counters, cpus: u32) -> Outcome
{
    let shape = WindowShape::for_ops(ANY_GRANTS)
        .ok_or_else(|| "path=grant affinity=any: no window".to_string())?;
    let info = startup_info();
    // The warm-up, each window's untimed grant and its timed ones, and the
    // untimed grant after the last window.
    let chunks = u64::from(shape.windows)
        .saturating_mul(u64::from(shape.ops).saturating_add(1))
        .saturating_add(WARMUP_CHUNKS)
        .saturating_add(1);
    let reservation = reserve_pages(chunks.saturating_mul(CHUNK_PAGES))
        .map_err(|e| format!("path=grant affinity=any: reserve the chunks' pages: {e:?}"))?;
    let base = reservation.va_start();
    let mut next = 0u64;
    let mut grant = || -> Outcome {
        let chunk = next;
        next = next.saturating_add(1);
        if chunk >= chunks
        {
            return Err(format!(
                "path=grant affinity=any: chunk {chunk} past the reservation"
            ));
        }
        let va = chunk_va(base, chunk);
        let cap = request_contiguous(info.memmgr_endpoint, CHUNK_PAGES).ok_or_else(|| {
            format!("path=grant affinity=any: chunk {chunk}: memmgr granted no chunk")
        })?;
        // SAFETY: the chunk lies in this process's own reservation, which
        // nothing else maps and where no Rust object or IPC page lies.
        let mapped = unsafe {
            std::os::seraph::mem_map_funded(cap, info.self_aspace, va, 0, CHUNK_PAGES, MAP_WRITABLE)
        };
        mapped.map_err(|e| format!("path=grant affinity=any: chunk {chunk}: map: error {e}"))?;
        // SAFETY: the chunk was just mapped read-write in this process's own
        // reservation and holds no Rust object.
        unsafe { core::ptr::write_volatile(va as *mut u64, 1) };
        Ok(())
    };
    for _ in 0..WARMUP_CHUNKS
    {
        grant()?;
    }
    let thread = std::os::seraph::thread::current_thread_cap();
    let mut samples = Vec::with_capacity(shape.windows as usize);
    let mut tally = WindowTally::default();
    let mut idle_halts = 0u64;
    let mut remote = Some(0u64);
    for _ in 0..shape.windows
    {
        grant()?;
        let wakes_before = remote_wakes(thread);
        let idle = IdleSpan::open();
        let start = counters.read();
        set_affinity(thread, AFFINITY_ANY)?;
        let ran = (0..shape.ops).try_for_each(|_| grant());
        let elapsed = counters.read().since(&start).cycles;
        let halts = idle.close();
        set_affinity(thread, BENCH_CPU)?;
        ran?;
        let wakes_after = remote_wakes(thread);
        idle_halts = idle_halts.saturating_add(halts.unwrap_or(0));
        let end = WindowEnd::from_close(halts);
        tally.record(end);
        if end == WindowEnd::Counted
        {
            samples.push(elapsed);
            // The counter is a wrapping 32-bit count.
            let wakes = wakes_before
                .zip(wakes_after)
                .map(|(before, after)| after.wrapping_sub(before) & u64::from(u32::MAX));
            remote = remote.zip(wakes).map(|(sum, w)| sum.saturating_add(w));
        }
    }
    // Back on BENCH_CPU before the next benchmark reads its counters.
    grant()?;
    if !tally.reaches_floor(shape)
    {
        std::os::seraph::log!(
            warn: "fault_fill path=grant affinity=any: counted windows below the floor, counted={} windows={} floor={} moved={} halted={}",
            tally.counted,
            shape.windows,
            shape.floor(),
            tally.moved,
            tally.halted
        );
        return Ok(());
    }
    let mut extras = vec![
        (WINDOW_OPS_KEY, u64::from(shape.ops)),
        (MOVED, u64::from(tally.moved)),
        (HALTED, u64::from(tally.halted)),
    ];
    extras.extend(remote.map(|w| (REMOTE_WAKES, w)));
    report(
        "fault_fill",
        &[
            ("path", Value::Word("grant")),
            PAGES,
            ("affinity", Value::Word("any")),
        ],
        cpus,
        &mut samples,
        &extras,
        Some(idle_halts),
    )
}

/// Set the affinity of `thread`, the calling thread, to `cpu`.
fn set_affinity(thread: u64, cpu: u32) -> Outcome
{
    syscall::thread_set_affinity(thread, cpu)
        .map_err(|e| format!("path=grant affinity=any: set affinity to {cpu:#x}: error {e}"))
}

/// The thread's remote wakes so far; `None` when the read failed.
fn remote_wakes(thread: u64) -> Option<u64>
{
    syscall::cap_info_thread_placement(thread, syscall_abi::THREAD_PLACEMENT_REMOTE_WAKES).ok()
}

/// One Memory cap of `pages` contiguous pages from memmgr
/// (`REQUEST_MEMORY_CAPS` with `REQUIRE_CONTIGUOUS`). `None` when the
/// request fails or the reply is not one cap of `pages` pages.
#[expect(
    clippy::inline_always,
    reason = "both grant rows time the request inside their windows, so a call around it would be measured with it"
)]
#[inline(always)]
fn request_contiguous(memmgr_ep: u64, pages: u64) -> Option<u64>
{
    let flags = u64::from(ipc::memmgr_labels::REQUIRE_CONTIGUOUS) << 32;
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, pages | flags)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) }.ok()?;
    let (counts, _) = ipc::memmgr_grant_layout(&reply)?;
    if counts != [pages]
    {
        return None;
    }
    reply.caps().first().copied()
}

/// `fault_scaling`: for each thread count k of [`SCALING_THREADS`] that the
/// system has CPUs for, k threads, thread i pinned to CPU i with its own
/// counters and its own demand region, fault their chunks at once. The line
/// of k holds every thread's timed samples, and as `idle_halts=` the halts of
/// every thread's CPU over that thread's measured loop, summed. A count above
/// the CPUs online logs a SKIP line.
pub fn scaling(cpus: u32) -> Outcome
{
    for threads in SCALING_THREADS
    {
        if threads > cpus
        {
            skip(
                "fault_scaling",
                &format!("threads={threads}: needs {threads} CPUs, {cpus} online"),
            );
            continue;
        }
        let (mut samples, idle_halts) =
            scale(threads).map_err(|e| format!("threads={threads}: {e}"))?;
        report(
            "fault_scaling",
            &[("threads", Value::Num(u64::from(threads))), PAGES],
            cpus,
            &mut samples,
            &[],
            idle_halts,
        )?;
    }
    Ok(())
}

/// What the workers of one `fault_scaling` count are told once all are set
/// up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signal
{
    /// Not yet decided.
    Wait,
    /// Every worker was spawned: start faulting.
    Go,
    /// A worker could not be spawned: stop without faulting.
    Abort,
}

/// The start of one `fault_scaling` count: the workers set up, each arrives,
/// and once all have arrived the harness thread signals them together.
struct Gate
{
    /// The workers that arrived, and the signal.
    state: Mutex<(u32, Signal)>,
    cv: Condvar,
}

impl Gate
{
    /// A worker is set up: count it, wake the harness thread, and wait for
    /// the signal.
    fn arrive_and_wait(&self) -> Signal
    {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.0 = state.0.saturating_add(1);
        self.cv.notify_all();
        while state.1 == Signal::Wait
        {
            state = self.cv.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        state.1
    }

    /// The harness thread: wait until `workers` have arrived, then send
    /// `signal` to every one of them.
    fn release(&self, workers: u32, signal: Signal)
    {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while signal == Signal::Go && state.0 < workers
        {
            state = self.cv.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        state.1 = signal;
        drop(state);
        self.cv.notify_all();
    }
}

/// Run one thread count: spawn its workers, start them together, and merge
/// their samples and the idle halts of their CPUs over their measured loops,
/// the halts `None` when a worker's read failed.
fn scale(threads: u32) -> Result<(Vec<u64>, Option<u64>), String>
{
    let gate = Arc::new(Gate {
        state: Mutex::new((0, Signal::Wait)),
        cv: Condvar::new(),
    });
    let mut workers = Vec::new();
    let mut spawn_error = None;
    for cpu in 0..threads
    {
        let gate = Arc::clone(&gate);
        match std::thread::Builder::new()
            .name(format!("ubench-fault-{cpu}"))
            .spawn(move || fault_worker(cpu, &gate))
        {
            Ok(worker) => workers.push(worker),
            Err(e) =>
            {
                spawn_error = Some(format!("spawn the worker for CPU {cpu}: {e}"));
                break;
            }
        }
    }
    // Every spawned worker arrives before it waits, so a Go waits for all of
    // them and an Abort releases those that did.
    let spawned = u32::try_from(workers.len()).unwrap_or(u32::MAX);
    gate.release(
        spawned,
        if spawn_error.is_none()
        {
            Signal::Go
        }
        else
        {
            Signal::Abort
        },
    );
    let mut merged = Vec::with_capacity(workers.len().saturating_mul(CHUNKS_LEN));
    let mut idle_halts = Some(0u64);
    let mut first_error = spawn_error;
    for worker in workers
    {
        match worker.join()
        {
            Ok(Ok((samples, halts))) =>
            {
                merged.extend(samples);
                idle_halts = idle_halts.zip(halts).map(|(sum, h)| sum.saturating_add(h));
            }
            Ok(Err(e)) => _ = first_error.get_or_insert(e),
            Err(_) => _ = first_error.get_or_insert_with(|| "a worker panicked".to_string()),
        }
    }
    match first_error
    {
        Some(e) => Err(e),
        None => Ok((merged, idle_halts)),
    }
}

/// One worker of `fault_scaling`: pinned to `cpu`, with counters opened
/// there and a demand region of its own, it faults its chunks once the gate
/// opens and returns its timed samples and the halts of its CPU over its
/// measured loop ([`IdleSpan`]).
///
/// It arrives at the gate whatever its set-up's outcome, so a failed set-up
/// never holds the others back; it reports the failure after the gate.
fn fault_worker(cpu: u32, gate: &Gate) -> Result<(Vec<u64>, Option<u64>), String>
{
    let setup = pin_to(cpu).and_then(|()| {
        // The CPU count bounds `cpu`: a worker past it would not run there.
        let online = cpu_count()?;
        if cpu >= online
        {
            return Err(format!("CPU {cpu} is not online ({online} CPUs)"));
        }
        register_demand_paged(TOTAL_CHUNKS * CHUNK_PAGES)
            .map_err(|e| format!("CPU {cpu}: register the demand region: {e}"))
    });
    let counters = Counters::open();
    let signal = gate.arrive_and_wait();
    let region = setup?;
    if signal != Signal::Go
    {
        // SAFETY: nothing touched the region, and the IPC buffer lies outside
        // it.
        let _ = unsafe { unregister_demand_paged(region) };
        return Err(format!("CPU {cpu}: the run was aborted"));
    }
    let base = region.va_start();
    let mut samples = Vec::with_capacity(CHUNKS_LEN);
    let idle = IdleSpan::open();
    for chunk in 0..TOTAL_CHUNKS
    {
        let va = chunk_va(base, chunk);
        let start = counters.read();
        // SAFETY: `va` starts a chunk of a read-write demand region this
        // thread registered, which holds no Rust object; the store's fault is
        // backed by the pager.
        unsafe { core::ptr::write_volatile(va as *mut u64, 1) };
        let cycles = counters.read().since(&start).cycles;
        if chunk >= WARMUP_CHUNKS
        {
            samples.push(cycles);
        }
    }
    let idle_halts = idle.close();
    // SAFETY: no reference into the region outlives the stores above, and the
    // IPC buffer lies outside it.
    unsafe { unregister_demand_paged(region) }
        .map_err(|e| format!("CPU {cpu}: unregister the demand region: {e}"))?;
    Ok((samples, idle_halts))
}
