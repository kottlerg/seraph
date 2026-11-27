// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/ubench/src/pipeline.rs

//! `pipeline`: the throughput of a producer and a consumer thread, neither
//! pinned, that hand items to each other through a byte ring with the stdio
//! pipe's doorbell protocol (`shared/shmem/README.md` § Doorbell protocol),
//! each doing a fixed amount of work per item, and where the kernel ran them.
//!
//! Neither thread can time the pipeline with its own counter: a counter is the
//! CPU's, and either thread may move between two reads. ubench's own thread,
//! pinned to [`BENCH_CPU`], times it instead as the pipeline's head and tail:
//! per window it reads its counter, wakes the producer, waits for the
//! consumer's word that the window's items have passed, and reads again. Both
//! reads are on one CPU, so a window is the elapsed counter time on that CPU
//! wherever the pair ran. That CPU halts in a window when nothing else runs
//! there, so every window is also checked against the kernel's elapsed
//! microseconds, a clock that runs through halts ([`bench::CycleRate`]), and a
//! window whose counter did not count its elapsed time is left out of the
//! samples (services/ubench/README.md § Benchmarks).

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::Scope;

use bench::{Counters, CycleRate, Value, WINDOW_OPS_KEY};
use shmem::{SpscHeader, SpscReader, SpscWriter};
use syscall_abi::{
    SyscallError, SystemInfoType, THREAD_PLACEMENT_CPU, THREAD_PLACEMENT_IDLE_WAKES,
    THREAD_PLACEMENT_PULLS, THREAD_PLACEMENT_REMOTE_WAKES, THREAD_PLACEMENT_WAKE_MOVES,
};

use crate::harness::{IdleSpan, Outcome, report};

/// The work values measured: iterations of [`spin`] on each side per item,
/// from none, where a sample is the handoff alone, to work that dwarfs a
/// wake of another CPU.
const WORKS: [u64; 4] = [0, 1024, 8192, 65536];

/// The bytes of one item: a cache line.
const ITEM_BYTES: usize = 64;

/// The ring's data capacity: the stdio pipe's (`RING_CAPACITY` in
/// `runtime/ruststd/src/sys/pipe/seraph.rs`), 32 items.
const RING_CAPACITY: u32 = 2048;

/// Items per window: two ring-fulls, so that the producer also waits for
/// space.
const WINDOW_ITEMS: u64 = 64;

/// Untimed windows before each work value's timed ones.
const WARMUP_WINDOWS: u64 = 2;

/// Timed windows per work value.
const WINDOWS: u64 = 32;

/// The microseconds over which the counter's rate is measured on
/// [`BENCH_CPU`] before the windows.
const CALIBRATION_MICROS: u64 = 2000;

/// The sequence number of the item that ends the consumer.
const STOP_SEQ: u64 = u64::MAX;

/// The go notification's bit that starts a window's items.
const GO: u64 = 1;
/// The go notification's bit that ends the producer.
const STOP: u64 = 1 << 1;
/// The done notification's bit that ends a window.
const DONE: u64 = 1;
/// The done notification's bit of the producer's start.
const PRODUCER_READY: u64 = 1 << 1;
/// The done notification's bit of the consumer's start.
const CONSUMER_READY: u64 = 1 << 2;
/// The bit every notification is sent when a thread of the pipeline fails.
const FAILED: u64 = 1 << 3;

/// The placement counts a work value's placement line reports, in its order
/// (core/kernel/docs/scheduler.md § Placement Counters).
const COUNT_VIEWS: [(&str, u64); 4] = [
    ("remote_wakes", THREAD_PLACEMENT_REMOTE_WAKES),
    ("idle_wakes", THREAD_PLACEMENT_IDLE_WAKES),
    ("wake_moves", THREAD_PLACEMENT_WAKE_MOVES),
    ("pulls", THREAD_PLACEMENT_PULLS),
];

/// Run the benchmark: one result line per work value.
pub fn run(counters: &Counters, cpus: u32) -> Outcome
{
    for work in WORKS
    {
        line(counters, cpus, work).map_err(|e| format!("work={work}: {e}"))?;
    }
    Ok(())
}

/// The counter's rate against the elapsed clock, over
/// [`CALIBRATION_MICROS`] in which the calling thread keeps its CPU busy, so
/// that the CPU does not halt.
fn calibrate(counters: &Counters) -> Result<CycleRate, String>
{
    let first = elapsed_us()?;
    let mut last = first;
    let cycles = timed(counters, &mut || {
        while last.saturating_sub(first) < CALIBRATION_MICROS
        {
            last = elapsed_us()?;
        }
        Ok(())
    })?;
    CycleRate::new(cycles, last.saturating_sub(first))
        .ok_or_else(|| format!("no counter rate: {cycles} cycles in {CALIBRATION_MICROS} us"))
}

/// The cycles `region` took, between two counter reads. Every window of the
/// benchmark, the calibration's included, is read here, so that all of them
/// read the counter at the same two addresses: `cargo xtask path-account`
/// divides a program's windows among its result lines by those addresses
/// (xtask/README.md § `cargo xtask path-account`).
#[inline(never)]
fn timed(counters: &Counters, region: &mut dyn FnMut() -> Outcome) -> Result<u64, String>
{
    let start = counters.read();
    let ran = region();
    let cycles = counters.read().since(&start).cycles;
    ran.map(|()| cycles)
}

/// The kernel's elapsed microseconds (`SystemInfoType::ElapsedUs`).
fn elapsed_us() -> Result<u64, String>
{
    syscall::system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|e| format!("elapsed time: error {e}"))
}

/// Measure one work value with a pair of its own, on a ring and notifications
/// of its own, and log its line.
fn line(counters: &Counters, cpus: u32, work: u64) -> Outcome
{
    let chan = Channel::new()?;
    // The region the ring lives in: its header, then its data, 8-byte
    // aligned as `shmem_ring`'s is.
    let region_bytes = SpscHeader::SIZE.saturating_add(RING_CAPACITY as usize);
    let mut region = vec![0u64; region_bytes.div_ceil(8)];
    let header = region.as_mut_ptr().cast::<SpscHeader>();
    // SAFETY: `header` points at `region`, which this function owns, holds
    // the header and the ring's data, and is 8-byte aligned; no reader or
    // writer exists yet.
    unsafe { SpscHeader::init(header, RING_CAPACITY) };
    // SAFETY: the region is mapped read-write and aligned, its header was
    // just initialised, and it outlives the scope below, which joins the
    // only threads the writer and the reader move to.
    let (writer, reader) = unsafe { shmem::spsc_pair(header.addr() as u64, RING_CAPACITY) }
        .ok_or_else(|| "the ring refused its own capacity".to_string())?;
    let chan = &chan;
    let measured = std::thread::scope(|s| {
        let producer_thread = std::thread::Builder::new()
            .name("ubench-pipe-producer".into())
            .spawn_scoped(s, move || produce(s, chan, writer, reader, work))
            .map_err(|e| format!("spawn the producer: {e}"))?;
        let observed = observe(counters, chan);
        match &observed
        {
            Ok(_) => chan.signal(chan.go, STOP),
            Err(_) => chan.fail(),
        }
        let produced = producer_thread
            .join()
            .map_err(|_| "the producer panicked".to_string())
            .and_then(|r| r);
        observed.and_then(|m| produced.map(|()| m))
    });
    // The writer and the reader borrow `region` without a lifetime the
    // compiler sees; the scope above joined every thread that held them.
    drop(region);
    let mut measured = measured?;
    if measured.samples.is_empty()
    {
        return Err(format!(
            "no window counted its elapsed time: clock_stopped={} window_us={}",
            measured.clock_stopped, measured.window_us
        ));
    }
    let extras = [
        (WINDOW_OPS_KEY, WINDOW_ITEMS),
        ("apart", measured.apart),
        ("clock_stopped", measured.clock_stopped),
        ("window_us", measured.window_us),
    ];
    report(
        "pipeline",
        &[("work", Value::Num(work))],
        cpus,
        &mut measured.samples,
        &extras,
        measured.idle_halts,
    )?;
    // The placement counts take a line of their own: with them the result
    // line could pass the length the log carries whole (harness::LOG_LINE_BYTES).
    let counts: Vec<String> = measured
        .placement
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect();
    std::os::seraph::log!(
        "pipeline placement: work={work} cpus={cpus} {}",
        counts.join(" ")
    );
    Ok(())
}

/// The notifications of one pipeline and what its threads share besides the
/// ring.
struct Channel
{
    /// The consumer waits on it for items; the producer rings it.
    data: u64,
    /// The producer waits on it for space; the consumer rings it.
    space: u64,
    /// The producer waits on it for a window to start ([`GO`]) or for its
    /// end ([`STOP`]).
    go: u64,
    /// The observer waits on it for a window's end ([`DONE`]) and the
    /// threads' start.
    done: u64,
    /// A thread of the pipeline failed: every wait returns an error.
    failed: AtomicBool,
    /// The producer's Thread cap, once it started.
    producer: AtomicU64,
    /// The consumer's Thread cap, once it started.
    consumer: AtomicU64,
}

impl Channel
{
    /// Four fresh notifications, no thread started.
    fn new() -> Result<Self, String>
    {
        let mut caps = [0u64; 4];
        for (i, cap) in caps.iter_mut().enumerate()
        {
            let Some(created) = notification()
            else
            {
                for made in caps.iter().take(i)
                {
                    let _ = syscall::cap_delete(*made);
                }
                return Err("create a notification".to_string());
            };
            *cap = created;
        }
        let [data, space, go, done] = caps;
        Ok(Self {
            data,
            space,
            go,
            done,
            failed: AtomicBool::new(false),
            producer: AtomicU64::new(0),
            consumer: AtomicU64::new(0),
        })
    }

    /// Send `bits` to `cap`. A failed send fails the pipeline, since its
    /// waiter would never wake.
    fn signal(&self, cap: u64, bits: u64)
    {
        if syscall::notification_send(cap, bits).is_err()
        {
            self.fail();
        }
    }

    /// Mark the pipeline failed and wake every thread waiting on it.
    fn fail(&self)
    {
        self.failed.store(true, Ordering::Release);
        for cap in [self.data, self.space, self.go, self.done]
        {
            let _ = syscall::notification_send(cap, FAILED);
        }
    }

    /// Wait on `cap` for its bits; an error when the wait fails or the
    /// pipeline failed.
    fn wait(&self, cap: u64) -> Result<u64, String>
    {
        loop
        {
            let waited = syscall::notification_wait(cap);
            if self.failed.load(Ordering::Acquire)
            {
                return Err("another thread of the pipeline failed".to_string());
            }
            match waited
            {
                Ok(bits) => return Ok(bits),
                Err(e) if e == SyscallError::Interrupted as i64 =>
                {}
                Err(e) => return Err(format!("notification wait: error {e}")),
            }
        }
    }
}

impl Drop for Channel
{
    fn drop(&mut self)
    {
        // The notifications are this pipeline's alone; a failed delete leaks
        // one slot of a process that exits after the suite.
        for cap in [self.data, self.space, self.go, self.done]
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// A fresh notification cap.
fn notification() -> Option<u64>
{
    std::os::seraph::object_slab_retype(syscall_abi::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
}

/// The producer: it creates the consumer, as a thread that hands its work on
/// does, then sends [`WINDOW_ITEMS`] items each time the observer starts a
/// window, until it is told to stop.
fn produce<'scope, 'env>(
    s: &'scope Scope<'scope, 'env>,
    chan: &'env Channel,
    mut writer: SpscWriter<'env>,
    reader: SpscReader<'env>,
    work: u64,
) -> Outcome
{
    let consumer_thread = std::thread::Builder::new()
        .name("ubench-pipe-consumer".into())
        .spawn_scoped(s, move || consume(chan, reader, work));
    let Ok(consumer_thread) = consumer_thread
    else
    {
        chan.fail();
        return Err("spawn the consumer".to_string());
    };
    chan.producer.store(
        std::os::seraph::thread::current_thread_cap(),
        Ordering::Release,
    );
    chan.signal(chan.done, PRODUCER_READY);
    let produced = send_windows(chan, &mut writer, work);
    if produced.is_err()
    {
        chan.fail();
    }
    let consumed = consumer_thread
        .join()
        .map_err(|_| "the consumer panicked".to_string())
        .and_then(|r| r);
    produced.and(consumed)
}

/// The producer's loop: per [`GO`], [`WINDOW_ITEMS`] items, each after
/// [`spin`] of `work`; on [`STOP`], the item that ends the consumer.
fn send_windows(chan: &Channel, writer: &mut SpscWriter<'_>, work: u64) -> Outcome
{
    let mut seq = 0u64;
    loop
    {
        let bits = chan.wait(chan.go)?;
        if bits & STOP != 0
        {
            return send(chan, writer, &item(STOP_SEQ, 0));
        }
        for _ in 0..WINDOW_ITEMS
        {
            let value = spin(work, seq);
            send(chan, writer, &item(seq, value))?;
            seq = seq.wrapping_add(1);
        }
    }
}

/// The consumer: it takes each item, checks that it is the next, and does
/// [`spin`] of `work` on it; after a window's [`WINDOW_ITEMS`], it tells
/// the observer.
fn consume(chan: &Channel, mut reader: SpscReader<'_>, work: u64) -> Outcome
{
    chan.consumer.store(
        std::os::seraph::thread::current_thread_cap(),
        Ordering::Release,
    );
    chan.signal(chan.done, CONSUMER_READY);
    let consumed = take_windows(chan, &mut reader, work);
    if consumed.is_err()
    {
        chan.fail();
    }
    consumed
}

/// The consumer's loop, until the item of [`STOP_SEQ`].
fn take_windows(chan: &Channel, reader: &mut SpscReader<'_>, work: u64) -> Outcome
{
    let mut expected = 0u64;
    let mut sink = 0u64;
    loop
    {
        for _ in 0..WINDOW_ITEMS
        {
            let (seq, value) = receive(chan, reader)?;
            if seq == STOP_SEQ
            {
                black_box(sink);
                return Ok(());
            }
            if seq != expected
            {
                return Err(format!("item {seq} arrived, {expected} expected"));
            }
            sink ^= spin(work, value);
            expected = expected.wrapping_add(1);
        }
        chan.signal(chan.done, DONE);
    }
}

/// An item: its sequence number and the producer's work value, the rest of
/// the line zero.
fn item(seq: u64, value: u64) -> [u8; ITEM_BYTES]
{
    let mut bytes = [0u8; ITEM_BYTES];
    let (seq_bytes, rest) = bytes.split_at_mut(8);
    seq_bytes.copy_from_slice(&seq.to_le_bytes());
    if let Some(value_bytes) = rest.get_mut(..8)
    {
        value_bytes.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Write `item` into the ring, waiting for space as the pipe's writer does,
/// and ring the consumer when it announced a wait.
fn send(chan: &Channel, writer: &mut SpscWriter<'_>, item: &[u8; ITEM_BYTES]) -> Outcome
{
    let mut sent = 0usize;
    while sent < ITEM_BYTES
    {
        let n = writer.write(item.get(sent..).unwrap_or_default());
        sent = sent.saturating_add(n);
        if n > 0
        {
            if writer.take_waiting_reader()
            {
                chan.signal(chan.data, 1);
            }
            continue;
        }
        if writer.prepare_wait()
        {
            let waited = chan.wait(chan.space);
            writer.end_wait();
            waited?;
        }
    }
    Ok(())
}

/// Read one item from the ring, waiting for it as the pipe's reader does, and
/// ring the producer when it announced a wait; its sequence number and work
/// value.
fn receive(chan: &Channel, reader: &mut SpscReader<'_>) -> Result<(u64, u64), String>
{
    let mut bytes = [0u8; ITEM_BYTES];
    let mut received = 0usize;
    while received < ITEM_BYTES
    {
        let n = reader.read(bytes.get_mut(received..).unwrap_or_default());
        received = received.saturating_add(n);
        if n > 0
        {
            if reader.take_waiting_writer()
            {
                chan.signal(chan.space, 1);
            }
            continue;
        }
        if reader.prepare_wait()
        {
            let waited = chan.wait(chan.data);
            reader.end_wait();
            waited?;
        }
    }
    let word = |at: usize| {
        let mut w = [0u8; 8];
        if let Some(src) = bytes.get(at..at.saturating_add(8))
        {
            w.copy_from_slice(src);
        }
        u64::from_le_bytes(w)
    };
    Ok((word(0), word(8)))
}

/// `iterations` steps of a multiply-add chain from `seed`: a fixed amount
/// of work, the same instructions wherever the thread runs, which no CPU it
/// shares or moves to shortens.
fn spin(iterations: u64, seed: u64) -> u64
{
    let mut x = seed;
    for _ in 0..iterations
    {
        x = black_box(x.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1));
    }
    x
}

/// What the observer measured of one work value.
struct Measured
{
    /// Each counted window's cycles, for its [`WINDOW_ITEMS`] items.
    samples: Vec<u64>,
    /// How much each of [`COUNT_VIEWS`] grew over the timed windows, summed
    /// over the two threads.
    placement: [(&'static str, u64); COUNT_VIEWS.len()],
    /// Timed windows at whose end the two threads' CPUs differed.
    apart: u64,
    /// Timed windows left out because their counter did not count their
    /// elapsed time.
    clock_stopped: u64,
    /// The mean elapsed microseconds of a timed window, over every one.
    window_us: u64,
    /// The halts of [`BENCH_CPU`] over the windows.
    idle_halts: Option<u64>,
}

/// The observer: once both threads started, time each window and read where
/// the threads ran, outside the timed reads.
fn observe(counters: &Counters, chan: &Channel) -> Result<Measured, String>
{
    let mut started = 0u64;
    while started & (PRODUCER_READY | CONSUMER_READY) != PRODUCER_READY | CONSUMER_READY
    {
        started |= chan.wait(chan.done)?;
    }
    let threads = [
        chan.producer.load(Ordering::Acquire),
        chan.consumer.load(Ordering::Acquire),
    ];
    let mut samples = Vec::new();
    let mut apart = 0u64;
    let mut clock_stopped = 0u64;
    let mut elapsed = 0u64;
    let mut before = [[0u32; COUNT_VIEWS.len()]; 2];
    let idle = IdleSpan::open();
    let rate = calibrate(counters)?;
    for i in 0..WARMUP_WINDOWS + WINDOWS
    {
        if i == WARMUP_WINDOWS
        {
            before = counts(threads)?;
        }
        let (cycles, micros) = window(counters, chan)?;
        if i < WARMUP_WINDOWS
        {
            continue;
        }
        elapsed = elapsed.saturating_add(micros);
        if rate.counted(cycles, micros)
        {
            samples.push(cycles);
        }
        else
        {
            clock_stopped = clock_stopped.saturating_add(1);
        }
        if view(threads[0], THREAD_PLACEMENT_CPU)? != view(threads[1], THREAD_PLACEMENT_CPU)?
        {
            apart = apart.saturating_add(1);
        }
    }
    let idle_halts = idle.close();
    let after = counts(threads)?;
    Ok(Measured {
        samples,
        placement: grown(&before, &after),
        apart,
        clock_stopped,
        window_us: elapsed / WINDOWS,
        idle_halts,
    })
}

/// One window: the counter read, the producer started, the consumer's word
/// that the window's items passed awaited, the counter read again, between
/// two reads of the elapsed clock; its cycles and its elapsed microseconds.
fn window(counters: &Counters, chan: &Channel) -> Result<(u64, u64), String>
{
    let first = elapsed_us()?;
    let mut bits = 0;
    let cycles = timed(counters, &mut || {
        chan.signal(chan.go, GO);
        bits = chan.wait(chan.done)?;
        Ok(())
    })?;
    let last = elapsed_us()?;
    if bits & DONE == 0
    {
        return Err(format!("the window ended on bits {bits:#x}"));
    }
    Ok((cycles, last.saturating_sub(first)))
}

/// One placement view of a thread.
fn view(thread: u64, which: u64) -> Result<u64, String>
{
    syscall::cap_info_thread_placement(thread, which)
        .map_err(|e| format!("placement view {which}: error {e}"))
}

/// Each of [`COUNT_VIEWS`] of each of `threads`, as the kernel's 32-bit
/// counters hold them.
fn counts(threads: [u64; 2]) -> Result<[[u32; COUNT_VIEWS.len()]; 2], String>
{
    let mut all = [[0u32; COUNT_VIEWS.len()]; 2];
    for (thread, slots) in threads.into_iter().zip(all.iter_mut())
    {
        for ((_, which), slot) in COUNT_VIEWS.iter().zip(slots.iter_mut())
        {
            let count = view(thread, *which)?;
            *slot = u32::try_from(count).map_err(|_| format!("placement count {count}"))?;
        }
    }
    Ok(all)
}

/// How much each of [`COUNT_VIEWS`] grew from `before` to `after`, wrapping
/// as the counters do, summed over the threads.
fn grown(
    before: &[[u32; COUNT_VIEWS.len()]; 2],
    after: &[[u32; COUNT_VIEWS.len()]; 2],
) -> [(&'static str, u64); COUNT_VIEWS.len()]
{
    let mut extras = COUNT_VIEWS.map(|(name, _)| (name, 0u64));
    for (start, end) in before.iter().zip(after)
    {
        for (((_, sum), from), to) in extras.iter_mut().zip(start).zip(end)
        {
            *sum = sum.saturating_add(u64::from(to.wrapping_sub(*from)));
        }
    }
    extras
}
