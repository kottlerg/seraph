// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/ubench/src/shmem_ring.rs

//! `shmem_ring`: the copy cost of the stdio pipe's byte ring, `shared/shmem`'s
//! `SpscWriter::write` and `SpscReader::read`, which every program's stdout
//! and stdin pass through (`runtime/ruststd/src/sys/pipe/seraph.rs`).
//!
//! One thread writes `bytes` into a ring of the pipe's capacity and reads them
//! out again, a ring's worth at a time, as a pipe's writer and reader take
//! turns when the transfer is larger than the ring. No peer, notification or
//! IPC is involved: a sample is the two copies and the index updates alone.

use bench::{Counters, Value};
use shmem::{SpscHeader, SpscReader, SpscWriter};

use crate::harness::{Outcome, report};

/// The ring's data capacity: the stdio pipe's (`RING_CAPACITY` in
/// `runtime/ruststd/src/sys/pipe/seraph.rs`).
const RING_CAPACITY: u32 = 2048;

/// The transfer sizes measured, from one short write to 32 ring-fulls.
const SIZES: [usize; 4] = [64, 512, 4096, 65536];

/// The largest of [`SIZES`].
const MAX_SIZE: usize = 65536;

/// Untimed transfers before each size's timed ones.
const WARMUP: usize = 16;

/// Timed transfers per size.
const ITERS: usize = 256;

/// Run the benchmark: one result line per transfer size.
pub fn run(counters: &Counters, cpus: u32) -> Outcome
{
    // The region the ring lives in: its header, then its data. A `u64`
    // buffer gives the header the 4-byte alignment it needs.
    let region_bytes = SpscHeader::SIZE.saturating_add(RING_CAPACITY as usize);
    let mut region = vec![0u64; region_bytes.div_ceil(8)];
    let header = region.as_mut_ptr().cast::<SpscHeader>();
    // SAFETY: `header` points at `region`, which this function owns, holds
    // the header and the ring's data, and is 8-byte aligned; no reader or
    // writer exists yet.
    unsafe { SpscHeader::init(header, RING_CAPACITY) };
    let vaddr = header.addr() as u64;
    // SAFETY: the region is mapped read-write and aligned, its header was
    // just initialised, and it outlives the writer and the reader, which are
    // its only ones and are dropped before it.
    let (mut writer, mut reader) = unsafe { shmem::spsc_pair(vaddr, RING_CAPACITY) }
        .ok_or_else(|| "the ring refused its own capacity".to_string())?;

    let src: Vec<u8> = (0..MAX_SIZE).map(|i| i.to_le_bytes()[0]).collect();
    let mut dst = vec![0u8; MAX_SIZE];
    let mut samples = Vec::with_capacity(ITERS);
    for bytes in SIZES
    {
        let (Some(src), Some(dst)) = (src.get(..bytes), dst.get_mut(..bytes))
        else
        {
            return Err(format!("bytes={bytes} exceeds the buffers"));
        };
        samples.clear();
        for i in 0..WARMUP + ITERS
        {
            dst.fill(0);
            let start = counters.read();
            transfer(&mut writer, &mut reader, src, dst);
            let cycles = counters.read().since(&start).cycles;
            if dst != src
            {
                return Err(format!(
                    "bytes={bytes}: the bytes read differ from those written"
                ));
            }
            if i >= WARMUP
            {
                samples.push(cycles);
            }
        }
        report(
            "shmem_ring",
            &[("bytes", Value::Num(bytes as u64))],
            cpus,
            &mut samples,
            &[],
        )?;
    }
    // The ring's writer and reader borrow `region` without a lifetime the
    // compiler sees; their last use is above, before it is freed here.
    drop(region);
    Ok(())
}

/// Move `src` through the ring into `dst`, of the same length: write what
/// fits, read it out, until every byte has passed.
fn transfer(writer: &mut SpscWriter<'_>, reader: &mut SpscReader<'_>, src: &[u8], dst: &mut [u8])
{
    let mut sent = 0usize;
    let mut received = 0usize;
    while received < dst.len()
    {
        sent = sent.saturating_add(writer.write(src.get(sent..).unwrap_or_default()));
        received =
            received.saturating_add(reader.read(dst.get_mut(received..).unwrap_or_default()));
    }
}
