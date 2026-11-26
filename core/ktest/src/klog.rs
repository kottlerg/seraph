// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/klog.rs

//! ktest as the kernel log's reader.
//!
//! ktest, loaded as init, holds the root `KernelLog` capability. It attaches
//! at its start ([`attach`]) and drains the log ([`drain`]) before each line
//! it writes and in its waits, so each kernel line reaches the console whole,
//! in order with ktest's own, rather than written by the kernel into the
//! middle of one of them (core/kernel/docs/kernel-log.md § Readers). Only the
//! main thread writes the console, so only it drains.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use syscall_abi::{KLOG_FLAG_TRUNCATED, KernelLogRecord};

/// Bytes of the drain buffer: several records of the longest line.
const BUF_BYTES: usize = 4096;

/// Reads one drain makes at most, so a kernel that appends as fast as ktest
/// writes cannot hold it in the drain.
const MAX_READS: u32 = 64;

/// ktest's `KernelLog` capability; 0 before [`attach`], and when init's
/// descriptors name none.
static CAP: AtomicU64 = AtomicU64::new(0);

/// The sequence number of the last record written to the console, which the
/// next read acknowledges.
static WRITTEN: AtomicU64 = AtomicU64::new(0);

/// A drain is running: a second one (a log line written inside the first)
/// returns at once.
static BUSY: AtomicBool = AtomicBool::new(false);

/// The drain's buffer, reached only by the drain that holds [`BUSY`].
static mut BUF: [u8; BUF_BYTES] = [0; BUF_BYTES];

/// Attach as the kernel log's reader through `cap` and write what the log
/// holds. A `cap` of 0 leaves the kernel writing its lines itself.
pub fn attach(cap: u64)
{
    CAP.store(cap, Ordering::Relaxed);
    drain();
}

/// The sequence number of the last record written to the console.
pub fn written() -> u64
{
    WRITTEN.load(Ordering::Relaxed)
}

/// Write the records the kernel holds after the last one written, each as the
/// kernel's own console line, and acknowledge them.
pub fn drain()
{
    let cap = CAP.load(Ordering::Relaxed);
    if cap == 0 || BUSY.swap(true, Ordering::Acquire)
    {
        return;
    }
    // SAFETY: BUSY is held, so no other drain reaches BUF until it is
    // released below.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    for _ in 0..MAX_READS
    {
        let ack = WRITTEN.load(Ordering::Relaxed);
        // `from_seq` 0: the records after the acknowledged one, less any a
        // kernel flush has already written.
        let Ok(n) = syscall::kernel_log_read(cap, 0, ack, buf)
        else
        {
            break;
        };
        if n == 0
        {
            break;
        }
        for rec in syscall_abi::kernel_log_records(buf.get(..n).unwrap_or_default())
        {
            let expected = WRITTEN.load(Ordering::Relaxed).saturating_add(1);
            if rec.seq > expected && expected > 1
            {
                crate::log_line_raw(format_args!(
                    "ktest: kernel log records {}-{} lost",
                    expected,
                    rec.seq.saturating_sub(1)
                ));
            }
            write_record(&rec);
            WRITTEN.store(rec.seq, Ordering::Relaxed);
        }
    }
    BUSY.store(false, Ordering::Release);
}

/// Write `rec` as the kernel writes a line itself:
/// `[S.UUUUUU] kernel: <text>`, the time being the record's.
fn write_record(rec: &KernelLogRecord<'_>)
{
    let text = core::str::from_utf8(rec.text).unwrap_or("(text not UTF-8)");
    let cut = if rec.flags & KLOG_FLAG_TRUNCATED != 0
    {
        " (cut)"
    }
    else
    {
        ""
    };
    crate::log_line_at(rec.us, format_args!("kernel: {text}{cut}"));
}
