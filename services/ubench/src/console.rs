// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/ubench/src/console.rs

//! `console_write`: the cost of console text output on the framebuffer, a
//! run of text sent to the framebuffer driver as `FB_WRITE_BYTES` calls of at
//! most 512 bytes each, as the terminal sends its child's output
//! (`programs/terminal/src/output.rs`).
//!
//! The text is lines of 63 letters and a newline, so a sample of 4096 bytes
//! draws 64 lines and scrolls the screen with each once it is full. Before
//! each size's samples the screen is filled with untimed writes, so every
//! timed write of either size scrolls it, whatever the screen held before. A boot with no framebuffer (headless, the
//! default of `cargo xtask run --runs`) logs a SKIP line.

use bench::{Counters, Value};
use ipc::{IpcMessage, fb_errors, fb_labels};

use crate::harness::{IdleSpan, Outcome, report, skip};

/// The most payload bytes one `FB_WRITE_BYTES` call carries (label bits
/// 16 to 31).
const PAYLOAD_MAX: usize = 512;

/// The text sizes measured: one line, and 64 lines.
const SIZES: [usize; 2] = [64, 4096];

/// The largest of [`SIZES`].
const MAX_SIZE: usize = 4096;

/// Bytes per line of the text, its newline included.
const LINE: usize = 64;

/// Untimed writes of the largest size before each size's samples: 1024
/// lines, enough to fill any screen QEMU's adapter gives, so every timed
/// write scrolls.
const FILL: usize = 16;

/// Untimed writes of each size before its timed ones.
const WARMUP: usize = 16;

/// Timed writes per size.
const ITERS: usize = 64;

/// Run the benchmark through the framebuffer class SEND `fb_class`: one
/// result line per text size, or a SKIP line when the class serves no driver.
pub fn run(fb_class: u64, counters: &Counters, cpus: u32) -> Outcome
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let device = unsafe { device_tracker::Device::start(fb_class, "framebuffer", ipc_buf) };
    let Some(driver) = device.current()
    else
    {
        skip(
            "console_write",
            "no framebuffer driver runs: a headless boot",
        );
        return Ok(());
    };
    let text: Vec<u8> = (0..MAX_SIZE)
        .map(|i| {
            if i % LINE == LINE - 1
            {
                b'\n'
            }
            else
            {
                b'a'.saturating_add((i % 26).to_le_bytes()[0])
            }
        })
        .collect();
    let mut samples = Vec::with_capacity(ITERS);
    let text_all = text.as_slice();
    for bytes in SIZES
    {
        let text = text
            .get(..bytes)
            .ok_or_else(|| format!("bytes={bytes} exceeds the text"))?;
        for _ in 0..FILL
        {
            write(driver.cap, text_all, ipc_buf).map_err(|e| format!("bytes={bytes}: {e}"))?;
        }
        samples.clear();
        let idle = IdleSpan::open();
        for i in 0..WARMUP + ITERS
        {
            let start = counters.read();
            let written = write(driver.cap, text, ipc_buf);
            let cycles = counters.read().since(&start).cycles;
            written.map_err(|e| format!("bytes={bytes}: {e}"))?;
            if i >= WARMUP
            {
                samples.push(cycles);
            }
        }
        let idle_halts = idle.close();
        report(
            "console_write",
            &[("bytes", Value::Num(bytes as u64))],
            cpus,
            &mut samples,
            &[],
            idle_halts,
        )?;
    }
    Ok(())
}

/// Send `text` to the framebuffer driver `cap` as `FB_WRITE_BYTES` calls
/// of at most [`PAYLOAD_MAX`] bytes.
fn write(cap: u64, text: &[u8], ipc_buf: *mut u64) -> Result<(), String>
{
    for chunk in text.chunks(PAYLOAD_MAX)
    {
        let msg = IpcMessage::builder(fb_labels::FB_WRITE_BYTES | ((chunk.len() as u64) << 16))
            .bytes(0, chunk)
            .build();
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
            .map_err(|e| format!("FB_WRITE_BYTES call failed: error {e}"))?;
        if reply.label != fb_errors::SUCCESS
        {
            return Err(format!("FB_WRITE_BYTES answered label={:#x}", reply.label));
        }
    }
    Ok(())
}
