// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/mod.rs

//! Tier 3 — Benchmarks / profiling. The file layout and what each benchmark
//! reports are specified in `core/ktest/README.md` § Source Layout and
//! § Tier 3; benchmarks log through `crate::log` / `crate::log_u64`.
//!
//! # Cycle counter access
//!
//! Benchmarks read the hardware cycle counter directly — no syscall overhead
//! on the measurement path:
//!
//! - **x86-64**: `rdtsc` (accessible from U-mode by default; CR4.TSD is not
//!   set by the kernel).
//! - **RISC-V**: `csrr cycle` (accessible from U-mode after the kernel sets
//!   `scounteren.CY = 1` during Phase 5 init).
//!
//! # Adding a new benchmark
//!
//! 1. Add a `fn bench_<name>` to the surface's file under `bench/`, placed as
//!    the README's § Tier 3 layout rule says.
//! 2. Use `super::cycles_now()` to bracket the measured operation
//!    per-iteration and accumulate min/mean/max locally, then print the
//!    header with `super::log_bench_header()` and the three values with
//!    `crate::log_u64`.
//! 3. Call it from `run_all` below.

mod cap;
mod event;
mod ipc;
mod mm;
mod notification;
mod null;
mod thread;
mod tlb;
mod wait_set;

// ── Cycle counter ─────────────────────────────────────────────────────────────

/// Read the hardware cycle counter (`crate::arch::cycles_now`).
///
/// Returns raw cycle counts. Units differ by architecture; use deltas only.
// inline_always: the counter read must be inlined to avoid call overhead in cycle benchmarks.
#[allow(clippy::inline_always)]
#[inline(always)]
pub(super) fn cycles_now() -> u64
{
    crate::arch::cycles_now()
}

/// Log the benchmark header line `ktest: bench  <name>  N=<n>`.
pub(super) fn log_bench_header(name: &str, n: u32)
{
    // Build "ktest: bench  <name>  N=<n>" string.
    let mut buf = [0u8; 128];
    let prefix = b"ktest: bench  ";
    let plen = prefix.len().min(buf.len());
    buf[..plen].copy_from_slice(&prefix[..plen]);
    let mut pos = plen;

    let nb = name.as_bytes();
    let nlen = nb.len().min(buf.len() - pos);
    buf[pos..pos + nlen].copy_from_slice(&nb[..nlen]);
    pos += nlen;

    let sep = b"  N=";
    let slen = sep.len().min(buf.len() - pos);
    buf[pos..pos + slen].copy_from_slice(&sep[..slen]);
    pos += slen;

    // Write N as decimal.
    let mut digits = [0u8; 10];
    let mut dlen = 0;
    let mut val = n;
    if val == 0
    {
        digits[0] = b'0';
        dlen = 1;
    }
    else
    {
        while val > 0
        {
            let d = (val % 10) as u8;
            digits[dlen] = b'0' + d;
            val /= 10;
            dlen += 1;
        }
        digits[..dlen].reverse();
    }
    let dlen_copy = dlen.min(buf.len() - pos);
    buf[pos..pos + dlen_copy].copy_from_slice(&digits[..dlen_copy]);
    pos += dlen_copy;

    if let Ok(s) = core::str::from_utf8(&buf[..pos])
    {
        crate::log(s);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run all Tier 3 benchmarks.
///
/// Called from `main.rs` after other tiers complete. Results are logged
/// directly via `log`/`log_u64`; no PASS/FAIL counters are updated.
pub fn run_all(ctx: &crate::TestContext, iters: u32)
{
    null::bench_null_syscall(ctx, iters);
    ipc::bench_ipc_round_trip(ctx, iters);
    notification::bench_notification_roundtrip(ctx, iters);
    cap::bench_cap_create_delete(ctx, iters);
    mm::bench_mem_map_unmap(ctx, iters);
    mm::bench_mem_protect(ctx, iters);
    thread::bench_thread_lifecycle(ctx, iters);
    thread::bench_context_switch(ctx, iters);
    event::bench_event_post_recv(ctx, iters);
    wait_set::bench_wait_set(ctx, iters);
    tlb::bench_tlb_shootdown(ctx, iters);
    tlb::bench_tlb_shootdown_concurrent(ctx, iters);
}
