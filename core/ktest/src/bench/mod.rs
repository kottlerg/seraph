// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/bench/mod.rs

//! Tier 3 — Benchmarks / profiling.
//!
//! Rule (durable, mirrors `unit/mod.rs`):
//!
//! > **One file per kernel surface measured. New surface ⇒ new file.**
//!
//! Each benchmark runs an operation N times and logs min/mean/max cycle counts
//! to the kernel serial console. No PASS/FAIL verdict is produced; the numbers
//! are for human inspection and regression tracking.
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
//! 1. If the surface already has a file (e.g. `mm.rs`), add a `fn bench_<name>`
//!    to that file. Otherwise create a sibling file under `bench/`.
//! 2. Use `super::cycles_now()` to bracket the measured operation
//!    per-iteration; track min/mean/max via `super::log_bench_header()`.
//! 3. Call it from `run_all` below.

mod cap;
mod event;
mod ipc;
mod mm;
mod null;
mod signal;
mod thread;
mod tlb;
mod wait_set;

// ── Cycle counter ─────────────────────────────────────────────────────────────

/// Read the hardware cycle counter.
///
/// On x86-64, uses `rdtsc`. On RISC-V, uses `csrr cycle`.
/// On RISC-V, requires the kernel to have set `scounteren.CY = 1`.
///
/// Returns raw cycle counts. Units differ by architecture; use deltas only.
// inline_always: RDTSC must be inlined to avoid call overhead in cycle benchmarks.
#[allow(clippy::inline_always)]
#[inline(always)]
pub(super) fn cycles_now() -> u64
{
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: rdtsc is a user-mode instruction when CR4.TSD = 0 (the
        // kernel does not set TSD). preserves_flags: rdtsc does not modify
        // RFLAGS, only EAX/EDX.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem, preserves_flags),
            );
        }
        u64::from(hi) << 32 | u64::from(lo)
    }
    #[cfg(target_arch = "riscv64")]
    {
        let c: u64;
        // SAFETY: cycle CSR is accessible from U-mode when scounteren.CY = 1,
        // which the kernel sets during Phase 5 init.
        unsafe {
            core::arch::asm!(
                "csrr {}, cycle",
                out(reg) c,
                options(nostack, nomem),
            );
        }
        c
    }
}

/// Log benchmark results with configurable N.
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
            #[allow(clippy::cast_possible_truncation)]
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
    signal::bench_signal_roundtrip(ctx, iters);
    cap::bench_cap_create_delete(ctx, iters);
    mm::bench_mem_map_unmap(ctx, iters);
    mm::bench_mem_protect(ctx, iters);
    thread::bench_thread_lifecycle(ctx, iters);
    thread::bench_context_switch(ctx, iters);
    event::bench_event_post_recv(ctx, iters);
    wait_set::bench_wait_set(ctx, iters);
    tlb::bench_tlb_shootdown(ctx, iters);
}
