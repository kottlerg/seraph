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
    crate::log_args(format_args!("ktest: bench  {name}  N={n}"));
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
    cap::bench_cap_info_lookup(ctx, iters);
    mm::bench_mem_map_unmap(ctx, iters);
    mm::bench_mem_protect(ctx, iters);
    thread::bench_thread_lifecycle(ctx, iters);
    thread::bench_context_switch(ctx, iters);
    event::bench_event_post_recv(ctx, iters);
    wait_set::bench_wait_set(ctx, iters);
    tlb::bench_tlb_shootdown(ctx, iters);
    tlb::bench_tlb_shootdown_concurrent(ctx, iters);
}
