// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/bench/mod.rs

//! Tier 3 — Benchmarks / profiling.
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
//! 1. Write a `fn bench_<name>(ctx: &crate::TestContext, iters: u32)` function below.
//! 2. Call it from `run_all`.
//! 3. Use `cycles_now()` to bracket the measured operation.
//! 4. Log results with `crate::log_u64` (no heap required).

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_signal, cap_create_thread,
    cap_delete, event_post, event_queue_create, event_recv, signal_send, signal_wait,
    thread_configure, thread_exit, thread_start, wait_set_add, wait_set_remove, wait_set_wait,
};
use syscall_abi::SystemInfoType;

use crate::ChildStack;

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
fn cycles_now() -> u64
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
fn log_bench_header(name: &str, n: u32)
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

// ── Benchmarks ────────────────────────────────────────────────────────────────

/// Benchmark: null syscall round-trip (kernel entry + exit cost baseline).
fn bench_null_syscall(_ctx: &crate::TestContext, iters: u32)
{
    let n = u64::from(iters);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        let _ = syscall::system_info(SystemInfoType::KernelVersion as u64);
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    log_bench_header("null_syscall_roundtrip", iters);
    crate::log_u64("ktest: bench  cycles_min=", min);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);
    crate::log_u64("ktest: bench  cycles_max=", max);
}

// ── IPC round-trip benchmark ──────────────────────────────────────────────────

static mut BENCH_IPC_STACK: ChildStack = ChildStack::ZERO;

fn ipc_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let n = arg >> 32;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 1).ok();
        thread_exit()
    }
    let ipc_buf = buf_addr as *mut u64;
    let msg = IpcMessage::new(0);

    for _ in 0..n
    {
        // SAFETY: buf_addr was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_call(ep_slot, &msg, ipc_buf) }.is_err()
        {
            break;
        }
    }
    signal_send(done_slot, 1).ok();
    thread_exit()
}

fn bench_ipc_round_trip(ctx: &crate::TestContext, iters: u32)
{
    const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);
    let n = u64::from(iters);

    let Ok(ep) = cap_create_endpoint(ctx.memory_frame_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };

    let Ok(cs) = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
    else
    {
        return;
    };
    let Ok(child_ep) = cap_copy(ep, cs, RIGHTS_SEND_GRANT)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, cs, 1 << 7)
    else
    {
        return;
    };

    let arg = u64::from(child_ep) | (u64::from(child_done) << 16) | (n << 32);
    let Ok(th) = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
    else
    {
        return;
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_IPC_STACK));

    if thread_configure(th, ipc_caller_entry as *const () as u64, stack_top, arg).is_err()
        || thread_start(th).is_err()
    {
        return;
    }

    let reply = IpcMessage::new(0);
    let t0 = cycles_now();
    for _ in 0..n
    {
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }.is_err()
        {
            break;
        }
    }
    let t1 = cycles_now();

    signal_wait(done).ok();

    let total = t1.saturating_sub(t0);
    log_bench_header("ipc_round_trip_wrapped", iters);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);

    cap_delete(th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(cs).ok();
}

// ── Signal round-trip benchmark ───────────────────────────────────────────────

static mut BENCH_SIGNAL_STACK: ChildStack = ChildStack::ZERO;

fn signal_pong_entry(arg: u64) -> !
{
    let in_slot = (arg & 0xFFFF) as u32;
    let out_slot = ((arg >> 16) & 0xFFFF) as u32;
    let done_slot = ((arg >> 32) & 0xFFFF) as u32;
    let n = arg >> 48;

    for _ in 0..n
    {
        if signal_wait(in_slot).is_err()
        {
            break;
        }
        if signal_send(out_slot, 1).is_err()
        {
            break;
        }
    }
    signal_send(done_slot, 1).ok();
    thread_exit()
}

// similar_names: ping/pong are intentionally paired names for the two directions.
#[allow(clippy::similar_names)]
fn bench_signal_roundtrip(ctx: &crate::TestContext, iters: u32)
{
    const RIGHTS_SIGNAL: u64 = 1 << 7;
    const RIGHTS_WAIT: u64 = 1 << 8;
    let n = u64::from(iters);

    let Ok(ping) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };
    let Ok(pong) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };

    let Ok(cs) = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
    else
    {
        return;
    };
    let Ok(child_ping) = cap_copy(ping, cs, RIGHTS_WAIT)
    else
    {
        return;
    };
    let Ok(child_pong) = cap_copy(pong, cs, RIGHTS_SIGNAL)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, cs, RIGHTS_SIGNAL)
    else
    {
        return;
    };

    let arg = u64::from(child_ping)
        | (u64::from(child_pong) << 16)
        | (u64::from(child_done) << 32)
        | (n << 48);
    let Ok(th) = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
    else
    {
        return;
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_SIGNAL_STACK));

    if thread_configure(th, signal_pong_entry as *const () as u64, stack_top, arg).is_err()
        || thread_start(th).is_err()
    {
        return;
    }

    let t0 = cycles_now();
    for _ in 0..n
    {
        if signal_send(ping, 1).is_err()
        {
            break;
        }
        if signal_wait(pong).is_err()
        {
            break;
        }
    }
    let t1 = cycles_now();

    let total = t1.saturating_sub(t0);
    signal_wait(done).ok();

    log_bench_header("signal_roundtrip", iters);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);

    cap_delete(th).ok();
    cap_delete(ping).ok();
    cap_delete(pong).ok();
    cap_delete(done).ok();
    cap_delete(cs).ok();
}

// ── New benchmarks ───────────────────────────────────────────────────────────

/// Benchmark: cap create + delete cycle.
fn bench_cap_create_delete(ctx: &crate::TestContext, iters: u32)
{
    let n = u64::from(iters);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        let Ok(sig) = cap_create_signal(ctx.memory_frame_base)
        else
        {
            break;
        };
        cap_delete(sig).ok();
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    log_bench_header("cap_create_delete", iters);
    crate::log_u64("ktest: bench  cycles_min=", min);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);
    crate::log_u64("ktest: bench  cycles_max=", max);
}

/// Benchmark: memory map + unmap cycle.
fn bench_mem_map_unmap(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x6000_0000;

    let n = u64::from(iters);
    let Some(frame) = crate::frame_pool::alloc()
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        if syscall::mem_map(frame, ctx.aspace_cap, BENCH_VA, 0, 1, syscall::MAP_WRITABLE).is_err()
        {
            break;
        }
        let _ = syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1);
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    // SAFETY: frame is from pool and now unmapped.
    unsafe { crate::frame_pool::free(frame) };

    log_bench_header("mem_map_unmap", iters);
    crate::log_u64("ktest: bench  cycles_min=", min);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);
    crate::log_u64("ktest: bench  cycles_max=", max);
}

/// Benchmark: thread create + start + exit + cleanup lifecycle.
static mut BENCH_LIFECYCLE_STACK: ChildStack = ChildStack::ZERO;

fn lifecycle_entry(done_slot: u64) -> !
{
    // cast_possible_truncation: done_slot is a kernel cap slot index < 2^32.
    #[allow(clippy::cast_possible_truncation)]
    signal_send(done_slot as u32, 0x1).ok();
    thread_exit()
}

fn bench_thread_lifecycle(ctx: &crate::TestContext, iters: u32)
{
    // Use fewer iterations for this heavier benchmark.
    let n = iters.min(100);
    let n64 = u64::from(n);

    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_LIFECYCLE_STACK));

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();

        let Ok(cs) = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        else
        {
            break;
        };
        let Ok(child_done) = cap_copy(done, cs, 1 << 7)
        else
        {
            break;
        };
        let Ok(th) = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        else
        {
            break;
        };
        if thread_configure(
            th,
            lifecycle_entry as *const () as u64,
            stack_top,
            u64::from(child_done),
        )
        .is_err()
            || thread_start(th).is_err()
        {
            break;
        }
        signal_wait(done).ok();
        cap_delete(th).ok();
        cap_delete(cs).ok();

        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    cap_delete(done).ok();

    log_bench_header("thread_lifecycle", n);
    crate::log_u64("ktest: bench  cycles_min=", min);
    crate::log_u64("ktest: bench  cycles_mean=", total / n64);
    crate::log_u64("ktest: bench  cycles_max=", max);
}

/// Benchmark: event queue post + recv cycle.
fn bench_event_post_recv(ctx: &crate::TestContext, iters: u32)
{
    let n = u64::from(iters);

    let Ok(eq) = event_queue_create(ctx.memory_frame_base, 4)
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for i in 0..n
    {
        let t0 = cycles_now();
        if event_post(eq, i).is_err()
        {
            break;
        }
        if event_recv(eq).is_err()
        {
            break;
        }
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    cap_delete(eq).ok();

    log_bench_header("event_post_recv", iters);
    crate::log_u64("ktest: bench  cycles_min=", min);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);
    crate::log_u64("ktest: bench  cycles_max=", max);
}

/// Benchmark: wait set create + add + wait + remove + delete cycle.
fn bench_wait_set(ctx: &crate::TestContext, iters: u32)
{
    // Cap this benchmark at 100 iterations; wait set create/delete involves
    // heap allocations that fragment under high churn.
    let n = u64::from(iters.min(100));

    let Ok(sig) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        // Pre-arm the signal so wait_set_wait returns immediately.
        signal_send(sig, 0x1).ok();

        let t0 = cycles_now();
        let Ok(ws) = cap_create_wait_set(ctx.memory_frame_base)
        else
        {
            break;
        };
        if wait_set_add(ws, sig, 42).is_err()
        {
            cap_delete(ws).ok();
            break;
        }
        let _ = wait_set_wait(ws);
        let _ = wait_set_remove(ws, sig);
        cap_delete(ws).ok();
        let t1 = cycles_now();

        // Drain bits left by signal_send.
        signal_wait(sig).ok();

        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
    }

    cap_delete(sig).ok();

    // cast_possible_truncation: n is capped at 100; fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let actual_n = n as u32;
    log_bench_header("wait_set_cycle", actual_n);
    crate::log_u64("ktest: bench  cycles_min=", min);
    crate::log_u64("ktest: bench  cycles_mean=", total / n);
    crate::log_u64("ktest: bench  cycles_max=", max);
}

// Thin wrapper — same as in unit/cap.rs.
fn cap_create_wait_set(frame_cap: u32) -> Result<u32, i64>
{
    syscall::wait_set_create(frame_cap)
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run all Tier 3 benchmarks.
///
/// Called from `main.rs` after other tiers complete. Results are logged
/// directly via `log`/`log_u64`; no PASS/FAIL counters are updated.
pub fn run_all(ctx: &crate::TestContext, iters: u32)
{
    bench_null_syscall(ctx, iters);
    bench_ipc_round_trip(ctx, iters);
    bench_signal_roundtrip(ctx, iters);
    bench_cap_create_delete(ctx, iters);
    bench_mem_map_unmap(ctx, iters);
    bench_thread_lifecycle(ctx, iters);
    bench_event_post_recv(ctx, iters);
    bench_wait_set(ctx, iters);
}
