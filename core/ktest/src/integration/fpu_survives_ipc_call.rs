// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fpu_survives_ipc_call.rs

//! Tier 2 integration: FPU register file survives a raw `SYS_IPC_CALL`
//! round-trip across CPU migration.
//!
//! Mirrors `unit/fpu.rs::preempt_isolation_cross_cpu` but substitutes the
//! signal rendezvous for an IPC call/reply. The child issues `SYS_IPC_CALL`
//! directly via inline asm so no Rust function boundary clobbers the live
//! FP register file between "load pattern" and "capture pattern
//! post-migration"; this is the only ktest call site that exercises the
//! `SYS_IPC_CALL` register ABI without going through `shared/ipc`'s
//! wrappers.
//!
//! Coverage: the kernel's eager-save / lazy-restore path is already
//! exercised by `unit/fpu.rs::preempt_isolation_cross_cpu` via the signal
//! rendezvous. This file adds the IPC-dispatch path — `sys_ipc_call`'s
//! endpoint-block branch into the scheduler, and `sys_ipc_reply`'s wake —
//! so a future IPC fast-path optimisation that skipped `switch_out_save`
//! would surface here. Requires SMP; skips on UP.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_signal, cap_delete, ipc_buffer_set, signal_send,
    signal_wait, system_info, thread_exit, thread_set_affinity,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// SEND | GRANT (bits 4 and 6) — the child needs SEND to issue `ipc_call`.
const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);
/// Signal right (bit 7) — covers both `signal_send` and `signal_wait`.
const RIGHTS_SIGNAL: u64 = 1 << 7;

/// 64-bit pattern loaded into every FP register before the call.
const PATTERN: u64 = 0xA5A5_A5A5_A5A5_A5A5;

/// Sentinel labels for the request/reply pair.
const REQ_LABEL: u64 = 0xCAFE;
const REPLY_LABEL: u64 = 0xBEEF;

/// Spin between FP load and `SYS_IPC_CALL` so timer ticks fire while the
/// child is `fpu_owner` on the source CPU. Same sizing rationale as the
/// cross-CPU signal test in `unit/fpu.rs`.
const SPIN_ITERS: u64 = 50_000;

static mut STACK: ChildStack = ChildStack::ZERO;

// Resources are published to the child via statics rather than the entry
// argument so the inline-asm block can load them without depending on any
// register the kernel-side entry-frame setup may not preserve. Matches the
// publishing scheme in `unit/fpu.rs::preempt_isolation_cross_cpu`.
static CHILD_EP: AtomicU32 = AtomicU32::new(0);
static CHILD_DONE: AtomicU32 = AtomicU32::new(0);
static MISMATCHES: AtomicU64 = AtomicU64::new(0);
static OBSERVED_CPU: AtomicU32 = AtomicU32::new(u32::MAX);

#[cfg(target_arch = "x86_64")]
fn child_entry(_arg: u64) -> !
{
    // Empty messages do not touch the IPC buffer, but the kernel rejects
    // any IPC syscall from a thread without a registered buffer. Register
    // before the FP-preserving block so any clobber here is irrelevant.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if ipc_buffer_set(buf_addr).is_err()
    {
        thread_exit();
    }

    let pat128 = [PATTERN, PATTERN];
    let mut buf = [[0u64; 2]; 16];
    let ep = CHILD_EP.load(Ordering::Acquire);
    let spin: u64 = SPIN_ITERS;

    // SAFETY: inline asm loads PATTERN into xmm0..xmm15, issues
    // SYS_IPC_CALL preserving the live FP register file across it, then
    // captures xmm0..xmm15 back to `buf`. Operand lifetimes match. rcx/r11
    // are syscall-architecturally-clobbered; rdx and r9 receive the
    // secondary/tertiary returns (reply_label, reply_word_count) from
    // `set_ipc_call_return` and are discarded. rdi/rsi/r10/r8 carry args.
    unsafe {
        core::arch::asm!(
            "vmovdqu xmm0,  [{p}]",
            "vmovdqu xmm1,  [{p}]",
            "vmovdqu xmm2,  [{p}]",
            "vmovdqu xmm3,  [{p}]",
            "vmovdqu xmm4,  [{p}]",
            "vmovdqu xmm5,  [{p}]",
            "vmovdqu xmm6,  [{p}]",
            "vmovdqu xmm7,  [{p}]",
            "vmovdqu xmm8,  [{p}]",
            "vmovdqu xmm9,  [{p}]",
            "vmovdqu xmm10, [{p}]",
            "vmovdqu xmm11, [{p}]",
            "vmovdqu xmm12, [{p}]",
            "vmovdqu xmm13, [{p}]",
            "vmovdqu xmm14, [{p}]",
            "vmovdqu xmm15, [{p}]",
            "2:",
            "pause",
            "dec {it}",
            "jnz 2b",
            // SYS_IPC_CALL(ep, REQ_LABEL, data=0, caps=0, packed=0).
            "xor rax, rax",
            "mov edi, {ep:e}",
            "mov rsi, {label}",
            "xor rdx, rdx",
            "xor r10, r10",
            "xor r8, r8",
            "syscall",
            // Resumed (possibly on CPU 1). The first FP op triggers #NM;
            // the handler XRSTORs the saved area into CPU 1's live regs
            // before the store retires.
            "vmovdqu [{b} + 0x000], xmm0",
            "vmovdqu [{b} + 0x010], xmm1",
            "vmovdqu [{b} + 0x020], xmm2",
            "vmovdqu [{b} + 0x030], xmm3",
            "vmovdqu [{b} + 0x040], xmm4",
            "vmovdqu [{b} + 0x050], xmm5",
            "vmovdqu [{b} + 0x060], xmm6",
            "vmovdqu [{b} + 0x070], xmm7",
            "vmovdqu [{b} + 0x080], xmm8",
            "vmovdqu [{b} + 0x090], xmm9",
            "vmovdqu [{b} + 0x0a0], xmm10",
            "vmovdqu [{b} + 0x0b0], xmm11",
            "vmovdqu [{b} + 0x0c0], xmm12",
            "vmovdqu [{b} + 0x0d0], xmm13",
            "vmovdqu [{b} + 0x0e0], xmm14",
            "vmovdqu [{b} + 0x0f0], xmm15",
            p = in(reg) pat128.as_ptr(),
            b = in(reg) buf.as_mut_ptr(),
            it = inout(reg) spin => _,
            ep = in(reg) ep,
            label = in(reg) REQ_LABEL,
            out("rax") _, out("rcx") _, out("rdx") _, out("rdi") _, out("rsi") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }

    let mut mismatches = 0u64;
    for lane in &buf
    {
        if lane[0] != PATTERN || lane[1] != PATTERN
        {
            mismatches += 1;
        }
    }
    MISMATCHES.store(mismatches, Ordering::Release);
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    OBSERVED_CPU.store(u32::try_from(cpu).unwrap_or(u32::MAX), Ordering::Release);

    let _ = signal_send(CHILD_DONE.load(Ordering::Acquire), 0x1);
    thread_exit();
}

#[cfg(target_arch = "riscv64")]
#[allow(clippy::too_many_lines)] // 32 FP loads + ecall + 32 FP stores dominate the body.
fn child_entry(_arg: u64) -> !
{
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if ipc_buffer_set(buf_addr).is_err()
    {
        thread_exit();
    }

    let pattern: u64 = PATTERN;
    let mut buf = [0u64; 32];
    let ep = CHILD_EP.load(Ordering::Acquire);
    let spin: u64 = SPIN_ITERS;

    // SAFETY: inline asm loads PATTERN into f0..f31, issues SYS_IPC_CALL
    // (a7=0, a0..a4 carry args) preserving the live FP register file
    // across it, then captures f0..f31 back to `buf`. `.option arch, +d`
    // locally enables the D extension because the kernel target is
    // RV64IMAC. a0/a1/a2 are written by the kernel as (ret, reply_label,
    // reply_word_count) via `set_ipc_call_return` and are discarded.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fmv.d.x f0,  {p}",
            "fmv.d.x f1,  {p}",
            "fmv.d.x f2,  {p}",
            "fmv.d.x f3,  {p}",
            "fmv.d.x f4,  {p}",
            "fmv.d.x f5,  {p}",
            "fmv.d.x f6,  {p}",
            "fmv.d.x f7,  {p}",
            "fmv.d.x f8,  {p}",
            "fmv.d.x f9,  {p}",
            "fmv.d.x f10, {p}",
            "fmv.d.x f11, {p}",
            "fmv.d.x f12, {p}",
            "fmv.d.x f13, {p}",
            "fmv.d.x f14, {p}",
            "fmv.d.x f15, {p}",
            "fmv.d.x f16, {p}",
            "fmv.d.x f17, {p}",
            "fmv.d.x f18, {p}",
            "fmv.d.x f19, {p}",
            "fmv.d.x f20, {p}",
            "fmv.d.x f21, {p}",
            "fmv.d.x f22, {p}",
            "fmv.d.x f23, {p}",
            "fmv.d.x f24, {p}",
            "fmv.d.x f25, {p}",
            "fmv.d.x f26, {p}",
            "fmv.d.x f27, {p}",
            "fmv.d.x f28, {p}",
            "fmv.d.x f29, {p}",
            "fmv.d.x f30, {p}",
            "fmv.d.x f31, {p}",
            "2:",
            "addi {it}, {it}, -1",
            "bnez {it}, 2b",
            // SYS_IPC_CALL(ep, REQ_LABEL, data=0, caps=0, packed=0).
            "li a7, 0",
            "mv a0, {ep}",
            "mv a1, {label}",
            "li a2, 0",
            "li a3, 0",
            "li a4, 0",
            "ecall",
            // Resumed (possibly on CPU 1). The first FP op triggers an
            // illegal-instruction trap (FS=Off); `lazy_restore_fp_v`
            // restores f0..f31 from the TCB save area before the store
            // retires.
            "fsd f0,    0({b})",
            "fsd f1,    8({b})",
            "fsd f2,   16({b})",
            "fsd f3,   24({b})",
            "fsd f4,   32({b})",
            "fsd f5,   40({b})",
            "fsd f6,   48({b})",
            "fsd f7,   56({b})",
            "fsd f8,   64({b})",
            "fsd f9,   72({b})",
            "fsd f10,  80({b})",
            "fsd f11,  88({b})",
            "fsd f12,  96({b})",
            "fsd f13, 104({b})",
            "fsd f14, 112({b})",
            "fsd f15, 120({b})",
            "fsd f16, 128({b})",
            "fsd f17, 136({b})",
            "fsd f18, 144({b})",
            "fsd f19, 152({b})",
            "fsd f20, 160({b})",
            "fsd f21, 168({b})",
            "fsd f22, 176({b})",
            "fsd f23, 184({b})",
            "fsd f24, 192({b})",
            "fsd f25, 200({b})",
            "fsd f26, 208({b})",
            "fsd f27, 216({b})",
            "fsd f28, 224({b})",
            "fsd f29, 232({b})",
            "fsd f30, 240({b})",
            "fsd f31, 248({b})",
            ".option pop",
            p = in(reg) pattern,
            b = in(reg) buf.as_mut_ptr(),
            it = inout(reg) spin => _,
            ep = in(reg) u64::from(ep),
            label = in(reg) REQ_LABEL,
            out("a0") _, out("a1") _, out("a2") _, out("a3") _, out("a4") _,
            out("a7") _,
            options(nostack),
        );
    }

    let mut mismatches = 0u64;
    for &v in &buf
    {
        if v != PATTERN
        {
            mismatches += 1;
        }
    }
    MISMATCHES.store(mismatches, Ordering::Release);
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    OBSERVED_CPU.store(u32::try_from(cpu).unwrap_or(u32::MAX), Ordering::Release);

    let _ = signal_send(CHILD_DONE.load(Ordering::Acquire), 0x1);
    thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "fpu_survives_ipc_call: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("integration::fpu_survives_ipc_call SKIP (requires SMP)");
        return Ok(());
    }

    MISMATCHES.store(0, Ordering::Release);
    OBSERVED_CPU.store(u32::MAX, Ordering::Release);

    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "fpu_survives_ipc_call: cap_create_endpoint failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "fpu_survives_ipc_call: cap_create_signal failed")?;

    let child =
        spawn::new_child(ctx).map_err(|_| "fpu_survives_ipc_call: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "fpu_survives_ipc_call: cap_copy ep failed")?;
    let child_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "fpu_survives_ipc_call: cap_copy done failed")?;

    CHILD_EP.store(child_ep, Ordering::Release);
    CHILD_DONE.store(child_done, Ordering::Release);

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK));
    // Pin to CPU 0 initially: the child must run there long enough to
    // become `fpu_owner` on CPU 0 before it blocks in SYS_IPC_CALL.
    spawn::configure_and_start_pinned(&child, child_entry, stack_top, 0, 0)
        .map_err(|_| "fpu_survives_ipc_call: configure_and_start_pinned failed")?;

    // Wait for the child's call. `ipc_recv` blocks the harness thread
    // (yielding CPU 0) so the child can run, load the pattern, and issue
    // SYS_IPC_CALL.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fpu_survives_ipc_call: ipc_recv failed")?;
    if msg.label != REQ_LABEL
    {
        return Err("fpu_survives_ipc_call: ipc_recv returned wrong label");
    }

    // Flip child affinity to CPU 1 while it's blocked in BlockedSendRecv
    // awaiting reply. Mirrors the affinity flip in
    // unit/fpu.rs::preempt_isolation_cross_cpu.
    thread_set_affinity(child.th, 1)
        .map_err(|_| "fpu_survives_ipc_call: thread_set_affinity(1) failed")?;

    // Reply. The kernel enqueues the child on CPU 1. CPU 0's
    // `switch_out_save` (when the child blocked at the call site) already
    // persisted the live FP regs into the child's TCB area; the lazy
    // restore on CPU 1's first FP op completes the migration.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(REPLY_LABEL), ctx.ipc_buf) }
        .map_err(|_| "fpu_survives_ipc_call: ipc_reply failed")?;

    let _ = signal_wait(done).map_err(|_| "fpu_survives_ipc_call: signal_wait done failed")?;

    let mismatches = MISMATCHES.load(Ordering::Acquire);
    let observed_cpu = OBSERVED_CPU.load(Ordering::Acquire);

    cap_delete(child.th).map_err(|_| "fpu_survives_ipc_call: cap_delete child.th failed")?;
    cap_delete(child.cs).map_err(|_| "fpu_survives_ipc_call: cap_delete child.cs failed")?;
    cap_delete(ep).map_err(|_| "fpu_survives_ipc_call: cap_delete ep failed")?;
    cap_delete(done).map_err(|_| "fpu_survives_ipc_call: cap_delete done failed")?;

    crate::log_u64(
        "integration::fpu_survives_ipc_call observed_cpu=",
        u64::from(observed_cpu),
    );
    crate::log_u64("integration::fpu_survives_ipc_call mismatches=", mismatches);
    if mismatches != 0
    {
        return Err("FP register file corrupted across SYS_IPC_CALL round-trip");
    }
    // Diagnostic only — do not gate on `observed_cpu`. The scheduler may
    // keep the child on its original CPU; the FP-state invariant must
    // hold either way. Same rationale as
    // unit/fpu.rs::preempt_isolation_cross_cpu.
    Ok(())
}
