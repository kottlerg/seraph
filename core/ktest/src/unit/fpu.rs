// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/fpu.rs

//! Tier 1 test for extended-state (FPU / SIMD / V) isolation across
//! preemption.
//!
//! Two children are pinned to CPU 0 so the scheduler must time-slice them
//! against each other on a single hart. Each loads a distinct bit pattern
//! into every architecturally addressable FP register (and on RISC-V every
//! V register), spins long enough to be preempted many times by the timer,
//! and finally captures the live register file into memory. The parent
//! verifies both captures match the pattern the child wrote. Any
//! cross-thread bleed surfaces as a mismatch and fails the test.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, thread_configure, thread_exit, thread_set_affinity, thread_start,
};

use crate::{ChildStack, TestContext, TestResult};

const RIGHTS_SIGNAL: u64 = 1 << 7;

/// Spin-loop length in the inline-asm hot path. Sized to give the timer
/// many opportunities to preempt at the default tick rate while finishing
/// the test in well under a second of wall time on QEMU TCG.
const SPIN_ITERS: u64 = 200_000;

/// Distinct lane pattern per child. Bytes chosen so a byte-granular swap
/// between the two patterns is unambiguous.
const PATTERN_A: u64 = 0xA5A5_A5A5_A5A5_A5A5;
const PATTERN_B: u64 = 0x5A5A_5A5A_5A5A_5A5A;

static mut STACK_A: ChildStack = ChildStack::ZERO;
static mut STACK_B: ChildStack = ChildStack::ZERO;

// All statics zero-initialise. ktest's frame pool draws backing pages from
// the BSS segment, and any non-zero initialised static in this binary
// forces LLD to emit a separate `.data` section, which the current
// bootloader/kernel pipeline then surfaces as a sub-page-aligned segment
// Frame cap — breaking the pool's frame_split path. Children write the
// mismatch count after the spin completes and the parent reads it only
// after the corresponding signal_send is observed, so the zero default is
// never mistaken for a result.
static A_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static B_MISMATCHES: AtomicU64 = AtomicU64::new(0);

extern "C" fn child_a_entry(sig_slot: u64) -> !
{
    // SAFETY: spin_and_check holds the relevant register file across a
    // bounded asm block and stores the final live values back to a local
    // buffer; no aliasing with outer state.
    let mismatches = unsafe { spin_and_check(PATTERN_A) };
    A_MISMATCHES.store(mismatches, Ordering::Release);
    let _ = signal_send(u32::try_from(sig_slot).unwrap_or(0), 0x1);
    thread_exit();
}

extern "C" fn child_b_entry(sig_slot: u64) -> !
{
    // SAFETY: see child_a_entry.
    let mismatches = unsafe { spin_and_check(PATTERN_B) };
    B_MISMATCHES.store(mismatches, Ordering::Release);
    let _ = signal_send(u32::try_from(sig_slot).unwrap_or(0), 0x1);
    thread_exit();
}

#[cfg(target_arch = "x86_64")]
unsafe fn spin_and_check(pattern: u64) -> u64
{
    // 128-bit pattern (the lane width of xmm).
    let pat128 = [pattern, pattern];
    let mut buf = [[0u64; 2]; 16];
    let iters: u64 = SPIN_ITERS;
    // SAFETY: inline asm loads pat128 (16 bytes, aligned), spins, then
    // stores xmm0..xmm15 into buf (256 bytes, aligned). All operands have
    // matching lifetimes; pause has no side effects.
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
            it = inout(reg) iters => _,
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
        if lane[0] != pattern || lane[1] != pattern
        {
            mismatches += 1;
        }
    }
    mismatches
}

#[cfg(target_arch = "riscv64")]
#[allow(clippy::too_many_lines)]
unsafe fn spin_and_check(pattern: u64) -> u64
{
    // 32 × f64 + 32 × v[lane0] = 64 lanes worth of state to verify.
    let mut fbuf = [0u64; 32];
    let mut vbuf = [0u64; 32];
    let iters: u64 = SPIN_ITERS;
    // SAFETY: inline asm loads pattern into f0..f31 then sets VL=1,e64,m1
    // and broadcasts pattern into v0..v31 via vmv.v.x, spins to invite
    // preemption, then stores each register back to its slot in fbuf/vbuf.
    // .option arch directives locally enable D and V even though the
    // kernel target is RV64IMAC; these instructions only execute when
    // sstatus.FS/VS != Off, which the U-mode lazy-trap path guarantees on
    // first touch.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d, +v",
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
            "li {tmp}, 1",
            "vsetvli zero, {tmp}, e64, m1, ta, ma",
            "vmv.v.x v0,  {p}",
            "vmv.v.x v1,  {p}",
            "vmv.v.x v2,  {p}",
            "vmv.v.x v3,  {p}",
            "vmv.v.x v4,  {p}",
            "vmv.v.x v5,  {p}",
            "vmv.v.x v6,  {p}",
            "vmv.v.x v7,  {p}",
            "vmv.v.x v8,  {p}",
            "vmv.v.x v9,  {p}",
            "vmv.v.x v10, {p}",
            "vmv.v.x v11, {p}",
            "vmv.v.x v12, {p}",
            "vmv.v.x v13, {p}",
            "vmv.v.x v14, {p}",
            "vmv.v.x v15, {p}",
            "vmv.v.x v16, {p}",
            "vmv.v.x v17, {p}",
            "vmv.v.x v18, {p}",
            "vmv.v.x v19, {p}",
            "vmv.v.x v20, {p}",
            "vmv.v.x v21, {p}",
            "vmv.v.x v22, {p}",
            "vmv.v.x v23, {p}",
            "vmv.v.x v24, {p}",
            "vmv.v.x v25, {p}",
            "vmv.v.x v26, {p}",
            "vmv.v.x v27, {p}",
            "vmv.v.x v28, {p}",
            "vmv.v.x v29, {p}",
            "vmv.v.x v30, {p}",
            "vmv.v.x v31, {p}",
            "2:",
            "addi {it}, {it}, -1",
            "bnez {it}, 2b",
            "fsd f0,    0({fb})",
            "fsd f1,    8({fb})",
            "fsd f2,   16({fb})",
            "fsd f3,   24({fb})",
            "fsd f4,   32({fb})",
            "fsd f5,   40({fb})",
            "fsd f6,   48({fb})",
            "fsd f7,   56({fb})",
            "fsd f8,   64({fb})",
            "fsd f9,   72({fb})",
            "fsd f10,  80({fb})",
            "fsd f11,  88({fb})",
            "fsd f12,  96({fb})",
            "fsd f13, 104({fb})",
            "fsd f14, 112({fb})",
            "fsd f15, 120({fb})",
            "fsd f16, 128({fb})",
            "fsd f17, 136({fb})",
            "fsd f18, 144({fb})",
            "fsd f19, 152({fb})",
            "fsd f20, 160({fb})",
            "fsd f21, 168({fb})",
            "fsd f22, 176({fb})",
            "fsd f23, 184({fb})",
            "fsd f24, 192({fb})",
            "fsd f25, 200({fb})",
            "fsd f26, 208({fb})",
            "fsd f27, 216({fb})",
            "fsd f28, 224({fb})",
            "fsd f29, 232({fb})",
            "fsd f30, 240({fb})",
            "fsd f31, 248({fb})",
            "mv {tmp}, {vb}",
            "vse64.v v0,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v1,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v2,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v3,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v4,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v5,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v6,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v7,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v8,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v9,  ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v10, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v11, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v12, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v13, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v14, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v15, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v16, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v17, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v18, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v19, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v20, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v21, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v22, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v23, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v24, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v25, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v26, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v27, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v28, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v29, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v30, ({tmp})",
            "addi {tmp}, {tmp}, 8",
            "vse64.v v31, ({tmp})",
            ".option pop",
            p = in(reg) pattern,
            fb = in(reg) fbuf.as_mut_ptr(),
            vb = in(reg) vbuf.as_mut_ptr(),
            tmp = out(reg) _,
            it = inout(reg) iters => _,
            options(nostack),
        );
    }
    let mut mismatches = 0u64;
    for &v in &fbuf
    {
        if v != pattern
        {
            mismatches += 1;
        }
    }
    for &v in &vbuf
    {
        if v != pattern
        {
            mismatches += 1;
        }
    }
    mismatches
}

/// Two threads pinned to CPU 0 each load a distinct pattern into every
/// architecturally addressable extended-state register, spin long enough
/// to be preempted many times, and capture the live registers afterward.
/// Both captures must equal the child's own pattern — any mismatch
/// indicates the lazy save/restore path leaked state across the context
/// switch.
pub fn preempt_isolation(ctx: &TestContext) -> TestResult
{
    A_MISMATCHES.store(0, Ordering::Release);
    B_MISMATCHES.store(0, Ordering::Release);

    let sig_a = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal a for fpu::preempt_isolation failed")?;
    let sig_b = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "create_signal b for fpu::preempt_isolation failed")?;
    let cs_a = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "create_cspace a for fpu::preempt_isolation failed")?;
    let cs_b = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "create_cspace b for fpu::preempt_isolation failed")?;
    let child_sig_a = cap_copy(sig_a, cs_a, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy sig_a for fpu::preempt_isolation failed")?;
    let child_sig_b = cap_copy(sig_b, cs_b, RIGHTS_SIGNAL)
        .map_err(|_| "cap_copy sig_b for fpu::preempt_isolation failed")?;

    let th_a = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs_a)
        .map_err(|_| "cap_create_thread a for fpu::preempt_isolation failed")?;
    let th_b = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs_b)
        .map_err(|_| "cap_create_thread b for fpu::preempt_isolation failed")?;

    let stack_a = ChildStack::top(core::ptr::addr_of!(STACK_A));
    let stack_b = ChildStack::top(core::ptr::addr_of!(STACK_B));

    thread_configure(
        th_a,
        child_a_entry as *const () as u64,
        stack_a,
        u64::from(child_sig_a),
    )
    .map_err(|_| "thread_configure a for fpu::preempt_isolation failed")?;
    thread_configure(
        th_b,
        child_b_entry as *const () as u64,
        stack_b,
        u64::from(child_sig_b),
    )
    .map_err(|_| "thread_configure b for fpu::preempt_isolation failed")?;

    // Pin both children to CPU 0 to force time-sliced co-residency.
    thread_set_affinity(th_a, 0)
        .map_err(|_| "thread_set_affinity a for fpu::preempt_isolation failed")?;
    thread_set_affinity(th_b, 0)
        .map_err(|_| "thread_set_affinity b for fpu::preempt_isolation failed")?;

    thread_start(th_a).map_err(|_| "thread_start a for fpu::preempt_isolation failed")?;
    thread_start(th_b).map_err(|_| "thread_start b for fpu::preempt_isolation failed")?;

    let _ = signal_wait(sig_a).map_err(|_| "signal_wait a for fpu::preempt_isolation failed")?;
    let _ = signal_wait(sig_b).map_err(|_| "signal_wait b for fpu::preempt_isolation failed")?;

    let a_mis = A_MISMATCHES.load(Ordering::Acquire);
    let b_mis = B_MISMATCHES.load(Ordering::Acquire);

    cap_delete(th_a).map_err(|_| "cap_delete th_a after fpu::preempt_isolation failed")?;
    cap_delete(th_b).map_err(|_| "cap_delete th_b after fpu::preempt_isolation failed")?;
    cap_delete(sig_a).map_err(|_| "cap_delete sig_a after fpu::preempt_isolation failed")?;
    cap_delete(sig_b).map_err(|_| "cap_delete sig_b after fpu::preempt_isolation failed")?;
    cap_delete(cs_a).map_err(|_| "cap_delete cs_a after fpu::preempt_isolation failed")?;
    cap_delete(cs_b).map_err(|_| "cap_delete cs_b after fpu::preempt_isolation failed")?;

    if a_mis != 0
    {
        return Err("thread A observed extended-state corruption across preemption");
    }
    if b_mis != 0
    {
        return Err("thread B observed extended-state corruption across preemption");
    }
    Ok(())
}
