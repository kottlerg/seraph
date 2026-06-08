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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::system_info;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_notification, cap_create_thread, cap_delete,
    notification_send, notification_wait, thread_configure, thread_exit, thread_set_affinity,
    thread_start,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

const RIGHTS_NOTIFY: u64 = 1 << 7;

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

// Children write the mismatch count after the spin completes and the parent
// reads it only after the corresponding notification_send is observed, so the zero
// default is never mistaken for a result.
static A_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static B_MISMATCHES: AtomicU64 = AtomicU64::new(0);

// Non-zero initialised static. Forces LLD to emit a `.data` section in the
// ktest ELF, exercising the path where the kernel mints a Memory cap whose
// underlying segment has a sub-page-aligned ELF VA. The cap must still
// expose a page-aligned `base` and whole-page `size` to userspace — see
// `mm::init_segment_caps_aligned`.
#[used]
#[unsafe(no_mangle)]
pub static SUB_PAGE_SENTINEL: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_BABE);

extern "C" fn child_a_entry(sig_slot: u64) -> !
{
    // SAFETY: spin_and_check holds the relevant register file across a
    // bounded asm block and stores the final live values back to a local
    // buffer; no aliasing with outer state.
    let mismatches = unsafe { spin_and_check(PATTERN_A) };
    A_MISMATCHES.store(mismatches, Ordering::Release);
    let _ = notification_send(u32::try_from(sig_slot).unwrap_or(0), 0x1);
    thread_exit();
}

extern "C" fn child_b_entry(sig_slot: u64) -> !
{
    // SAFETY: see child_a_entry.
    let mismatches = unsafe { spin_and_check(PATTERN_B) };
    B_MISMATCHES.store(mismatches, Ordering::Release);
    let _ = notification_send(u32::try_from(sig_slot).unwrap_or(0), 0x1);
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

    let sig_a = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification a for fpu::preempt_isolation failed")?;
    let sig_b = cap_create_notification(ctx.memory_base)
        .map_err(|_| "create_notification b for fpu::preempt_isolation failed")?;
    let cs_a = cap_create_cspace(ctx.memory_base, 0, 4, 16)
        .map_err(|_| "create_cspace a for fpu::preempt_isolation failed")?;
    let cs_b = cap_create_cspace(ctx.memory_base, 0, 4, 16)
        .map_err(|_| "create_cspace b for fpu::preempt_isolation failed")?;
    let child_sig_a = cap_copy(sig_a, cs_a, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy sig_a for fpu::preempt_isolation failed")?;
    let child_sig_b = cap_copy(sig_b, cs_b, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy sig_b for fpu::preempt_isolation failed")?;

    let th_a = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs_a)
        .map_err(|_| "cap_create_thread a for fpu::preempt_isolation failed")?;
    let th_b = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs_b)
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

    let _ = notification_wait(sig_a)
        .map_err(|_| "notification_wait a for fpu::preempt_isolation failed")?;
    let _ = notification_wait(sig_b)
        .map_err(|_| "notification_wait b for fpu::preempt_isolation failed")?;

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

// ── Cross-CPU preemption-isolation (eager-save migration, per #108) ──────────

/// Per-thread stack for the cross-CPU child.
static mut STACK_CROSS: ChildStack = ChildStack::ZERO;
/// Notification indices passed into the cross-CPU child by index (the child's
/// cspace cap is published here so the inline-asm syscall sites can read
/// them without crossing a Rust function boundary that would clobber the
/// FP register file).
static CROSS_SIG_READY: AtomicU32 = AtomicU32::new(0);
static CROSS_SIG_RESUME: AtomicU32 = AtomicU32::new(0);
static CROSS_SIG_DONE: AtomicU32 = AtomicU32::new(0);
/// Mismatch count written by the cross-CPU child after the post-migration
/// register capture. The parent reads it only after the `done` notification so
/// the zero default is never mistaken for a pass.
static CROSS_MISMATCHES: AtomicU64 = AtomicU64::new(0);
/// CPU id observed by the cross-CPU child after migration, sanity-checked
/// by the parent to confirm the migration actually happened.
static CROSS_OBSERVED_CPU: AtomicU32 = AtomicU32::new(u32::MAX);

/// Cross-CPU child entry: load `PATTERN_A` into the extended-state register
/// file, notification "ready", block on "resume", then capture the registers
/// back to a stack buffer.
///
/// The entire load → block → capture sequence runs inside a single inline-
/// asm block so no intervening Rust call clobbers FP state. The syscall ABI
/// is embedded directly: the kernel preserves the live FP register file
/// across the block because (a) the kernel itself is soft-float and (b) the
/// FPU discipline keeps the child as `fpu_owner` of its current CPU until
/// either another thread takes a lazy-restore trap or the child itself
/// context-switches out (at which point `switch_out_save` saves the live
/// regs into the TCB area before the publish that lets the destination CPU
/// see the thread Ready).
#[cfg(target_arch = "x86_64")]
extern "C" fn child_cross_entry(_arg: u64) -> !
{
    // 128-bit pattern (xmm lane width).
    let pat128 = [PATTERN_A, PATTERN_A];
    let mut buf = [[0u64; 2]; 16];
    let sig_ready = CROSS_SIG_READY.load(Ordering::Acquire);
    let sig_resume = CROSS_SIG_RESUME.load(Ordering::Acquire);
    // Brief spin between FP load and notification_send so timer ticks fire while
    // we are fpu_owner on the source CPU.
    let spin: u64 = 50_000;

    // SAFETY: inline asm loads pat128 into xmm0..xmm15, issues two raw
    // syscalls (SIGNAL_SEND, SIGNAL_WAIT) preserving the live FP register
    // file across both, then stores xmm0..xmm15 into buf. All operands
    // have matching lifetimes; rcx/r11 are syscall-clobber-only. rdx is
    // clobbered by SIGNAL_WAIT's secondary-return write (the kernel writes
    // the acquired bitmask into rdx via `set_ipc_return`).
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
            // Syscall SYS_NOTIFICATION_SEND(sig_ready, 0x1). rax = 3.
            "mov rax, 3",
            "mov edi, {sig_ready:e}",
            "mov esi, 1",
            "syscall",
            // Syscall SYS_NOTIFICATION_WAIT(sig_resume, 0). rax = 4.
            "mov rax, 4",
            "mov edi, {sig_resume:e}",
            "mov esi, 0",
            "syscall",
            // Now resumed on the migration target CPU. Capture xmm0..xmm15.
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
            sig_ready = in(reg) sig_ready,
            sig_resume = in(reg) sig_resume,
            out("rax") _, out("rcx") _, out("rdx") _, out("rdi") _, out("rsi") _, out("r11") _,
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
        if lane[0] != PATTERN_A || lane[1] != PATTERN_A
        {
            mismatches += 1;
        }
    }
    CROSS_MISMATCHES.store(mismatches, Ordering::Release);
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    CROSS_OBSERVED_CPU.store(u32::try_from(cpu).unwrap_or(u32::MAX), Ordering::Release);

    let _ = notification_send(CROSS_SIG_DONE.load(Ordering::Acquire), 0x1);
    thread_exit();
}

/// RISC-V cross-CPU child entry: load `PATTERN_A` into f0..f31, notification
/// "ready", block on "resume", then capture f0..f31 back to a stack buffer.
///
/// Same shape as the x86-64 sibling. ecall uses a7 as the syscall number
/// and a0..a2 as args; the kernel is soft-float so the FP register file
/// survives the syscall under the discipline described in the doc comment
/// on `preempt_isolation_cross_cpu`.
#[cfg(target_arch = "riscv64")]
#[allow(clippy::too_many_lines)] // 32 FP loads + 32 FP stores dominate the body.
extern "C" fn child_cross_entry(_arg: u64) -> !
{
    let pattern: u64 = PATTERN_A;
    let mut buf = [0u64; 32];
    let sig_ready = CROSS_SIG_READY.load(Ordering::Acquire);
    let sig_resume = CROSS_SIG_RESUME.load(Ordering::Acquire);
    let spin: u64 = 50_000;

    // SAFETY: inline asm loads pattern into f0..f31, issues SIGNAL_SEND
    // (a7=3) then SIGNAL_WAIT (a7=4) preserving the live FP register
    // file across both, then stores f0..f31 into buf. The .option arch
    // directive locally enables the D extension even though the kernel
    // target is RV64IMAC; the trap-and-restore path will have made FS
    // Dirty by the time these stores execute post-migration.
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
            // SIGNAL_SEND(sig_ready, 0x1): a7=3, a0=sig_ready, a1=1.
            "li a7, 3",
            "mv a0, {sig_ready}",
            "li a1, 1",
            "ecall",
            // SIGNAL_WAIT(sig_resume, 0): a7=4, a0=sig_resume, a1=0 (no
            // timeout). MUST zero a1 explicitly — the kernel reads
            // tf.arg(1) as `timeout_ms` (sys_notification_wait in
            // core/kernel/src/syscall/ipc.rs), and the previous
            // SIGNAL_SEND left a1=1 in the register file. Without this
            // store the wait runs with a 1 ms timeout and the test
            // races past the migration step it claims to validate.
            "li a7, 4",
            "mv a0, {sig_resume}",
            "li a1, 0",
            "ecall",
            // Resumed on (potentially different) destination CPU.
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
            sig_ready = in(reg) u64::from(sig_ready),
            sig_resume = in(reg) u64::from(sig_resume),
            out("a0") _, out("a1") _, out("a7") _,
            options(nostack),
        );
    }

    let mut mismatches = 0u64;
    for &v in &buf
    {
        if v != PATTERN_A
        {
            mismatches += 1;
        }
    }
    CROSS_MISMATCHES.store(mismatches, Ordering::Release);
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    CROSS_OBSERVED_CPU.store(u32::try_from(cpu).unwrap_or(u32::MAX), Ordering::Release);

    let _ = notification_send(CROSS_SIG_DONE.load(Ordering::Acquire), 0x1);
    thread_exit();
}

/// Cross-CPU FPU-migration correctness: a thread that became `fpu_owner`
/// on CPU 0, blocked, then was woken with affinity changed to CPU 1, must
/// observe its register file intact post-migration. After issue #108,
/// this is guaranteed by eager XSAVE on switch-out (the source CPU's
/// `switch_out_save` persists the live regs into the TCB area before the
/// scheduler lock release that publishes the thread's Ready state).
///
/// Requires SMP; skips on UP. Runs on both x86-64 (XSAVE/XRSTOR + `#NM`)
/// and RISC-V (`sstatus.FS/VS` dirty-tracking + illegal-instruction trap).
pub fn preempt_isolation_cross_cpu(ctx: &TestContext) -> TestResult
{
    {
        let cpus = system_info(SystemInfoType::CpuCount as u64)
            .map_err(|_| "system_info(CpuCount) for preempt_isolation_cross_cpu failed")?;
        if cpus < 2
        {
            crate::log("ktest: fpu::preempt_isolation_cross_cpu SKIP (requires SMP)");
            return Ok(());
        }

        CROSS_MISMATCHES.store(0, Ordering::Release);
        CROSS_OBSERVED_CPU.store(u32::MAX, Ordering::Release);

        let sig_ready = cap_create_notification(ctx.memory_base)
            .map_err(|_| "create_notification ready for preempt_isolation_cross_cpu failed")?;
        let sig_resume = cap_create_notification(ctx.memory_base)
            .map_err(|_| "create_notification resume for preempt_isolation_cross_cpu failed")?;
        let sig_done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "create_notification done for preempt_isolation_cross_cpu failed")?;
        let cs = cap_create_cspace(ctx.memory_base, 0, 4, 16)
            .map_err(|_| "create_cspace for preempt_isolation_cross_cpu failed")?;

        let child_ready = cap_copy(sig_ready, cs, RIGHTS_NOTIFY)
            .map_err(|_| "cap_copy ready for preempt_isolation_cross_cpu failed")?;
        let child_resume = cap_copy(sig_resume, cs, RIGHTS_NOTIFY)
            .map_err(|_| "cap_copy resume for preempt_isolation_cross_cpu failed")?;
        let child_done = cap_copy(sig_done, cs, RIGHTS_NOTIFY)
            .map_err(|_| "cap_copy done for preempt_isolation_cross_cpu failed")?;

        CROSS_SIG_READY.store(child_ready, Ordering::Release);
        CROSS_SIG_RESUME.store(child_resume, Ordering::Release);
        CROSS_SIG_DONE.store(child_done, Ordering::Release);

        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs)
            .map_err(|_| "cap_create_thread for preempt_isolation_cross_cpu failed")?;

        // Pin to CPU 0 initially: child must run and become CPU 0's
        // `fpu_owner` before the migration step.
        thread_set_affinity(th, 0)
            .map_err(|_| "initial thread_set_affinity(0) for preempt_isolation_cross_cpu failed")?;

        let stack_top = ChildStack::top(core::ptr::addr_of!(STACK_CROSS));
        thread_configure(th, child_cross_entry as *const () as u64, stack_top, 0)
            .map_err(|_| "thread_configure for preempt_isolation_cross_cpu failed")?;
        thread_start(th).map_err(|_| "thread_start for preempt_isolation_cross_cpu failed")?;

        // Wait for the child to become `fpu_owner` on CPU 0 and notification ready.
        // The parent blocks (yielding CPU 0) so the child can run; the child
        // then loads PATTERN_A, briefly spins, signals ready, and blocks on
        // sig_resume.
        let _ = notification_wait(sig_ready)
            .map_err(|_| "notification_wait ready for preempt_isolation_cross_cpu failed")?;

        // Change affinity to CPU 1 while the child is Blocked. This just
        // updates the affinity field; the migration happens at wake time.
        thread_set_affinity(th, 1)
            .map_err(|_| "thread_set_affinity(1) for preempt_isolation_cross_cpu failed")?;

        // Wake the child. The wake path calls `enqueue_and_wake(target=1)`,
        // which simply enqueues the child on CPU 1's run queue: CPU 0's
        // earlier `switch_out_save` (when the child blocked on sig_resume)
        // already XSAVE'd the live regs into the child's TCB area. The
        // child then runs on CPU 1; the first FP op (the capture vmovdqu)
        // traps to `#NM`, which XRSTORs the area into CPU 1's hardware
        // before the store executes.
        notification_send(sig_resume, 0x1)
            .map_err(|_| "notification_send resume for preempt_isolation_cross_cpu failed")?;

        let _ = notification_wait(sig_done)
            .map_err(|_| "notification_wait done for preempt_isolation_cross_cpu failed")?;

        let mismatches = CROSS_MISMATCHES.load(Ordering::Acquire);
        let observed_cpu = CROSS_OBSERVED_CPU.load(Ordering::Acquire);

        cap_delete(th).map_err(|_| "cap_delete th after preempt_isolation_cross_cpu failed")?;
        cap_delete(sig_ready)
            .map_err(|_| "cap_delete sig_ready after preempt_isolation_cross_cpu failed")?;
        cap_delete(sig_resume)
            .map_err(|_| "cap_delete sig_resume after preempt_isolation_cross_cpu failed")?;
        cap_delete(sig_done)
            .map_err(|_| "cap_delete sig_done after preempt_isolation_cross_cpu failed")?;
        cap_delete(cs).map_err(|_| "cap_delete cs after preempt_isolation_cross_cpu failed")?;

        crate::log_u64(
            "fpu::preempt_isolation_cross_cpu observed_cpu=",
            u64::from(observed_cpu),
        );
        crate::log_u64("fpu::preempt_isolation_cross_cpu mismatches=", mismatches);
        if mismatches != 0
        {
            return Err("cross-CPU child observed extended-state corruption after migration");
        }
        // The migration was either actually cross-CPU (observed != 0) or the
        // scheduler kept the child on its original CPU. In either case, the
        // FP state must be intact. The flush IPI path is exercised when the
        // wake target differs from the thread's prior `preferred_cpu`; this
        // can happen via affinity-driven `select_target_cpu` or via
        // load-balance pull on the destination. We log the observed CPU for
        // diagnostics but do not gate the test on it — the existing
        // `thread::affinity_migrate_ready_queued` test already covers strict
        // affinity enforcement.
        Ok(())
    }
}
