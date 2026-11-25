// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/fpu.rs

//! RISC-V extended-state probes (the F registers, and the V registers where noted) for the
//! FPU isolation tests.
//!
//! Each probe loads `pattern` into every register of the file, lets the kernel
//! run (a preemption window, or a blocking syscall issued from inside the same
//! inline-asm block), then captures the registers and returns the count of
//! lanes that no longer hold `pattern`. One asm block spans the whole
//! load → kernel → capture sequence, so no compiler-generated code touches the
//! registers in between. The kernel is soft-float and saves and restores the
//! live extended state as `core/kernel/docs/scheduler.md` § What Gets Saved and
//! Restored specifies. Callers: `crate::unit::fpu` and
//! `crate::integration::fpu_survives_ipc_call`. [`load_and_spin`] instead
//! holds the loaded values while the thread spins, for a stop to find them in
//! the image `SYS_THREAD_READ_EXT_REGS` reads (`crate::integration::thread_ext_regs`).
//! [`initial_state_check`], [`control_state_check`] and
//! [`inexact_divide_check`] read the control state a thread starts with
//! (`crate::unit::fpu::initial_state`). [`touch_vector_register`] is the vector-register
//! touch of the `fpu=both` case of `crate::bench::ipc`.

/// Load `pattern` into f0..f31 and lane 0 of v0..v31, spin `iters` iterations so the timer can
/// preempt the thread, then capture the registers; returns the mismatched-lane
/// count.
#[expect(
    clippy::too_many_lines,
    reason = "32 F loads, 32 V broadcasts, and 64 register stores dominate the body"
)]
pub fn preempt_capture(pattern: u64, iters: u64) -> u64
{
    // 32 × f64 + 32 × v[lane0] = 64 lanes worth of state to verify.
    let mut fbuf = [0u64; 32];
    let mut vbuf = [0u64; 32];
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
            mismatches = mismatches.saturating_add(1);
        }
    }
    for &v in &vbuf
    {
        if v != pattern
        {
            mismatches = mismatches.saturating_add(1);
        }
    }
    mismatches
}

/// Load `pattern` into f0..f31, spin `spin` iterations, send bit 1 on
/// `sig_ready` (`SYS_NOTIFICATION_SEND`), block on `sig_resume`
/// (`SYS_NOTIFICATION_WAIT`, no timeout), then capture the registers on
/// whichever CPU the thread resumes; returns the mismatched-lane count.
pub fn notification_rendezvous_capture(
    pattern: u64,
    spin: u64,
    sig_ready: u64,
    sig_resume: u64,
) -> u64
{
    let mut buf = [0u64; 32];

    // SAFETY: inline asm loads pattern into f0..f31, issues
    // SYS_NOTIFICATION_SEND (a7=3) then SYS_NOTIFICATION_WAIT (a7=4) preserving
    // the live FP register file across both, then stores f0..f31 into buf.
    // The .option arch directive locally enables the D extension even
    // though the kernel target is RV64IMAC; the trap-and-restore path will have made FS
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
            // SYS_NOTIFICATION_SEND(sig_ready, 0x1): a7=3, a0=sig_ready, a1=1.
            "li a7, 3",
            "mv a0, {sig_ready}",
            "li a1, 1",
            "ecall",
            // SYS_NOTIFICATION_WAIT(sig_resume, 0): a7=4, a0=sig_resume, a1=0 (no
            // timeout). MUST zero a1 explicitly — the kernel reads
            // tf.arg(1) as `timeout_ms` (sys_notification_wait in
            // core/kernel/src/syscall/ipc.rs), and the previous
            // SYS_NOTIFICATION_SEND left a1=1 in the register file. Without this
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
            sig_ready = in(reg) sig_ready,
            sig_resume = in(reg) sig_resume,
            out("a0") _, out("a1") _, out("a7") _,
            options(nostack),
        );
    }

    let mut mismatches = 0u64;
    for &v in &buf
    {
        if v != pattern
        {
            mismatches = mismatches.saturating_add(1);
        }
    }
    mismatches
}

/// Load `pattern` into f0..f31, spin `spin` iterations, issue `SYS_IPC_CALL`
/// on `ep` with `msg_label` and no data or caps, then capture the registers on
/// whichever CPU the thread resumes after the reply; returns the
/// mismatched-lane count. The caller has registered its IPC buffer.
pub fn ipc_call_capture(pattern: u64, spin: u64, ep: u64, msg_label: u64) -> u64
{
    let mut buf = [0u64; 32];

    // SAFETY: inline asm loads pattern into f0..f31, issues SYS_IPC_CALL
    // (a7=0, a0..a5 carry args; a5 declared clobbered so the allocator
    // never assigns it to a generic operand) preserving the live FP
    // register file across it, then captures f0..f31 back to `buf`.
    // `.option arch, +d` locally enables the D extension because ktest's
    // low-level userspace target (`riscv64imac-seraph-lowuser`) is RV64IMAC.
    // a0/a1/a2 are written by the kernel as (ret, reply_label,
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
            // SYS_IPC_CALL(ep, msg_label, data=0, caps=0); args 4-5 are
            // unused and passed as zero.
            "li a7, 0",
            "mv a0, {ep}",
            "mv a1, {label}",
            "li a2, 0",
            "li a3, 0",
            "li a4, 0",
            "li a5, 0",
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
            ep = in(reg) ep,
            label = in(reg) msg_label,
            out("a0") _, out("a1") _, out("a2") _, out("a3") _, out("a4") _,
            out("a5") _, out("a7") _,
            options(nostack),
        );
    }

    let mut mismatches = 0u64;
    for &v in &buf
    {
        if v != pattern
        {
            mismatches = mismatches.saturating_add(1);
        }
    }
    mismatches
}

/// Load `f0`..`f31` and element 0 of `v0`..`v31` with per-register values
/// (`vl` = 1 at `e64`, `m1`, tail and mask agnostic), then spin for ever,
/// adding one to `progress` each pass, so a stop finds the values in the
/// thread's saved extended state. `f{i}` holds `pattern ^ i` and element 0 of
/// `v{i}` holds `!pattern ^ i`. [`for_each_ext_word`] states where the image
/// holds them. Caller: `crate::integration::thread_ext_regs`.
#[expect(
    clippy::too_many_lines,
    reason = "32 F loads and 32 V broadcasts, each from its own pattern, dominate the body"
)]
pub fn load_and_spin(pattern: u64, progress: &core::sync::atomic::AtomicU32) -> !
{
    // SAFETY: the asm writes only the F and V registers and the scratch
    // registers `t0` and `t1`, which a block that never returns may
    // overwrite, and increments `progress`, a live atomic, with an AMO. The
    // scratch registers are named, not allocated, since the compiler may give
    // two operands of one value one register. The D and V instructions run
    // with FS and VS enabled on first touch by the kernel's lazy trap, as for
    // [`preempt_capture`].
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d, +v",
            "xori t0, {p}, 0",
            "fmv.d.x f0, t0",
            "xori t0, {p}, 1",
            "fmv.d.x f1, t0",
            "xori t0, {p}, 2",
            "fmv.d.x f2, t0",
            "xori t0, {p}, 3",
            "fmv.d.x f3, t0",
            "xori t0, {p}, 4",
            "fmv.d.x f4, t0",
            "xori t0, {p}, 5",
            "fmv.d.x f5, t0",
            "xori t0, {p}, 6",
            "fmv.d.x f6, t0",
            "xori t0, {p}, 7",
            "fmv.d.x f7, t0",
            "xori t0, {p}, 8",
            "fmv.d.x f8, t0",
            "xori t0, {p}, 9",
            "fmv.d.x f9, t0",
            "xori t0, {p}, 10",
            "fmv.d.x f10, t0",
            "xori t0, {p}, 11",
            "fmv.d.x f11, t0",
            "xori t0, {p}, 12",
            "fmv.d.x f12, t0",
            "xori t0, {p}, 13",
            "fmv.d.x f13, t0",
            "xori t0, {p}, 14",
            "fmv.d.x f14, t0",
            "xori t0, {p}, 15",
            "fmv.d.x f15, t0",
            "xori t0, {p}, 16",
            "fmv.d.x f16, t0",
            "xori t0, {p}, 17",
            "fmv.d.x f17, t0",
            "xori t0, {p}, 18",
            "fmv.d.x f18, t0",
            "xori t0, {p}, 19",
            "fmv.d.x f19, t0",
            "xori t0, {p}, 20",
            "fmv.d.x f20, t0",
            "xori t0, {p}, 21",
            "fmv.d.x f21, t0",
            "xori t0, {p}, 22",
            "fmv.d.x f22, t0",
            "xori t0, {p}, 23",
            "fmv.d.x f23, t0",
            "xori t0, {p}, 24",
            "fmv.d.x f24, t0",
            "xori t0, {p}, 25",
            "fmv.d.x f25, t0",
            "xori t0, {p}, 26",
            "fmv.d.x f26, t0",
            "xori t0, {p}, 27",
            "fmv.d.x f27, t0",
            "xori t0, {p}, 28",
            "fmv.d.x f28, t0",
            "xori t0, {p}, 29",
            "fmv.d.x f29, t0",
            "xori t0, {p}, 30",
            "fmv.d.x f30, t0",
            "xori t0, {p}, 31",
            "fmv.d.x f31, t0",
            "li t0, 1",
            "vsetvli zero, t0, e64, m1, ta, ma",
            "not t1, {p}",
            "xori t0, t1, 0",
            "vmv.v.x v0, t0",
            "xori t0, t1, 1",
            "vmv.v.x v1, t0",
            "xori t0, t1, 2",
            "vmv.v.x v2, t0",
            "xori t0, t1, 3",
            "vmv.v.x v3, t0",
            "xori t0, t1, 4",
            "vmv.v.x v4, t0",
            "xori t0, t1, 5",
            "vmv.v.x v5, t0",
            "xori t0, t1, 6",
            "vmv.v.x v6, t0",
            "xori t0, t1, 7",
            "vmv.v.x v7, t0",
            "xori t0, t1, 8",
            "vmv.v.x v8, t0",
            "xori t0, t1, 9",
            "vmv.v.x v9, t0",
            "xori t0, t1, 10",
            "vmv.v.x v10, t0",
            "xori t0, t1, 11",
            "vmv.v.x v11, t0",
            "xori t0, t1, 12",
            "vmv.v.x v12, t0",
            "xori t0, t1, 13",
            "vmv.v.x v13, t0",
            "xori t0, t1, 14",
            "vmv.v.x v14, t0",
            "xori t0, t1, 15",
            "vmv.v.x v15, t0",
            "xori t0, t1, 16",
            "vmv.v.x v16, t0",
            "xori t0, t1, 17",
            "vmv.v.x v17, t0",
            "xori t0, t1, 18",
            "vmv.v.x v18, t0",
            "xori t0, t1, 19",
            "vmv.v.x v19, t0",
            "xori t0, t1, 20",
            "vmv.v.x v20, t0",
            "xori t0, t1, 21",
            "vmv.v.x v21, t0",
            "xori t0, t1, 22",
            "vmv.v.x v22, t0",
            "xori t0, t1, 23",
            "vmv.v.x v23, t0",
            "xori t0, t1, 24",
            "vmv.v.x v24, t0",
            "xori t0, t1, 25",
            "vmv.v.x v25, t0",
            "xori t0, t1, 26",
            "vmv.v.x v26, t0",
            "xori t0, t1, 27",
            "vmv.v.x v27, t0",
            "xori t0, t1, 28",
            "vmv.v.x v28, t0",
            "xori t0, t1, 29",
            "vmv.v.x v29, t0",
            "xori t0, t1, 30",
            "vmv.v.x v30, t0",
            "xori t0, t1, 31",
            "vmv.v.x v31, t0",
            "li t0, 1",
            "2:",
            "amoadd.w zero, t0, ({c})",
            "j 2b",
            ".option pop",
            p = in(reg) pattern,
            c = in(reg) progress.as_ptr(),
            in("t0") 0u64,
            in("t1") 0u64,
            options(noreturn, nostack),
        );
    }
}

/// Pass each 64-bit word of the extended-state image `SYS_THREAD_READ_EXT_REGS`
/// returns that [`load_and_spin`] with `pattern` sets, as its byte offset, the
/// mask of the bits to compare, and their value, to `check`; stops at the
/// first word `check` refuses and returns whether every word passed. The
/// image of `image_bytes` bytes holds `f{i}` at
/// `EXT_REGS_RISCV64_F0_OFFSET + 8i`, `vl` and `vtype` at their offsets, and
/// `v{i}` at `EXT_REGS_RISCV64_V0_OFFSET + i * vlenb`, `vlenb` being a 32nd of
/// the bytes past that offset.
pub fn for_each_ext_word(
    pattern: u64,
    image_bytes: u64,
    check: &mut dyn FnMut(u64, u64, u64) -> bool,
) -> bool
{
    use syscall_abi::{
        EXT_REGS_RISCV64_F0_OFFSET, EXT_REGS_RISCV64_V0_OFFSET, EXT_REGS_RISCV64_VL_OFFSET,
        EXT_REGS_RISCV64_VTYPE_OFFSET,
    };
    /// `vtype` for `e64`, `m1`, `ta`, `ma`: `vsew` 3 at bits 5:3, `vta` bit 6,
    /// `vma` bit 7.
    const VTYPE_E64_M1_TA_MA: u64 = 0xD8;
    let v0 = EXT_REGS_RISCV64_V0_OFFSET as u64;
    let vlenb = image_bytes.saturating_sub(v0) / 32;
    let f = (EXT_REGS_RISCV64_F0_OFFSET as u64..).step_by(8);
    let v = core::iter::successors(Some(v0), |at| at.checked_add(vlenb));
    check(EXT_REGS_RISCV64_VL_OFFSET as u64, u64::MAX, 1)
        && check(
            EXT_REGS_RISCV64_VTYPE_OFFSET as u64,
            u64::MAX,
            VTYPE_E64_M1_TA_MA,
        )
        && (0u64..32).zip(f.zip(v)).all(|(i, (f_at, v_at))| {
            check(f_at, u64::MAX, pattern ^ i) && check(v_at, u64::MAX, !pattern ^ i)
        })
}

// ── A new thread's initial state ─────────────────────────────────────────────

/// Names of the control words [`initial_state_check`] and
/// [`control_state_check`] read, in the order their errors index.
pub const STATE_WORDS: [&str; 5] = ["fcsr", "vl", "vtype", "vstart", "vcsr"];

/// `fcsr`'s rounding-mode field `frm` (bits 7:5); 0 is round to nearest,
/// ties to even.
const FCSR_FRM: u64 = 0b111 << 5;

/// `fcsr`'s inexact flag `NX`, which an inexact result sets.
const FCSR_NX: u64 = 1;

/// Read `fcsr`, `vl`, `vtype`, `vstart` and `vcsr`, in that order, in one
/// asm block, so no compiled code runs between the reads. The `fcsr` read
/// is the thread's first use of the extended state when it has made none, so
/// the illegal-instruction trap it takes restores the thread's saved F/D and
/// V state first.
fn read_control_words() -> [u64; 5]
{
    let (fcsr, vl, vtype, vstart, vcsr): (u64, u64, u64, u64, u64);
    // SAFETY: the asm reads five CSRs into the five output registers and
    // writes nothing else. `.option arch, +d, +v` enables the CSR names
    // locally, since ktest's target is RV64IMAC; the reads execute once the
    // U-mode lazy-trap path has turned sstatus.FS and VS on.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d, +v",
            "csrr {fcsr}, fcsr",
            "csrr {vl}, vl",
            "csrr {vtype}, vtype",
            "csrr {vstart}, vstart",
            "csrr {vcsr}, vcsr",
            ".option pop",
            fcsr = out(reg) fcsr,
            vl = out(reg) vl,
            vtype = out(reg) vtype,
            vstart = out(reg) vstart,
            vcsr = out(reg) vcsr,
            options(nostack, nomem),
        );
    }
    [fcsr, vl, vtype, vstart, vcsr]
}

/// The index into [`STATE_WORDS`] and the value of the first of `words`
/// (the value read, the mask of the bits compared, and their expected value)
/// whose bits under its mask differ from its expected value.
fn first_mismatch(words: [(u64, u64, u64); 5]) -> Result<(), (usize, u64)>
{
    match words
        .iter()
        .enumerate()
        .find(|&(_, &(got, mask, want))| got & mask != want)
    {
        Some((i, &(got, _, _))) => Err((i, got)),
        None => Ok(()),
    }
}

/// Check the executing thread's extended-state control words against a new
/// thread's, before the thread has used the state: `fcsr`, `vl`, `vtype`,
/// `vstart` and `vcsr` all 0, exactly.
///
/// # Errors
///
/// The index into [`STATE_WORDS`] and the value of the first word that
/// differs.
pub fn initial_state_check() -> Result<(), (usize, u64)>
{
    let [fcsr, vl, vtype, vstart, vcsr] = read_control_words();
    first_mismatch([
        (fcsr, u64::MAX, 0),
        (vl, u64::MAX, 0),
        (vtype, u64::MAX, 0),
        (vstart, u64::MAX, 0),
        (vcsr, u64::MAX, 0),
    ])
}

/// Check the control field a thread keeps until it writes it: `fcsr`'s
/// rounding mode. The vector configuration is the program's own once it
/// runs a `vsetvl`, and the flags accrue, so neither is compared. For a
/// thread that may have computed since its first use, such as ktest's own.
///
/// # Errors
///
/// The index into [`STATE_WORDS`] and the value of the first word that
/// differs.
pub fn control_state_check() -> Result<(), (usize, u64)>
{
    let [fcsr, vl, vtype, vstart, vcsr] = read_control_words();
    first_mismatch([
        (fcsr, FCSR_FRM, 0),
        (vl, 0, 0),
        (vtype, 0, 0),
        (vstart, 0, 0),
        (vcsr, 0, 0),
    ])
}

/// Divide 1.0 by 3.0 with `fdiv.d`, whose result is inexact, then read
/// `fcsr`, which must be 0 with the inexact flag set. The F and D extensions
/// never trap on a floating-point exception, so the division completes on
/// any `fcsr`.
///
/// # Errors
///
/// `fcsr` after the division, when it is not the expected value.
pub fn inexact_divide_check() -> Result<(), u64>
{
    let (one, three) = (1.0f64.to_bits(), 3.0f64.to_bits());
    let fcsr: u64;
    // SAFETY: the asm moves the two operands into ft0 and ft1, divides, and
    // reads fcsr into an output register. It clobbers ft0 and ft1, which this
    // soft-float binary's compiled code never holds a value in;
    // `.option arch, +d` enables D locally, since ktest's target is RV64IMAC.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fmv.d.x ft0, {one}",
            "fmv.d.x ft1, {three}",
            "fdiv.d ft0, ft0, ft1",
            "csrr {fcsr}, fcsr",
            ".option pop",
            one = in(reg) one,
            three = in(reg) three,
            fcsr = out(reg) fcsr,
            options(nostack, nomem),
        );
    }
    if fcsr == FCSR_NX { Ok(()) } else { Err(fcsr) }
}

/// Write `value` into element 0 of `v1` and read it back: the vector-register touch each side
/// of the `fpu=both` case of `crate::bench::ipc` makes once per round trip, as a std-built
/// thread's vector copies do.
pub fn touch_vector_register(value: u64)
{
    // SAFETY: the asm sets VL and VTYPE and moves between a general-purpose register and v1,
    // state no compiler-generated code of this soft-float crate uses; no memory is accessed.
    // `.option arch` enables V for these instructions only.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v",
            "vsetivli zero, 1, e64, m1, ta, ma",
            "vmv.s.x v1, {v}",
            "vmv.x.s {o}, v1",
            ".option pop",
            v = in(reg) value,
            o = lateout(reg) _,
            options(nomem, nostack),
        );
    }
}
