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
//! `crate::integration::fpu_survives_ipc_call`.

/// Load `pattern` into f0..f31 and lane 0 of v0..v31, spin `iters` iterations so the timer can
/// preempt the thread, then capture the registers; returns the mismatched-lane
/// count.
// too_many_lines: 32 F loads, 32 V broadcasts, and 64 register stores dominate the body.
#[allow(clippy::too_many_lines)]
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

/// Load `pattern` into f0..f31, spin `spin` iterations, send bit 1 on
/// `sig_ready` (`SYS_NOTIFICATION_SEND`), block on `sig_resume`
/// (`SYS_NOTIFICATION_WAIT`, no timeout), then capture the registers on
/// whichever CPU the thread resumes; returns the mismatched-lane count.
// too_many_lines: 32 FP loads + 32 FP stores dominate the body.
#[allow(clippy::too_many_lines)]
pub fn notification_rendezvous_capture(
    pattern: u64,
    spin: u64,
    sig_ready: u32,
    sig_resume: u32,
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
            sig_ready = in(reg) u64::from(sig_ready),
            sig_resume = in(reg) u64::from(sig_resume),
            out("a0") _, out("a1") _, out("a7") _,
            options(nostack),
        );
    }

    let mut mismatches = 0u64;
    for &v in &buf
    {
        if v != pattern
        {
            mismatches += 1;
        }
    }
    mismatches
}

/// Load `pattern` into f0..f31, spin `spin` iterations, issue `SYS_IPC_CALL`
/// on `ep` with `msg_label` and no data or caps, then capture the registers on
/// whichever CPU the thread resumes after the reply; returns the
/// mismatched-lane count. The caller has registered its IPC buffer.
// too_many_lines: 32 FP loads, the ecall, and 32 FP stores dominate the body.
#[allow(clippy::too_many_lines)]
pub fn ipc_call_capture(pattern: u64, spin: u64, ep: u32, msg_label: u64) -> u64
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
            // SYS_IPC_CALL(ep, msg_label, data=0, caps=0,
            // cap_handles_lo=0, cap_handles_hi=0).
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
            ep = in(reg) u64::from(ep),
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
            mismatches += 1;
        }
    }
    mismatches
}
