// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/fpu.rs

//! x86-64 extended-state probes (the 16 `xmm` registers) for the FPU isolation tests.
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

/// Load `pattern` into xmm0..xmm15, spin `iters` iterations so the timer can
/// preempt the thread, then capture the registers; returns the mismatched-lane
/// count.
pub fn preempt_capture(pattern: u64, iters: u64) -> u64
{
    // 128-bit pattern (the lane width of xmm).
    let pat128 = [pattern, pattern];
    let mut buf = [[0u64; 2]; 16];
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

/// Load `pattern` into xmm0..xmm15, spin `spin` iterations, send bit 1 on
/// `sig_ready` (`SYS_NOTIFICATION_SEND`), block on `sig_resume`
/// (`SYS_NOTIFICATION_WAIT`, no timeout), then capture the registers on
/// whichever CPU the thread resumes; returns the mismatched-lane count.
pub fn notification_rendezvous_capture(
    pattern: u64,
    spin: u64,
    sig_ready: u32,
    sig_resume: u32,
) -> u64
{
    // 128-bit pattern (xmm lane width).
    let pat128 = [pattern, pattern];
    let mut buf = [[0u64; 2]; 16];

    // SAFETY: inline asm loads pat128 into xmm0..xmm15, issues two raw
    // syscalls (SYS_NOTIFICATION_SEND, SYS_NOTIFICATION_WAIT) preserving the
    // live FP register file across both, then stores xmm0..xmm15 into buf. All
    // operands have matching lifetimes; rcx/r11 are syscall-clobber-only. rdx
    // is clobbered by SYS_NOTIFICATION_WAIT's secondary-return write (the kernel
    // writes the acquired bitmask into rdx via `set_ipc_return`).
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
        if lane[0] != pattern || lane[1] != pattern
        {
            mismatches += 1;
        }
    }
    mismatches
}

/// Load `pattern` into xmm0..xmm15, spin `spin` iterations, issue `SYS_IPC_CALL`
/// on `ep` with `msg_label` and no data or caps, then capture the registers on
/// whichever CPU the thread resumes after the reply; returns the
/// mismatched-lane count. The caller has registered its IPC buffer.
pub fn ipc_call_capture(pattern: u64, spin: u64, ep: u32, msg_label: u64) -> u64
{
    let pat128 = [pattern, pattern];
    let mut buf = [[0u64; 2]; 16];

    // SAFETY: inline asm loads pattern into xmm0..xmm15, issues
    // SYS_IPC_CALL preserving the live FP register file across it, then
    // captures xmm0..xmm15 back to `buf`. Operand lifetimes match. rcx/r11
    // are syscall-architecturally-clobbered. rax carries the syscall number
    // in and the primary return out; rdi/rsi/rdx/r10/r8/r9 carry the six
    // arguments in; rdx and r9 then receive the secondary/tertiary returns
    // (reply_label, reply_word_count) from `set_ipc_call_return`. All are
    // declared clobbered and discarded.
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
            // SYS_IPC_CALL(ep, msg_label, data=0, caps=0,
            // cap_handles_lo=0, cap_handles_hi=0).
            "xor rax, rax",
            "mov edi, {ep:e}",
            "mov rsi, {label}",
            "xor rdx, rdx",
            "xor r10, r10",
            "xor r8, r8",
            "xor r9, r9",
            "syscall",
            // Resumed (possibly on CPU 1). The first FP op (the capture
            // `vmovdqu`) traps to `#NM` because `switch_in_restore` set
            // `CR0.TS=1`; the handler XRSTORs the saved area into CPU 1's
            // hardware before the store executes.
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
            label = in(reg) msg_label,
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
        if lane[0] != pattern || lane[1] != pattern
        {
            mismatches += 1;
        }
    }
    mismatches
}
