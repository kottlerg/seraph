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
//! `crate::integration::fpu_survives_ipc_call`. [`load_and_spin`] instead
//! holds the loaded values while the thread spins, for a stop to find them in
//! the image `SYS_THREAD_READ_EXT_REGS` reads (`crate::integration::thread_ext_regs`).
//! [`initial_state_check`], [`control_state_check`] and
//! [`inexact_divide_check`] read the control state a thread starts with
//! (`crate::unit::fpu::initial_state`).

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
            mismatches = mismatches.saturating_add(1);
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
    sig_ready: u64,
    sig_resume: u64,
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
            "mov rdi, {sig_ready}",
            "mov esi, 1",
            "syscall",
            // Syscall SYS_NOTIFICATION_WAIT(sig_resume, 0). rax = 4.
            "mov rax, 4",
            "mov rdi, {sig_resume}",
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
            mismatches = mismatches.saturating_add(1);
        }
    }
    mismatches
}

/// Load `pattern` into xmm0..xmm15, spin `spin` iterations, issue `SYS_IPC_CALL`
/// on `ep` with `msg_label` and no data or caps, then capture the registers on
/// whichever CPU the thread resumes after the reply; returns the
/// mismatched-lane count. The caller has registered its IPC buffer.
pub fn ipc_call_capture(pattern: u64, spin: u64, ep: u64, msg_label: u64) -> u64
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
            // SYS_IPC_CALL(ep, msg_label, data=0, caps=0); args 4-5 are
            // unused and passed as zero.
            "xor rax, rax",
            "mov rdi, {ep}",
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
            mismatches = mismatches.saturating_add(1);
        }
    }
    mismatches
}

/// Load `ymm0`..`ymm15` with per-register values, then spin for ever, adding
/// one to `progress` each pass, so a stop finds the values in the thread's
/// saved extended state. Register `i` holds `pattern ^ i` in both 64-bit
/// words of its low 128 bits (`xmm{i}`) and `!pattern ^ i` in both words of
/// its upper 128 bits. [`for_each_ext_word`] states where the image holds
/// them. Caller: `crate::integration::thread_ext_regs`.
pub fn load_and_spin(pattern: u64, progress: &core::sync::atomic::AtomicU32) -> !
{
    let mut table = [[0u64; 4]; 16];
    for (i, lanes) in (0u64..).zip(table.iter_mut())
    {
        let (lo, hi) = (pattern ^ i, !pattern ^ i);
        *lanes = [lo, lo, hi, hi];
    }
    // SAFETY: the asm reads the 512-byte table on this frame, which outlives
    // it since the block never returns, and increments `progress`, a live
    // atomic, with a locked add; it touches nothing else.
    unsafe {
        core::arch::asm!(
            "vmovdqu ymm0, [{t} + 0x000]",
            "vmovdqu ymm1, [{t} + 0x020]",
            "vmovdqu ymm2, [{t} + 0x040]",
            "vmovdqu ymm3, [{t} + 0x060]",
            "vmovdqu ymm4, [{t} + 0x080]",
            "vmovdqu ymm5, [{t} + 0x0a0]",
            "vmovdqu ymm6, [{t} + 0x0c0]",
            "vmovdqu ymm7, [{t} + 0x0e0]",
            "vmovdqu ymm8, [{t} + 0x100]",
            "vmovdqu ymm9, [{t} + 0x120]",
            "vmovdqu ymm10, [{t} + 0x140]",
            "vmovdqu ymm11, [{t} + 0x160]",
            "vmovdqu ymm12, [{t} + 0x180]",
            "vmovdqu ymm13, [{t} + 0x1a0]",
            "vmovdqu ymm14, [{t} + 0x1c0]",
            "vmovdqu ymm15, [{t} + 0x1e0]",
            "2:",
            "lock inc dword ptr [{c}]",
            "pause",
            "jmp 2b",
            t = in(reg) table.as_ptr(),
            c = in(reg) progress.as_ptr(),
            options(noreturn, nostack),
        );
    }
}

/// Pass each 64-bit word of the extended-state image `SYS_THREAD_READ_EXT_REGS`
/// returns that [`load_and_spin`] with `pattern` sets, as its byte offset, the
/// mask of the bits to compare, and their value, to `check`; stops at the
/// first word `check` refuses and returns whether every word passed. The image
/// is the XSAVE standard format (`syscall_abi::EXT_REGS_X86_64_XCR0`): `xmm{i}`
/// at 160 + 16i, `XSTATE_BV` at 512, whose SSE and AVX bits the loads set, and
/// the upper halves at 576 + 16i (Intel SDM Vol. 1 § 13.4 and § 13.5.3).
pub fn for_each_ext_word(
    pattern: u64,
    _image_bytes: u64,
    check: &mut dyn FnMut(u64, u64, u64) -> bool,
) -> bool
{
    /// `XSTATE_BV` bits of the SSE and AVX components.
    const SSE_AVX: u64 = 0b110;
    if !check(512, SSE_AVX, SSE_AVX)
    {
        return false;
    }
    // Each register's slot is 16-byte aligned, so `| 8` is its second word.
    let legacy = (160u64..).step_by(16);
    let upper = (576u64..).step_by(16);
    (0u64..16)
        .zip(legacy.zip(upper))
        .all(|(i, (low_at, high_at))| {
            let (lo, hi) = (pattern ^ i, !pattern ^ i);
            check(low_at, u64::MAX, lo)
                && check(low_at | 8, u64::MAX, lo)
                && check(high_at, u64::MAX, hi)
                && check(high_at | 8, u64::MAX, hi)
        })
}

// ── A new thread's initial state ─────────────────────────────────────────────

/// Names of the control words [`initial_state_check`] and
/// [`control_state_check`] read, in the order their errors index.
pub const STATE_WORDS: [&str; 2] = ["mxcsr", "x87 control word"];

/// `MXCSR` at power-up, the value a new thread starts with: every SIMD
/// floating-point exception masked, round to nearest, flush-to-zero and
/// denormals-are-zero clear, no flag set (Intel SDM Vol. 1 § 10.2.3).
const MXCSR_INIT: u64 = 0x1F80;

/// `MXCSR`'s sticky exception flags (bits 5:0), which arithmetic sets.
const MXCSR_FLAGS: u64 = 0x3F;

/// `MXCSR`'s precision flag (`PE`), which an inexact result sets.
const MXCSR_PE: u64 = 1 << 5;

/// The x87 control word `FNINIT` sets, the value a new thread starts with:
/// every x87 exception masked, double-extended precision, round to nearest
/// (Intel SDM Vol. 1 § 8.1.5).
const FCW_INIT: u64 = 0x037F;

/// Read `MXCSR` and the x87 control word, in that order. The `stmxcsr` is
/// the thread's first use of the extended state when it has made none, so
/// the `#NM` it takes restores the thread's saved state first.
fn read_control_words() -> [u64; 2]
{
    let mut mxcsr = 0u32;
    let mut fcw = 0u16;
    // SAFETY: `stmxcsr` stores MXCSR's 4 bytes into `mxcsr` and `fnstcw` the
    // x87 control word's 2 bytes into `fcw`, both live locals; neither
    // writes a register, and neither changes the extended state.
    unsafe {
        core::arch::asm!(
            "stmxcsr [{m}]",
            "fnstcw [{c}]",
            m = in(reg) &raw mut mxcsr,
            c = in(reg) &raw mut fcw,
            options(nostack, preserves_flags),
        );
    }
    [u64::from(mxcsr), u64::from(fcw)]
}

/// The index into [`STATE_WORDS`] and the value of the first of `words`
/// whose bits under its mask differ from its expected value.
fn first_mismatch(words: [(u64, u64, u64); 2]) -> Result<(), (usize, u64)>
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
/// thread's, before the thread has used the state: `MXCSR` 0x1F80 and the
/// x87 control word 0x037F, exactly.
///
/// # Errors
///
/// The index into [`STATE_WORDS`] and the value of the first word that
/// differs.
pub fn initial_state_check() -> Result<(), (usize, u64)>
{
    let [mxcsr, fcw] = read_control_words();
    first_mismatch([(mxcsr, u64::MAX, MXCSR_INIT), (fcw, u64::MAX, FCW_INIT)])
}

/// Check the control fields a thread keeps until it writes them: `MXCSR`
/// apart from its sticky flags, and the x87 control word. For a thread that
/// may have computed since its first use, such as ktest's own.
///
/// # Errors
///
/// The index into [`STATE_WORDS`] and the value of the first word that
/// differs.
pub fn control_state_check() -> Result<(), (usize, u64)>
{
    let [mxcsr, fcw] = read_control_words();
    first_mismatch([(mxcsr, !MXCSR_FLAGS, MXCSR_INIT), (fcw, u64::MAX, FCW_INIT)])
}

/// Divide 1.0 by 3.0 with `divsd`, whose result is inexact, then read
/// `MXCSR`, which must be 0x1F80 with the precision flag set. A thread whose
/// `MXCSR` unmasks the precision exception takes `#XM` at the division and
/// dies instead.
///
/// # Errors
///
/// `MXCSR` after the division, when it is not the expected value.
pub fn inexact_divide_check() -> Result<(), u64>
{
    let operands = [1.0f64, 3.0f64];
    let mut mxcsr = 0u32;
    // SAFETY: the asm loads `operands[0]` into xmm0, divides it by
    // `operands[1]` read from memory, and stores MXCSR into `mxcsr`; both
    // are live locals. It clobbers xmm0, which this soft-float binary's
    // compiled code never holds a value in.
    unsafe {
        core::arch::asm!(
            "movsd xmm0, qword ptr [{o}]",
            "divsd xmm0, qword ptr [{o} + 8]",
            "stmxcsr [{m}]",
            o = in(reg) operands.as_ptr(),
            m = in(reg) &raw mut mxcsr,
            options(nostack, preserves_flags),
        );
    }
    let mxcsr = u64::from(mxcsr);
    if mxcsr == MXCSR_INIT | MXCSR_PE
    {
        Ok(())
    }
    else
    {
        Err(mxcsr)
    }
}
