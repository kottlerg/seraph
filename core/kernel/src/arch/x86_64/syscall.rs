// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/syscall.rs

//! SYSCALL/SYSRET MSR setup and entry stub for x86-64 (Phase 9).
//!
//! Configures the MSRs required by the SYSCALL instruction:
//!
//! - `IA32_EFER.SCE` — enables SYSCALL/SYSRET.
//! - `IA32_STAR` — segment selectors:
//!     - bits [47:32] = 0x0008: SYSCALL sets CS=0x08 (kernel), SS=0x10.
//!     - bits [63:48] = 0x0010: SYSRET64 gives CS=(0x10+16)|3=0x23 (user),
//!       SS=(0x10+8)|3=0x1B (user DS).
//! - `IA32_LSTAR` — 64-bit entry point (`syscall_entry`).
//! - `IA32_SFMASK` — clears RFLAGS.IF on entry.
//!
//! ## Entry contract
//! On SYSCALL: hardware saves RIP→RCX, RFLAGS→R11, applies SFMASK.
//! RSP and segment registers are NOT changed by the hardware.
//!
//! We save R11 (user RFLAGS) to `SYSCALL_SCRATCH` immediately, use R11 to
//! shuttle user RSP to `SYSCALL_USER_RSP`, switch to `SYSCALL_KERNEL_RSP`,
//! then rebuild R11 from the scratch before saving the full `TrapFrame.`
//!
//! ## Per-CPU layout (`PerCpuData` GS-relative offsets)
//! - `gs:[8]`  (`PERCPU_KERNEL_RSP_OFFSET`) — kernel RSP loaded at entry
//! - `gs:[16]` (`PERCPU_USER_RSP_OFFSET`)   — saved user RSP
//! - `gs:[24]` (`PERCPU_SCRATCH_OFFSET`)    — temp save of R11 (user RFLAGS)

#[cfg(not(test))]
use super::cpu;

// ── MSR addresses ─────────────────────────────────────────────────────────────

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_SFMASK: u32 = 0xC000_0084;

const EFER_SCE: u64 = 1 << 0;
const SFMASK_CLEAR_IF: u64 = 1 << 9;

/// STAR value:
/// - bits [47:32] = 0x0008: SYSCALL → CS=0x08 (kernel), SS=0x10.
/// - bits [63:48] = 0x0010: SYSRET64 → CS=(0x10+16)|3=0x23, SS=(0x10+8)|3=0x1B.
const STAR_VALUE: u64 = (0x0010u64 << 48) | (0x0008u64 << 32);

/// Set the kernel RSP for the current CPU's SYSCALL entry path.
///
/// Writes `rsp` to `gs:[8]` (`PerCpuData::kernel_rsp`). The `syscall_entry`
/// stub reads this value to switch from user to kernel stack.
///
/// Must be called with the current thread's `kernel_stack_top` before every
/// return to user mode so the next SYSCALL lands on the correct kernel stack.
///
/// # Safety
/// Ring 0 only. GS-base must point to a valid `PerCpuData` (after Phase 5).
#[cfg(not(test))]
pub unsafe fn set_kernel_rsp(rsp: u64)
{
    // SAFETY: gs:[8] == PerCpuData::kernel_rsp; valid after percpu::init_bsp/ap.
    unsafe {
        core::arch::asm!(
            "mov gs:[8], {}",
            in(reg) rsp,
            options(nostack, nomem),
        );
    }
}

// ── syscall_entry ─────────────────────────────────────────────────────────────

/// SYSCALL entry stub (Phase 9).
///
/// On SYSCALL hardware saves: RIP→RCX, RFLAGS→R11. Does NOT change RSP.
/// This stub:
/// 1. Saves R11 (user RFLAGS) to `gs:[24]` (`PerCpuData::scratch`).
/// 2. Saves user RSP (via R11) to `gs:[16]` (`PerCpuData::user_rsp`).
/// 3. Switches to `gs:[8]` (`PerCpuData::kernel_rsp`).
/// 4. Allocates a 168-byte [`TrapFrame`] on the kernel stack.
/// 5. Saves all GPRs and CPU-state fields into the frame.
/// 6. Calls `crate::syscall::dispatch`.
/// 7. Restores registers and executes `sysretq`.
///
/// GS-base must point to a valid `PerCpuData` (installed by `percpu::init_bsp`
/// in Phase 5) before any user thread executes a SYSCALL.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry()
{
    // TrapFrame field offsets (trap_frame.rs):
    //   rax=0, rbx=8, rcx=16, rdx=24, rsi=32, rdi=40, rbp=48,
    //   r8=56, r9=64, r10=72, r11=80, r12=88, r13=96, r14=104, r15=112,
    //   rip=120, rflags=128, rsp=136, cs=144, ss=152, fs_base=160
    //
    // PerCpuData GS offsets: kernel_rsp=gs:[8], user_rsp=gs:[16], scratch=gs:[24]
    core::arch::naked_asm!(
        // ── Phase 1: stack switch (use R11 as scratch, restore later) ─────
        // Save user RFLAGS (R11) to PerCpuData::scratch before repurposing R11.
        "mov gs:[24], r11",
        // Use R11 to carry user RSP to PerCpuData::user_rsp, then switch stacks.
        "mov r11, rsp",
        "mov gs:[16], r11",
        "mov rsp, gs:[8]",

        // ── Phase 2: allocate TrapFrame and save all registers ────────────
        "sub rsp, 168",
        "mov [rsp +   0], rax",     // syscall number
        "mov [rsp +   8], rbx",
        "mov [rsp +  16], rcx",     // user RIP (hardware → rcx; unchanged)
        "mov [rsp +  24], rdx",
        "mov [rsp +  32], rsi",
        "mov [rsp +  40], rdi",
        "mov [rsp +  48], rbp",
        "mov [rsp +  56], r8",
        "mov [rsp +  64], r9",
        "mov [rsp +  72], r10",     // user arg3 (r10 unmodified ✓)
        // Restore R11 (user RFLAGS) from PerCpuData::scratch and save to frame.
        "mov r11, gs:[24]",
        "mov [rsp +  80], r11",     // user RFLAGS
        "mov [rsp +  88], r12",
        "mov [rsp +  96], r13",
        "mov [rsp + 104], r14",
        "mov [rsp + 112], r15",

        // CPU-state fields:
        "mov [rsp + 120], rcx",     // rip    = user RIP
        "mov [rsp + 128], r11",     // rflags = user RFLAGS
        "mov r11, gs:[16]",         // load saved user RSP from PerCpuData::user_rsp
        "mov [rsp + 136], r11",     // rsp    = user RSP
        "mov qword ptr [rsp + 144], 0x23", // cs = USER_CS
        "mov qword ptr [rsp + 152], 0x1b", // ss = USER_DS
        "mov qword ptr [rsp + 160], 0",    // fs_base (Phase 9: zero)

        // ── Phase 3: dispatch ─────────────────────────────────────────────
        "mov rdi, rsp",             // arg0 = *mut TrapFrame
        "call {dispatch}",

        // ── Phase 4: restore registers for sysretq ────────────────────────
        // sysretq: RIP←RCX, RFLAGS←R11, RSP stays as set.
        "mov rax, [rsp +   0]",     // return value (dispatch set tf.rax)
        "mov rbx, [rsp +   8]",
        "mov rcx, [rsp + 120]",     // user RIP → rcx for sysretq
        "mov rdx, [rsp +  24]",
        "mov rsi, [rsp +  32]",
        "mov rdi, [rsp +  40]",
        "mov rbp, [rsp +  48]",
        "mov r8,  [rsp +  56]",
        "mov r9,  [rsp +  64]",
        "mov r10, [rsp +  72]",
        "mov r11, [rsp + 128]",     // user RFLAGS → r11 for sysretq
        "mov r12, [rsp +  88]",
        "mov r13, [rsp +  96]",
        "mov r14, [rsp + 104]",
        "mov r15, [rsp + 112]",
        // Switch to user RSP last (TrapFrame still on kernel stack until here).
        "mov rsp, [rsp + 136]",     // rsp = user RSP

        "sysretq",

        dispatch = sym crate::syscall::dispatch,
    );
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Configure the SYSCALL/SYSRET mechanism.
///
/// Enables SYSCALL in EFER, programs STAR/LSTAR/SFMASK.
///
/// # Safety
/// Ring 0. GDT must have the Seraph layout before this call.
#[cfg(not(test))]
pub unsafe fn init()
{
    // SAFETY: ring 0; MSR writes.
    unsafe {
        let efer = cpu::read_msr(IA32_EFER);
        cpu::write_msr(IA32_EFER, efer | EFER_SCE);
        cpu::write_msr(IA32_STAR, STAR_VALUE);
        cpu::write_msr(IA32_LSTAR, syscall_entry as *const () as u64);
        cpu::write_msr(IA32_SFMASK, SFMASK_CLEAR_IF);
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn init() {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn star_syscall_cs_is_0x08()
    {
        assert_eq!((STAR_VALUE >> 32) & 0xFFFF, 0x0008);
    }

    #[test]
    fn star_sysret_base_is_0x10()
    {
        // SYSRET64 → CS = (0x10+16)|3 = 0x23, SS = (0x10+8)|3 = 0x1B.
        assert_eq!((STAR_VALUE >> 48) & 0xFFFF, 0x0010);
    }

    #[test]
    fn sfmask_clears_if_only()
    {
        assert_eq!(SFMASK_CLEAR_IF, 1 << 9);
    }

    #[test]
    fn efer_sce_is_bit_0()
    {
        assert_eq!(EFER_SCE, 1);
    }
}
