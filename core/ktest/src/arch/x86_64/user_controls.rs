// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/user_controls.rs

//! The x86-64 half of `integration::user_mode_controls`: the instructions
//! ring 3 is denied and the fault each raises, and the checks of the controls
//! it is granted.
//!
//! The kernel clears every CR4 control ring 3 reaches that it does not grant
//! on every CPU (`cpu::enable_smep_smap`). Each entry of [`DENIED`] fails the
//! case where its control is left set:
//!
//! - `CR4.PCE` clear while a thread `SYS_PMU_BIND` has not granted counter
//!   reads runs (ktest's children are never bound): `RDPMC` raises `#GP(0)`. With it set, `RDPMC` of
//!   counter 0 completes where the CPU has that counter (CPUID leaf 0AH reports
//!   at least one general-purpose counter), and raises `#UD` under QEMU's TCG.
//! - `CR4.PVI` clear: `CLI` under `IOPL` 0 (the kernel clears `IOPL` in every
//!   user frame) raises `#GP(0)`. With it set, `CLI` clears `RFLAGS.VIF` and
//!   completes.
//! - `CR4.PKE` clear: `RDPKRU` raises `#UD`.
//! - `CR4.UINTR` clear: `TESTUI` raises `#UD`.
//! - `CR4.KL` clear: `ENCODEKEY128` raises `#UD`.
//!
//! A CPU without the feature faults the same way whatever the control: no
//! performance counter (`RDPMC` raises `#GP(0)` for every index), and no PKU,
//! UINTR or Key Locker (`#UD`). On such a CPU the entry shows the instruction
//! faults, not which control faulted it. The instructions are written as bytes,
//! since the assembler accepts their mnemonics only under target features
//! ktest is not built with. The granted timestamp counter (`CR4.TSD` clear) is
//! the read `bench::Counters` makes; [`STATE_CHECKS`] checks the
//! controls the kernel sets in `cpu::set_user_msr_controls` and
//! `fpu::enable_xsave`.

use core::sync::atomic::AtomicU64;

use syscall_abi::{FAULT_EXC_ILLEGAL_INSTRUCTION, FAULT_EXC_PROTECTION};

use crate::integration::user_mode_controls::{DeniedInstruction, StateCheck};

/// The state of the controls ring 3 sees on every CPU: the processor
/// identifier the kernel writes to `IA32_TSC_AUX` (0), `CPUID` executing
/// (CPUID faulting off), no alignment checking (`CR0.AM` clear), and no user
/// shadow stack (`IA32_U_CET` clear).
pub const STATE_CHECKS: &[StateCheck] = &[
    StateCheck {
        holds: rdtscp_reads_zero,
        wrong: "integration::user_mode_controls: RDTSCP read a nonzero IA32_TSC_AUX",
    },
    StateCheck {
        holds: rdpid_reads_zero,
        wrong: "integration::user_mode_controls: RDPID read a nonzero IA32_TSC_AUX",
    },
    StateCheck {
        holds: cpuid_executes,
        wrong: "integration::user_mode_controls: ring-3 CPUID did not execute",
    },
    StateCheck {
        holds: user_shadow_stack_off,
        wrong: "integration::user_mode_controls: RDSSPQ read a ring-3 shadow-stack pointer",
    },
    StateCheck {
        holds: misaligned_load_with_ac_completes,
        wrong: "integration::user_mode_controls: a misaligned load with RFLAGS.AC set did not complete",
    },
];

/// The instructions ring 3 is denied.
pub const DENIED: &[DeniedInstruction] = &[
    DeniedInstruction {
        exec: exec_rdpmc,
        fault: FAULT_EXC_PROTECTION,
        fault_code: Some(0),
        not_denied: "integration::user_mode_controls: ring-3 RDPMC did not raise #GP",
    },
    DeniedInstruction {
        exec: exec_cli,
        fault: FAULT_EXC_PROTECTION,
        fault_code: Some(0),
        not_denied: "integration::user_mode_controls: ring-3 CLI did not raise #GP",
    },
    DeniedInstruction {
        exec: exec_rdpkru,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: ring-3 RDPKRU did not raise #UD",
    },
    DeniedInstruction {
        exec: exec_testui,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: ring-3 TESTUI did not raise #UD",
    },
    DeniedInstruction {
        exec: exec_encodekey128,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: ring-3 ENCODEKEY128 did not raise #UD",
    },
];

/// Store the address of an `RDPMC` of counter 0 into `slot`, then execute it.
fn exec_rdpmc(slot: &AtomicU64)
{
    let slot = slot.as_ptr();
    // SAFETY: `lea` and the store use the scratch register `t` and write only
    // the `AtomicU64` behind `slot`; `rdpmc` reads counter ECX = 0 into EDX:EAX,
    // both declared clobbered, and touches no memory or flag. Under
    // `CR4.PCE` clear it raises #GP and writes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            "rdpmc",
            t = out(reg) _,
            slot = in(reg) slot,
            inout("ecx") 0u32 => _,
            out("eax") _,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
}

/// Store the address of a `CLI` into `slot`, then execute it.
fn exec_cli(slot: &AtomicU64)
{
    let slot = slot.as_ptr();
    // SAFETY: `lea` and the store use the scratch register `t` and write only
    // the `AtomicU64` behind `slot`; `cli` at CPL 3 changes at most
    // `RFLAGS.IF` or `RFLAGS.VIF`, so the flags are not declared preserved.
    // Under `CR4.PVI` clear and `IOPL` 0 it raises #GP and changes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            "cli",
            t = out(reg) _,
            slot = in(reg) slot,
            options(nostack),
        );
    }
}

/// Store the address of an `RDPKRU` into `slot`, then execute it.
fn exec_rdpkru(slot: &AtomicU64)
{
    let slot = slot.as_ptr();
    // SAFETY: `lea` and the store use the scratch register `t` and write only
    // the `AtomicU64` behind `slot`; `rdpkru` (0F 01 EE) requires ECX = 0,
    // reads `PKRU` into EAX, zeroes EDX, both declared clobbered, and touches no
    // memory or flag. Under `CR4.PKE` clear it raises #UD and writes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            ".byte 0x0f, 0x01, 0xee",
            t = out(reg) _,
            slot = in(reg) slot,
            inout("ecx") 0u32 => _,
            out("eax") _,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
}

/// Store the address of a `TESTUI` into `slot`, then execute it.
fn exec_testui(slot: &AtomicU64)
{
    let slot = slot.as_ptr();
    // SAFETY: `lea` and the store use the scratch register `t` and write only
    // the `AtomicU64` behind `slot`; `testui` (F3 0F 01 ED) copies `UIF` to
    // `RFLAGS.CF` and clears the other arithmetic flags, so the flags are not
    // declared preserved, and touches no register or memory. Under
    // `CR4.UINTR` clear it raises #UD and changes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            ".byte 0xf3, 0x0f, 0x01, 0xed",
            t = out(reg) _,
            slot = in(reg) slot,
            options(nostack),
        );
    }
}

/// Store the address of an `ENCODEKEY128 eax, eax` into `slot`, then execute
/// it.
fn exec_encodekey128(slot: &AtomicU64)
{
    let slot = slot.as_ptr();
    // SAFETY: `lea` and the store use the scratch register `t` and write only
    // the `AtomicU64` behind `slot`; `encodekey128 eax, eax` (F3 0F 38 FA C0)
    // reads the key from XMM0 and the handle restrictions from EAX, writes the
    // handle to XMM0 to XMM2, zeroes XMM4 to XMM6, writes EAX and the
    // arithmetic flags, all declared clobbered, and touches no memory. Under
    // `CR4.KL` clear it raises #UD and changes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            ".byte 0xf3, 0x0f, 0x38, 0xfa, 0xc0",
            t = out(reg) _,
            slot = in(reg) slot,
            inout("eax") 0u32 => _,
            out("xmm0") _,
            out("xmm1") _,
            out("xmm2") _,
            out("xmm4") _,
            out("xmm5") _,
            out("xmm6") _,
            options(nostack),
        );
    }
}

/// Whether `RDTSCP` reads 0 as the processor identifier, or the CPU has no
/// `RDTSCP` (`CPUID.80000001H:EDX[27]`).
fn rdtscp_reads_zero() -> bool
{
    let has = core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001
        && core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 27) != 0;
    if !has
    {
        return true;
    }
    let aux: u32;
    // SAFETY: `rdtscp` writes EDX:EAX (the timestamp, declared clobbered) and
    // ECX (`IA32_TSC_AUX`), and touches no memory or flag; CPUID enumerates it
    // and `CR4.TSD` is clear.
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("ecx") aux,
            out("eax") _,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    aux == 0
}

/// Whether `RDPID` reads 0 as the processor identifier, or the CPU has no
/// `RDPID` (`CPUID.(EAX=07H,ECX=0):ECX[22]`).
fn rdpid_reads_zero() -> bool
{
    if core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 22) == 0
    {
        return true;
    }
    let aux: u64;
    // SAFETY: `rdpid rax` (F3 0F C7 F8) writes RAX (`IA32_TSC_AUX`) and
    // touches no memory or flag; CPUID enumerates it. Written as bytes, since
    // the assembler accepts the mnemonic only under a target feature ktest is
    // not built with.
    unsafe {
        core::arch::asm!(
            ".byte 0xf3, 0x0f, 0xc7, 0xf8",
            out("rax") aux,
            options(nomem, nostack, preserves_flags),
        );
    }
    aux == 0
}

/// Whether ring-3 `CPUID` executes: it raises `#GP` instead, which fails the
/// case as a trap of a state check, where CPUID faulting is on.
fn cpuid_executes() -> bool
{
    core::hint::black_box(core::arch::x86_64::__cpuid(0));
    true
}

/// An 8-byte buffer at an 8-byte boundary, for the misaligned load.
#[repr(C, align(8))]
struct Aligned([u8; 8]);

/// The buffer [`misaligned_load_with_ac_completes`] loads from.
static MISALIGNED: Aligned = Aligned([0; 8]);

/// Whether a misaligned 4-byte load with `RFLAGS.AC` set completes: it raises
/// `#AC` instead, which fails the case as a trap of a state check, where
/// `CR0.AM` is set.
fn misaligned_load_with_ac_completes() -> bool
{
    let misaligned = MISALIGNED.0.as_ptr().wrapping_add(1);
    // SAFETY: `pushfq`/`popfq` use the stack below RSP (no `nostack`) and set
    // then clear `RFLAGS.AC` (bit 18), which at CPL 3 only selects alignment
    // checking; the load reads bytes 1 to 4 of `MISALIGNED`, a live static,
    // into the scratch register `v`. The flags are not declared preserved.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "bts qword ptr [rsp], 18",
            "popfq",
            "mov {v:e}, dword ptr [{p}]",
            "pushfq",
            "btr qword ptr [rsp], 18",
            "popfq",
            p = in(reg) misaligned,
            v = out(reg) _,
            options(readonly),
        );
    }
    true
}

/// Whether ring 3 runs without a shadow stack: `RDSSPQ` leaves its register
/// unchanged where the user shadow stack is off (`IA32_U_CET.SH_STK_EN` or
/// `CR4.CET` clear) and on a CPU without CET, where it is a no-op hint, and
/// reads the shadow-stack pointer where it is on.
fn user_shadow_stack_off() -> bool
{
    let ssp: u64;
    // SAFETY: `rdsspq rax` (F3 48 0F 1E C8, as bytes since the assembler
    // accepts the mnemonic only under the shadow-stack target feature) writes
    // RAX or nothing, and touches no memory or flag; RAX starts at 0.
    unsafe {
        core::arch::asm!(
            ".byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8",
            inout("rax") 0u64 => ssp,
            options(nomem, nostack, preserves_flags),
        );
    }
    ssp == 0
}
