// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/mitigation.rs

//! x86-64 user-to-kernel transient-execution controls: their selection from
//! the vulnerability table, their per-CPU application, and the flags and
//! sequences the entry and exit code runs.
//!
//! [`Inputs::of`] reduces the boot CPU's enumeration and
//! [`VulnerabilityTable`] to the facts the selection reads, and [`select`]
//! maps them to the [`Controls`] as a pure function of them. [`install`]
//! publishes the selection once, on the boot CPU in Phase 1, before any AP
//! starts or any thread enters user mode; [`apply_this_cpu`] sets the MSR
//! controls on each CPU in its bring-up. The rules and their vendor sources are
//! core/kernel/docs/transient-execution.md § Controls.
//!
//! The entry and exit code reads the selection through flag bytes: the stubs
//! of `idt.rs`, `syscall.rs` and `context.rs` name [`verw_asm`]'s flag and
//! selector and call `seraph_clear_branch_history` by their link names, and
//! the compiler's retpoline calls reach `__x86_indirect_thunk_r11` by the
//! name LLVM gives it (`-Zretpoline-external-thunk`, set by
//! `cargo xtask build` for the x86-64 kernel).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ::syscall::{
    SPECULATION_CONTROL_AUTO_IBRS, SPECULATION_CONTROL_BHB_CLEAR, SPECULATION_CONTROL_BHI_DIS_S,
    SPECULATION_CONTROL_DOITM, SPECULATION_CONTROL_EIBRS, SPECULATION_CONTROL_RETPOLINE,
    SPECULATION_CONTROL_RSB_FILL_IBPB, SPECULATION_CONTROL_RSB_FILL_SWITCH,
    SPECULATION_CONTROL_VERW_EXIT, SPECULATION_CONTROL_VERW_IDLE, SPECULATION_INPUT_AUTO_IBRS,
    SPECULATION_INPUT_BHI, SPECULATION_INPUT_BHI_CTRL, SPECULATION_INPUT_DOITM,
    SPECULATION_INPUT_IBPB_LEAVES_RSB, SPECULATION_INPUT_IBRS_ALL, SPECULATION_INPUT_MDS,
    SPECULATION_INPUT_MMIO, SPECULATION_INPUT_RFDS, SPECULATION_INPUT_RSB_ALTERNATE,
    SPECULATION_INPUT_SPECTRE_V2, SPECULATION_INPUT_TAA, SPECULATION_INPUT_TSA,
};

use super::vulnerability::{Behaviour, Class, CpuEnumeration, Exposure, VulnerabilityTable};

// ── Selection ─────────────────────────────────────────────────────────────────

/// The facts the selection reads, as a `SPECULATION_INPUT_*` set: the classes
/// the table gives kernel action that a control answers, the two predictor
/// behaviours, and the enumerated bits that choose between the controls that
/// answer one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs(u64);

impl Inputs
{
    /// The inputs of the CPU `cpu` whose table is `table`.
    pub fn of(cpu: &CpuEnumeration, table: &VulnerabilityTable) -> Self
    {
        let classes = [
            (Class::SpectreV2, SPECULATION_INPUT_SPECTRE_V2),
            (Class::Bhi, SPECULATION_INPUT_BHI),
            (Class::Mds, SPECULATION_INPUT_MDS),
            (Class::TsxAsyncAbort, SPECULATION_INPUT_TAA),
            (Class::MmioStaleData, SPECULATION_INPUT_MMIO),
            (Class::RegFileDataSampling, SPECULATION_INPUT_RFDS),
            (Class::Tsa, SPECULATION_INPUT_TSA),
        ];
        let behaviours = [
            (Behaviour::RsbAlternate, SPECULATION_INPUT_RSB_ALTERNATE),
            (Behaviour::IbpbLeavesRsb, SPECULATION_INPUT_IBPB_LEAVES_RSB),
        ];
        let enumerated = [
            (cpu.ibrs_all(), SPECULATION_INPUT_IBRS_ALL),
            (cpu.auto_ibrs(), SPECULATION_INPUT_AUTO_IBRS),
            (cpu.bhi_ctrl(), SPECULATION_INPUT_BHI_CTRL),
            (cpu.doitm(), SPECULATION_INPUT_DOITM),
        ];
        let mut bits = 0;
        for (class, bit) in classes
        {
            if table.exposure(class) == Exposure::Kernel
            {
                bits |= bit;
            }
        }
        for (behaviour, bit) in behaviours
        {
            if table.has(behaviour)
            {
                bits |= bit;
            }
        }
        for (holds, bit) in enumerated
        {
            if holds
            {
                bits |= bit;
            }
        }
        Self(bits)
    }

    /// The `SPECULATION_INPUT_*` set.
    pub fn bits(self) -> u64
    {
        self.0
    }

    /// Whether any input of `bits` holds.
    fn any(self, bits: u64) -> bool
    {
        self.0 & bits != 0
    }
}

/// The selected controls, as a `SPECULATION_CONTROL_*` set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controls(u64);

impl Controls
{
    /// The `SPECULATION_CONTROL_*` set.
    pub fn bits(self) -> u64
    {
        self.0
    }

    /// Whether every control of `bits` is selected.
    pub fn has(self, bits: u64) -> bool
    {
        self.0 & bits == bits
    }
}

/// The controls `inputs` select (core/kernel/docs/transient-execution.md
/// § Controls).
///
/// - Branch target injection, where the table gives it kernel action:
///   enhanced IBRS where the CPU enumerates it, else Automatic IBRS where an
///   AMD CPU enumerates it, else the retpoline sequence.
/// - Branch history injection, where the table gives it kernel action:
///   `BHI_DIS_S` where the CPU implements it, else the clearing sequence on
///   every entry from user mode.
/// - `VERW` on every return to user mode where microarchitectural data
///   sampling, TSX asynchronous abort, MMIO stale data, register file data
///   sampling or transient scheduler attacks reach the kernel; before the idle
///   halt as well where microarchitectural data sampling or transient
///   scheduler attacks do.
/// - The return stack buffer fill on context switch where the retpoline
///   sequence is selected and returns fall back to an alternate predictor,
///   and after an IBPB where an IBPB leaves the buffer usable.
/// - `DOITM` where the CPU implements it.
pub fn select(inputs: Inputs) -> Controls
{
    let mut bits = 0;
    if inputs.any(SPECULATION_INPUT_SPECTRE_V2)
    {
        bits |= if inputs.any(SPECULATION_INPUT_IBRS_ALL)
        {
            SPECULATION_CONTROL_EIBRS
        }
        else if inputs.any(SPECULATION_INPUT_AUTO_IBRS)
        {
            SPECULATION_CONTROL_AUTO_IBRS
        }
        else
        {
            SPECULATION_CONTROL_RETPOLINE
        };
    }
    if inputs.any(SPECULATION_INPUT_BHI)
    {
        bits |= if inputs.any(SPECULATION_INPUT_BHI_CTRL)
        {
            SPECULATION_CONTROL_BHI_DIS_S
        }
        else
        {
            SPECULATION_CONTROL_BHB_CLEAR
        };
    }
    if inputs.any(
        SPECULATION_INPUT_MDS
            | SPECULATION_INPUT_TAA
            | SPECULATION_INPUT_MMIO
            | SPECULATION_INPUT_RFDS
            | SPECULATION_INPUT_TSA,
    )
    {
        bits |= SPECULATION_CONTROL_VERW_EXIT;
    }
    if inputs.any(SPECULATION_INPUT_MDS | SPECULATION_INPUT_TSA)
    {
        bits |= SPECULATION_CONTROL_VERW_IDLE;
    }
    if bits & SPECULATION_CONTROL_RETPOLINE != 0 && inputs.any(SPECULATION_INPUT_RSB_ALTERNATE)
    {
        bits |= SPECULATION_CONTROL_RSB_FILL_SWITCH;
    }
    if inputs.any(SPECULATION_INPUT_IBPB_LEAVES_RSB)
    {
        bits |= SPECULATION_CONTROL_RSB_FILL_IBPB;
    }
    if inputs.any(SPECULATION_INPUT_DOITM)
    {
        bits |= SPECULATION_CONTROL_DOITM;
    }
    Controls(bits)
}

/// Every control, with its name in the serial log, in `SPECULATION_CONTROL_*`
/// bit order.
const CONTROL_NAMES: [(u64, &str); 10] = [
    (SPECULATION_CONTROL_EIBRS, "eibrs"),
    (SPECULATION_CONTROL_AUTO_IBRS, "auto_ibrs"),
    (SPECULATION_CONTROL_RETPOLINE, "retpoline"),
    (SPECULATION_CONTROL_BHI_DIS_S, "bhi_dis_s"),
    (SPECULATION_CONTROL_BHB_CLEAR, "bhb_clear"),
    (SPECULATION_CONTROL_VERW_EXIT, "verw_exit"),
    (SPECULATION_CONTROL_VERW_IDLE, "verw_idle"),
    (SPECULATION_CONTROL_RSB_FILL_SWITCH, "rsb_fill_switch"),
    (SPECULATION_CONTROL_RSB_FILL_IBPB, "rsb_fill_ibpb"),
    (SPECULATION_CONTROL_DOITM, "doitm"),
];

/// The names of the controls `controls` selects, space-separated, or `none`.
struct ControlList(Controls);

impl core::fmt::Display for ControlList
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        let mut any = false;
        for (bit, name) in CONTROL_NAMES
        {
            if self.0.has(bit)
            {
                if any
                {
                    f.write_str(" ")?;
                }
                f.write_str(name)?;
                any = true;
            }
        }
        if !any
        {
            f.write_str("none")?;
        }
        Ok(())
    }
}

// ── The installed selection ───────────────────────────────────────────────────

/// The boot CPU's inputs, written once by [`install`].
static INPUTS: AtomicU64 = AtomicU64::new(0);

/// The selected controls, written once by [`install`].
static SELECTED: AtomicU64 = AtomicU64::new(0);

/// Set when [`SPECULATION_CONTROL_RETPOLINE`] is selected: the retpoline thunk
/// takes the retpoline sequence. A byte the thunk reads.
static RETPOLINE: AtomicBool = AtomicBool::new(false);

/// Set when [`SPECULATION_CONTROL_BHB_CLEAR`] is selected: the clearing
/// routine runs the sequence. A byte the routine reads.
static BHB_CLEAR: AtomicBool = AtomicBool::new(false);

/// Set when [`SPECULATION_CONTROL_RSB_FILL_SWITCH`] is selected: `switch`
/// fills the return stack buffer. A byte `switch` reads.
pub(super) static RSB_FILL_ON_SWITCH: AtomicBool = AtomicBool::new(false);

/// Set when [`SPECULATION_CONTROL_VERW_IDLE`] is selected: the idle halt runs
/// `VERW` first.
static VERW_BEFORE_IDLE: AtomicBool = AtomicBool::new(false);

/// Set when [`SPECULATION_CONTROL_VERW_EXIT`] is selected: every return to user
/// mode runs `VERW`. A byte [`verw_asm`] reads by its link name.
#[unsafe(no_mangle)]
static SERAPH_VERW_ON_EXIT: AtomicBool = AtomicBool::new(false);

/// The memory operand of every `VERW`: a writable data-segment selector, the
/// kernel's data segment, as Intel's MDS guidance asks. Read by [`verw_asm`]
/// by its link name.
#[cfg(not(test))]
#[unsafe(no_mangle)]
static SERAPH_VERW_SELECTOR: u16 = super::gdt::KERNEL_DS;

/// Publish `controls`, selected from `inputs`: the selection word every CPU
/// applies and the flags the entry and exit code read.
///
/// Called once, on the boot CPU in Phase 1, before any AP starts and before
/// any thread enters user mode, so every later reader sees the stores.
pub fn install(inputs: Inputs, controls: Controls)
{
    INPUTS.store(inputs.bits(), Ordering::Relaxed);
    SELECTED.store(controls.bits(), Ordering::Relaxed);
    RETPOLINE.store(
        controls.has(SPECULATION_CONTROL_RETPOLINE),
        Ordering::Relaxed,
    );
    BHB_CLEAR.store(
        controls.has(SPECULATION_CONTROL_BHB_CLEAR),
        Ordering::Relaxed,
    );
    RSB_FILL_ON_SWITCH.store(
        controls.has(SPECULATION_CONTROL_RSB_FILL_SWITCH),
        Ordering::Relaxed,
    );
    VERW_BEFORE_IDLE.store(
        controls.has(SPECULATION_CONTROL_VERW_IDLE),
        Ordering::Relaxed,
    );
    SERAPH_VERW_ON_EXIT.store(
        controls.has(SPECULATION_CONTROL_VERW_EXIT),
        Ordering::Relaxed,
    );
}

/// Log the selected controls, and a warning when `VERW` is selected on a CPU
/// that does not enumerate that it clears the buffers.
#[cfg(not(test))]
pub fn report(cpu: &CpuEnumeration, controls: Controls)
{
    crate::kprintln!("x86 mitigations: {}", ControlList(controls));
    if controls.has(SPECULATION_CONTROL_VERW_EXIT) && !cpu.verw_clears()
    {
        crate::kprintln!(
            "x86 mitigations: VERW selected, but the CPU enumerates no buffer clearing \
             (MD_CLEAR, RFDS_CLEAR, VERW_CLEAR): its microcode clears nothing"
        );
    }
}

// ── Per-CPU MSR controls ──────────────────────────────────────────────────────

/// `IA32_SPEC_CTRL`.
const IA32_SPEC_CTRL: u32 = 0x48;
/// `IA32_SPEC_CTRL.IBRS`.
const SPEC_CTRL_IBRS: u64 = 1 << 0;
/// `IA32_SPEC_CTRL.BHI_DIS_S`.
const SPEC_CTRL_BHI_DIS_S: u64 = 1 << 10;
/// `IA32_EFER`.
const IA32_EFER: u32 = 0xC000_0080;
/// `EFER.AIBRSE`, Automatic IBRS enable (AMD).
const EFER_AIBRSE: u64 = 1 << 21;
/// `IA32_UARCH_MISC_CTL`.
const IA32_UARCH_MISC_CTL: u32 = 0x1B01;
/// `IA32_UARCH_MISC_CTL.DOITM`.
const UARCH_MISC_CTL_DOITM: u64 = 1 << 0;

/// The MSR bits the selected `controls` set: one entry per MSR, with the bits
/// in it, empty bits for an MSR no control writes.
fn msr_bits(controls: Controls) -> [(u32, u64); 3]
{
    let pick = |control: u64, bit: u64| if controls.has(control) { bit } else { 0 };
    [
        (
            IA32_SPEC_CTRL,
            pick(SPECULATION_CONTROL_EIBRS, SPEC_CTRL_IBRS)
                | pick(SPECULATION_CONTROL_BHI_DIS_S, SPEC_CTRL_BHI_DIS_S),
        ),
        (IA32_EFER, pick(SPECULATION_CONTROL_AUTO_IBRS, EFER_AIBRSE)),
        (
            IA32_UARCH_MISC_CTL,
            pick(SPECULATION_CONTROL_DOITM, UARCH_MISC_CTL_DOITM),
        ),
    ]
}

/// Set this CPU's MSR controls of the installed selection: enhanced IBRS and
/// `BHI_DIS_S` in `IA32_SPEC_CTRL`, Automatic IBRS in `EFER`, and `DOITM` in
/// `IA32_UARCH_MISC_CTL`, each by a read-modify-write that keeps the MSR's
/// other bits. Each is per logical processor, so every CPU sets its own.
///
/// # Safety
/// Ring 0, on the CPU being brought up, after [`install`], with the boot CPU's
/// enumeration holding for this CPU (core/kernel/docs/transient-execution.md
/// § Inputs): a control is selected only where the boot CPU implements its
/// MSR, so neither the read nor the write faults.
#[cfg(not(test))]
pub unsafe fn apply_this_cpu()
{
    let controls = Controls(SELECTED.load(Ordering::Relaxed));
    for (msr, bits) in msr_bits(controls)
    {
        if bits == 0
        {
            continue;
        }
        // SAFETY: ring 0; a selected control implies the boot CPU implements
        // `msr` (`select`), and this CPU's enumeration is the boot CPU's
        // (caller's contract).
        let value = unsafe { super::cpu::read_msr(msr) };
        // SAFETY: as for the read; the write sets only the control's bits, which
        // the implemented MSR defines, and keeps every other bit.
        unsafe { super::cpu::write_msr(msr, value | bits) };
    }
}

/// The controls in effect on the calling CPU, a `SPECULATION_CONTROL_*` set:
/// the MSR controls as this CPU's MSRs hold them, read where the boot CPU
/// implements the MSR, and the others as the flags the entry and exit code
/// test hold them. The fill after an IBPB is reported as selected: the kernel
/// issues no IBPB, so no IBPB is left without it.
#[cfg(not(test))]
pub fn in_effect() -> u64
{
    let inputs = Inputs(INPUTS.load(Ordering::Relaxed));
    let selected = Controls(SELECTED.load(Ordering::Relaxed));
    let mut bits = 0;
    let mut read_bits = |msr: u32, controls: &[(u64, u64)]| {
        // SAFETY: ring 0; the callers below read only an MSR the boot CPU
        // implements, which every CPU does (core/kernel/docs/transient-execution.md
        // § Inputs).
        let value = unsafe { super::cpu::read_msr(msr) };
        for &(control, bit) in controls
        {
            if value & bit != 0
            {
                bits |= control;
            }
        }
    };
    if inputs.any(SPECULATION_INPUT_IBRS_ALL | SPECULATION_INPUT_BHI_CTRL)
    {
        read_bits(
            IA32_SPEC_CTRL,
            &[
                (SPECULATION_CONTROL_EIBRS, SPEC_CTRL_IBRS),
                (SPECULATION_CONTROL_BHI_DIS_S, SPEC_CTRL_BHI_DIS_S),
            ],
        );
    }
    read_bits(IA32_EFER, &[(SPECULATION_CONTROL_AUTO_IBRS, EFER_AIBRSE)]);
    if inputs.any(SPECULATION_INPUT_DOITM)
    {
        read_bits(
            IA32_UARCH_MISC_CTL,
            &[(SPECULATION_CONTROL_DOITM, UARCH_MISC_CTL_DOITM)],
        );
    }
    let flags = [
        (&RETPOLINE, SPECULATION_CONTROL_RETPOLINE),
        (&BHB_CLEAR, SPECULATION_CONTROL_BHB_CLEAR),
        (&SERAPH_VERW_ON_EXIT, SPECULATION_CONTROL_VERW_EXIT),
        (&VERW_BEFORE_IDLE, SPECULATION_CONTROL_VERW_IDLE),
        (&RSB_FILL_ON_SWITCH, SPECULATION_CONTROL_RSB_FILL_SWITCH),
    ];
    for (flag, control) in flags
    {
        if flag.load(Ordering::Relaxed)
        {
            bits |= control;
        }
    }
    bits | (selected.bits() & SPECULATION_CONTROL_RSB_FILL_IBPB)
}

/// One word of the mitigation state for `SYS_SYSTEM_INFO`
/// (`SystemInfoType::SpeculationControls`): the view `view` names
/// (`SPECULATION_VIEW_*`), or `None` for an unknown view.
#[cfg(not(test))]
pub fn info(view: u64) -> Option<u64>
{
    match view
    {
        ::syscall::SPECULATION_VIEW_INPUTS => Some(INPUTS.load(Ordering::Relaxed)),
        ::syscall::SPECULATION_VIEW_SELECTED => Some(SELECTED.load(Ordering::Relaxed)),
        ::syscall::SPECULATION_VIEW_IN_EFFECT => Some(in_effect()),
        _ => None,
    }
}

/// `VERW` before the idle halt, where the selection asks for it.
#[cfg(not(test))]
#[inline]
pub fn verw_before_idle()
{
    if VERW_BEFORE_IDLE.load(Ordering::Relaxed)
    {
        // SAFETY: `VERW` with a memory operand checks whether the selector is
        // writable and, on a CPU with the clearing, overwrites the buffers; it
        // reads the two-byte selector static and writes only ZF (`nostack`; not
        // `preserves_flags`). The selector is the kernel's data segment, which
        // the loaded GDT holds, so it does not fault.
        unsafe {
            core::arch::asm!(
                "verw word ptr [rip + {sel}]",
                sel = sym SERAPH_VERW_SELECTOR,
                options(nostack, readonly),
            );
        }
    }
}

// ── Entry and exit sequences ──────────────────────────────────────────────────

/// Naked-asm fragment: `VERW` when [`SPECULATION_CONTROL_VERW_EXIT`] is
/// selected. Placed after the last register restore and the GS swap of every
/// return to user mode, so no kernel load follows it before `iretq` or
/// `sysretq`. Clobbers RFLAGS only, which both instructions reload (`iretq`
/// from its frame, `sysretq` from R11); reads no register.
#[cfg(not(test))]
macro_rules! verw_asm {
    () => {
        concat!(
            "cmp byte ptr [rip + SERAPH_VERW_ON_EXIT], 0\n",
            "je 90f\n",
            "verw word ptr [rip + SERAPH_VERW_SELECTOR]\n",
            "90:\n",
        )
    };
}
#[cfg(not(test))]
pub(super) use verw_asm;

// The retpoline thunk and the branch history clearing routine.
//
// `__x86_indirect_thunk_r11` is the target of every indirect call and jump the
// compiler emits for the kernel (`-Zretpoline-external-thunk`), with the branch
// target in R11. With the retpoline sequence selected it runs it: the `call`
// pushes a return address whose `ret` the return stack buffer predicts into
// the `pause; lfence` trap, and the `ret` itself goes to R11, so no branch
// target buffer prediction steers the branch. Otherwise it jumps to R11 after
// an `lfence`, which keeps a mispredicted test of the flag from running the
// plain jump on a part that needs the sequence.
//
// `seraph_clear_branch_history` runs Intel's branch history clearing sequence
// (the long form, 12 outer and 7 inner iterations, which covers the short form's
// parts as well) when the clearing is selected, and returns. Its calls and
// returns pair up, so it runs on a supervisor shadow stack too. It clobbers EAX,
// ECX and RFLAGS and needs a stack; both of its paths end in `lfence`, so no
// later instruction runs before the flag's test resolves.
#[cfg(not(test))]
core::arch::global_asm!(
    ".pushsection .text.seraph_mitigation, \"ax\"",
    ".global __x86_indirect_thunk_r11",
    ".p2align 4",
    "__x86_indirect_thunk_r11:",
    "    cmp byte ptr [rip + {retpoline}], 0",
    "    jne 2f",
    "    lfence",
    "    jmp r11",
    "2:",
    "    call 4f",
    "3:",
    "    pause",
    "    lfence",
    "    jmp 3b",
    "4:",
    "    mov [rsp], r11",
    "    ret",
    ".global seraph_clear_branch_history",
    ".p2align 4",
    "seraph_clear_branch_history:",
    "    cmp byte ptr [rip + {bhb_clear}], 0",
    "    je 6f",
    "    mov ecx, 12",
    "    call 7f",
    "    jmp 6f",
    "    .p2align 6, 0xcc",
    "7:",
    "    call 8f",
    "    ret",
    "    .p2align 6, 0xcc",
    "8:",
    "    mov eax, 7",
    "9:",
    "    jmp 10f",
    "    nop",
    "10:",
    "    dec eax",
    "    jnz 9b",
    "    dec ecx",
    "    jnz 7b",
    "    ret",
    "6:",
    "    lfence",
    "    ret",
    ".popsection",
    retpoline = sym RETPOLINE,
    bhb_clear = sym BHB_CLEAR,
);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use super::super::vulnerability::{Vendor, derive};

    /// A CPU of `vendor` with `CPUID.01H:EAX` = `signature` and every other
    /// input zero; the vectors below set the words they need.
    fn cpu(vendor: Vendor, signature: u32) -> CpuEnumeration
    {
        CpuEnumeration {
            vendor,
            signature,
            leaf7_ebx: 0,
            leaf7_edx: 0,
            leaf7_2_edx: 0,
            ext8_ebx: 0,
            ext21_eax: 0,
            ext21_ecx: 0,
            arch_capabilities: 0,
        }
    }

    /// The controls the CPU `cpu` selects, through its derived table.
    fn controls_of(cpu: &CpuEnumeration) -> u64
    {
        select(Inputs::of(cpu, &derive(cpu))).bits()
    }

    // Defect caught: a selection that misses a control the development host's
    // table asks for (enhanced IBRS, BHI_DIS_S, VERW for RFDS), or adds one it
    // does not. The CPU is the Alder Lake vector of the vulnerability table's tests, the i9-12900K the
    // development host passes to a KVM guest (`vulnerability::tests::alder_lake`).
    #[test]
    fn development_host_selects_eibrs_bhi_dis_s_and_verw()
    {
        let mut host = cpu(Vendor::Intel, 0x0009_0672);
        host.leaf7_edx = 1 << 29;
        host.leaf7_2_edx = 0x17;
        host.arch_capabilities = 0x4000_0000_1400_E06B;
        assert_eq!(
            controls_of(&host),
            SPECULATION_CONTROL_EIBRS
                | SPECULATION_CONTROL_BHI_DIS_S
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: a part with neither enhanced nor Automatic IBRS left
    // without the retpoline sequence. The CPU is the one QEMU's TCG presents to
    // the CI boots: `AuthenticAMD` family 6, `Fn8000_0008 EBX` 204H (no
    // `IBPB_RET`), `Fn8000_0021 EAX` 41H (no Automatic IBRS).
    #[test]
    fn tcg_selects_retpoline()
    {
        let mut tcg = cpu(Vendor::Amd, 0x0000_0663);
        tcg.ext8_ebx = 0x204;
        tcg.ext21_eax = 0x41;
        assert_eq!(
            controls_of(&tcg),
            SPECULATION_CONTROL_RETPOLINE | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: an AMD part that enumerates Automatic IBRS given the
    // retpoline sequence instead, or a Family 19h part (transient scheduler
    // attacks, AMD-SB-7029) left without VERW on exit and before the idle halt.
    // Zen 4, family 19h model 61H, with Automatic IBRS and `VERW_CLEAR`.
    #[test]
    fn zen4_selects_auto_ibrs_and_verw()
    {
        let mut zen4 = cpu(Vendor::Amd, 0x00A6_0F12);
        zen4.ext21_eax = (1 << 8) | (1 << 5);
        assert_eq!(
            controls_of(&zen4),
            SPECULATION_CONTROL_AUTO_IBRS
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_VERW_IDLE
                | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: Zen 3 (family 19h model 21H, no Automatic IBRS) given no
    // branch target injection control: it takes the retpoline sequence, AMD's
    // recommendation for it (AMD-SB-1036).
    #[test]
    fn zen3_selects_retpoline()
    {
        let zen3 = cpu(Vendor::Amd, 0x00A2_0F10);
        assert_eq!(
            controls_of(&zen3),
            SPECULATION_CONTROL_RETPOLINE
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_VERW_IDLE
                | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: Zen 2 (EPYC 7002, family 17h model 31H, the
    // `vulnerability::tests::amd_zen2` vector: no Automatic IBRS, no `IBPB_RET`) given anything but
    // the retpoline sequence and the fill after an IBPB: AMD names no data
    // sampling class for it, so no VERW.
    #[test]
    fn zen2_selects_retpoline()
    {
        let zen2 = cpu(Vendor::Amd, 0x0083_0F10);
        assert_eq!(
            controls_of(&zen2),
            SPECULATION_CONTROL_RETPOLINE | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: a part whose returns fall back to the branch target buffer
    // left without the switch fill in the retpoline build, or given the
    // clearing sequence or VERW its table does not ask for. Ice Lake U/Y
    // (06_7EH stepping 5) and Comet Lake (06_A5H, 06_A6H) as the vulnerability table's
    // tests give them, with no `IA32_ARCH_CAPABILITIES` bit: branch history injection
    // without `BHI_CTRL`, and microarchitectural data sampling mitigated by
    // microcode (Ice Lake) or not affected (Comet Lake).
    #[test]
    fn ice_lake_and_comet_lake_select_retpoline_fill_and_clearing()
    {
        for signature in [0x0007_06E5, 0x000A_0652, 0x000A_0660]
        {
            let mut part = cpu(Vendor::Intel, signature);
            part.leaf7_edx = 1 << 29;
            assert_eq!(
                controls_of(&part),
                SPECULATION_CONTROL_RETPOLINE
                    | SPECULATION_CONTROL_BHB_CLEAR
                    | SPECULATION_CONTROL_RSB_FILL_SWITCH
                    | SPECULATION_CONTROL_RSB_FILL_IBPB,
                "signature {signature:#x}"
            );
            part.arch_capabilities = 1 << 1;
            assert_eq!(
                controls_of(&part),
                SPECULATION_CONTROL_EIBRS
                    | SPECULATION_CONTROL_BHB_CLEAR
                    | SPECULATION_CONTROL_RSB_FILL_IBPB,
                "signature {signature:#x} with IBRS_ALL"
            );
        }
    }

    // Defect caught: a part that reports every `*_NO` bit given a control
    // whose class the bits rule out. The `vulnerability::tests::every_no_bit`
    // vectors: on
    // Intel only Spectre v2 and `retbleed` (no `*_NO` bit) remain, with
    // returns falling back; on AMD only Spectre v2.
    #[test]
    fn every_no_bit_part_selects_only_branch_target_controls()
    {
        let mut intel = cpu(Vendor::Intel, 0x000B_06F0);
        intel.leaf7_edx = 1 << 29;
        intel.leaf7_ebx = 1 << 11;
        intel.arch_capabilities = (1 << 0)
            | (1 << 4)
            | (1 << 5)
            | (1 << 8)
            | (1 << 13)
            | (1 << 14)
            | (1 << 15)
            | (1 << 20)
            | (1 << 24)
            | (1 << 26)
            | (1 << 27)
            | (1 << 62);
        assert_eq!(
            controls_of(&intel),
            SPECULATION_CONTROL_RETPOLINE | SPECULATION_CONTROL_RSB_FILL_SWITCH
        );
        let mut amd = cpu(Vendor::Amd, 0x00B0_0F21);
        amd.ext8_ebx = (1 << 26) | (1 << 29) | (1 << 30);
        amd.ext21_eax = (1 << 29) | (1 << 30) | (1 << 8);
        amd.ext21_ecx = (1 << 1) | (1 << 2) | (1 << 7);
        assert_eq!(controls_of(&amd), SPECULATION_CONTROL_AUTO_IBRS);
    }

    // Defect caught: a CPU of another vendor, whose table gives every class
    // kernel action, left without a software control.
    #[test]
    fn other_vendor_selects_every_software_control()
    {
        let other = cpu(Vendor::Other, 0x0009_0672);
        assert_eq!(
            controls_of(&other),
            SPECULATION_CONTROL_RETPOLINE
                | SPECULATION_CONTROL_BHB_CLEAR
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_VERW_IDLE
                | SPECULATION_CONTROL_RSB_FILL_SWITCH
                | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: a part whose table gives every class kernel action and both
    // behaviours (an Intel model Intel's list does not name, and no
    // `IA32_ARCH_CAPABILITIES`) missing a control: the retpoline sequence with
    // the switch fill (returns fall back to an alternate predictor), the branch
    // history clearing (no `BHI_CTRL`), and VERW on exit and before the idle
    // halt (MDS).
    #[test]
    fn unlisted_intel_part_selects_every_software_control()
    {
        let unlisted = cpu(Vendor::Intel, 0x000F_FFF0);
        assert_eq!(
            controls_of(&unlisted),
            SPECULATION_CONTROL_RETPOLINE
                | SPECULATION_CONTROL_BHB_CLEAR
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_VERW_IDLE
                | SPECULATION_CONTROL_RSB_FILL_SWITCH
                | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
    }

    // Defect caught: an input read from the wrong class, behaviour or bit.
    #[test]
    fn inputs_follow_the_table_and_the_enumeration()
    {
        let mut host = cpu(Vendor::Intel, 0x0009_0672);
        host.leaf7_edx = 1 << 29;
        host.leaf7_2_edx = 0x17;
        host.arch_capabilities = 0x4000_0000_1400_E06B | (1 << 12);
        assert_eq!(
            Inputs::of(&host, &derive(&host)).bits(),
            SPECULATION_INPUT_SPECTRE_V2
                | SPECULATION_INPUT_BHI
                | SPECULATION_INPUT_RFDS
                | SPECULATION_INPUT_IBPB_LEAVES_RSB
                | SPECULATION_INPUT_IBRS_ALL
                | SPECULATION_INPUT_BHI_CTRL
                | SPECULATION_INPUT_DOITM
        );
    }

    // Defect caught: a rule that selects a control without its class, picks the
    // wrong one of two controls for a class, or ties a control to the wrong
    // input. Each case is one input set and the controls it selects.
    #[test]
    fn each_rule_selects_its_control()
    {
        let cases: [(u64, u64); 14] = [
            (0, 0),
            (SPECULATION_INPUT_IBRS_ALL | SPECULATION_INPUT_AUTO_IBRS, 0),
            (
                SPECULATION_INPUT_SPECTRE_V2
                    | SPECULATION_INPUT_IBRS_ALL
                    | SPECULATION_INPUT_AUTO_IBRS,
                SPECULATION_CONTROL_EIBRS,
            ),
            (
                SPECULATION_INPUT_SPECTRE_V2 | SPECULATION_INPUT_AUTO_IBRS,
                SPECULATION_CONTROL_AUTO_IBRS,
            ),
            (SPECULATION_INPUT_SPECTRE_V2, SPECULATION_CONTROL_RETPOLINE),
            (
                SPECULATION_INPUT_SPECTRE_V2 | SPECULATION_INPUT_RSB_ALTERNATE,
                SPECULATION_CONTROL_RETPOLINE | SPECULATION_CONTROL_RSB_FILL_SWITCH,
            ),
            (
                SPECULATION_INPUT_SPECTRE_V2
                    | SPECULATION_INPUT_IBRS_ALL
                    | SPECULATION_INPUT_RSB_ALTERNATE,
                SPECULATION_CONTROL_EIBRS,
            ),
            (SPECULATION_INPUT_BHI_CTRL, 0),
            (
                SPECULATION_INPUT_BHI | SPECULATION_INPUT_BHI_CTRL,
                SPECULATION_CONTROL_BHI_DIS_S,
            ),
            (SPECULATION_INPUT_BHI, SPECULATION_CONTROL_BHB_CLEAR),
            (
                SPECULATION_INPUT_TAA | SPECULATION_INPUT_MMIO | SPECULATION_INPUT_RFDS,
                SPECULATION_CONTROL_VERW_EXIT,
            ),
            (
                SPECULATION_INPUT_MDS,
                SPECULATION_CONTROL_VERW_EXIT | SPECULATION_CONTROL_VERW_IDLE,
            ),
            (
                SPECULATION_INPUT_IBPB_LEAVES_RSB,
                SPECULATION_CONTROL_RSB_FILL_IBPB,
            ),
            (SPECULATION_INPUT_DOITM, SPECULATION_CONTROL_DOITM),
        ];
        for (inputs, controls) in cases
        {
            assert_eq!(
                select(Inputs(inputs)).bits(),
                controls,
                "inputs {inputs:#x}"
            );
        }
        for class in [SPECULATION_INPUT_TSA, SPECULATION_INPUT_MDS]
        {
            assert!(select(Inputs(class)).has(SPECULATION_CONTROL_VERW_IDLE));
        }
    }

    // Defect caught: a per-CPU write of the wrong MSR or bit, or a write for a
    // control that is not selected.
    #[test]
    fn msr_bits_name_each_controls_register()
    {
        assert_eq!(
            msr_bits(Controls(0)),
            [(0x48, 0), (0xC000_0080, 0), (0x1B01, 0)]
        );
        assert_eq!(
            msr_bits(Controls(
                SPECULATION_CONTROL_EIBRS
                    | SPECULATION_CONTROL_BHI_DIS_S
                    | SPECULATION_CONTROL_AUTO_IBRS
                    | SPECULATION_CONTROL_DOITM
                    | SPECULATION_CONTROL_RETPOLINE
            )),
            [(0x48, 0x401), (0xC000_0080, 1 << 21), (0x1B01, 1)]
        );
    }

    // Defect caught: a log line that drops or misnames a control.
    #[test]
    fn control_list_names_each_control()
    {
        assert_eq!(ControlList(Controls(0)).to_string(), "none");
        assert_eq!(
            ControlList(Controls(
                SPECULATION_CONTROL_EIBRS
                    | SPECULATION_CONTROL_VERW_EXIT
                    | SPECULATION_CONTROL_DOITM
            ))
            .to_string(),
            "eibrs verw_exit doitm"
        );
        let all = CONTROL_NAMES.iter().fold(0, |bits, (bit, _)| bits | bit);
        assert_eq!(all, ::syscall::SPECULATION_CONTROL_ALL);
    }

    // Defect caught: `install` leaving a flag the entry and exit code test out of
    // step with the selection it publishes.
    #[test]
    fn install_sets_each_flag_from_the_selection()
    {
        let controls = Controls(
            SPECULATION_CONTROL_RETPOLINE
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_RSB_FILL_SWITCH,
        );
        install(Inputs(SPECULATION_INPUT_SPECTRE_V2), controls);
        assert!(RETPOLINE.load(Ordering::Relaxed));
        assert!(SERAPH_VERW_ON_EXIT.load(Ordering::Relaxed));
        assert!(RSB_FILL_ON_SWITCH.load(Ordering::Relaxed));
        assert!(!BHB_CLEAR.load(Ordering::Relaxed));
        assert!(!VERW_BEFORE_IDLE.load(Ordering::Relaxed));
        assert_eq!(SELECTED.load(Ordering::Relaxed), controls.bits());
        assert_eq!(INPUTS.load(Ordering::Relaxed), SPECULATION_INPUT_SPECTRE_V2);
    }
}
