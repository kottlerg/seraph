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
//! The entry and exit code reads the selection through flag bytes and the
//! `IA32_SPEC_CTRL` values: the stubs of `idt.rs`, `syscall.rs` and
//! `context.rs` name the statics of [`verw_asm`], [`ibrs_exit_asm`],
//! [`ibrs_paranoid_entry_asm`] and [`ibrs_paranoid_exit_asm`] and call
//! `seraph_enter_from_user` by their link names, and the compiler's retpoline
//! calls reach `__x86_indirect_thunk_r11` by the name LLVM gives it
//! (`-Zretpoline-external-thunk`, set by `cargo xtask build` for the x86-64
//! kernel).
//!
//! A kernel built with `SERAPH_FORCE_RETURN_MITIGATION` set forces the inputs
//! of the return mitigations ([`FORCED_RETURN`]), so that a host whose CPU
//! does not need them runs them.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ::syscall::{
    SPECULATION_CONTROL_AUTO_IBRS, SPECULATION_CONTROL_BHB_CLEAR, SPECULATION_CONTROL_BHI_DIS_S,
    SPECULATION_CONTROL_DOITM, SPECULATION_CONTROL_EIBRS, SPECULATION_CONTROL_IBPB_ENTRY,
    SPECULATION_CONTROL_IBRS_ENTRY, SPECULATION_CONTROL_RETPOLINE,
    SPECULATION_CONTROL_RSB_FILL_IBPB, SPECULATION_CONTROL_RSB_FILL_SWITCH,
    SPECULATION_CONTROL_STIBP, SPECULATION_CONTROL_VERW_EXIT, SPECULATION_CONTROL_VERW_IDLE,
    SPECULATION_INPUT_AUTO_IBRS, SPECULATION_INPUT_BHI, SPECULATION_INPUT_BHI_CTRL,
    SPECULATION_INPUT_DOITM, SPECULATION_INPUT_IBPB, SPECULATION_INPUT_IBPB_LEAVES_BRTYPE,
    SPECULATION_INPUT_IBPB_LEAVES_RSB, SPECULATION_INPUT_IBRS, SPECULATION_INPUT_IBRS_ALL,
    SPECULATION_INPUT_MDS, SPECULATION_INPUT_MMIO, SPECULATION_INPUT_RETBLEED,
    SPECULATION_INPUT_RFDS, SPECULATION_INPUT_RSB_ALTERNATE, SPECULATION_INPUT_SMT,
    SPECULATION_INPUT_SPECTRE_V2, SPECULATION_INPUT_SRSO, SPECULATION_INPUT_STIBP,
    SPECULATION_INPUT_TAA, SPECULATION_INPUT_TSA,
};

use super::vulnerability::{
    Behaviour, Class, CpuEnumeration, Exposure, Vendor, VulnerabilityTable,
};

// ── Selection ─────────────────────────────────────────────────────────────────

/// The facts the selection and the report read, as a `SPECULATION_INPUT_*`
/// set: the classes the table gives kernel action that a control answers, the
/// three predictor behaviours, the enumerated bits that choose between the
/// controls that answer one class or that a control needs, and whether SMT is
/// on.
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
            (Class::Retbleed, SPECULATION_INPUT_RETBLEED),
            (Class::SpecRstackOverflow, SPECULATION_INPUT_SRSO),
        ];
        let behaviours = [
            (Behaviour::RsbAlternate, SPECULATION_INPUT_RSB_ALTERNATE),
            (Behaviour::IbpbLeavesRsb, SPECULATION_INPUT_IBPB_LEAVES_RSB),
            (
                Behaviour::IbpbLeavesBranchType,
                SPECULATION_INPUT_IBPB_LEAVES_BRTYPE,
            ),
        ];
        let enumerated = [
            (cpu.ibrs_all(), SPECULATION_INPUT_IBRS_ALL),
            (cpu.auto_ibrs(), SPECULATION_INPUT_AUTO_IBRS),
            (cpu.bhi_ctrl(), SPECULATION_INPUT_BHI_CTRL),
            (cpu.doitm(), SPECULATION_INPUT_DOITM),
            (cpu.ibrs(), SPECULATION_INPUT_IBRS),
            (cpu.ibpb(), SPECULATION_INPUT_IBPB),
            (cpu.stibp(), SPECULATION_INPUT_STIBP),
            (cpu.smt, SPECULATION_INPUT_SMT),
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

    /// These inputs with the override `force` applied: [`ForcedReturn::Intel`]
    /// adds `retbleed` and `rsb_alternate` and removes `IBRS_ALL`, the inputs
    /// of an Intel part whose returns fall back to the branch target buffer and
    /// that has no enhanced IBRS; [`ForcedReturn::Amd`] adds `retbleed` and
    /// `spec_rstack_overflow` and removes `rsb_alternate`, the inputs of an AMD
    /// part affected by branch type confusion and speculative return stack
    /// overflow. Neither adds an enumerated bit, so a CPU without IBRS or IBPB
    /// still selects no control it cannot run.
    pub fn forced(self, force: ForcedReturn) -> Self
    {
        match force
        {
            ForcedReturn::None => self,
            ForcedReturn::Intel => Self(
                (self.0 | SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_RSB_ALTERNATE)
                    & !SPECULATION_INPUT_IBRS_ALL,
            ),
            ForcedReturn::Amd => Self(
                (self.0 | SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_SRSO)
                    & !SPECULATION_INPUT_RSB_ALTERNATE,
            ),
        }
    }

    /// Whether any input of `bits` holds.
    fn any(self, bits: u64) -> bool
    {
        self.0 & bits != 0
    }

    /// Whether every input of `bits` holds.
    fn has(self, bits: u64) -> bool
    {
        self.0 & bits == bits
    }
}

/// A build-time override of the inputs the return mitigations read
/// ([`Inputs::forced`]), so that the development host, whose CPU needs none
/// of them, runs them and measures their cost
/// (core/kernel/docs/transient-execution.md § Forced return mitigations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForcedReturn
{
    /// No override: the inputs are the CPU's.
    None,
    /// The inputs of an Intel part that the table gives `retbleed` kernel
    /// action, without enhanced IBRS.
    Intel,
    /// The inputs of an AMD part that the table gives `retbleed` (branch type
    /// confusion) and `spec_rstack_overflow` kernel action; the boot also
    /// makes the `SBPB` probe and every CPU the `DE_CFG` step, whatever its
    /// vendor, so that a host refusing them runs their recovery.
    Amd,
}

/// The override named by `value`, the build's
/// `SERAPH_FORCE_RETURN_MITIGATION`: unset or empty for none, `intel` for
/// [`ForcedReturn::Intel`], `amd` for [`ForcedReturn::Amd`].
///
/// # Panics
/// On any other value; evaluated for [`FORCED_RETURN`], the panic fails the
/// build.
#[expect(
    clippy::panic,
    reason = "the kernel evaluates it only for the const FORCED_RETURN, where the panic is a \
              compile error that rejects an unknown build value; no kernel code path reaches it"
)]
pub const fn forced_return(value: Option<&str>) -> ForcedReturn
{
    let Some(value) = value
    else
    {
        return ForcedReturn::None;
    };
    match value.as_bytes()
    {
        b"" => ForcedReturn::None,
        b"intel" => ForcedReturn::Intel,
        b"amd" => ForcedReturn::Amd,
        _ => panic!("SERAPH_FORCE_RETURN_MITIGATION is neither unset, empty, `intel` nor `amd`"),
    }
}

/// The override this kernel was built with: `SERAPH_FORCE_RETURN_MITIGATION`
/// in the environment of `cargo xtask build` (core/kernel/docs/transient-execution.md
/// § Forced return mitigations).
pub const FORCED_RETURN: ForcedReturn =
    forced_return(option_env!("SERAPH_FORCE_RETURN_MITIGATION"));

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

    /// Whether a selected control rewrites a return, which keeps the kernel
    /// off shadow stacks (`shadow_stack::decide`;
    /// core/kernel/docs/return-address-integrity.md § x86-64 Mechanism): the
    /// mitigation of an enumerated vulnerability takes precedence over
    /// return-address integrity.
    pub fn rewrites_returns(self) -> bool
    {
        self.0 & RETURN_REWRITING != 0
    }
}

/// The controls `inputs` select (core/kernel/docs/transient-execution.md
/// § Controls).
///
/// - Branch target injection, where the table gives it kernel action, and
///   `retbleed` on a part whose returns fall back to an alternate predictor:
///   enhanced IBRS where the CPU enumerates it; else, for `retbleed` on such
///   a part, IBRS on every entry from user mode where the CPU implements IBRS;
///   else Automatic IBRS where an AMD CPU enumerates it; else, for branch target
///   injection, the retpoline sequence.
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
/// - An IBPB on every entry from user mode where the CPU implements an IBPB
///   that flushes branch types and the table gives kernel action to
///   `retbleed` whose returns do not fall back to an alternate predictor
///   (AMD's branch type confusion) or to speculative return stack overflow;
///   with it, STIBP where the CPU implements it.
pub fn select(inputs: Inputs) -> Controls
{
    let mut bits = 0;
    let spectre_v2 = inputs.any(SPECULATION_INPUT_SPECTRE_V2);
    let return_fallback = inputs.has(SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_RSB_ALTERNATE);
    if spectre_v2 || return_fallback
    {
        bits |= if inputs.any(SPECULATION_INPUT_IBRS_ALL)
        {
            SPECULATION_CONTROL_EIBRS
        }
        else if return_fallback && inputs.any(SPECULATION_INPUT_IBRS)
        {
            SPECULATION_CONTROL_IBRS_ENTRY
        }
        else if !spectre_v2
        {
            0
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
    let branch_type_confusion =
        inputs.any(SPECULATION_INPUT_RETBLEED) && !inputs.any(SPECULATION_INPUT_RSB_ALTERNATE);
    let ibpb_flushes_branch_types =
        inputs.any(SPECULATION_INPUT_IBPB) && !inputs.any(SPECULATION_INPUT_IBPB_LEAVES_BRTYPE);
    if ibpb_flushes_branch_types && (branch_type_confusion || inputs.any(SPECULATION_INPUT_SRSO))
    {
        bits |= SPECULATION_CONTROL_IBPB_ENTRY;
        if inputs.any(SPECULATION_INPUT_STIBP)
        {
            bits |= SPECULATION_CONTROL_STIBP;
        }
    }
    Controls(bits)
}

/// The controls whose code returns to an address the shadow stack does not
/// hold: the retpoline sequence's `ret` goes to the branch target, not to the
/// caller, which raises `#CP` under CET shadow stacks. Every such control
/// excludes shadow stacks ([`Controls::rewrites_returns`]). The IBPB on entry
/// and the fill after it rewrite none: the fill's calls and returns are dropped
/// from both stacks together.
const RETURN_REWRITING: u64 = SPECULATION_CONTROL_RETPOLINE;

/// Every control, with its name in the serial log, in `SPECULATION_CONTROL_*`
/// bit order.
const CONTROL_NAMES: [(u64, &str); 13] = [
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
    (SPECULATION_CONTROL_IBRS_ENTRY, "ibrs_entry"),
    (SPECULATION_CONTROL_IBPB_ENTRY, "ibpb_entry"),
    (SPECULATION_CONTROL_STIBP, "stibp"),
];

/// Why a class the table gives kernel action stays open: the report's
/// reason for each (core/kernel/docs/transient-execution.md § Report).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Open
{
    /// No control the kernel has answers the class on this part.
    NoControl,
    /// The class's control is the IBPB, which the CPU does not implement.
    NoIbpb,
    /// The IBPB does not flush the branch type predictions the class uses: on
    /// AMD Family 19h, the SRSO microcode of AMD-SB-7005 is not loaded.
    IbpbLeavesBranchType,
    /// The IBPB answers the class for this thread, but SMT is on and the CPU
    /// has no STIBP to keep the sibling thread's training out (Zen, Zen+).
    SmtWithoutStibp,
}

impl Open
{
    /// The reason's text in the serial log.
    pub fn text(self) -> &'static str
    {
        match self
        {
            Open::NoControl => "no control answers it",
            Open::NoIbpb => "no IBPB",
            Open::IbpbLeavesBranchType => "IBPB does not flush branch types",
            Open::SmtWithoutStibp => "SMT on without STIBP",
        }
    }
}

/// The classes the table gives kernel action that the selected controls leave
/// vulnerable, by their log names, each with its reason:
///
/// - `retbleed` where its returns fall back to the branch target buffer on an
///   Intel part (`rsb_alternate` with the IBRS input, which is read on Intel
///   parts only) is answered by enhanced IBRS or IBRS on entry; another
///   vendor's `retbleed` of that form, and an Intel part left on the retpoline
///   sequence, have no control.
/// - `retbleed` where they do not (AMD's branch type confusion) and
///   `spec_rstack_overflow` are answered by the IBPB on entry, which needs an
///   IBPB that flushes branch types, and STIBP where SMT is on to keep the
///   sibling thread's training out.
pub fn vulnerable(inputs: Inputs, controls: Controls) -> [Option<(&'static str, Open)>; 2]
{
    let ibpb_open = if !inputs.any(SPECULATION_INPUT_IBPB)
    {
        Some(Open::NoIbpb)
    }
    else if inputs.any(SPECULATION_INPUT_IBPB_LEAVES_BRTYPE)
    {
        Some(Open::IbpbLeavesBranchType)
    }
    else if !controls.has(SPECULATION_CONTROL_IBPB_ENTRY)
    {
        Some(Open::NoControl)
    }
    else if inputs.any(SPECULATION_INPUT_SMT) && !controls.has(SPECULATION_CONTROL_STIBP)
    {
        Some(Open::SmtWithoutStibp)
    }
    else
    {
        None
    };
    let retbleed = if !inputs.any(SPECULATION_INPUT_RETBLEED)
    {
        None
    }
    else if inputs.any(SPECULATION_INPUT_RSB_ALTERNATE)
    {
        let ibrs =
            controls.bits() & (SPECULATION_CONTROL_EIBRS | SPECULATION_CONTROL_IBRS_ENTRY) != 0;
        (!(ibrs && inputs.any(SPECULATION_INPUT_IBRS))).then_some(Open::NoControl)
    }
    else
    {
        ibpb_open
    };
    let srso = if inputs.any(SPECULATION_INPUT_SRSO)
    {
        ibpb_open
    }
    else
    {
        None
    };
    [
        retbleed.map(|open| ("retbleed", open)),
        srso.map(|open| ("spec_rstack_overflow", open)),
    ]
}

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

/// Set when [`SPECULATION_CONTROL_IBRS_ENTRY`] is selected: every entry from
/// user mode writes [`SERAPH_SPEC_CTRL_KERNEL`] to `IA32_SPEC_CTRL`, and every
/// return to it [`SERAPH_SPEC_CTRL_USER`]. A byte `seraph_enter_from_user`
/// and the `ibrs_*` fragments read by its link name.
#[unsafe(no_mangle)]
static SERAPH_IBRS_ENTRY: AtomicBool = AtomicBool::new(false);

/// The `IA32_SPEC_CTRL` value the kernel runs with when
/// [`SPECULATION_CONTROL_IBRS_ENTRY`] is selected: the selection's
/// `IA32_SPEC_CTRL` bits ([`msr_bits`]), `IBRS` among them. Read by its link
/// name.
#[unsafe(no_mangle)]
static SERAPH_SPEC_CTRL_KERNEL: AtomicU64 = AtomicU64::new(0);

/// The `IA32_SPEC_CTRL` value user mode runs with when
/// [`SPECULATION_CONTROL_IBRS_ENTRY`] is selected:
/// [`SERAPH_SPEC_CTRL_KERNEL`] without `IBRS`. Read by its link name.
#[unsafe(no_mangle)]
static SERAPH_SPEC_CTRL_USER: AtomicU64 = AtomicU64::new(0);

/// Set when [`SPECULATION_CONTROL_IBPB_ENTRY`] is selected: every entry from
/// user mode issues an IBPB. A byte [`ibpb_asm`] reads by its link name.
#[unsafe(no_mangle)]
static SERAPH_IBPB_ENTRY: AtomicBool = AtomicBool::new(false);

/// Set when [`SPECULATION_CONTROL_RSB_FILL_IBPB`] is selected: every IBPB the
/// kernel issues is followed by the return stack buffer fill. A byte
/// [`ibpb_asm`] reads by its link name.
#[unsafe(no_mangle)]
static SERAPH_RSB_FILL_IBPB: AtomicBool = AtomicBool::new(false);

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

/// The controls [`install`] published.
pub fn selected() -> Controls
{
    Controls(SELECTED.load(Ordering::Relaxed))
}

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
    let (kernel, user) = spec_ctrl_values(controls);
    SERAPH_SPEC_CTRL_KERNEL.store(kernel, Ordering::Relaxed);
    SERAPH_SPEC_CTRL_USER.store(user, Ordering::Relaxed);
    SERAPH_IBRS_ENTRY.store(
        controls.has(SPECULATION_CONTROL_IBRS_ENTRY),
        Ordering::Relaxed,
    );
    SERAPH_IBPB_ENTRY.store(
        controls.has(SPECULATION_CONTROL_IBPB_ENTRY),
        Ordering::Relaxed,
    );
    SERAPH_RSB_FILL_IBPB.store(
        controls.has(SPECULATION_CONTROL_RSB_FILL_IBPB),
        Ordering::Relaxed,
    );
}

/// The `IA32_SPEC_CTRL` values of the kernel and of user mode under
/// [`SPECULATION_CONTROL_IBRS_ENTRY`]: the selection's `IA32_SPEC_CTRL` bits,
/// and the same without `IBRS`. The kernel owns the whole MSR under that
/// control: the entry and exit code write these values whole, so a bit the
/// firmware set and the selection does not hold is cleared.
fn spec_ctrl_values(controls: Controls) -> (u64, u64)
{
    let kernel = msr_bits(controls)
        .iter()
        .find(|&&(msr, _)| msr == IA32_SPEC_CTRL)
        .map_or(0, |&(_, bits)| bits);
    (kernel, kernel & !SPEC_CTRL_IBRS)
}

/// Log the inputs override the kernel was built with, if any (with the outcome
/// of the `SBPB` probe an `amd` override makes whatever the vendor), the
/// selected controls, a warning when `VERW` is selected on a CPU that does not
/// enumerate that it clears the buffers, and one line for each class the table
/// gives kernel action that the selection leaves vulnerable ([`vulnerable`]).
///
/// # Safety
/// As `super::vulnerability::sbpb_probe`, which an `amd` override runs.
#[cfg(not(test))]
pub unsafe fn report(cpu: &CpuEnumeration, inputs: Inputs, controls: Controls)
{
    match FORCED_RETURN
    {
        ForcedReturn::None =>
        {}
        ForcedReturn::Intel => crate::kprintln!(
            "x86 mitigations: inputs forced (SERAPH_FORCE_RETURN_MITIGATION=intel): \
             retbleed, rsb_alternate, no IBRS_ALL"
        ),
        ForcedReturn::Amd => crate::kprintln!(
            "x86 mitigations: inputs forced (SERAPH_FORCE_RETURN_MITIGATION=amd): \
             retbleed, spec_rstack_overflow, no rsb_alternate; SBPB probe {}",
            // SAFETY: the caller's contract is `sbpb_probe`'s.
            if unsafe { super::vulnerability::sbpb_probe() }
            {
                "accepted"
            }
            else
            {
                "faulted"
            }
        ),
    }
    crate::kprintln!("x86 mitigations: {}", ControlList(controls));
    for (class, open) in vulnerable(inputs, controls).into_iter().flatten()
    {
        crate::kprintln!("x86 mitigations: vulnerable: {class} ({})", open.text());
    }
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
/// `IA32_SPEC_CTRL.STIBP`.
const SPEC_CTRL_STIBP: u64 = 1 << 1;
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
/// AMD's `DE_CFG` (`MSR C001_1029`).
const AMD_DE_CFG: u32 = 0xC001_1029;
/// `DE_CFG[1]`: `LFENCE` is dispatch-serializing.
const DE_CFG_LFENCE_SERIALIZE: u64 = 1 << 1;

/// The MSR bits the selected `controls` set: one entry per MSR, with the bits
/// in it, empty bits for an MSR no control writes.
fn msr_bits(controls: Controls) -> [(u32, u64); 3]
{
    let pick = |control: u64, bit: u64| if controls.has(control) { bit } else { 0 };
    [
        (
            IA32_SPEC_CTRL,
            pick(SPECULATION_CONTROL_EIBRS, SPEC_CTRL_IBRS)
                | pick(SPECULATION_CONTROL_IBRS_ENTRY, SPEC_CTRL_IBRS)
                | pick(SPECULATION_CONTROL_BHI_DIS_S, SPEC_CTRL_BHI_DIS_S)
                | pick(SPECULATION_CONTROL_STIBP, SPEC_CTRL_STIBP),
        ),
        (IA32_EFER, pick(SPECULATION_CONTROL_AUTO_IBRS, EFER_AIBRSE)),
        (
            IA32_UARCH_MISC_CTL,
            pick(SPECULATION_CONTROL_DOITM, UARCH_MISC_CTL_DOITM),
        ),
    ]
}

/// Each control that sets or writes an MSR, with the input that enumerates its
/// MSR bit and the message a CPU that does not enumerate it halts with.
const MSR_CONTROLS: [(u64, u64, &str); 7] = [
    (
        SPECULATION_CONTROL_EIBRS,
        SPECULATION_INPUT_IBRS_ALL,
        "CPU lacks the enhanced IBRS the boot CPU selected",
    ),
    (
        SPECULATION_CONTROL_IBRS_ENTRY,
        SPECULATION_INPUT_IBRS,
        "CPU lacks the IBRS on entry the boot CPU selected",
    ),
    (
        SPECULATION_CONTROL_AUTO_IBRS,
        SPECULATION_INPUT_AUTO_IBRS,
        "CPU lacks the Automatic IBRS the boot CPU selected",
    ),
    (
        SPECULATION_CONTROL_BHI_DIS_S,
        SPECULATION_INPUT_BHI_CTRL,
        "CPU lacks the BHI_DIS_S control the boot CPU selected",
    ),
    (
        SPECULATION_CONTROL_DOITM,
        SPECULATION_INPUT_DOITM,
        "CPU lacks the DOITM control the boot CPU selected",
    ),
    (
        SPECULATION_CONTROL_IBPB_ENTRY,
        SPECULATION_INPUT_IBPB,
        "CPU lacks the IBPB on entry the boot CPU selected",
    ),
    (
        SPECULATION_CONTROL_STIBP,
        SPECULATION_INPUT_STIBP,
        "CPU lacks the STIBP the boot CPU selected",
    ),
];

/// The halt message for the first MSR control of `controls` that a CPU with
/// the inputs `inputs` does not enumerate, or `None` when it enumerates every
/// one. The selection is made from the boot CPU's enumeration, which no vendor
/// guarantees for every other CPU (core/kernel/docs/transient-execution.md
/// § Inputs), and an MSR access to a bit the CPU does not implement faults.
pub fn missing_msr_control(controls: Controls, inputs: Inputs) -> Option<&'static str>
{
    MSR_CONTROLS
        .iter()
        .find(|&&(control, input, _)| controls.has(control) && !inputs.any(input))
        .map(|&(_, _, message)| message)
}

/// Whether a CPU `cpu` sets `DE_CFG[1]`, which makes `LFENCE`
/// dispatch-serializing (AMD's "Software Techniques for Managing Speculation
/// on AMD Processors", mitigation G-2): an AMD part of Family 10h or later
/// other than 11h that does not enumerate `LfenceAlwaysSerializing`
/// (`CPUID Fn8000_0021 EAX[2]`), or any CPU under [`ForcedReturn::Amd`]. Not
/// on Intel, whose `LFENCE` is serializing by its architecture; not on Family
/// 0Fh or 11h, where it already is; not where the CPU enumerates that it
/// always is; not on another vendor, whose `DE_CFG` the kernel does not read.
pub fn de_cfg_wanted(cpu: &CpuEnumeration, force: ForcedReturn) -> bool
{
    let family = cpu.family();
    force == ForcedReturn::Amd
        || (cpu.vendor == Vendor::Amd
            && family >= 0x10
            && family != 0x11
            && !cpu.lfence_always_serializing())
}

/// What the `DE_CFG[1]` step left on one CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeCfg
{
    /// The bit reads back set.
    Set,
    /// The read or the write raised `#GP`: a hypervisor that does not give
    /// the guest the MSR.
    Refused,
    /// The write completed but the bit reads back clear: a hypervisor that
    /// ignores the write.
    DidNotStick,
}

impl DeCfg
{
    /// The outcome's text in the serial log.
    pub fn text(self) -> &'static str
    {
        match self
        {
            DeCfg::Set => "set",
            DeCfg::Refused => "not set: the MSR access raised #GP",
            DeCfg::DidNotStick => "not set: the write did not hold",
        }
    }
}

/// The outcome of the `DE_CFG[1]` step from what its accesses returned: the
/// first read, the write where one was made (`None` for none), and the read
/// back.
fn de_cfg_outcome(read: Option<u64>, wrote: Option<bool>, read_back: Option<u64>) -> DeCfg
{
    match (read, wrote, read_back)
    {
        (None, _, _) | (_, Some(false), _) | (_, _, None) => DeCfg::Refused,
        (_, _, Some(value)) if value & DE_CFG_LFENCE_SERIALIZE != 0 => DeCfg::Set,
        _ => DeCfg::DidNotStick,
    }
}

/// Set `DE_CFG[1]` on this CPU by a fault-tolerant read-modify-write, and read
/// it back.
///
/// # Safety
/// As [`super::idt::msr_recovering`]: ring 0 on the kernel's GDT, interrupts
/// off, no shadow stack. The write sets one bit the vendor defines and keeps
/// the others.
#[cfg(not(test))]
unsafe fn set_de_cfg() -> DeCfg
{
    use super::idt::msr_recovering;
    // SAFETY: the caller's contract.
    let read = unsafe { msr_recovering(AMD_DE_CFG, None) };
    let wrote = match read
    {
        Some(value) if value & DE_CFG_LFENCE_SERIALIZE == 0 =>
        {
            // SAFETY: the caller's contract; the value is the one read, with
            // the one bit set.
            Some(
                unsafe { msr_recovering(AMD_DE_CFG, Some(value | DE_CFG_LFENCE_SERIALIZE)) }
                    .is_some(),
            )
        }
        _ => None,
    };
    let read_back = if read.is_some()
    {
        // SAFETY: the caller's contract.
        unsafe { msr_recovering(AMD_DE_CFG, None) }
    }
    else
    {
        None
    };
    de_cfg_outcome(read, wrote, read_back)
}

/// Whether a CPU has logged its `DE_CFG[1]` outcome: the first CPU to take the
/// step, the boot CPU, logs it whatever it is, and every later CPU only one
/// that is not [`DeCfg::Set`].
#[cfg(not(test))]
static DE_CFG_LOGGED: AtomicBool = AtomicBool::new(false);

/// Set this CPU's MSR controls of the installed selection: enhanced IBRS,
/// `BHI_DIS_S` and STIBP in `IA32_SPEC_CTRL`, Automatic IBRS in `EFER`, and
/// `DOITM` in `IA32_UARCH_MISC_CTL`, each by a read-modify-write that keeps
/// the MSR's other bits. With IBRS on entry selected, `IA32_SPEC_CTRL` is
/// instead written whole with the kernel's value ([`spec_ctrl_values`]), the
/// value every entry from user mode writes. Each is per logical processor, so
/// every CPU sets its own. Then, where [`de_cfg_wanted`] holds, set
/// `DE_CFG[1]` ([`set_de_cfg`]) and log the outcome as [`DE_CFG_LOGGED`]
/// says, naming the CPU by its initial APIC ID (`CPUID.01H:EBX[31:24]`).
///
/// # Panics
/// Halts via `crate::fatal`, naming the control, when this CPU does not
/// enumerate an MSR control the boot CPU selected ([`missing_msr_control`]),
/// before any access to its MSR.
///
/// # Safety
/// Ring 0, on the CPU being brought up and on the kernel's GDT
/// (`gdt::load_boot_segments` on the boot CPU, `gdt::init_ap` on an AP),
/// after [`install`], with interrupts off and before `shadow_stack::enable`
/// on it.
#[cfg(not(test))]
pub unsafe fn apply_this_cpu()
{
    let controls = selected();
    // SAFETY: the caller's contract, which is `sbpb_probe`'s.
    let cpu = unsafe { super::vulnerability::enumerate() };
    if let Some(message) = missing_msr_control(
        controls,
        Inputs::of(&cpu, &super::vulnerability::derive(&cpu)),
    )
    {
        crate::fatal(message);
    }
    let owns_spec_ctrl = controls.has(SPECULATION_CONTROL_IBRS_ENTRY);
    for (msr, bits) in msr_bits(controls)
    {
        if bits == 0
        {
            continue;
        }
        if msr == IA32_SPEC_CTRL && owns_spec_ctrl
        {
            // SAFETY: ring 0; this CPU implements IBRS (checked above), so it
            // implements `IA32_SPEC_CTRL`, and the value holds only bits of
            // selected controls, each of which this CPU enumerates.
            unsafe { super::cpu::write_msr(msr, bits) };
            continue;
        }
        // SAFETY: ring 0; this CPU enumerates every selected control's MSR bit
        // (checked above), so it implements `msr` and the read cannot fault.
        let value = unsafe { super::cpu::read_msr(msr) };
        // SAFETY: as for the read; the write sets only the control's bits, which
        // the implemented MSR defines, and keeps every other bit.
        unsafe { super::cpu::write_msr(msr, value | bits) };
    }
    if de_cfg_wanted(&cpu, FORCED_RETURN)
    {
        // SAFETY: the caller's contract.
        let outcome = unsafe { set_de_cfg() };
        let first = !DE_CFG_LOGGED.swap(true, Ordering::Relaxed);
        if first || outcome != DeCfg::Set
        {
            crate::kprintln!(
                "x86 mitigations: cpu {}: DE_CFG[1] (LFENCE dispatch-serializing) {}",
                super::cpu::cpuid(1).1 >> 24,
                outcome.text()
            );
        }
    }
}

/// The controls in effect on the calling CPU, a `SPECULATION_CONTROL_*` set:
/// the MSR controls as this CPU's MSRs hold them, each MSR read where a
/// selected control lives in it, and the others as the flags the entry and
/// exit code test hold them. `IA32_SPEC_CTRL.IBRS` reads as IBRS on entry
/// when that is selected, and as enhanced IBRS otherwise; the call runs in the
/// kernel, after the entry that set it.
#[cfg(not(test))]
pub fn in_effect() -> u64
{
    let selected = selected();
    let mut bits = 0;
    let mut read_bits = |msr: u32, controls: &[(u64, u64)]| {
        // SAFETY: ring 0; the callers below read `EFER`, which every x86-64
        // CPU implements, or an MSR in which a selected control lives, which
        // `apply_this_cpu` checked this CPU implements at its bring-up.
        let value = unsafe { super::cpu::read_msr(msr) };
        for &(control, bit) in controls
        {
            if value & bit != 0
            {
                bits |= control;
            }
        }
    };
    if selected.bits()
        & (SPECULATION_CONTROL_EIBRS
            | SPECULATION_CONTROL_IBRS_ENTRY
            | SPECULATION_CONTROL_BHI_DIS_S
            | SPECULATION_CONTROL_STIBP)
        != 0
    {
        let ibrs = if selected.has(SPECULATION_CONTROL_IBRS_ENTRY)
        {
            SPECULATION_CONTROL_IBRS_ENTRY
        }
        else
        {
            SPECULATION_CONTROL_EIBRS
        };
        read_bits(
            IA32_SPEC_CTRL,
            &[
                (ibrs, SPEC_CTRL_IBRS),
                (SPECULATION_CONTROL_BHI_DIS_S, SPEC_CTRL_BHI_DIS_S),
                (SPECULATION_CONTROL_STIBP, SPEC_CTRL_STIBP),
            ],
        );
    }
    read_bits(IA32_EFER, &[(SPECULATION_CONTROL_AUTO_IBRS, EFER_AIBRSE)]);
    if selected.has(SPECULATION_CONTROL_DOITM)
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
        (&SERAPH_IBPB_ENTRY, SPECULATION_CONTROL_IBPB_ENTRY),
        (&SERAPH_RSB_FILL_IBPB, SPECULATION_CONTROL_RSB_FILL_IBPB),
    ];
    for (flag, control) in flags
    {
        if flag.load(Ordering::Relaxed)
        {
            bits |= control;
        }
    }
    bits
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

/// Naked-asm fragment: write the user-mode `IA32_SPEC_CTRL` value
/// (`SERAPH_SPEC_CTRL_USER`, `IBRS` clear) when
/// [`SPECULATION_CONTROL_IBRS_ENTRY`] is selected. Placed on every return to
/// user mode with interrupts off, after the last kernel `call`, `ret` and
/// indirect branch, so none runs with `IBRS` clear; an NMI or `#MC` that
/// arrives after it runs [`ibrs_paranoid_entry_asm`] first. Clobbers EAX, ECX,
/// EDX and RFLAGS, so it runs before the registers are restored.
#[cfg(not(test))]
macro_rules! ibrs_exit_asm {
    () => {
        concat!(
            "cmp byte ptr [rip + SERAPH_IBRS_ENTRY], 0\n",
            "je 91f\n",
            "mov ecx, 0x48\n",
            "mov eax, dword ptr [rip + SERAPH_SPEC_CTRL_USER]\n",
            "mov edx, dword ptr [rip + SERAPH_SPEC_CTRL_USER + 4]\n",
            "wrmsr\n",
            "91:\n",
        )
    };
}
#[cfg(not(test))]
pub(super) use ibrs_exit_asm;

/// Naked-asm fragment for the stubs that can interrupt the kernel between a
/// return's [`ibrs_exit_asm`] and its `iretq` or `sysretq`, or an entry
/// before its `IA32_SPEC_CTRL` write (NMI, `#DB`, `#DF`, `#MC`): when
/// [`SPECULATION_CONTROL_IBRS_ENTRY`] is selected, save the interrupted
/// `IA32_SPEC_CTRL` in R13 (callee-saved across the handler call, and saved in
/// the frame) and write the kernel's value. Runs before the handler call, after
/// the registers it clobbers (EAX, ECX, EDX, R13, RFLAGS) are saved.
#[cfg(not(test))]
macro_rules! ibrs_paranoid_entry_asm {
    () => {
        concat!(
            "cmp byte ptr [rip + SERAPH_IBRS_ENTRY], 0\n",
            "je 93f\n",
            "mov ecx, 0x48\n",
            "rdmsr\n",
            "mov r13d, eax\n",
            "shl rdx, 32\n",
            "or r13, rdx\n",
            "mov eax, dword ptr [rip + SERAPH_SPEC_CTRL_KERNEL]\n",
            "mov edx, dword ptr [rip + SERAPH_SPEC_CTRL_KERNEL + 4]\n",
            "wrmsr\n",
            "93:\n",
        )
    };
}
#[cfg(not(test))]
pub(super) use ibrs_paranoid_entry_asm;

/// Naked-asm fragment: undo [`ibrs_paranoid_entry_asm`]. When
/// [`SPECULATION_CONTROL_IBRS_ENTRY`] is selected, write the user-mode value
/// on a return to ring 3 (the frame's CS at `[rsp + $cs]` has a non-zero RPL),
/// and otherwise the value saved in R13, which is the interrupted kernel's:
/// the kernel's own, or the user-mode value when the stub interrupted a
/// return after its [`ibrs_exit_asm`] or an entry before its write. Runs with
/// interrupts off, before the registers are restored; clobbers EAX, ECX, EDX
/// and RFLAGS.
#[cfg(not(test))]
macro_rules! ibrs_paranoid_exit_asm {
    ($cs:literal) => {
        concat!(
            "cmp byte ptr [rip + SERAPH_IBRS_ENTRY], 0\n",
            "je 94f\n",
            "mov ecx, 0x48\n",
            "test byte ptr [rsp + ",
            $cs,
            "], 0x3\n",
            "jz 95f\n",
            "mov eax, dword ptr [rip + SERAPH_SPEC_CTRL_USER]\n",
            "mov edx, dword ptr [rip + SERAPH_SPEC_CTRL_USER + 4]\n",
            "jmp 96f\n",
            "95:\n",
            "mov eax, r13d\n",
            "mov rdx, r13\n",
            "shr rdx, 32\n",
            "96:\n",
            "wrmsr\n",
            "94:\n",
        )
    };
}
#[cfg(not(test))]
pub(super) use ibrs_paranoid_exit_asm;

/// Asm fragment: the IBPB on entry, when [`SPECULATION_CONTROL_IBPB_ENTRY`] is
/// selected, and after it, when [`SPECULATION_CONTROL_RSB_FILL_IBPB`] is, the
/// return stack buffer fill: 32 entries that trap speculation (`int3`), two
/// calls per iteration whose return addresses are dropped from the stack.
/// Where a supervisor shadow stack is on, on this CPU at this moment
/// (`rdsspq` leaves the zeroed register where it is not), `incsspq` drops
/// the 32 entries the calls pushed there too, so the shadow stack again
/// matches the stack and no return is rewritten.
///
/// Placed on every entry from user mode before the first `ret` and indirect
/// branch that the entry's own `call`s do not pair (`seraph_enter_from_user`),
/// and in the paranoid stubs; the fragment's own calls make no `ret`.
/// Clobbers EAX, ECX, EDX and RFLAGS; uses 16 bytes of stack below RSP. Its
/// caller ends the sequence in `lfence`, so a mispredicted test of a flag
/// runs no later instruction. Labels 70 to 79.
#[cfg(not(test))]
macro_rules! ibpb_asm {
    () => {
        concat!(
            "cmp byte ptr [rip + SERAPH_IBPB_ENTRY], 0\n",
            "je 79f\n",
            "mov ecx, 0x49\n",
            "mov eax, 1\n",
            "xor edx, edx\n",
            "wrmsr\n",
            "cmp byte ptr [rip + SERAPH_RSB_FILL_IBPB], 0\n",
            "je 79f\n",
            "mov ecx, 16\n",
            "70:\n",
            "call 71f\n",
            "int3\n",
            "71:\n",
            "call 72f\n",
            "int3\n",
            "72:\n",
            "add rsp, 16\n",
            "dec ecx\n",
            "jnz 70b\n",
            "xor eax, eax\n",
            "rdsspq rax\n",
            "test rax, rax\n",
            "jz 79f\n",
            "mov eax, 32\n",
            "incsspq rax\n",
            "79:\n",
        )
    };
}
#[cfg(not(test))]
pub(super) use ibpb_asm;

// The retpoline thunk and the entry routine.
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
// `seraph_enter_from_user` runs on every entry from user mode, before any
// indirect branch and any `ret` that its own `call` did not pair. With IBRS on
// entry selected it first writes the kernel's `IA32_SPEC_CTRL` value, `IBRS`
// set, so the predictions user mode trained steer no later indirect branch or
// `ret` (Intel's RSBU guidance). With the IBPB on entry selected it then
// issues the IBPB, and the fill after it where that is selected (`ibpb_asm`),
// before its own `ret`, the first of the entry (AMD's branch type confusion and
// speculative return stack overflow guidance). Then, with the clearing
// selected, it runs Intel's branch history clearing sequence (the long form,
// 12 outer and 7 inner iterations, which covers the short form's parts as
// well), and returns. Its calls and returns pair up, or are dropped from both
// stacks together, so it runs on a supervisor shadow stack too. It clobbers
// EAX, ECX, EDX and RFLAGS and needs a stack; both of its paths end in
// `lfence`, so no later instruction runs before the MSR writes complete and
// the flags' tests resolve.
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
    ".global seraph_enter_from_user",
    ".p2align 4",
    "seraph_enter_from_user:",
    "    cmp byte ptr [rip + {ibrs_entry}], 0",
    "    je 5f",
    "    mov ecx, 0x48",
    "    mov eax, dword ptr [rip + {spec_ctrl_kernel}]",
    "    mov edx, dword ptr [rip + {spec_ctrl_kernel} + 4]",
    "    wrmsr",
    "5:",
    ibpb_asm!(),
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
    ibrs_entry = sym SERAPH_IBRS_ENTRY,
    spec_ctrl_kernel = sym SERAPH_SPEC_CTRL_KERNEL,
);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::super::vulnerability::{Vendor, derive};
    use super::*;

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
            smt: false,
            sbpb_accepted: false,
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

    // Defect caught: a Zen or Zen+ part, which AMD's branch type confusion
    // guidance ("Technical Guidance for Mitigating Branch Type Confusion",
    // Rev 3.0) names affected and whose IBPB flushes every branch type, left
    // without the IBPB on entry, or reported mitigated while SMT is on and the
    // CPU has no STIBP to keep the sibling thread's training out. EPYC 7001
    // (family 17h model 01H) with IBPB and without `IBPB_RET` or STIBP.
    #[test]
    fn zen1_selects_ibpb_on_entry_and_reports_smt_without_stibp()
    {
        let mut zen1 = cpu(Vendor::Amd, 0x0080_0F12);
        zen1.ext8_ebx = 1 << 12;
        zen1.smt = true;
        let inputs = Inputs::of(&zen1, &derive(&zen1));
        let controls = select(inputs);
        assert_eq!(
            controls.bits(),
            SPECULATION_CONTROL_RETPOLINE
                | SPECULATION_CONTROL_RSB_FILL_IBPB
                | SPECULATION_CONTROL_IBPB_ENTRY
        );
        assert_eq!(
            vulnerable(inputs, controls),
            [
                Some(("retbleed", Open::SmtWithoutStibp)),
                Some(("spec_rstack_overflow", Open::SmtWithoutStibp))
            ]
        );
        zen1.smt = false;
        let inputs = Inputs::of(&zen1, &derive(&zen1));
        assert_eq!(vulnerable(inputs, select(inputs)), [None, None]);
    }

    // Defect caught: Zen 2 with the IBPB and STIBP of its microcode left
    // without the IBPB on entry for branch type confusion and speculative
    // return stack overflow, without the fill after it (no `IBPB_RET`), or
    // without STIBP while SMT is on ("Technical Guidance for Mitigating Branch
    // Type Confusion", Rev 3.0; "Technical Update Regarding Speculative Return
    // Stack Overflow", Rev 2.0: family 17h treats its IBPB as `IBPB_BRTYPE`).
    // The `vulnerability::tests::amd_zen2` part, family 17h model 31H.
    #[test]
    fn zen2_with_ibpb_selects_ibpb_on_entry_fill_and_stibp()
    {
        let mut zen2 = cpu(Vendor::Amd, 0x0083_0F10);
        zen2.ext8_ebx = (1 << 12) | (1 << 15);
        zen2.smt = true;
        let inputs = Inputs::of(&zen2, &derive(&zen2));
        let controls = select(inputs);
        assert_eq!(
            controls.bits(),
            SPECULATION_CONTROL_RETPOLINE
                | SPECULATION_CONTROL_RSB_FILL_IBPB
                | SPECULATION_CONTROL_IBPB_ENTRY
                | SPECULATION_CONTROL_STIBP
        );
        assert_eq!(vulnerable(inputs, controls), [None, None]);
    }

    // Defect caught: Zen 3 whose IBPB leaves branch types (no SRSO microcode,
    // AMD-SB-7005) given the IBPB on entry, which would not answer speculative
    // return stack overflow, or reported mitigated; or Zen 3 with that
    // microcode, which the `SBPB` probe detects or `Fn8000_0021 EAX` reports
    // as `SBPB` or `IBPB_BRTYPE` ("Technical Update Regarding Speculative
    // Return Stack Overflow", Rev 2.0), left without it. Family 19h model 21H
    // with IBPB and STIBP, SMT on.
    #[test]
    fn zen3_takes_ibpb_on_entry_only_with_the_srso_microcode()
    {
        let mut zen3 = cpu(Vendor::Amd, 0x00A2_0F10);
        zen3.ext8_ebx = (1 << 12) | (1 << 15);
        zen3.smt = true;
        let base = SPECULATION_CONTROL_RETPOLINE
            | SPECULATION_CONTROL_VERW_EXIT
            | SPECULATION_CONTROL_VERW_IDLE
            | SPECULATION_CONTROL_RSB_FILL_IBPB;
        let inputs = Inputs::of(&zen3, &derive(&zen3));
        assert_eq!(select(inputs).bits(), base);
        assert_eq!(
            vulnerable(inputs, select(inputs)),
            [
                None,
                Some(("spec_rstack_overflow", Open::IbpbLeavesBranchType))
            ]
        );
        let mut accepted = zen3;
        accepted.sbpb_accepted = true;
        let mut sbpb = zen3;
        sbpb.ext21_eax = 1 << 27;
        let mut brtype = zen3;
        brtype.ext21_eax = 1 << 28;
        for (name, part) in [("probe", accepted), ("SBPB", sbpb), ("IBPB_BRTYPE", brtype)]
        {
            let inputs = Inputs::of(&part, &derive(&part));
            assert_eq!(
                select(inputs).bits(),
                base | SPECULATION_CONTROL_IBPB_ENTRY | SPECULATION_CONTROL_STIBP,
                "{name}"
            );
            assert_eq!(vulnerable(inputs, select(inputs)), [None, None], "{name}");
        }
    }

    // Defect caught: Zen 4 with `IBPB_BRTYPE` left without the IBPB on entry
    // for speculative return stack overflow, given the fill its `IBPB_RET`
    // makes unneeded, or kept off shadow stacks, which the IBPB on entry does
    // not require ("Technical Update Regarding Speculative Return Stack
    // Overflow", Rev 2.0). Family 19h model 61H with Automatic IBRS,
    // `VERW_CLEAR`, IBPB, STIBP and `IBPB_RET`, SMT on.
    #[test]
    fn zen4_with_ibpb_brtype_selects_ibpb_on_entry_and_keeps_shadow_stacks()
    {
        let mut zen4 = cpu(Vendor::Amd, 0x00A6_0F12);
        zen4.ext8_ebx = (1 << 12) | (1 << 15) | (1 << 30);
        zen4.ext21_eax = (1 << 28) | (1 << 8) | (1 << 5);
        zen4.smt = true;
        let inputs = Inputs::of(&zen4, &derive(&zen4));
        let controls = select(inputs);
        assert_eq!(
            controls.bits(),
            SPECULATION_CONTROL_AUTO_IBRS
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_VERW_IDLE
                | SPECULATION_CONTROL_IBPB_ENTRY
                | SPECULATION_CONTROL_STIBP
        );
        assert!(!controls.rewrites_returns());
        assert_eq!(vulnerable(inputs, controls), [None, None]);
    }

    // Defect caught: `DE_CFG[1]` written where it is not defined or not
    // needed, or left unwritten where an `lfence` needs it to serialize (AMD
    // STMS mitigation G-2): every AMD family from 10h but 11h, unless
    // `Fn8000_0021 EAX[2]` reports `lfence` always serializing; never on
    // Intel or another vendor, unless the `amd` override forces the step.
    #[test]
    fn de_cfg_is_wanted_on_amd_parts_whose_lfence_may_not_serialize()
    {
        let mut zen4 = cpu(Vendor::Amd, 0x00A6_0F12);
        for (name, part, wanted) in [
            ("Zen 2", cpu(Vendor::Amd, 0x0083_0F10), true),
            ("Zen 4", zen4, true),
            ("family 10h", cpu(Vendor::Amd, 0x0010_0F42), true),
            ("family 11h", cpu(Vendor::Amd, 0x0020_0F31), false),
            ("family 0Fh", cpu(Vendor::Amd, 0x0002_0F12), false),
            ("TCG", cpu(Vendor::Amd, 0x0000_0663), false),
            ("Intel", cpu(Vendor::Intel, 0x0009_0672), false),
            ("other vendor", cpu(Vendor::Other, 0x0083_0F10), false),
        ]
        {
            assert_eq!(de_cfg_wanted(&part, ForcedReturn::None), wanted, "{name}");
            assert_eq!(de_cfg_wanted(&part, ForcedReturn::Intel), wanted, "{name}");
            assert!(de_cfg_wanted(&part, ForcedReturn::Amd), "{name}");
        }
        zen4.ext21_eax = 1 << 2;
        assert!(!de_cfg_wanted(&zen4, ForcedReturn::None));
    }

    // Defect caught: a `DE_CFG` step reported set when an access faulted or
    // the bit did not hold, or reported failed when it reads back set.
    #[test]
    fn de_cfg_outcome_follows_each_access()
    {
        for (read, wrote, read_back, outcome) in [
            (Some(0), Some(true), Some(2), DeCfg::Set),
            (Some(2), None, Some(2), DeCfg::Set),
            (Some(0x10), Some(true), Some(0x12), DeCfg::Set),
            (None, None, None, DeCfg::Refused),
            (Some(0), Some(false), Some(0), DeCfg::Refused),
            (Some(0), Some(true), None, DeCfg::Refused),
            (Some(0), Some(true), Some(0), DeCfg::DidNotStick),
        ]
        {
            assert_eq!(
                de_cfg_outcome(read, wrote, read_back),
                outcome,
                "{read:?} {wrote:?} {read_back:?}"
            );
        }
        assert_eq!(DeCfg::Set.text(), "set");
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
    // kernel action, left without a software control, or given IBRS on entry
    // for a `retbleed` that may be branch type confusion when it reports IBRS
    // (a Zen-derived part of another vendor reports AMD's bit), with the class
    // then dropped from the log.
    #[test]
    fn other_vendor_selects_every_software_control()
    {
        let software = SPECULATION_CONTROL_RETPOLINE
            | SPECULATION_CONTROL_BHB_CLEAR
            | SPECULATION_CONTROL_VERW_EXIT
            | SPECULATION_CONTROL_VERW_IDLE
            | SPECULATION_CONTROL_RSB_FILL_SWITCH
            | SPECULATION_CONTROL_RSB_FILL_IBPB;
        let mut other = cpu(Vendor::Other, 0x0009_0672);
        assert_eq!(controls_of(&other), software);
        other.leaf7_edx = 1 << 26;
        other.ext8_ebx = 1 << 14;
        assert_eq!(controls_of(&other), software);
        let inputs = Inputs::of(&other, &derive(&other));
        let open = [
            Some(("retbleed", Open::NoControl)),
            Some(("spec_rstack_overflow", Open::IbpbLeavesBranchType)),
        ];
        assert_eq!(vulnerable(inputs, select(inputs)), open);
        other.leaf7_edx |= 1 << 29;
        other.arch_capabilities = 1 << 1;
        let inputs = Inputs::of(&other, &derive(&other));
        assert!(select(inputs).bits() & SPECULATION_CONTROL_EIBRS != 0);
        assert_eq!(vulnerable(inputs, select(inputs)), open);
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
        host.leaf7_edx |= 1 << 26;
        assert!(Inputs::of(&host, &derive(&host)).any(SPECULATION_INPUT_IBRS));
        let mut zen2 = cpu(Vendor::Amd, 0x0083_0F10);
        assert_eq!(
            Inputs::of(&zen2, &derive(&zen2)).bits()
                & (SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_SRSO | SPECULATION_INPUT_IBRS),
            SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_SRSO
        );
        zen2.ext8_ebx = 1 << 14;
        zen2.leaf7_edx = 1 << 26;
        assert!(!Inputs::of(&zen2, &derive(&zen2)).any(SPECULATION_INPUT_IBRS));
        let mut other = cpu(Vendor::Other, 0x0009_0672);
        other.leaf7_edx = 1 << 26;
        assert!(!Inputs::of(&other, &derive(&other)).any(SPECULATION_INPUT_IBRS));
    }

    // Defect caught: an Intel part whose returns fall back to the branch target
    // buffer (`retbleed` and `rsb_alternate`, Intel's RSBU guidance) and that
    // implements IBRS without enhanced IBRS given the retpoline sequence, which
    // leaves `retbleed` open, instead of IBRS on entry, or given the switch fill
    // beside it, which IBRS on entry makes unneeded. Skylake S (06_5EH stepping
    // 3) and Coffee Lake H (06_9EH stepping A), whose rows in Intel's list give
    // the RSBA column `Software`, with IBRS enumerated
    // (`CPUID.(EAX=07H,ECX=0):EDX[26]`); microarchitectural data sampling gives
    // both `VERW`s.
    #[test]
    fn retbleed_part_with_ibrs_selects_ibrs_on_entry()
    {
        for signature in [0x0005_06E3, 0x0009_06EA]
        {
            let mut part = cpu(Vendor::Intel, signature);
            part.leaf7_edx = (1 << 29) | (1 << 26);
            let inputs = Inputs::of(&part, &derive(&part));
            let controls = select(inputs);
            assert_eq!(
                controls.bits(),
                SPECULATION_CONTROL_IBRS_ENTRY
                    | SPECULATION_CONTROL_VERW_EXIT
                    | SPECULATION_CONTROL_VERW_IDLE,
                "signature {signature:#x}"
            );
            assert_eq!(vulnerable(inputs, controls), [None, None]);
        }
    }

    // Defect caught: the build override read wrongly, or one that adds an
    // enumerated bit (so a CPU without IBRS would select IBRS on entry and
    // fault at its first entry) or leaves enhanced IBRS selected. The
    // development host's inputs, forced, select IBRS on entry in place of
    // enhanced IBRS and keep its other controls; inputs without IBRS fall back
    // to the retpoline sequence.
    #[test]
    fn forced_intel_inputs_select_ibrs_on_entry()
    {
        assert_eq!(forced_return(None), ForcedReturn::None);
        assert_eq!(forced_return(Some("")), ForcedReturn::None);
        assert_eq!(forced_return(Some("intel")), ForcedReturn::Intel);
        let mut host = cpu(Vendor::Intel, 0x0009_0672);
        host.leaf7_edx = (1 << 29) | (1 << 26);
        host.leaf7_2_edx = 0x17;
        host.arch_capabilities = 0x4000_0000_1400_E06B;
        let inputs = Inputs::of(&host, &derive(&host));
        assert_eq!(inputs.forced(ForcedReturn::None), inputs);
        let forced = inputs.forced(ForcedReturn::Intel);
        assert_eq!(
            forced.bits(),
            (inputs.bits() | SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_RSB_ALTERNATE)
                & !SPECULATION_INPUT_IBRS_ALL
        );
        assert_eq!(
            select(forced).bits(),
            SPECULATION_CONTROL_IBRS_ENTRY
                | SPECULATION_CONTROL_BHI_DIS_S
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_RSB_FILL_IBPB
        );
        assert_eq!(missing_msr_control(select(forced), inputs), None);
        let without_ibrs = Inputs(SPECULATION_INPUT_SPECTRE_V2 | SPECULATION_INPUT_IBRS_ALL)
            .forced(ForcedReturn::Intel);
        assert_eq!(
            select(without_ibrs).bits(),
            SPECULATION_CONTROL_RETPOLINE | SPECULATION_CONTROL_RSB_FILL_SWITCH
        );
    }

    // Defect caught: the `amd` override read wrongly, or one that adds an
    // enumerated bit (so a CPU without IBPB would select the IBPB on entry and
    // fault at its first entry) or keeps `rsb_alternate`, which would read
    // `retbleed` as an Intel part's. The development host's inputs, with IBPB
    // and STIBP enumerated as KVM passes them, forced, keep enhanced IBRS for
    // branch target injection and add the IBPB on entry and STIBP; inputs
    // without IBPB select neither and leave both classes vulnerable.
    #[test]
    fn forced_amd_inputs_select_ibpb_on_entry()
    {
        assert_eq!(forced_return(Some("amd")), ForcedReturn::Amd);
        let mut host = cpu(Vendor::Intel, 0x0009_0672);
        host.leaf7_edx = (1 << 29) | (1 << 27) | (1 << 26);
        host.leaf7_2_edx = 0x17;
        host.arch_capabilities = 0x4000_0000_1400_E06B;
        host.smt = true;
        let inputs = Inputs::of(&host, &derive(&host));
        let forced = inputs.forced(ForcedReturn::Amd);
        assert_eq!(
            forced.bits(),
            inputs.bits() | SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_SRSO
        );
        let controls = select(forced);
        assert_eq!(
            controls.bits(),
            SPECULATION_CONTROL_EIBRS
                | SPECULATION_CONTROL_BHI_DIS_S
                | SPECULATION_CONTROL_VERW_EXIT
                | SPECULATION_CONTROL_RSB_FILL_IBPB
                | SPECULATION_CONTROL_IBPB_ENTRY
                | SPECULATION_CONTROL_STIBP
        );
        assert!(!controls.rewrites_returns());
        assert_eq!(missing_msr_control(controls, inputs), None);
        assert_eq!(vulnerable(forced, controls), [None, None]);
        let without_ibpb = Inputs(SPECULATION_INPUT_SPECTRE_V2).forced(ForcedReturn::Amd);
        assert_eq!(select(without_ibpb).bits(), SPECULATION_CONTROL_RETPOLINE);
        assert_eq!(
            vulnerable(without_ibpb, select(without_ibpb)),
            [
                Some(("retbleed", Open::NoIbpb)),
                Some(("spec_rstack_overflow", Open::NoIbpb))
            ]
        );
    }

    // Defect caught: a build with an unknown override value that builds,
    // running the CPU's own inputs while its builder expects forced ones.
    #[test]
    #[should_panic(expected = "SERAPH_FORCE_RETURN_MITIGATION")]
    fn an_unknown_forced_value_is_refused()
    {
        let _ = forced_return(Some("zen"));
    }

    // Defect caught: a class with kernel action that the selection leaves open
    // left out of the log or reported as mitigated, given the wrong reason, or
    // a class a control answers reported. Zen 2 without IBPB leaves `retbleed`
    // and `spec_rstack_overflow` open for want of the barrier; enhanced IBRS
    // and IBRS on entry each answer `retbleed` whose returns fall back to the
    // branch target buffer on an Intel part, and neither answers it otherwise;
    // the IBPB on entry answers branch type confusion and speculative return
    // stack overflow unless the IBPB leaves branch types or SMT is on without
    // STIBP.
    #[test]
    fn vulnerable_names_each_open_class_and_its_reason()
    {
        let zen2 = cpu(Vendor::Amd, 0x0083_0F10);
        let inputs = Inputs::of(&zen2, &derive(&zen2));
        assert_eq!(
            vulnerable(inputs, select(inputs)),
            [
                Some(("retbleed", Open::NoIbpb)),
                Some(("spec_rstack_overflow", Open::NoIbpb))
            ]
        );
        let retbleed = Inputs(
            SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_RSB_ALTERNATE | SPECULATION_INPUT_IBRS,
        );
        let other_vendor = Inputs(SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_RSB_ALTERNATE);
        for answer in [SPECULATION_CONTROL_EIBRS, SPECULATION_CONTROL_IBRS_ENTRY]
        {
            assert_eq!(vulnerable(retbleed, Controls(answer)), [None, None]);
            assert_eq!(
                vulnerable(other_vendor, Controls(answer)),
                [Some(("retbleed", Open::NoControl)), None]
            );
        }
        assert_eq!(
            vulnerable(retbleed, Controls(SPECULATION_CONTROL_RETPOLINE)),
            [Some(("retbleed", Open::NoControl)), None]
        );
        let ibpb = SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_SRSO | SPECULATION_INPUT_IBPB;
        let entry = Controls(SPECULATION_CONTROL_IBPB_ENTRY);
        let both = |open| {
            [
                Some(("retbleed", open)),
                Some(("spec_rstack_overflow", open)),
            ]
        };
        assert_eq!(vulnerable(Inputs(ibpb), entry), [None, None]);
        assert_eq!(vulnerable(Inputs(ibpb), Controls(0)), both(Open::NoControl));
        assert_eq!(
            vulnerable(
                Inputs(ibpb | SPECULATION_INPUT_IBPB_LEAVES_BRTYPE),
                Controls(0)
            ),
            both(Open::IbpbLeavesBranchType)
        );
        assert_eq!(
            vulnerable(Inputs(ibpb | SPECULATION_INPUT_SMT), entry),
            both(Open::SmtWithoutStibp)
        );
        assert_eq!(
            vulnerable(
                Inputs(ibpb | SPECULATION_INPUT_SMT | SPECULATION_INPUT_STIBP),
                Controls(SPECULATION_CONTROL_IBPB_ENTRY | SPECULATION_CONTROL_STIBP)
            ),
            [None, None]
        );
        assert_eq!(vulnerable(Inputs(0), Controls(0)), [None, None]);
        for (open, text) in [
            (Open::NoControl, "no control answers it"),
            (Open::NoIbpb, "no IBPB"),
            (
                Open::IbpbLeavesBranchType,
                "IBPB does not flush branch types",
            ),
            (Open::SmtWithoutStibp, "SMT on without STIBP"),
        ]
        {
            assert_eq!(open.text(), text);
        }
    }

    // Defect caught: a rule that selects a control without its class, picks the
    // wrong one of two controls for a class, or ties a control to the wrong
    // input. Each case is one input set and the controls it selects.
    #[test]
    fn each_rule_selects_its_control()
    {
        let cases: [(u64, u64); 20] = [
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
            (
                SPECULATION_INPUT_SPECTRE_V2
                    | SPECULATION_INPUT_RETBLEED
                    | SPECULATION_INPUT_RSB_ALTERNATE
                    | SPECULATION_INPUT_IBRS,
                SPECULATION_CONTROL_IBRS_ENTRY,
            ),
            (
                SPECULATION_INPUT_RETBLEED
                    | SPECULATION_INPUT_RSB_ALTERNATE
                    | SPECULATION_INPUT_IBRS,
                SPECULATION_CONTROL_IBRS_ENTRY,
            ),
            (
                SPECULATION_INPUT_SPECTRE_V2
                    | SPECULATION_INPUT_RETBLEED
                    | SPECULATION_INPUT_RSB_ALTERNATE
                    | SPECULATION_INPUT_IBRS
                    | SPECULATION_INPUT_IBRS_ALL,
                SPECULATION_CONTROL_EIBRS,
            ),
            (
                SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_RSB_ALTERNATE,
                0,
            ),
            (
                SPECULATION_INPUT_SPECTRE_V2
                    | SPECULATION_INPUT_RETBLEED
                    | SPECULATION_INPUT_IBRS
                    | SPECULATION_INPUT_SRSO,
                SPECULATION_CONTROL_RETPOLINE,
            ),
            (
                SPECULATION_INPUT_SPECTRE_V2
                    | SPECULATION_INPUT_RSB_ALTERNATE
                    | SPECULATION_INPUT_IBRS,
                SPECULATION_CONTROL_RETPOLINE | SPECULATION_CONTROL_RSB_FILL_SWITCH,
            ),
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

    // Defect caught: the IBPB on entry selected without the class it answers,
    // without an IBPB, or with one that leaves branch types; for `retbleed`
    // whose returns fall back to an alternate predictor, which it does not
    // answer; or STIBP selected without it.
    #[test]
    fn each_ibpb_rule_selects_its_control()
    {
        let cases: [(u64, u64); 6] = [
            (
                SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_IBPB,
                SPECULATION_CONTROL_IBPB_ENTRY,
            ),
            (
                SPECULATION_INPUT_SRSO | SPECULATION_INPUT_IBPB | SPECULATION_INPUT_STIBP,
                SPECULATION_CONTROL_IBPB_ENTRY | SPECULATION_CONTROL_STIBP,
            ),
            (
                SPECULATION_INPUT_RETBLEED
                    | SPECULATION_INPUT_SRSO
                    | SPECULATION_INPUT_IBPB
                    | SPECULATION_INPUT_STIBP
                    | SPECULATION_INPUT_IBPB_LEAVES_BRTYPE,
                0,
            ),
            (
                SPECULATION_INPUT_RETBLEED
                    | SPECULATION_INPUT_RSB_ALTERNATE
                    | SPECULATION_INPUT_IBPB,
                0,
            ),
            (
                SPECULATION_INPUT_RETBLEED | SPECULATION_INPUT_SRSO | SPECULATION_INPUT_STIBP,
                0,
            ),
            (
                SPECULATION_INPUT_IBPB | SPECULATION_INPUT_STIBP | SPECULATION_INPUT_SMT,
                0,
            ),
        ];
        for (inputs, controls) in cases
        {
            assert_eq!(
                select(Inputs(inputs)).bits(),
                controls,
                "inputs {inputs:#x}"
            );
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
        assert_eq!(
            msr_bits(Controls(SPECULATION_CONTROL_IBRS_ENTRY)),
            [(0x48, 1), (0xC000_0080, 0), (0x1B01, 0)]
        );
        assert_eq!(
            msr_bits(Controls(
                SPECULATION_CONTROL_STIBP | SPECULATION_CONTROL_IBPB_ENTRY
            )),
            [(0x48, 2), (0xC000_0080, 0), (0x1B01, 0)]
        );
    }

    // Defect caught: IBRS on entry that leaves `IBRS` set in user mode, writes a
    // kernel value without it, or drops `BHI_DIS_S` on either side.
    #[test]
    fn spec_ctrl_values_differ_in_ibrs_alone()
    {
        assert_eq!(
            spec_ctrl_values(Controls(
                SPECULATION_CONTROL_IBRS_ENTRY | SPECULATION_CONTROL_BHI_DIS_S
            )),
            (0x401, 0x400)
        );
        assert_eq!(
            spec_ctrl_values(Controls(SPECULATION_CONTROL_IBRS_ENTRY)),
            (1, 0)
        );
        assert_eq!(
            spec_ctrl_values(Controls(
                SPECULATION_CONTROL_IBRS_ENTRY | SPECULATION_CONTROL_STIBP
            )),
            (3, 2)
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
        assert!(!SERAPH_IBRS_ENTRY.load(Ordering::Relaxed));
        assert_eq!(SELECTED.load(Ordering::Relaxed), controls.bits());
        assert_eq!(INPUTS.load(Ordering::Relaxed), SPECULATION_INPUT_SPECTRE_V2);
        let ibrs = Controls(SPECULATION_CONTROL_IBRS_ENTRY | SPECULATION_CONTROL_BHB_CLEAR);
        install(Inputs(SPECULATION_INPUT_RETBLEED), ibrs);
        assert!(SERAPH_IBRS_ENTRY.load(Ordering::Relaxed));
        assert!(BHB_CLEAR.load(Ordering::Relaxed));
        assert!(!RETPOLINE.load(Ordering::Relaxed));
        assert_eq!(SERAPH_SPEC_CTRL_KERNEL.load(Ordering::Relaxed), 1);
        assert_eq!(SERAPH_SPEC_CTRL_USER.load(Ordering::Relaxed), 0);
        assert!(!SERAPH_IBPB_ENTRY.load(Ordering::Relaxed));
        assert!(!SERAPH_RSB_FILL_IBPB.load(Ordering::Relaxed));
        let ibpb = Controls(
            SPECULATION_CONTROL_IBPB_ENTRY
                | SPECULATION_CONTROL_STIBP
                | SPECULATION_CONTROL_RSB_FILL_IBPB,
        );
        install(Inputs(SPECULATION_INPUT_SRSO), ibpb);
        assert!(SERAPH_IBPB_ENTRY.load(Ordering::Relaxed));
        assert!(SERAPH_RSB_FILL_IBPB.load(Ordering::Relaxed));
        assert!(!SERAPH_IBRS_ENTRY.load(Ordering::Relaxed));
        assert_eq!(SERAPH_SPEC_CTRL_KERNEL.load(Ordering::Relaxed), 2);
        assert_eq!(SERAPH_SPEC_CTRL_USER.load(Ordering::Relaxed), 2);
    }

    // Defect caught: shadow stacks turned on beside the retpoline sequence,
    // whose `ret` to the branch target raises #CP, or kept off where no
    // selected control rewrites a return. The vectors above, each with
    // `CET_SS` enumerated: the development host (Alder Lake, enhanced IBRS),
    // Skylake with IBRS (IBRS on entry, which rewrites no return) and Zen 4
    // (Automatic IBRS, AMD's APM2 § 3.1.7) keep shadow stacks; Zen 3
    // (no Automatic IBRS, so the retpoline sequence, AMD-SB-1036) and the CI's
    // TCG CPU lose them.
    #[test]
    fn shadow_stacks_yield_to_a_return_rewriting_control()
    {
        let mut host = cpu(Vendor::Intel, 0x0009_0672);
        host.leaf7_edx = 1 << 29;
        host.leaf7_2_edx = 0x17;
        host.arch_capabilities = 0x4000_0000_1400_E06B;
        let mut zen4 = cpu(Vendor::Amd, 0x00A6_0F12);
        zen4.ext21_eax = (1 << 8) | (1 << 5);
        let zen3 = cpu(Vendor::Amd, 0x00A2_0F10);
        let mut tcg = cpu(Vendor::Amd, 0x0000_0663);
        tcg.ext8_ebx = 0x204;
        tcg.ext21_eax = 0x41;
        let mut skylake = cpu(Vendor::Intel, 0x0005_06E3);
        skylake.leaf7_edx = (1 << 29) | (1 << 26);
        for (name, part, keeps_shadow_stacks) in [
            ("development host", &host, true),
            ("Skylake with IBRS", &skylake, true),
            ("Zen 4", &zen4, true),
            ("Zen 3", &zen3, false),
            ("TCG", &tcg, false),
        ]
        {
            let controls = select(Inputs::of(part, &derive(part)));
            assert_eq!(!controls.rewrites_returns(), keeps_shadow_stacks, "{name}");
        }
    }

    // Defect caught: a selection that fills the return stack buffer on a
    // switch while shadow stacks stay on: `switch`'s fill drops its return
    // addresses from the stack alone, which is sound only with shadow stacks
    // off. Every input set is tried.
    #[test]
    fn switch_fill_is_never_selected_with_shadow_stacks()
    {
        for inputs in 0..=::syscall::SPECULATION_INPUT_ALL
        {
            let controls = select(Inputs(inputs));
            if controls.has(SPECULATION_CONTROL_RSB_FILL_SWITCH)
            {
                assert!(controls.rewrites_returns(), "inputs {inputs:#x}");
            }
        }
    }

    // Defect caught: a CPU that does not enumerate an MSR control the boot CPU
    // selected brought up anyway, so its MSR access raises #GP, or a CPU
    // halted for a control that was not selected. Each MSR control is tried
    // selected and missing, selected and present, and not selected.
    #[test]
    fn a_cpu_without_a_selected_msr_control_is_named()
    {
        for (control, input, message) in MSR_CONTROLS
        {
            assert_eq!(
                missing_msr_control(Controls(control), Inputs(0)),
                Some(message)
            );
            assert_eq!(missing_msr_control(Controls(control), Inputs(input)), None);
            assert_eq!(
                missing_msr_control(Controls(0), Inputs(0)),
                None,
                "{message}"
            );
        }
        let all = Controls(::syscall::SPECULATION_CONTROL_ALL);
        assert_eq!(
            missing_msr_control(all, Inputs(::syscall::SPECULATION_INPUT_ALL)),
            None
        );
    }
}
