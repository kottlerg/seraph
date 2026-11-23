// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/cpu.rs

//! RISC-V 64-bit CPU control primitives.

// ── Halt / interrupt helpers ─────────────────────────────────────────────────

/// Atomically wait for an interrupt and enable interrupts on return.
///
/// Precondition: `sstatus.SIE = 0` on entry (supervisor interrupts
/// disabled). The caller — the idle loop — disables SIE before its
/// flag/run-queue check and invokes this primitive if neither is set.
///
/// Postcondition: `sstatus.SIE = 1` on return. Any interrupt that became
/// pending in `sip` during the halt (or before the halt, while SIE was
/// still 0) traps immediately as SIE is re-enabled; the handler runs
/// before control returns to the caller.
///
/// Per RISC-V privileged spec §3.3.2 (20211203 / 20250508):
///
/// > The operation of WFI must be unaffected by the global interrupt bits
/// > in `mstatus` (MIE and SIE) [...], but should honor the individual
/// > interrupt enables (e.g., `mie`), allowing these to be used as
/// > intended to simply control the set of interrupts that would cause
/// > the hart to resume.
///
/// So `wfi` with `SIE=0` still resumes when a supervisor interrupt
/// becomes pending and individually enabled (via `sie`). This is the
/// spec-correct idiom for atomic "enable + halt": during the halt the
/// interrupt is held pending (because SIE=0 defers trap entry); `wfi`
/// wakes on the pending bit; the subsequent `csrsi sstatus, SIE` sets
/// SIE=1 and the pending interrupt traps immediately.
///
/// `nomem` is intentionally omitted so the compiler may not reorder
/// preceding atomic loads across this call.
pub fn halt_until_interrupt()
{
    // SAFETY: `wfi` is privileged and safe in S-mode with MSTATUS.TW=0
    // (the kernel never sets TW). The subsequent `csrsi` sets SIE=1,
    // releasing any pending supervisor interrupt into the trap path.
    // Caller contract: SIE=0 on entry.
    unsafe {
        core::arch::asm!(
            "wfi",
            "csrsi sstatus, 0x2",
            options(nostack, preserves_flags),
        );
    }
}

// ── Stack and memory sampling ─────────────────────────────────────────────────

/// Load one word that another CPU may be writing concurrently, as an opaque
/// machine load the compiler neither elides nor reasons about.
///
/// For diagnostics that sample memory a running CPU owns (the idle-stack depth
/// scan, `crate::stack_depth`): a Rust read racing a plain store is undefined
/// behaviour, an `ld` instruction is not, and a stale value only changes the
/// sample.
///
/// # Safety
/// `p` is a mapped, 8-byte aligned kernel address.
#[cfg(not(test))]
pub unsafe fn load_word_racy(p: *const u64) -> u64
{
    let v: u64;
    // SAFETY: p is mapped and aligned per the contract; a load has no side
    // effect.
    unsafe {
        core::arch::asm!(
            "ld {}, 0({})",
            out(reg) v,
            in(reg) p,
            options(nostack, readonly, preserves_flags)
        );
    }
    v
}

/// Read the current stack pointer (`sp`, x2).
///
/// Used by the panic-path backtrace scanner to bound the kernel-stack walk,
/// and at `kernel_entry`'s first statement to locate the handoff stack
/// (`crate::stack_depth::note_boot_entry`).
#[cfg(not(test))]
pub fn current_stack_pointer() -> u64
{
    let sp: u64;
    // SAFETY: reads the stack pointer register only; no memory access, no clobbers.
    unsafe {
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

// ── Baseline feature gate ─────────────────────────────────────────────────────

/// Verify the RISC-V platform baseline and refuse unsupported hardware.
///
/// This runs in early boot, where supervisor-mode detection is limited (`misa`
/// is not S-mode-readable and `satp` cannot be safely probed before the kernel
/// page tables are active). It probes the SBI HSM extension, which is required to
/// start secondary harts, and the SBI RFENCE extension, whose `remote_fence_i`
/// [`sync_instruction_fetch`] issues (`sbi_get_spec_version` is unsuitable as a
/// presence check — a compliant SBI always returns success, and a truly absent
/// SBI traps on the `ecall`). The remaining required features are asserted where each is
/// safely detectable: the Vector extension at `fpu::cache_vlenb` (the boot
/// hart) and `fpu::check_ap_vlenb` (each secondary hart), and the
/// ASID-tagged TLB at `paging::enable_tagged_tlb`. See
/// `docs/platform-requirements.md` § Boot-Time Feature Gate.
///
/// # Safety
/// Must execute in supervisor mode during early boot, after the console is live
/// so the diagnostic is visible.
#[cfg(not(test))]
pub unsafe fn verify_baseline()
{
    /// SBI Base extension ID.
    const SBI_EXT_BASE: u64 = 0x10;
    /// `sbi_probe_extension` function ID.
    const SBI_PROBE_EXTENSION: u64 = 3;
    /// HSM (Hart State Management) extension ID — ASCII "HSM".
    const SBI_EXT_HSM: u64 = 0x0048_534D;

    let probe = super::sbi::sbi_call(SBI_EXT_BASE, SBI_PROBE_EXTENSION, SBI_EXT_HSM, 0, 0);
    if probe.error != 0 || probe.value == 0
    {
        crate::fatal("SBI HSM extension not present — required to start secondary harts");
    }
    let probe = super::sbi::sbi_call(SBI_EXT_BASE, SBI_PROBE_EXTENSION, SBI_EXT_RFENCE, 0, 0);
    if probe.error != 0 || probe.value == 0
    {
        crate::fatal("SBI RFENCE extension not present — required for remote fence.i");
    }
}

/// SBI RFENCE extension ID — ASCII "RFNC".
const SBI_EXT_RFENCE: u64 = 0x5246_4E43;

/// Make instruction fetch on every hart see the stores made before the call
/// (`mm::icache::sync_user_code`): a local `fence.i`, then SBI RFENCE
/// `remote_fence_i` on every hart (`hart_mask_base` = -1), which returns once
/// each has run one. RISC-V instruction fetch is not coherent with stores
/// (the Zifencei rule), and `fence.i` orders only the hart that runs it.
/// Halts on an SBI error: the call takes no argument a caller supplies, so an
/// error is the firmware's, and code that might run stale must not.
#[cfg(not(test))]
pub fn sync_instruction_fetch()
{
    /// `sbi_remote_fence_i` function ID.
    const SBI_RFENCE_REMOTE_FENCE_I: u64 = 0;

    fence_i();
    let ret = super::sbi::sbi_call(SBI_EXT_RFENCE, SBI_RFENCE_REMOTE_FENCE_I, 0, u64::MAX, 0);
    if ret.error != 0
    {
        crate::fatal("sync_instruction_fetch: SBI remote_fence_i returned an error");
    }
}

/// Order this hart's instruction fetch after its earlier stores (`fence.i`,
/// Zifencei).
#[cfg(not(test))]
fn fence_i()
{
    // fence.i: invalidates this hart's instruction-fetch view so later fetches
    // observe every store this hart made, or observed, before it. No operands,
    // no register clobbers, no memory access, and no flags; it needs only
    // S-mode, which the kernel runs in.
    // SAFETY: the instruction changes no architectural state Rust tracks.
    unsafe { core::arch::asm!("fence.i", options(nostack, preserves_flags)) };
}

/// Test-build stub: the sync is an instruction and a firmware call.
#[cfg(test)]
pub fn sync_instruction_fetch() {}

/// Test-build stub: the baseline gate issues an SBI ecall and is a no-op in
/// host unit tests.
#[cfg(test)]
pub unsafe fn verify_baseline() {}

// ── ASID width probe ──────────────────────────────────────────────────────────

/// Probe the number of implemented ASID bits in `satp[59:44]`.
///
/// Per RISC-V Privileged ISA §4.1.11, software discovers the ASID width by
/// writing ones to every ASID bit and reading back which ones stick. This
/// writes a test `satp` with all ASID bits set (preserving MODE and PPN), reads
/// it back, restores the original `satp`, and issues `sfence.vma` to discard
/// any translation cached under the transient ASID. Returns the count of
/// implemented ASID bits; `0` means ASIDs are unsupported, which
/// `paging::enable_tagged_tlb` refuses as a platform-baseline violation.
///
/// # Safety
/// Must execute in S-mode with `satp` already holding a valid root (Phase 5
/// onward). Transiently changes the active ASID; the restore + fence makes the
/// change invisible to translation.
#[cfg(not(test))]
pub unsafe fn probe_asid_bits() -> u32
{
    /// ASID field starts at bit 44 of `satp` on RV64.
    const ASID_SHIFT: u64 = 44;
    /// 16 ASID bits maximum on RV64 (`satp[59:44]`).
    const ASID_MASK: u64 = 0xFFFF << ASID_SHIFT;

    let orig: u64;
    // SAFETY: reading satp is always safe in S-mode.
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) orig, options(nostack, nomem));
    }

    let probe = orig | ASID_MASK;
    let readback: u64;
    // SAFETY: the probe value keeps the original MODE and PPN, so the active
    // translation root is unchanged; only the (unused) ASID field differs. satp
    // is restored to `orig` and the TLB fenced before this returns.
    unsafe {
        core::arch::asm!(
            "csrw satp, {probe}",
            "csrr {back}, satp",
            "csrw satp, {orig}",
            "sfence.vma zero, zero",
            probe = in(reg) probe,
            back = out(reg) readback,
            orig = in(reg) orig,
            options(nostack),
        );
    }

    // Implemented ASID bits are the contiguous low-order bits of the field that
    // read back as 1.
    let implemented = (readback & ASID_MASK) >> ASID_SHIFT;
    implemented.count_ones()
}

// ── Firmware-granted CSR accesses (Smstateen) ─────────────────────────────────

// Under Smstateen, M-mode firmware grants S-mode each CSR the kernel touches
// that `mstateen0` gates, by a bit of that register: `sstateen0` (CSR 0x10C)
// by `SE0` (bit 63), `senvcfg` (CSR 0x10A) by `ENVCFG` (bit 62), `siselect`
// (0x150) and `sireg` (0x151) by `CSRIND` (bit 60), and `stopei` (0x15C) and
// the IMSIC interrupt file behind `sireg` by `IMSIC` (bit 58). A clear bit, or
// a hart without the CSR, makes the access raise an illegal-instruction
// exception. Each hart's first access to each of these CSRs is made through
// the routines below, which recover from that trap so the boot halts naming
// the CSR and its bit; later accesses go direct, since the grants do not
// change after boot.
//
// `__sstateen0_write` and `__senvcfg_write` each write their CSR (by number)
// from `a0` and read it back into `a0`; `__imsic_csr_probe` selects
// `eidelivery` (0x70) in `siselect` and reads it through `sireg`, then reads
// `stopei`, which claims nothing (only a write claims), returning `a0` = 0.
// Each returns `a1` = 0 and, apart from `a0` and `a1`, touches no register,
// memory or stack. The faultable range
// `__csr_grant_fault_start`..`__csr_grant_fault_end` spans the three
// routines, whose CSR accesses are the only instructions in it that can raise
// an illegal-instruction exception. A trap there resumes at
// `__csr_grant_fault_fixup`, which returns `a0` = 0 and `a1` = 1 to the caller
// of whichever routine trapped: each is a leaf, so `ra` still holds that
// caller's return address. See [`csr_grant_fault_fixup`] for the hook.
#[cfg(not(test))]
core::arch::global_asm!(
    ".section .text.csr_grant, \"ax\"",
    ".global __sstateen0_write",
    ".global __senvcfg_write",
    ".global __imsic_csr_probe",
    ".global __csr_grant_fault_start",
    ".global __csr_grant_fault_end",
    ".global __csr_grant_fault_fixup",
    "__csr_grant_fault_start:",
    // fn __sstateen0_write(value: a0) -> (a0: the read back, a1: 1 if trapped)
    "__sstateen0_write:",
    "    li    a1, 0",
    "    csrw  0x10C, a0",
    "    csrr  a0, 0x10C",
    "    ret",
    // fn __senvcfg_write(value: a0) -> (a0: the read back, a1: 1 if trapped)
    "__senvcfg_write:",
    "    li    a1, 0",
    "    csrw  0x10A, a0",
    "    csrr  a0, 0x10A",
    "    ret",
    // fn __imsic_csr_probe() -> (a0: 0, a1: 1 if trapped)
    "__imsic_csr_probe:",
    "    li    a1, 0",
    "    li    a0, 0x70",
    "    csrw  0x150, a0",
    "    csrr  a0, 0x151",
    "    csrr  a0, 0x15C",
    "    li    a0, 0",
    "    ret",
    "__csr_grant_fault_end:",
    "__csr_grant_fault_fixup:",
    "    li    a0, 0",
    "    li    a1, 1",
    "    ret",
);

/// What the firmware-granted CSR routines return in `a0` and `a1`: the RISC-V
/// calling convention returns a two-word aggregate in those registers.
#[cfg(not(test))]
#[repr(C)]
struct GrantedAccess
{
    /// The CSR read back after the write (0 from `__imsic_csr_probe`, and when
    /// an access trapped).
    read_back: u64,
    /// 1 when an access trapped, else 0.
    trapped: u64,
}

#[cfg(not(test))]
impl GrantedAccess
{
    /// The read back, or `None` when an access trapped.
    fn read_back(&self) -> Option<u64>
    {
        (self.trapped == 0).then_some(self.read_back)
    }
}

#[cfg(not(test))]
unsafe extern "C" {
    /// Write `value` to `sstateen0` and read the CSR back.
    fn __sstateen0_write(value: u64) -> GrantedAccess;
    /// Write `value` to `senvcfg` and read the CSR back.
    fn __senvcfg_write(value: u64) -> GrantedAccess;
    /// Access `siselect`, `sireg` (at `eidelivery`) and `stopei`.
    fn __imsic_csr_probe() -> GrantedAccess;
    /// The first instruction of the firmware-granted CSR routines.
    static __csr_grant_fault_start: u8;
    /// First byte past the last of them.
    static __csr_grant_fault_end: u8;
    /// Recovery landing pad: reports the trap.
    static __csr_grant_fault_fixup: u8;
}

/// If `pc` is one of the firmware-granted CSR accesses, return the address of
/// their recovery fixup; otherwise `None`. Consulted by
/// `interrupts::kernel_exception` on an S-mode illegal-instruction trap, which
/// redirects `sepc` to the fixup so the caller ([`disable_unswitched_user_state`]
/// or `aia::init_hart`) halts the boot by name instead of through the
/// unhandled-exception report.
#[cfg(not(test))]
pub(super) fn csr_grant_fault_fixup(pc: u64) -> Option<u64>
{
    let lo = core::ptr::addr_of!(__csr_grant_fault_start) as u64;
    let hi = core::ptr::addr_of!(__csr_grant_fault_end) as u64;
    if pc >= lo && pc < hi
    {
        Some(core::ptr::addr_of!(__csr_grant_fault_fixup) as u64)
    }
    else
    {
        None
    }
}

/// Whether S-mode reaches the AIA CSRs the kernel uses: `siselect` and `sireg`
/// (`mstateen0.CSRIND`) and `stopei` and the IMSIC interrupt file
/// (`mstateen0.IMSIC`). Accesses each once through `__imsic_csr_probe`, which
/// reads `eidelivery` and `stopei` and writes only `siselect`; false when an
/// access trapped.
///
/// # Safety
/// Supervisor mode on a hart with Ssaia, with interrupts disabled (no trap may
/// change `siselect` before the caller's next select), after the hart's
/// `stvec` is installed, `sscratch` is cleared and its per-CPU pointer is
/// installed: a trapped access is recovered through `kernel_exception`, whose
/// trap entry reads the per-CPU stack floor and which reads `current_cpu()`.
#[cfg(not(test))]
pub(super) unsafe fn imsic_csrs_reachable() -> bool
{
    // SAFETY: `__imsic_csr_probe` is a routine above, a C-ABI leaf that writes
    // `a0`, `a1` and `siselect` alone and touches no memory. Its three
    // instructions that can trap are the CSR accesses, whose
    // illegal-instruction trap `kernel_exception` resumes at the fixup through
    // `csr_grant_fault_fixup`; the caller's contract installs the trap path that
    // recovery runs on.
    let access = unsafe { __imsic_csr_probe() };
    access.trapped == 0
}

/// Disable, for U-mode, every state the kernel does not switch: write
/// `sstateen0` with no state enabled ([`super::encoding::SSTATEEN0_USER_ENABLES`]),
/// then `senvcfg` whole with no environment control granted
/// ([`super::encoding::SENVCFG_USER_ENABLES`]), replacing what the firmware or
/// reset left, and halt the boot unless each reads back so. No hart then grants
/// U-mode a cache-block operation, pointer masking, landing pads or a shadow
/// stack.
///
/// Ssstateen is required, and the M-mode firmware must grant S-mode both CSRs
/// (`mstateen0.SE0` and `mstateen0.ENVCFG`; docs/platform-requirements.md
/// § riscv64 Classification). A hart without Ssstateen, or whose firmware keeps
/// either CSR from S-mode, traps at the access, and the fixup turns the trap into
/// a halt that names the CSR and its `mstateen0` bit; a hart without `senvcfg`
/// (outside the RVA23 floor, which carries Privileged Architecture 1.13) halts
/// the same way. The CSRs are per hart: the BSP calls this in Phase 5 and each AP
/// in `kernel_entry_ap`. `sstateen1` to `sstateen3` are not written: no
/// ratified extension defines state in them.
///
/// # Safety
/// Must execute in S-mode on the hart being initialised, after its `stvec` is
/// installed, `sscratch` is cleared and its per-CPU pointer is installed: a
/// trapped access is recovered through `kernel_exception`, which reads
/// `current_cpu()`.
#[cfg(not(test))]
pub unsafe fn disable_unswitched_user_state()
{
    use super::encoding::{
        SENVCFG_USER_ENABLES, SSTATEEN0_USER_ENABLES, StateEnableError, check_state_enable,
    };

    // SAFETY: `__sstateen0_write` is a routine above, a C-ABI leaf that writes
    // `a0` and `a1` alone and touches no memory. Its two instructions that can
    // trap are the `sstateen0` accesses, whose illegal-instruction trap
    // `kernel_exception` resumes at the fixup through
    // `csr_grant_fault_fixup`; the caller's contract installs the trap path
    // that recovery runs on.
    let access = unsafe { __sstateen0_write(SSTATEEN0_USER_ENABLES) };
    match check_state_enable(SSTATEEN0_USER_ENABLES, access.read_back())
    {
        Ok(()) =>
        {}
        Err(StateEnableError::Inaccessible) => crate::fatal(
            "Ssstateen: sstateen0 not accessible from S-mode (no Ssstateen, or the firmware \
             left mstateen0.SE0 clear) — required (RVA23)",
        ),
        Err(StateEnableError::Kept(value)) =>
        {
            crate::kprintln!(
                "sstateen0 read back {:#x}, not the {:#x} written",
                value,
                SSTATEEN0_USER_ENABLES
            );
            crate::fatal("Ssstateen: sstateen0 kept a U-mode state enable set");
        }
    }

    // SAFETY: as for `__sstateen0_write`: `__senvcfg_write` is the other leaf
    // above, its two instructions that can trap are the `senvcfg` accesses, and
    // their trap resumes at the same fixup. `senvcfg` gates U-mode environment
    // features only.
    let access = unsafe { __senvcfg_write(SENVCFG_USER_ENABLES) };
    match check_state_enable(SENVCFG_USER_ENABLES, access.read_back())
    {
        Ok(()) =>
        {}
        Err(StateEnableError::Inaccessible) => crate::fatal(
            "senvcfg not accessible from S-mode (the firmware left mstateen0.ENVCFG clear, \
             or the hart has no senvcfg) — required (RVA23)",
        ),
        Err(StateEnableError::Kept(value)) =>
        {
            crate::kprintln!(
                "senvcfg read back {:#x}, not the {:#x} written",
                value,
                SENVCFG_USER_ENABLES
            );
            crate::fatal("senvcfg kept a U-mode environment enable set");
        }
    }
}

/// Test-build stub: the `sstateen0` and `senvcfg` writes are privileged CSR
/// accesses.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn disable_unswitched_user_state() {}

// ── Per-CPU tp register ───────────────────────────────────────────────────────

/// Install `addr` as the per-CPU data pointer for the current hart.
///
/// Writes `addr` into the `tp` (thread pointer) register so that
/// `current_cpu()` can recover the hart's `PerCpuData` without a
/// global lookup. Must be called from Phase 5 (BSP) and
/// `kernel_entry_ap` (each AP) before any `current_cpu()` call.
///
/// # Safety
/// Must execute in supervisor mode. `addr` must be the virtual address
/// of a valid `PerCpuData` that outlives the hart's execution.
#[cfg(not(test))]
pub unsafe fn install_percpu(addr: u64)
{
    // SAFETY: writing tp is always safe in S-mode; addr is valid per caller.
    unsafe {
        core::arch::asm!(
            "mv tp, {}",
            in(reg) addr,
            options(nostack, nomem),
        );
    }
}

/// Return the logical CPU index of the executing hart.
///
/// Reads `PerCpuData::cpu_id` (u32 at offset 0) via the `tp` register
/// which was set by [`install_percpu`].
///
/// On non-test builds this dereferences `tp`; in test builds returns 0.
pub fn current_cpu() -> u32
{
    #[cfg(not(test))]
    {
        let tp: u64;
        // SAFETY: reading tp is always safe.
        unsafe {
            core::arch::asm!(
                "mv {}, tp",
                out(reg) tp,
                options(nostack, nomem),
            );
        }
        // SAFETY: install_percpu ensures tp points to a valid PerCpuData with
        // cpu_id at offset 0.
        unsafe { *(tp as *const u32) }
    }
    #[cfg(test)]
    {
        0
    }
}

/// Read the pointer at byte `OFFSET` of this CPU's `PerCpuData` with one
/// `tp`-relative load.
///
/// # Safety
/// `tp` holds this CPU's `PerCpuData` address (`install_percpu`), and
/// `OFFSET` is the offset of a pointer field of it, below the 2 KiB reach of
/// a load's immediate.
#[cfg(not(test))]
#[inline]
pub unsafe fn read_percpu_ptr<T, const OFFSET: usize>() -> *const T
{
    let ptr: *const T;
    // SAFETY: OFFSET(tp) is the pointer field (caller contract); the load
    // writes no memory.
    unsafe {
        core::arch::asm!(
            "ld {}, {off}(tp)",
            out(reg) ptr,
            off = const OFFSET,
            options(nostack, readonly, preserves_flags),
        );
    }
    ptr
}

// ── Core topology ─────────────────────────────────────────────────────────────

/// The key of the core logical CPU `cpu` runs on: equal for exactly the CPUs
/// that share one core. Each hart is taken as a core of its own, so the key is
/// `cpu`: RISC-V has no instruction that reports harts sharing a core, the
/// platform describes it only through the device tree's `cpu-map` or the ACPI
/// PPTT, and the bootloader parses neither (core/kernel/docs/scheduler.md
/// § SMT Awareness records the deferral and when it ends).
pub fn core_key(cpu: u32) -> u32
{
    cpu
}

// ── Kernel trap stack ─────────────────────────────────────────────────────────

/// Set the kernel stack pointer used when a trap fires from U-mode.
///
/// On RISC-V, `sscratch` holds the per-CPU pointer (`per_cpu_ptr(cpu_id)`, the
/// kernel `tp` value) while in U-mode and 0 in S-mode, not the stack pointer,
/// so `trap_entry` can recover the per-CPU pointer on U-mode entry.  The
/// actual kernel stack top is stored in `PerCpuData::kernel_rsp` (offset 8
/// from `tp`), from which `trap_entry` loads it when switching stacks.
///
/// Must be called before the first `sret` to U-mode and again whenever the
/// current thread changes.
///
/// # Safety
/// Must execute in supervisor mode.  `tp` must already point to a valid
/// `PerCpuData` (guaranteed after [`install_percpu`] is called in Phase 5).
#[cfg(not(test))]
#[inline]
pub unsafe fn set_kernel_trap_stack(stack_top: u64)
{
    // SAFETY: tp = &PER_CPU[cpu_id] (installed in Phase 5). offset 8 =
    // PerCpuData::kernel_rsp. Storing via tp is safe in S-mode.
    unsafe {
        core::arch::asm!(
            "sd {}, 8(tp)",
            in(reg) stack_top,
            options(nostack),
        );
    }
}

// ── User-copy primitive (fault-recoverable) ───────────────────────────────────

// `copy_user` implements the user-copy contract in core/kernel/docs/arch-interface.md
// § cpu: it opens and closes the SUM window (sstatus.SUM, bit 18), and a fault inside
// the copy redirects to `__copy_user_fixup` (which clears SUM and returns the count of
// bytes not copied, the loop's `a2` at the fault). See `crate::uaccess` for the typed wrappers and
// `interrupts::trap_dispatch` for the fixup hook.
#[cfg(not(test))]
core::arch::global_asm!(
    ".section .text.copy_user, \"ax\"",
    ".global __copy_user",
    ".global __copy_user_fault_start",
    ".global __copy_user_fault_end",
    ".global __copy_user_fixup",
    // fn __copy_user(dst: a0, src: a1, len: a2) -> a0 (bytes not copied)
    "__copy_user:",
    "    li    t0, 0x40000",       // SUM = bit 18
    "    csrrs zero, sstatus, t0", // open the access window
    "1:",
    "    beqz  a2, 2f",
    "__copy_user_fault_start:",
    "    lb    t1, 0(a1)", // load from src (user side may fault)
    "    sb    t1, 0(a0)", // store to dst (user side may fault)
    "__copy_user_fault_end:",
    "    addi  a0, a0, 1",
    "    addi  a1, a1, 1",
    "    addi  a2, a2, -1",
    "    j     1b",
    "2:",
    "    csrrc zero, sstatus, t0", // close the access window
    "    li    a0, 0",
    "    ret",
    "__copy_user_fixup:",
    "    li    t0, 0x40000",
    "    csrrc zero, sstatus, t0", // close the access window (recovery path)
    "    mv    a0, a2",            // the faulting byte's remaining count: at least 1
    "    ret",
);

#[cfg(not(test))]
unsafe extern "C" {
    /// Raw user-copy routine (`dst=a0, src=a1, len=a2`); returns 0 on success or,
    /// if a fault on the user span was recovered, the bytes not copied.
    fn __copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    /// First byte of the faultable copy region (the `lb`/`sb` pair).
    static __copy_user_fault_start: u8;
    /// First byte past the faultable copy region.
    static __copy_user_fault_end: u8;
    /// Recovery landing pad: closes the SUM window, returns the bytes left.
    static __copy_user_fixup: u8;
}

/// Copy `len` bytes from `src` to `dst` across the SUM window with fault
/// recovery. Returns 0 on success; when a user-span fault was recovered, the
/// bytes not copied (at least 1), so the faulting byte is at offset
/// `len - returned`.
///
/// # Safety
/// Must execute in supervisor mode. The operands must be arranged so the user
/// pointer is the only one that may fault; the non-user side must be valid for
/// `len` bytes.
#[cfg(not(test))]
#[inline]
pub unsafe fn copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize
{
    // SAFETY: forwarded to the asm routine; a fault on the user span is recovered
    // by the trap dispatcher via __copy_user_fixup.
    unsafe { __copy_user(dst, src, len) }
}

/// Host-test stub: the SUM CSR write is privileged and the test pointers never
/// fault, so perform a plain copy and report success.
#[cfg(test)]
pub unsafe fn copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize
{
    // SAFETY: caller guarantees src/dst valid for len bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    0
}

/// If `pc` lies within `copy_user`'s faultable region, return the address of the
/// recovery fixup; otherwise `None`. Consulted by the trap dispatcher on an
/// S-mode page fault to convert an unmapped/read-only user access into an error
/// return instead of a panic.
#[cfg(not(test))]
pub fn user_copy_fixup(pc: u64) -> Option<u64>
{
    let lo = core::ptr::addr_of!(__copy_user_fault_start) as u64;
    let hi = core::ptr::addr_of!(__copy_user_fault_end) as u64;
    if pc >= lo && pc < hi
    {
        Some(core::ptr::addr_of!(__copy_user_fixup) as u64)
    }
    else
    {
        None
    }
}

// ── Interrupt save/restore ────────────────────────────────────────────────────
//
// Every `sstatus.SIE` write below omits `nomem`, as `disable_interrupts`
// does: an asm block marked `nomem` may have memory operations, atomics
// included, reordered across it, and a lock acquisition or a shared-state
// access moved across an interrupt-state change would run under the wrong
// interrupt state.

/// Save the current interrupt-enable state and disable supervisor interrupts.
/// Returns the sstatus value at the time of the call (opaque to callers).
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
#[inline]
pub unsafe fn save_and_disable_interrupts() -> u64
{
    let sstatus: u64;
    // SAFETY: csrrci atomically reads sstatus into the output register and
    // clears the SIE bit; it touches no memory and no other register.
    // Supervisor mode per the caller contract.
    unsafe {
        core::arch::asm!(
            "csrrci {sstatus}, sstatus, 2",
            sstatus = out(reg) sstatus,
            options(nostack, preserves_flags),
        );
    }
    sstatus
}

/// Restore the interrupt-enable state saved by [`save_and_disable_interrupts`].
///
/// Sets or clears `sstatus.SIE` from `saved`, per the restore contract in
/// `core/kernel/docs/arch-interface.md` § cpu.
///
/// # Safety
/// Must execute in supervisor mode. `saved` must be a value returned by
/// `save_and_disable_interrupts` on this hart.
#[cfg(not(test))]
#[inline]
pub unsafe fn restore_interrupts(saved: u64)
{
    let sie_bit = (saved >> 1) & 1;
    if sie_bit != 0
    {
        // SAFETY: csrsi sets the SIE bit of sstatus; it touches no memory
        // and clobbers no register. Supervisor mode per the caller contract.
        unsafe {
            core::arch::asm!("csrsi sstatus, 2", options(nostack, preserves_flags));
        }
    }
    else
    {
        // SAFETY: csrci clears the SIE bit of sstatus; it touches no memory
        // and clobbers no register. Supervisor mode per the caller contract.
        unsafe {
            core::arch::asm!("csrci sstatus, 2", options(nostack, preserves_flags));
        }
    }
}

// ── Kernel-entry flags check ──────────────────────────────────────────────────

/// `sstatus.SUM` (bit 18): S-mode access to U-mode pages.
const SSTATUS_SUM: u64 = 1 << 18;

/// Read `sstatus`.
///
/// Clobbers only the output register; touches no memory. Assumes S-mode.
#[cfg(not(test))]
#[inline]
fn read_sstatus() -> u64
{
    let sstatus: u64;
    // SAFETY: csrr sstatus is a privileged S-mode read with no side effect.
    unsafe {
        core::arch::asm!("csrr {0}, sstatus", out(reg) sstatus, options(nostack, nomem));
    }
    sstatus
}

/// Debug-build check, at syscall dispatch, that `sstatus.SUM` is clear: the
/// RISC-V analogue of the x86-64 RFLAGS AC/DF/TF check. An `ecall` from U-mode
/// runs with the `sstatus` the thread resumed under, which
/// `TrapFrame::sanitize_for_user_resume` and the first-entry value keep SUM-clear,
/// and only the user-copy routines open a SUM window, so a set SUM here is a
/// regression that lets kernel code touch user pages outside them. Not checked
/// on other trap entries: a trap taken from S-mode inside a user-copy window
/// carries SUM legitimately. A no-op in release builds (the CSR read is not
/// performed).
#[cfg(not(test))]
#[inline]
pub fn debug_assert_kernel_entry_flags()
{
    debug_assert!(
        read_sstatus() & SSTATUS_SUM == 0,
        "kernel entry: sstatus.SUM set at syscall dispatch"
    );
}

// ── Interrupt control ─────────────────────────────────────────────────────────

/// Disable supervisor-mode interrupts via sstatus.SIE.
///
/// # Safety
/// Changes global CPU interrupt state. Caller is responsible for managing
/// interrupt state across the transition.
///
/// `nomem` is intentionally omitted: the idle loop relies on no atomic
/// loads being reordered across this call.
pub unsafe fn disable_interrupts()
{
    // SAFETY: csrci clears the SIE bit (bit 1) in sstatus.
    // Caller guarantees this is called in supervisor mode.
    unsafe {
        core::arch::asm!("csrci sstatus, 0x2", options(nostack, preserves_flags));
    }
}

/// Disable interrupts and halt the CPU permanently using `wfi`.
///
/// `wfi` (wait-for-interrupt) suspends the hart until an interrupt arrives.
/// With SIE cleared the hart cannot actually handle the interrupt, so it
/// re-executes `wfi` immediately — achieving an effective halt without a
/// busy spin.
///
/// Never inlined, so the kernel image has a `halt_loop` symbol:
/// `cargo xtask test wedge` moves an idle hart's program counter to it to
/// wedge that hart with interrupts off.
#[inline(never)]
pub fn halt_loop() -> !
{
    // SAFETY: disabling interrupts before wfi is required for a safe permanent halt.
    unsafe {
        disable_interrupts();
    }
    loop
    {
        // SAFETY: wfi is a hint that the hart may be suspended; safe at any privilege level.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}
