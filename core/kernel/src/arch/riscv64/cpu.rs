// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/cpu.rs

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

/// Read the current stack pointer (`sp`, x2).
///
/// Used by the panic-path backtrace scanner to bound the kernel-stack walk.
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

/// Return the current hart ID.
///
/// Phase 5: only the BSP is running; returns 0.
/// Future: read `mhartid` via SBI `sbi_get_marchid` or from the boot-info
/// structure when SMP is brought up.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn current_id() -> u32
{
    0
}

// ── Baseline feature gate ─────────────────────────────────────────────────────

/// Verify the RISC-V platform baseline and refuse unsupported hardware.
///
/// This runs in early boot, where supervisor-mode detection is limited (`misa`
/// is not S-mode-readable and `satp` cannot be safely probed before the kernel
/// page tables are active). It probes the SBI HSM extension, which is required to
/// start secondary harts (`sbi_get_spec_version` is unsuitable as a presence
/// check — a compliant SBI always returns success, and a truly absent SBI traps
/// on the `ecall`). The remaining required features are asserted where each is
/// safely detectable: the Vector extension at `fpu::cache_vlenb`, and the
/// ASID-tagged TLB at `paging::enable_tagged_tlb`. See
/// [platform-requirements.md](../../../../docs/platform-requirements.md).
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
}

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
/// implemented ASID bits; `0` means ASIDs are unsupported and the kernel falls
/// back to full-flush context switches.
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
        // SAFETY: reading tp is always safe; install_percpu ensures it points
        // to a valid PerCpuData with cpu_id at offset 0.
        unsafe {
            core::arch::asm!(
                "mv {}, tp",
                out(reg) tp,
                options(nostack, nomem),
            );
            *(tp as *const u32)
        }
    }
    #[cfg(test)]
    {
        0
    }
}

// ── Kernel trap stack ─────────────────────────────────────────────────────────

/// Set the kernel stack pointer used when a trap fires from U-mode.
///
/// On RISC-V, `sscratch` holds `&PER_CPU[cpu_id]` (not the stack pointer)
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

// `copy_user` is the sole sanctioned path for kernel access to user memory. It
// owns the SUM access window (sstatus.SUM, bit 18) and is covered by the trap
// dispatcher's user-copy fixup: a fault on an unmapped or read-only user span
// inside the copy redirects to `__copy_user_fixup` (which clears SUM and returns
// a non-zero sentinel) instead of panicking. See `crate::uaccess` for the typed
// `copy_to_user`/`copy_from_user` wrappers and `interrupts::trap_dispatch` for
// the fixup hook.
#[cfg(not(test))]
core::arch::global_asm!(
    ".section .text.copy_user, \"ax\"",
    ".global __copy_user",
    ".global __copy_user_fault_start",
    ".global __copy_user_fault_end",
    ".global __copy_user_fixup",
    // fn __copy_user(dst: a0, src: a1, len: a2) -> a0 (0 = ok, 1 = faulted)
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
    "    li    a0, 1",
    "    ret",
);

#[cfg(not(test))]
unsafe extern "C" {
    /// Raw user-copy routine (`dst=a0, src=a1, len=a2`); returns 0 on success or
    /// 1 if a fault on the user span was recovered.
    fn __copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    /// First byte of the faultable copy region (the `lb`/`sb` pair).
    static __copy_user_fault_start: u8;
    /// First byte past the faultable copy region.
    static __copy_user_fault_end: u8;
    /// Recovery landing pad: closes the SUM window and returns the fault sentinel.
    static __copy_user_fixup: u8;
}

/// Copy `len` bytes from `src` to `dst` across the SUM window with fault
/// recovery. Returns 0 on success, non-zero if a user-span fault was recovered.
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
    // SAFETY: csrrci atomically reads sstatus and clears the SIE bit.
    unsafe {
        core::arch::asm!(
            "csrrci {sstatus}, sstatus, 2",
            sstatus = out(reg) sstatus,
            options(nostack, nomem),
        );
    }
    sstatus
}

/// Restore the interrupt-enable state saved by [`save_and_disable_interrupts`].
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
        // SAFETY: re-enabling SIE after we previously cleared it.
        unsafe {
            core::arch::asm!("csrsi sstatus, 2", options(nostack, nomem));
        }
    }
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
