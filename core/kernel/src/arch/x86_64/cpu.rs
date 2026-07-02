// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/cpu.rs

//! x86-64 CPU control primitives.
//!
//! # Phase 5 additions
//! - `cpuid` — execute CPUID with a given leaf.
//! - `read_cr4` / `write_cr4` — CR4 access.
//! - `read_msr` / `write_msr` — MSR access.
//! - `enable_smep_smap` — verify CPUID support and set CR4 bits 20+21.
//! - `halt_until_interrupt` — `sti; hlt` (allows timer to fire).
//! - `current_id` — return LAPIC ID from CPUID.01H.
//!
//! All privileged instructions are guarded with `#[cfg(not(test))]` so unit
//! tests can run on the host without requiring kernel privilege.

// ── CPUID ─────────────────────────────────────────────────────────────────────

/// Execute CPUID with leaf `leaf` (sub-leaf 0). Returns `(eax, ebx, ecx, edx)`.
///
/// `rbx` is callee-saved and reserved by LLVM, so the EBX result must be
/// shuttled out without leaving it in `rbx`. The `core` intrinsic does this
/// correctly; a hand-rolled `push rbx` / `mov out, ebx` / `pop rbx` sequence is
/// fragile because the chosen output register may itself alias `rbx`, in which
/// case the `pop` clobbers the result.
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32)
{
    let r = core::arch::x86_64::__cpuid_count(leaf, 0);
    (r.eax, r.ebx, r.ecx, r.edx)
}

// ── Stack pointer ───────────────────────────────────────────────────────────────

/// Read the current stack pointer (`rsp`).
///
/// Used by the panic-path backtrace scanner to bound the kernel-stack walk.
#[cfg(not(test))]
pub fn current_stack_pointer() -> u64
{
    let sp: u64;
    // SAFETY: reads the stack pointer register only; no memory access, no clobbers.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

// ── CR4 ───────────────────────────────────────────────────────────────────────

/// Read the current value of CR4.
#[cfg(not(test))]
pub fn read_cr4() -> u64
{
    let val: u64;
    // SAFETY: CR4 readable at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) val, options(nostack, nomem));
    }
    val
}

/// Write `val` to CR4.
///
/// # Safety
/// Caller must ensure the new CR4 value is valid and will not fault.
#[cfg(not(test))]
pub unsafe fn write_cr4(val: u64)
{
    // SAFETY: caller's responsibility.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) val, options(nostack, nomem));
    }
}

// ── MSR ───────────────────────────────────────────────────────────────────────

/// Read a model-specific register `msr`.
///
/// # Safety
/// Must execute at ring 0. The MSR must exist on this CPU.
#[cfg(not(test))]
pub unsafe fn read_msr(msr: u32) -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: caller guarantees ring 0 and valid MSR.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Write `val` to model-specific register `msr`.
///
/// # Safety
/// Must execute at ring 0. The MSR must exist and the value must be valid.
#[cfg(not(test))]
pub unsafe fn write_msr(msr: u32, val: u64)
{
    let lo = (val & 0xFFFF_FFFF) as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: caller's responsibility.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem),
        );
    }
}

// ── User-copy primitive (fault-recoverable) ───────────────────────────────────

// `copy_user` is the sole sanctioned path for kernel access to user memory. It
// owns the SMAP access window (`stac`/`clac`) and is covered by the page-fault
// handler's user-copy fixup: a fault on an unmapped or read-only user span
// inside the copy redirects to `__copy_user_fixup` (which executes `clac` and
// returns a non-zero sentinel) instead of panicking. See `crate::uaccess` for
// the typed `copy_to_user`/`copy_from_user` wrappers and `idt::page_fault_handler`
// for the fixup hook. The DF=0 ABI invariant makes `rep movsb` copy forward.
#[cfg(not(test))]
core::arch::global_asm!(
    ".section .text.copy_user, \"ax\"",
    ".global __copy_user",
    ".global __copy_user_fault_start",
    ".global __copy_user_fault_end",
    ".global __copy_user_fixup",
    // fn __copy_user(dst: rdi, src: rsi, len: rdx) -> rax (0 = ok, 1 = faulted)
    "__copy_user:",
    "    stac",
    "    mov rcx, rdx",
    "__copy_user_fault_start:",
    "    rep movsb",
    "__copy_user_fault_end:",
    "    clac",
    "    xor eax, eax",
    "    ret",
    "__copy_user_fixup:",
    "    clac",
    "    mov eax, 1",
    "    ret",
);

#[cfg(not(test))]
unsafe extern "C" {
    /// Raw user-copy routine (`dst=rdi, src=rsi, len=rdx`); returns 0 on success
    /// or 1 if a fault on the user span was recovered.
    fn __copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    /// First byte of the faultable copy instruction.
    static __copy_user_fault_start: u8;
    /// First byte past the faultable copy instruction.
    static __copy_user_fault_end: u8;
    /// Recovery landing pad: closes the SMAP window and returns the fault sentinel.
    static __copy_user_fixup: u8;
}

/// Copy `len` bytes from `src` to `dst` across the SMAP window with fault
/// recovery. Returns 0 on success, non-zero if a user-span fault was recovered.
///
/// # Safety
/// Must execute at ring 0 with SMAP enabled. The operands must be arranged so the
/// user pointer is the only one that may fault; the non-user side must be valid
/// for `len` bytes.
#[cfg(not(test))]
#[inline]
pub unsafe fn copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize
{
    // SAFETY: forwarded to the asm routine; a fault on the user span is recovered
    // by the page-fault handler via __copy_user_fixup.
    unsafe { __copy_user(dst, src, len) }
}

/// Host-test stub: `stac`/`clac` are privileged and the test pointers never
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
/// recovery fixup; otherwise `None`. Consulted by the page-fault handler on a
/// kernel-mode fault to convert an unmapped/read-only user access into an error
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

// ── SMEP / SMAP ───────────────────────────────────────────────────────────────

/// Enable Supervisor Mode Execution Prevention (SMEP) and Supervisor Mode
/// Access Prevention (SMAP) by setting CR4 bits 20 and 21.
///
/// Checks CPUID.07H:EBX bit 7 (SMEP) and bit 20 (SMAP). Halts with a fatal
/// message if either feature is absent, because the security model requires
/// both.
///
/// # Safety
/// Must execute at ring 0. May only be called after the IDT is loaded so that
/// a CR4 write fault is catchable (in practice both features are mandatory
/// on the x86_64-v3 baseline this kernel targets).
// similar_names: smep_present and smap_present are distinct CPU security features.
#[cfg(not(test))]
#[allow(clippy::similar_names)]
pub unsafe fn enable_smep_smap()
{
    // CPUID leaf 7, sub-leaf 0.
    let (_eax, ebx, _ecx, _edx) = cpuid(7);
    let smep_present = (ebx >> 7) & 1 != 0;
    let smap_present = (ebx >> 20) & 1 != 0;
    if !smep_present
    {
        crate::fatal("SMEP not supported by CPU — required");
    }
    if !smap_present
    {
        crate::fatal("SMAP not supported by CPU — required");
    }
    // Bit 20 = SMEP, bit 21 = SMAP.
    let cr4 = read_cr4();
    // SAFETY: CPUID confirmed both features are present; new CR4 value is valid.
    unsafe {
        write_cr4(cr4 | (1 << 20) | (1 << 21));
    }
}

// ── PCID (Process-Context Identifiers) ────────────────────────────────────────

/// Enable PCID-tagged TLBs by setting `CR4.PCIDE` (bit 17).
///
/// Tagged TLBs require both PCID (`CPUID.01H:ECX[17]`) and INVPCID
/// (`CPUID.(EAX=07H,ECX=0):EBX[10]`): the kernel uses `invpcid` for
/// single-address and single-context invalidation. Returns `true` if both
/// features are present and `CR4.PCIDE` was set, `false` otherwise.
///
/// Unlike [`enable_smep_smap`], absence is **not** fatal — tagging is an
/// optimization, not a security requirement, and the kernel falls back to
/// full-flush context switches.
///
/// Per Intel SDM Vol. 3A §4.10.1, `CR3[11:0]` must be 0 at the moment
/// `CR4.PCIDE` is set to 1, or the `MOV CR4` `#GP`s. At the call site (Phase 5
/// BSP / AP init) the active CR3 is the kernel root with zero low bits; this is
/// asserted in debug builds.
///
/// # Safety
/// Must execute at ring 0, after the IDT is loaded, with the kernel root in
/// CR3 (low 12 bits zero). Must be called at most once per CPU and before any
/// PCID-tagged CR3 load.
#[cfg(not(test))]
pub unsafe fn enable_pcid() -> bool
{
    // CPUID.01H:ECX[17] = PCID; CPUID.(07H,0):EBX[10] = INVPCID.
    let pcid = cpuid(1).2 & (1 << 17) != 0;
    let invpcid = cpuid(7).1 & (1 << 10) != 0;
    if !pcid || !invpcid
    {
        return false;
    }

    // CR3[11:0] must be zero before setting PCIDE (SDM Vol. 3A §4.10.1).
    let cr3: u64;
    // SAFETY: reading CR3 is a ring-0 primitive.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
    }
    debug_assert!(
        cr3.trailing_zeros() >= 12,
        "enable_pcid: CR3[11:0] must be 0 before setting CR4.PCIDE"
    );

    // Bit 17 = PCIDE.
    let cr4 = read_cr4();
    // SAFETY: CPUID confirmed PCID + INVPCID; CR3 low bits are zero (kernel
    // root); long mode and PAE are active (4-level paging). The new CR4 value
    // is valid.
    unsafe {
        write_cr4(cr4 | (1 << 17));
    }
    true
}

// ── Baseline feature gate ─────────────────────────────────────────────────────

/// Verify the x86-64 platform baseline and refuse unsupported hardware.
///
/// Checks the required CPUID-detectable features that every supported run
/// environment provides (see
/// [platform-requirements.md](../../../../docs/platform-requirements.md)) and
/// halts via [`crate::fatal`] naming the first missing feature, rather than
/// faulting obscurely later. A few required features are deliberately excluded
/// — see the note on the check table below. Also sets `CR0.WP`, without which
/// ring-0 writes would bypass read-only page permissions and the kernel's own
/// W^X would be unenforced on this CPU (UEFI may hand the BSP off with `CR0.WP`
/// clear; the AP trampoline already sets it).
///
/// # Safety
/// Must execute at ring 0 during early boot, after the console is live so the
/// diagnostic is visible, and before any subsystem that assumes the baseline.
// too_many_lines: a flat, exhaustive feature-check table; splitting it would
// only obscure the one-line-per-required-feature structure.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub unsafe fn verify_baseline()
{
    /// `CR0.WP` (supervisor write-protect).
    const CR0_WP: u64 = 1 << 16;

    let max_leaf = cpuid(0).0;
    let basic = cpuid(1).2; // leaf 1, ECX
    let structured = cpuid(7).1; // leaf 7 sub-leaf 0, EBX
    let ext = cpuid(0x8000_0001); // ext.2 = ECX, ext.3 = EDX

    // (feature present, diagnostic). The kernel halts naming the first absent one.
    //
    // Some required platform features (see docs/platform-requirements.md) are
    // deliberately not gated here because the emulator used for CI/dev (QEMU
    // TCG) cannot provide them, and the kernel already degrades correctly:
    // invariant TSC (a frequency-stability guarantee; the kernel calibrates the
    // TSC against the PIT), PCID/INVPCID tagged TLBs (the kernel keeps a
    // full-flush fallback), and the vendor-specific in-silicon mitigations.
    let checks: [(bool, &str); 19] = [
        // x86-64-v3 instruction baseline.
        (
            basic & (1 << 28) != 0,
            "AVX not supported by CPU — required (x86-64-v3)",
        ),
        (
            structured & (1 << 5) != 0,
            "AVX2 not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 12) != 0,
            "FMA not supported by CPU — required (x86-64-v3)",
        ),
        (
            structured & (1 << 3) != 0,
            "BMI1 not supported by CPU — required (x86-64-v3)",
        ),
        (
            structured & (1 << 8) != 0,
            "BMI2 not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 22) != 0,
            "MOVBE not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 29) != 0,
            "F16C not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 23) != 0,
            "POPCNT not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 13) != 0,
            "CMPXCHG16B not supported by CPU — required (x86-64-v3)",
        ),
        (
            ext.2 & (1 << 5) != 0,
            "LZCNT not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 26) != 0,
            "XSAVE not supported by CPU — required (x86-64-v3)",
        ),
        // Privilege and W^X substrate.
        (
            ext.3 & (1 << 29) != 0,
            "long mode not supported by CPU — required",
        ),
        (
            ext.3 & (1 << 11) != 0,
            "SYSCALL not supported by CPU — required",
        ),
        (ext.3 & (1 << 20) != 0, "NX not supported by CPU — required"),
        // Supervisor isolation.
        (
            structured & (1 << 7) != 0,
            "SMEP not supported by CPU — required",
        ),
        (
            structured & (1 << 20) != 0,
            "SMAP not supported by CPU — required",
        ),
        // Topology enumeration.
        (
            max_leaf >= 0x0B,
            "CPUID topology leaf 0x0B not supported by CPU — required",
        ),
        // Hardware entropy sources.
        (
            basic & (1 << 30) != 0,
            "RDRAND not supported by CPU — required",
        ),
        (
            structured & (1 << 18) != 0,
            "RDSEED not supported by CPU — required",
        ),
    ];
    for (present, feature) in checks
    {
        if !present
        {
            crate::fatal(feature);
        }
    }

    // SAFETY: ring 0 per the caller contract; setting WP only tightens
    // supervisor write checks. Kernel code paths are WP-safe — the APs run with
    // WP set from the trampoline through all of init.
    unsafe {
        super::fpu::write_cr0(super::fpu::read_cr0() | CR0_WP);
    }
}

/// Test-build stub: the baseline gate performs privileged operations and is a
/// no-op in host unit tests.
#[cfg(test)]
pub unsafe fn verify_baseline() {}

// ── Misc ──────────────────────────────────────────────────────────────────────

/// Atomically enable interrupts and halt until an interrupt is recognised.
///
/// Precondition: interrupts are **disabled** (IF=0) on entry.
/// Postcondition: interrupts are **enabled** (IF=1) on return; any pending
/// interrupt at the halt boundary has been recognised (handler ran during
/// halt).
///
/// Per Intel SDM Vol. 2B (STI): when `STI` is immediately followed by `HLT`,
/// the processor delays interrupt recognition until after `HLT` begins
/// execution. The pair is therefore atomic: no interrupt is lost between
/// the enable and the halt. A producer that raises a wake notification (IPI)
/// between the idle loop's flag check and this call will find the notification
/// pending in the local APIC at `HLT`, waking it immediately.
///
/// `nomem` is intentionally omitted so the compiler may not reorder
/// preceding atomic loads across this call.
pub fn halt_until_interrupt()
{
    // SAFETY: `sti; hlt` is atomic per Intel SDM; correct only when
    // interrupts were disabled on entry (caller contract).
    unsafe {
        core::arch::asm!("sti; hlt", options(nostack, preserves_flags));
    }
}

/// Return the local APIC ID of the current CPU (from CPUID.01H:EBX[31:24]).
///
/// Phase 5 only starts the BSP (Bootstrap Processor); this returns 0 on a
/// single-CPU system.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn current_id() -> u32
{
    let (_eax, ebx, _ecx, _edx) = cpuid(1);
    ebx >> 24
}

// ── Per-CPU GS-base ───────────────────────────────────────────────────────────

/// MSR address for `IA32_GS_BASE` — the canonical GS segment base.
const IA32_GS_BASE: u32 = 0xC000_0101;

/// Install `addr` as the per-CPU data pointer for the current CPU.
///
/// Writes `addr` to `IA32_GS_BASE` (MSR `0xC000_0101`) so that
/// GS-relative loads (`gs:[offset]`) reach the `PerCpuData` entry for
/// this CPU. Must be called from Phase 5 (BSP) and `kernel_entry_ap`
/// (each AP) before any GS-relative access occurs.
///
/// # Safety
/// Must execute at ring 0. `addr` must be the virtual address of a valid
/// `PerCpuData` that outlives the CPU's execution.
#[cfg(not(test))]
pub unsafe fn install_percpu(addr: u64)
{
    // SAFETY: IA32_GS_BASE is a valid MSR on all x86-64 CPUs; ring 0.
    unsafe {
        write_msr(IA32_GS_BASE, addr);
    }
}

/// Return the logical CPU index of the executing CPU.
///
/// Reads `gs:[0]` which holds `PerCpuData::cpu_id` (u32, offset 0).
/// Valid after [`install_percpu`] is called for this CPU.
///
/// # Safety (internal)
/// `gs:[0]` is always a valid u32 read once GS-base is installed.
/// The function is safe to call because the install guarantee is a
/// precondition of the kernel running on this CPU.
pub fn current_cpu() -> u32
{
    #[cfg(not(test))]
    {
        let id: u32;
        // SAFETY: gs:[0] is PerCpuData::cpu_id; GS-base installed by kernel before scheduler runs.
        unsafe {
            core::arch::asm!(
                "mov {:e}, gs:[0]",
                out(reg) id,
                options(nostack, readonly, preserves_flags),
            );
        }
        id
    }
    #[cfg(test)]
    {
        0
    }
}

// ── Kernel trap stack ─────────────────────────────────────────────────────────

/// Set the kernel stack pointer used when a trap fires from U-mode.
///
/// On x86-64 this requires two writes: TSS RSP0 (for hardware interrupt/
/// exception entry) and `SYSCALL_KERNEL_RSP` (for the `SYSCALL` fast path).
/// Must be called on every context switch to a user thread.
///
/// # Safety
/// Must execute at ring 0. Caller must ensure the stack is valid.
#[cfg(not(test))]
#[inline]
pub unsafe fn set_kernel_trap_stack(stack_top: u64)
{
    // SAFETY: caller guarantees stack_top is a valid kernel stack pointer.
    unsafe {
        super::gdt::set_rsp0(stack_top);
        super::syscall::set_kernel_rsp(stack_top);
    }
}

/// Save the current interrupt-enable state and disable hardware interrupts.
/// Returns an opaque value to pass to [`restore_interrupts`].
///
/// # Safety
/// Must execute at ring 0.
#[cfg(not(test))]
#[inline]
pub unsafe fn save_and_disable_interrupts() -> u64
{
    let flags: u64;
    // SAFETY: pushfq/popfq are valid at ring 0; cli is safe here.
    // `nostack` is intentionally absent: `pushfq` writes 8 bytes below RSP
    // and the matching `pop` reads them. Net RSP delta is zero but the body
    // is not red-zone-safe; only the kernel target's `disable-redzone: true`
    // makes this latent today. Be honest about the body.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {flags}",
            "cli",
            flags = out(reg) flags,
        );
    }
    flags
}

/// Restore the interrupt-enable state saved by [`save_and_disable_interrupts`].
///
/// # Safety
/// Must execute at ring 0. `saved` must be a value returned by
/// `save_and_disable_interrupts` on this CPU.
#[cfg(not(test))]
#[inline]
pub unsafe fn restore_interrupts(saved: u64)
{
    // SAFETY: restoring a previously captured FLAGS value is safe.
    // See save_and_disable_interrupts above for why `nostack` is absent.
    unsafe {
        core::arch::asm!(
            "push {flags}",
            "popfq",
            flags = in(reg) saved,
        );
    }
}

// ── Interrupts (hardware state) ───────────────────────────────────────────────

/// Disable hardware interrupts.
///
/// # Safety
/// Changes global CPU interrupt state. Caller is responsible for re-enabling
/// interrupts when appropriate (the kernel does not enable them during early boot).
///
/// `nomem` is intentionally omitted: the idle loop relies on no atomic
/// loads being reordered across this call.
pub unsafe fn disable_interrupts()
{
    // SAFETY: caller guarantees this is called in an appropriate context.
    unsafe {
        core::arch::asm!("cli", options(nostack, preserves_flags));
    }
}

/// Disable interrupts and halt the CPU permanently.
///
/// Loops on `hlt` so that any NMI that fires during early boot does not cause
/// an uncontrolled jump; interrupts remain disabled.
pub fn halt_loop() -> !
{
    // SAFETY: cli disables interrupts; hlt is safe to execute at any privilege level.
    unsafe {
        disable_interrupts();
    }
    loop
    {
        // SAFETY: hlt puts the CPU into a low-power wait state until the next interrupt.
        // Interrupts are disabled above, so this halts permanently.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
