// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/fpu.rs

//! x86-64 extended-state (x87 / SSE / AVX) control primitives.
//!
//! Concentrates the unsafe surface for FPU/SIMD state management:
//! CR0.TS (lazy-trap discipline gate), XSETBV/XCR0 setup, per-CPU XSAVE
//! enablement performed at boot, and the save/restore primitives consumed by
//! the `#NM` handler and the context-switch path. The per-thread XSAVE area is
//! the last page of the thread's slab, carved by the thread-create path
//! (`syscall::cap::sys_cap_create_thread`) and, for init's thread, by boot code
//! (`kernel_entry_post_rebase`).
//!
//! ## Eager-save, lazy-restore discipline
//!
//! On any CPU `C`, at every observation point external code can reach,
//! exactly one of the following holds:
//! - `(CR0.TS=1, fpu_owner=null)` — no live state; the next user FP
//!   instruction raises `#NM`.
//! - `(CR0.TS=0, fpu_owner=T)`    — T owns the live regs; FP runs
//!   trap-free.
//!
//! The other two combinations are forbidden at rest; each appears only as a
//! transient inside the code paths below and is unobservable from outside them:
//!
//! - `(CR0.TS=0, fpu_owner=null)` **inside `nm_handler`** (`idt::nm_handler`)
//!   between the `cr0_clear_ts()` that arms the live registers for XSAVE /
//!   XRSTOR and the final `fpu_owner.store(tcb, Release)`. Preemption is
//!   disabled across the handler body, the CPU enters from a hardware
//!   trap with `IF=0`, and the only architectural interrupt class that
//!   can fire (NMI) does not touch FPU state — so no other code on this
//!   CPU observes the transient. No other CPU writes this CPU's owner slot.
//! - `(CR0.TS=1, fpu_owner=T)` **inside `switch_out_save`** between the
//!   `cr0_set_ts()` that re-arms the lazy trap after XSAVE and the store that
//!   clears `fpu_owner` (its defensive null-area path instead holds
//!   `(CR0.TS=0, fpu_owner=null)` between clearing the slot and re-arming TS).
//!   Called with `IF=0` after the scheduler locks are dropped; the outgoing
//!   thread's `switch()` then publishes `context_saved = 1` (Release), which
//!   is what publishes the area to peer CPUs.
//!
//! [`switch_out_save`] eagerly XSAVEs the live regs into T's TCB area
//! and clears `fpu_owner` whenever this CPU still owns the outgoing
//! thread, then arms `CR0.TS=1`. [`switch_in_restore`] just sets
//! `CR0.TS=1`; the first FP op by the incoming thread traps to `#NM`
//! (`idt::nm_handler`), which XRSTORs the thread's area and installs
//! it as the new `fpu_owner`. The resulting migration guarantee (no cross-CPU
//! FPU coordination) is specified in core/kernel/docs/scheduling-internals.md
//! § IPI Taxonomy.
//!
//! Only save is eager; restore stays lazy via `#NM`. The cost is one XSAVE per
//! switch-out of a thread that owns the live FP state; in exchange no cross-CPU
//! FPU flush IPI is needed (core/kernel/docs/scheduling-internals.md § IPI
//! Taxonomy).

use core::sync::atomic::{AtomicUsize, Ordering};

// ── CR0 ───────────────────────────────────────────────────────────────────────

/// CR0.TS bit (Task Switched).
///
/// When set, any x87/SSE/AVX instruction raises `#NM` (vector 7). The kernel
/// uses this for the lazy-restore discipline: TS=1 on context-switch-in,
/// the first user FP/SIMD use traps and the handler restores extended state.
const CR0_TS: u64 = 1 << 3;

/// Read the current value of CR0.
#[cfg(not(test))]
pub fn read_cr0() -> u64
{
    let val: u64;
    // SAFETY: CR0 is readable at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) val, options(nostack, nomem));
    }
    val
}

/// Write `val` to CR0.
///
/// # Safety
/// Caller must ensure `val` is valid and that interactions with paging,
/// protected mode, and the FPU are intended.
#[cfg(not(test))]
pub unsafe fn write_cr0(val: u64)
{
    // SAFETY: caller's responsibility.
    unsafe {
        core::arch::asm!("mov cr0, {}", in(reg) val, options(nostack, nomem));
    }
}

/// Set CR0.TS so the next x87/SSE/AVX instruction raises `#NM`.
///
/// # Safety
/// Must execute at ring 0.
#[cfg(not(test))]
#[inline]
pub unsafe fn cr0_set_ts()
{
    // SAFETY: setting TS is always safe at ring 0; trap on first FP use is the desired effect.
    unsafe {
        write_cr0(read_cr0() | CR0_TS);
    }
}

/// Clear CR0.TS so x87/SSE/AVX instructions execute without trapping.
///
/// Called before XSAVE/XRSTOR, which raise `#NM` while CR0.TS=1: by the `#NM`
/// handler before saving the previous owner and restoring the trapping
/// thread's state, and by [`switch_out_save`] before saving the outgoing
/// thread's state.
///
/// # Safety
/// Must execute at ring 0. Caller is responsible for ensuring the live
/// extended-state register file matches the thread that will run next.
#[cfg(not(test))]
#[inline]
pub unsafe fn cr0_clear_ts()
{
    // SAFETY: clearing TS is safe at ring 0; effect documented above.
    unsafe {
        write_cr0(read_cr0() & !CR0_TS);
    }
}

// ── XSAVE / XCR0 ──────────────────────────────────────────────────────────────

/// CR4 bits set by [`enable_xsave`]:
/// - `OSFXSR` (bit 9): the OS supports FXSAVE/FXRSTOR. Required before
///   any SSE instruction can execute without raising `#UD`.
/// - `OSXMMEXCPT` (bit 10): the OS handles `#XM` (SIMD floating-point
///   exception). When clear, SSE FP exceptions degenerate into `#UD`.
/// - `OSXSAVE` (bit 18): the OS supports XSAVE/XRSTOR and uses XCR0 to
///   manage extended state. Unmasks XSETBV/XGETBV.
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;

/// XCR0 component bits we enable for the x86-64-v3 userspace baseline.
const XCR0_X87: u64 = 1 << 0;
const XCR0_SSE: u64 = 1 << 1;
const XCR0_AVX: u64 = 1 << 2;
const XCR0_V3: u64 = XCR0_X87 | XCR0_SSE | XCR0_AVX;

/// XSAVE area size (bytes) reported by CPUID.0Dh:0.ECX: the size for every
/// component the CPU supports, an upper bound on the size for the components
/// enabled in XCR0 (CPUID.0Dh:0.EBX).
///
/// Written by [`enable_xsave`] on each CPU (last writer wins); zero before
/// initialisation.
static XSAVE_AREA_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Return the XSAVE area size reported by CPUID.0Dh:0.ECX: the size for every
/// supported component, an upper bound on the size for the components enabled
/// in XCR0 (CPUID.0Dh:0.EBX).
///
/// Returns 0 before [`enable_xsave`] has run on the BSP.
// dead_code: no caller; the per-thread XSAVE area is a fixed PAGE_SIZE page
// carved by `syscall::cap::sys_cap_create_thread` and, for init's thread, by
// `kernel_entry_post_rebase`, neither of which consults this size.
#[allow(dead_code)]
pub fn xsave_area_size() -> usize
{
    XSAVE_AREA_SIZE.load(Ordering::Relaxed)
}

/// Write `val` to extended control register `xcr` via XSETBV.
///
/// # Safety
/// Must execute at ring 0 with `CR4.OSXSAVE` already set. `val` must encode
/// a valid set of XCR0 components supported by the CPU.
#[cfg(not(test))]
unsafe fn xsetbv(xcr: u32, val: u64)
{
    let lo = (val & 0xFFFF_FFFF) as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: XSETBV writes EDX:EAX into XCR[ECX]; gated by OSXSAVE.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") xcr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem),
        );
    }
}

/// Enable XSAVE and the x87+SSE+AVX component set in XCR0.
///
/// Must be called once per CPU during early init. On the BSP it runs from
/// `interrupts::init` before the IDT is loaded (a CR4/XCR0 fault there is not
/// catchable); on each AP (`interrupts::init_ap`) the IDT is already loaded.
/// Fatal if the CPU does not support XSAVE (CPUID.01H:ECX bit 26) — the kernel
/// targets x86-64-v3 which requires it.
///
/// After this returns, [`xsave_area_size`] reports an XSAVE area size large
/// enough for every supported component (CPUID.0Dh:0.ECX), and [`cr0_set_ts`] /
/// [`cr0_clear_ts`] can be used to arm and disarm the `#NM` lazy-trap discipline.
///
/// # Safety
/// Must execute at ring 0 during per-CPU early init.
#[cfg(not(test))]
pub unsafe fn enable_xsave()
{
    // CPUID.01H:ECX bit 26 = XSAVE support advertised.
    let (_eax, _ebx, ecx, _edx) = super::cpu::cpuid(1);
    let xsave_present = (ecx >> 26) & 1 != 0;
    if !xsave_present
    {
        crate::fatal("XSAVE not supported by CPU — required for x86-64-v3 baseline");
    }

    // Set CR4.OSFXSR + OSXMMEXCPT + OSXSAVE. The first is required for any
    // SSE instruction to execute at all (without it, SSE raises #UD); the
    // second routes SIMD FP exceptions through the architected #XM vector
    // instead of #UD; the third unmasks XSETBV/XGETBV for the XCR0 write
    // below.
    let cr4 = super::cpu::read_cr4();
    // SAFETY: CPUID confirmed XSAVE; OSFXSR is supported by every x86-64
    // CPU; setting all three bits is the architected OS-enable sequence.
    unsafe {
        super::cpu::write_cr4(cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE);
    }

    // Write XCR0 = x87 | SSE | AVX. Always-mandatory bit 0 (x87) included;
    // SSE (bit 1) and AVX (bit 2) are the v3 baseline. AVX-512 (bits 5/6/7)
    // is intentionally omitted.
    // SAFETY: OSXSAVE just set; XCR0 components are v3-mandatory.
    unsafe {
        xsetbv(0, XCR0_V3);
    }

    // Record the XSAVE area size. CPUID.0Dh:0.ECX is the size for every
    // component the CPU supports (an upper bound on the XCR0-enabled size,
    // which is EBX).
    let (_eax, _ebx, ecx, _edx) = super::cpu::cpuid(0xD);
    XSAVE_AREA_SIZE.store(ecx as usize, Ordering::Relaxed);
}

/// Save the live x87/SSE/AVX state of the executing CPU into `area`.
///
/// `area` must be 64-byte aligned and point at a writable XSAVE buffer of
/// at least the XCR0-enabled size (CPUID.0Dh:0.EBX) bytes, which XSAVE never
/// writes past; [`xsave_area_size`] is an upper bound on that size, not the
/// requirement. The component-mask passed in
/// `EDX:EAX = 0xFFFF_FFFF_FFFF_FFFF` instructs XSAVE to write every
/// component XCR0 currently enables; hardware intersects with XCR0, so
/// the actual written set is exactly the OS-enabled components.
///
/// Plain XSAVE (not XSAVEOPT) is intentional: XSAVEOPT may skip writing
/// components it tracks as "clean" since the last load, and the per-CPU
/// tracking is only correct when both load and save paths use matching
/// instructions consistently. XSAVE is unconditional and works the same
/// on every implementation (hardware, KVM, TCG).
///
/// # Safety
/// Must execute at ring 0 with CR0.TS clear. `area` must satisfy the alignment
/// and size requirements above. Called from `switch_out_save` (interrupts
/// disabled, after the scheduler locks are dropped and before `switch()`
/// publishes `context_saved`) and from the `#NM` handler (interrupts
/// disabled, preemption disabled).
#[cfg(not(test))]
#[inline]
pub unsafe fn save_to(area: *mut u8)
{
    // SAFETY: caller's contract; XSAVE requires OSXSAVE which the boot
    // path established. The component mask `0xFFFF_FFFF` (low 32 bits) is
    // intersected with XCR0 by hardware, so it saves exactly the enabled set.
    unsafe {
        core::arch::asm!(
            "xsave [{area}]",
            area = in(reg) area,
            in("eax") 0xFFFF_FFFFu32,
            in("edx") 0xFFFF_FFFFu32,
            options(nostack),
        );
    }
}

/// Restore the x87/SSE/AVX state of the executing CPU from `area`.
///
/// The `XSTATE_BV` header in `area` selects which components actually get
/// reloaded; the others reach the architected initial state. A zeroed
/// area reaches FINIT + zeroed XMM/YMM.
///
/// # Safety
/// Must execute at ring 0. `area` must point at an XSAVE buffer previously
/// written by [`save_to`] (or zero-initialised). Called from the `#NM`
/// trap handler with CR0.TS already cleared.
#[cfg(not(test))]
#[inline]
pub unsafe fn restore_from(area: *const u8)
{
    // SAFETY: caller's contract; XRSTOR is gated on OSXSAVE which boot set.
    unsafe {
        core::arch::asm!(
            "xrstor [{area}]",
            area = in(reg) area,
            in("eax") 0xFFFF_FFFFu32,
            in("edx") 0xFFFF_FFFFu32,
            options(nostack),
        );
    }
}

/// Context-switch hook called on switch-out of any thread.
///
/// Eagerly persists the live extended-state register file: if this CPU's
/// `fpu_owner` still names `tcb` and `tcb`'s extended-state area is
/// allocated, XSAVE into the area, clear `fpu_owner`, and arm
/// `CR0.TS=1`. Otherwise (no live state, or live state belongs to some
/// other thread that took an `#NM` since `tcb` last switched out), just
/// arm `CR0.TS=1`.
///
/// Postcondition: this CPU's `fpu_owner` does not name `tcb` on return.
/// `tcb`'s extended-state area, if any, is canonical and safe for any
/// other CPU to XRSTOR from on first FP use.
///
/// Hot-path cost: one Acquire load of `fpu_owner` and a CR0.TS re-arm for
/// threads this CPU's owner slot does not name (kernel-only / idle threads, and
/// threads that have not touched FP since their last switch-in). The
/// XSAVE+TS+null-store path runs only when this CPU genuinely holds `tcb`'s
/// live regs.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, before the outgoing
/// thread's `switch()` publishes `context_saved = 1` (Release). That store is
/// the publication edge: it orders the XSAVE into `tcb`'s extended-state area
/// before any other CPU's Acquire of `context_saved`. `tcb` must be a valid
/// TCB pointer.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_out_save(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    if tcb.is_null()
    {
        // SAFETY: ring 0; defensive arm of the lazy trap.
        unsafe {
            cr0_set_ts();
        }
        return;
    }
    let cpu = super::cpu::current_cpu() as usize;
    let owner_slot = crate::percpu::fpu_owner_for(cpu);
    let owner = owner_slot.load(core::sync::atomic::Ordering::Acquire);
    if owner == tcb
    {
        // SAFETY: caller guarantees tcb is valid; area is page-resident
        // for the TCB's lifetime when non-null.
        let area = unsafe { (*tcb).extended.area };
        if !area.is_null()
        {
            // SAFETY: ring 0; area satisfies XSAVE alignment and size;
            // we observed ownership, so the live regs belong to this TCB.
            unsafe {
                cr0_clear_ts();
                save_to(area);
                cr0_set_ts();
            }
            owner_slot.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
            return;
        }
        // Defensive: owner names tcb but its area is null. A user thread
        // that became owner must have a backing area (nm_handler refuses
        // to install ownership without one); reaching here implies a
        // kernel bug. Clear owner and re-arm TS so the invariant holds.
        owner_slot.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    }
    // SAFETY: ring 0; CR0.TS=1 is the architected lazy-trap arm.
    unsafe {
        cr0_set_ts();
    }
}

/// Context-switch hook called on switch-in of any thread.
///
/// Arms `CR0.TS=1` so the first user FP instruction by `tcb` traps to
/// `#NM`, which XRSTORs `tcb`'s extended-state area and installs `tcb`
/// as this CPU's `fpu_owner`. The eager-save discipline in
/// [`switch_out_save`] guarantees that `fpu_owner` on this CPU does not
/// transiently name some other thread whose live regs we would clobber.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, after the matching
/// `switch_out_save` for the outgoing thread has completed. `_tcb` must
/// be a valid TCB pointer.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    // SAFETY: ring 0; CR0.TS=1 is the architected lazy-trap arm.
    unsafe {
        cr0_set_ts();
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}
