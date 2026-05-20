// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/fpu.rs

//! x86-64 extended-state (x87 / SSE / AVX) control primitives.
//!
//! Concentrates the unsafe surface for FPU/SIMD state management:
//! CR0.TS (lazy-trap discipline gate), XSETBV/XCR0 setup, per-CPU XSAVE
//! enablement performed at boot, the per-thread XSAVE area allocation,
//! and the save/restore primitives consumed by the `#NM` handler and the
//! context-switch path.
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
//! `(CR0.TS=0, fpu_owner=null)` is the forbidden at-rest state; it
//! appears as a transient inside two code paths and is unobservable
//! from outside each:
//!
//! - **Inside `nm_handler`** (`idt.rs::nm_handler`) between the
//!   `cr0_clear_ts()` that arms the live registers for XSAVE / XRSTOR
//!   and the final `fpu_owner.store(tcb, Release)`. Preemption is
//!   disabled across the handler body, the CPU enters from a hardware
//!   trap with `IF=0`, and the only architectural interrupt class that
//!   can fire (NMI) does not touch FPU state — so no other code on this
//!   CPU observes the transient. No other CPU writes this CPU's owner
//!   slot.
//! - **Inside `switch_out_save`** between the `cr0_clear_ts()` that
//!   arms the live registers for XSAVE and the `cr0_set_ts()` that
//!   re-arms the lazy trap. Called inside the scheduler-lock critical
//!   section with `IF=0`; the Release on the subsequent lock unlock is
//!   what publishes the area to peer CPUs.
//!
//! The state `(CR0.TS=1, fpu_owner=T)` never appears under this
//! discipline: `nm_handler` clears CR0.TS *before* writing the owner
//! slot, and `switch_out_save` clears the owner slot only after
//! re-arming `CR0.TS=1`.
//!
//! [`switch_out_save`] eagerly XSAVEs the live regs into T's TCB area
//! and clears `fpu_owner` whenever this CPU still owns the outgoing
//! thread, then arms `CR0.TS=1`. [`switch_in_restore`] just sets
//! `CR0.TS=1`; the first FP op by the incoming thread traps to `#NM`
//! (`idt.rs::nm_handler`), which XRSTORs the thread's area and installs
//! it as the new `fpu_owner`. Migration therefore needs no cross-CPU
//! coordination: by the time T is observable as Ready on any other CPU's
//! run queue, T's TCB area is canonical (the source CPU saved it on its
//! own switch-out, inside the scheduler-lock critical section whose
//! Release on unlock the destination's Acquire on lock pairs with).
//!
//! This pattern matches seL4, NetBSD, OpenBSD, and Linux post-2018
//! (commit `bf15a8cf8`, which retired lazy-save after CVE-2018-3665
//! made the optimisation unsafe to keep defending). It is NOT the
//! eager-save-eager-restore of commit `190c3da`: restore stays lazy via
//! `#NM` — only save is eager. The cost is one XSAVE per switch-out of
//! an FP-touching thread (~300-600 cycles on x86-64-v3), paid in
//! exchange for deleting the cross-CPU migration-steal IPI and its
//! synchronous ack-wait (the source of issue #108).

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
/// Called from the `#NM` handler after restoring (or initialising) the
/// current thread's extended state.
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

/// Size (bytes) of the XSAVE area required for the components in XCR0.
///
/// Populated at boot by [`enable_xsave`] from CPUID.0Dh:0.ECX. Zero before
/// initialisation. Per-CPU values are guaranteed to agree by the v3 contract.
static XSAVE_AREA_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Return the XSAVE area size for the currently-enabled XCR0 components.
///
/// Returns 0 before [`enable_xsave`] has run on the BSP.
#[allow(dead_code)] // Consumed by the per-thread XSAVE area allocator in a later commit.
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
/// Must be called once per CPU during early init, after the IDT is loaded so
/// any fault during CR4/XCR0 setup is catchable. Fatal if the CPU does not
/// support XSAVE (CPUID.01H:ECX bit 26) — the kernel targets x86-64-v3 which
/// requires it.
///
/// After this returns, [`xsave_area_size`] reports the size required to save
/// the current XCR0 component set, and [`cr0_set_ts`] / [`cr0_clear_ts`] can
/// be used to arm and disarm the `#NM` lazy-trap discipline.
///
/// # Safety
/// Must execute at ring 0 with the IDT loaded.
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

    // Record XSAVE area size for the active component set. CPUID.0Dh:0.ECX
    // is the max enabled state size for the current XCR0.
    let (_eax, _ebx, ecx, _edx) = super::cpu::cpuid(0xD);
    XSAVE_AREA_SIZE.store(ecx as usize, Ordering::Relaxed);
}

/// Save the live x87/SSE/AVX state of the executing CPU into `area`.
///
/// `area` must be 64-byte aligned and point at a writable XSAVE buffer of
/// at least [`xsave_area_size`] bytes. The component-mask passed in
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
/// Must execute at ring 0. `area` must satisfy the alignment and size
/// requirements above. Called from the context-switch path with
/// interrupts disabled and the scheduler lock held.
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
/// Hot-path cost: one Acquire load of `fpu_owner` plus an early return
/// for kernel-only / idle threads (whose `extended.area` is null) and
/// for threads that have not touched FP since their last switch-in (no
/// matching `#NM` ran, so this CPU's owner slot still names someone
/// else or null). The XSAVE+TS+null-store path runs only when this CPU
/// genuinely holds `tcb`'s live regs.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, inside the scheduler
/// lock's critical section so its writes happen-before the
/// destination CPU's matching Acquire on the same scheduler lock. `tcb`
/// must be a valid TCB pointer.
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
