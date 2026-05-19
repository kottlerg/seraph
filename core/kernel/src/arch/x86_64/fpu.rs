// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/fpu.rs

//! x86-64 extended-state (x87 / SSE / AVX) control primitives.
//!
//! Concentrates the unsafe surface for FPU/SIMD state management:
//! CR0.TS (lazy-trap discipline gate), XSETBV/XCR0 setup, per-CPU XSAVE
//! enablement performed at boot, the per-thread XSAVE area allocation,
//! and the lazy save/restore primitives consumed by the `#NM` handler,
//! the context-switch fast path, and the cross-CPU FPU-flush IPI handler.
//!
//! ## Lazy save/restore discipline
//!
//! On any CPU `C` at any time, exactly one of the following holds:
//! - `(CR0.TS=1, fpu_owner=null)` — no live state worth saving; the next
//!   user FP instruction raises `#NM`.
//! - `(CR0.TS=1, fpu_owner=T)`    — T's data is still in the registers
//!   but the next FP instruction (from any thread) raises `#NM`.
//! - `(CR0.TS=0, fpu_owner=T)`    — T owns the live regs; FP runs trap-free.
//!
//! `(CR0.TS=0, fpu_owner=null)` is forbidden.
//!
//! [`switch_out_save`] sets TS=1 (no XSAVE — the regs stay live for the
//! next thread to reuse or for the migration IPI to flush). [`switch_in_restore`]
//! clears TS when the incoming thread is already the owner (fast re-run);
//! otherwise it leaves TS=1 so the first FP op traps. The `#NM` handler
//! (`idt.rs::nm_handler`) saves the previous owner's regs to its TCB area
//! before `XRSTOR`ing the trapping thread's area. The migration helper
//! (`sched/mod.rs`) flushes a stale remote owner via the FPU-flush IPI
//! (`idt.rs::ipi_fpu_flush_handler` → [`flush_owner_if`]) before enqueuing
//! a migrated thread on its destination CPU.

use core::sync::atomic::{AtomicUsize, Ordering};

// ── CR0 ───────────────────────────────────────────────────────────────────────

/// CR0.TS bit (Task Switched).
///
/// When set, any x87/SSE/AVX instruction raises `#NM` (vector 7). The kernel
/// uses this for the lazy save/restore discipline: TS=1 on context-switch-in,
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
/// Re-arms the `#NM` lazy trap by setting CR0.TS. Performs **no XSAVE**:
/// the live x87/SSE/AVX register file stays in the hardware registers and
/// the per-CPU `fpu_owner` slot is left untouched. If the outgoing thread
/// is rescheduled on this CPU before any other thread touches FP, the
/// matching [`switch_in_restore`] clears TS and resumes trap-free. If a
/// different thread tries to use FP first, the resulting `#NM` saves the
/// previous owner's registers into its TCB area lazily. If the outgoing
/// thread is migrated to another CPU, the migration-side flush IPI
/// (sched/mod.rs → [`flush_owner_if`]) extracts the live regs into the
/// thread's area before the destination CPU's `#NM` reloads them.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, before the scheduler
/// lock release that publishes this thread's state to other CPUs. `_tcb`
/// must be a valid TCB pointer.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_out_save(_tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    // SAFETY: ring 0; CR0.TS=1 is the architected lazy-trap arm.
    unsafe {
        cr0_set_ts();
    }
}

/// Context-switch hook called on switch-in of any thread.
///
/// Fast path: if this CPU's lazy-FPU owner is already `tcb` (i.e. `tcb`
/// re-runs on the same CPU it last ran on, and no other thread has used
/// FP since), clear CR0.TS so the thread resumes trap-free without any
/// XRSTOR. Otherwise leave/arm CR0.TS=1; the next FP instruction by
/// `tcb` (or by any later thread on this CPU) traps to `#NM`, which
/// saves the prior owner's regs and XRSTORs the trapping thread's area.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, after this thread's
/// preceding `switch_out_save` has completed. `tcb` must be a valid TCB
/// pointer; when its `extended.area` is non-null the area must satisfy
/// the alignment and size requirements of [`restore_from`].
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_in_restore(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    let cpu = super::cpu::current_cpu() as usize;
    let owner = crate::percpu::fpu_owner_for(cpu).load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: caller guarantees tcb is valid; the area is allocated for the
    // TCB's lifetime when non-null.
    let area_nonnull = !tcb.is_null() && !unsafe { (*tcb).extended.area }.is_null();
    if owner == tcb && area_nonnull
    {
        // Fast re-run path: live regs already hold this thread's state.
        // SAFETY: ring 0; invariant `(owner == tcb) ⇒ regs are tcb's` holds
        // because the owner slot is only written by the `#NM` handler and
        // by `flush_owner_if`, both of which keep the slot/regs coherent.
        unsafe {
            cr0_clear_ts();
        }
    }
    else
    {
        // Trap-on-first-FP path: the live regs (if any) belong to some
        // other thread; force `#NM` on the next FP op so the handler
        // saves the prior owner and reloads this thread's area.
        // SAFETY: ring 0.
        unsafe {
            cr0_set_ts();
        }
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

// ── Cross-CPU FPU-flush IPI ───────────────────────────────────────────────────

/// Local body of the FPU-flush IPI: if this CPU still owns `tcb`'s live
/// extended-state register file, XSAVE it into `tcb.extended.area` and
/// clear the owner slot. Idempotent: a no-op when this CPU's owner has
/// already been swapped to another value (e.g. by a concurrent `#NM`).
///
/// Called from two contexts: (a) the IPI handler in idt.rs after the
/// sender (a migration helper on another CPU) wrote `tcb` into this
/// CPU's `FPU_FLUSH_PENDING` slot and delivered the IPI; (b) the local
/// fast-path of `flush_owner_remote` when the caller's CPU is itself
/// the source CPU (no IPI required).
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled (the IPI-handler
/// caller runs under an interrupt gate; the local-call path is invoked
/// from syscall context with `IF=0`). `tcb` must be a valid TCB pointer
/// whose `extended.area` is allocated for the TCB's lifetime, or null,
/// in which case this function does nothing.
#[cfg(not(test))]
pub unsafe fn flush_owner_if(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    if tcb.is_null()
    {
        return;
    }
    let cpu = super::cpu::current_cpu() as usize;
    let owner = crate::percpu::fpu_owner_for(cpu);
    // Try to take ownership: if the slot still names `tcb`, claim it.
    if owner
        .compare_exchange(
            tcb,
            core::ptr::null_mut(),
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // Owner already differs (another `#NM` or flush displaced us).
        // The live regs no longer belong to `tcb`; nothing to extract.
        return;
    }
    // SAFETY: tcb is valid; we observed ownership; XSAVE requires the
    // hardware regs to be accessible (CR0.TS=0 during the instruction).
    let area = unsafe { (*tcb).extended.area };
    if area.is_null()
    {
        // Defensive: if the area is missing the regs cannot be persisted;
        // a thread that has ever been an owner must have had its area
        // lazy-allocated in the `#NM` handler, so this branch is
        // unreachable in normal operation. Re-arm TS for safety.
        // SAFETY: ring 0.
        unsafe {
            cr0_set_ts();
        }
        return;
    }
    // SAFETY: ring 0; the area is valid for this TCB's lifetime, and we
    // hold logical ownership of the live regs (no other CPU writes them).
    unsafe {
        cr0_clear_ts();
        save_to(area);
        cr0_set_ts();
    }
}

/// Test stub for [`flush_owner_if`].
#[cfg(test)]
pub unsafe fn flush_owner_if(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// Sender side of the cross-CPU FPU-flush IPI. Invoked from sched migration
/// helpers (active migration, load-balancer pull) on the path that moves
/// `tcb` from `src_cpu`'s run queue to a different CPU's run queue.
///
/// Early-outs if `src_cpu`'s owner slot does not currently name `tcb`
/// (the common case — most threads are not the lazy-FPU owner of the CPU
/// they're being migrated off of). Otherwise delegates to the arch-level
/// synchronous IPI sender, which writes the per-CPU `FPU_FLUSH_PENDING`
/// slot, fires the IPI vector, and spins for ack.
///
/// # Safety
/// Must execute at ring 0. `src_cpu` must be < `MAX_CPUS`. `tcb` must be
/// a valid TCB pointer that the caller is in the process of migrating
/// off `src_cpu`.
#[cfg(not(test))]
pub unsafe fn flush_owner_remote(src_cpu: usize, tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    if tcb.is_null()
    {
        return;
    }
    if src_cpu == super::cpu::current_cpu() as usize
    {
        // Local invalidation: do the work directly, no IPI.
        // SAFETY: ring 0; same contract as the IPI handler.
        unsafe {
            flush_owner_if(tcb);
        }
        return;
    }
    let owner = crate::percpu::fpu_owner_for(src_cpu).load(core::sync::atomic::Ordering::Acquire);
    if owner != tcb
    {
        // Common case: the source CPU does not currently own `tcb`'s
        // live regs. Either `tcb` has never touched FP, or a later
        // thread on the source CPU has displaced it via `#NM`. The
        // canonical state in `tcb.extended.area` is already fresh.
        return;
    }
    // SAFETY: src_cpu validated < MAX_CPUS by caller; tcb is the
    // migration target.
    unsafe {
        super::interrupts::send_fpu_flush_ipi(src_cpu, tcb);
    }
}

/// Test stub for [`flush_owner_remote`].
#[cfg(test)]
pub unsafe fn flush_owner_remote(
    _src_cpu: usize,
    _tcb: *mut crate::sched::thread::ThreadControlBlock,
)
{
}
