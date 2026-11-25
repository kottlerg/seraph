// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/fpu.rs

//! x86-64 extended-state (x87 / SSE / AVX) control primitives.
//!
//! Concentrates the unsafe surface for FPU/SIMD state management:
//! XSETBV/XCR0 setup, per-CPU XSAVE enablement and CR0's user-visible x87 and
//! alignment controls, set at boot, and the save/restore primitives the
//! context-switch path runs. The per-thread XSAVE area is
//! the pages after the TCB page of the thread's slot (`sched::thread_slot`),
//! carved and given its initial state ([`init_save_area`]) by the
//! thread-create path (`syscall::cap::sys_cap_create_thread`) and, for init's
//! thread, by boot code (`kernel_entry_post_rebase`).
//!
//! ## Switch-in restore
//!
//! A user thread's state is live in the registers whenever it runs in user
//! mode, and no other thread's is (`sched::fpu_switch`). [`switch_out_save`]
//! XSAVEs the outgoing user thread's registers into its area and leaves this
//! CPU's `fpu_owner` naming it. [`switch_in_restore`] XRSTORs the incoming
//! user thread's area unless `fpu_owner` names it and its `fpu_cpu` names this
//! CPU, which together mean the registers still hold its state, and records
//! both. A kernel thread or idle loads nothing: the kernel is soft-float, so the
//! registers keep the owner's state while it runs. CR0.TS stays clear, so no
//! instruction traps to `#NM`; a `#NM` is an unexpected exception
//! (`idt::exception_handler`). The migration guarantee (no cross-CPU FPU
//! coordination) is in core/kernel/docs/scheduling-internals.md § IPI Taxonomy.

// ── CR0 ───────────────────────────────────────────────────────────────────────

/// CR0.TS bit (Task Switched).
///
/// When set, any x87/SSE/AVX instruction raises `#NM` (vector 7), and so do
/// XSAVE and XRSTOR. [`enable_xsave`] clears it on every CPU at boot, and
/// nothing sets it.
const CR0_TS: u64 = 1 << 3;

/// CR0.MP (bit 1): `WAIT`/`FWAIT` honour CR0.TS, the setting the x87
/// architecture expects with `NE`; TS stays clear, so they never raise `#NM`.
const CR0_MP: u64 = 1 << 1;

/// CR0.EM (bit 2): x87 emulation; makes every x87 instruction raise `#NM` and
/// every SSE instruction `#UD`.
const CR0_EM: u64 = 1 << 2;

/// CR0.NE (bit 5): x87 errors are reported through `#MF`, not the legacy
/// external `FERR#` signal.
const CR0_NE: u64 = 1 << 5;

/// CR0.AM (bit 18): with `RFLAGS.AC` set, a misaligned CPL-3 access raises
/// `#AC`.
const CR0_AM: u64 = 1 << 18;

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
// The save area is the image `SYS_THREAD_READ_EXT_REGS` reads, whose layout
// the ABI states by this component set.
const _: () = assert!(
    XCR0_V3 == syscall::EXT_REGS_X86_64_XCR0,
    "the ABI's extended-state image is the XSAVE area of the XCR0 the kernel sets"
);

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
/// Also sets CR0's user-visible x87 and alignment controls (`MP`, `NE` set;
/// `EM`, `AM` clear) and clears `TS`, which nothing sets after.
///
/// Must be called once per CPU during early init. On the BSP it runs from
/// `interrupts::init` before the IDT is loaded (a CR4/XCR0 fault there is not
/// catchable); on each AP (`interrupts::init_ap`) the IDT is already loaded.
/// Fatal if the CPU does not support XSAVE (CPUID.01H:ECX bit 26) — the kernel
/// targets x86-64-v3 which requires it.
///
/// After this returns, XSAVE and XRSTOR run without trapping.
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

    // CR0's user-visible x87 and alignment controls, and TS. The BSP runs on
    // the CR0 the firmware left and each AP on the one INIT leaves (NE, MP and
    // AM clear), so set each explicitly: MP and NE set, EM, AM and TS clear.
    // Ring 3 then gets x87 errors as `#MF` and no alignment checking, and
    // XSAVE, XRSTOR and every x87/SSE/AVX instruction run without `#NM`, on
    // every CPU.
    // SAFETY: ring 0; MP and NE are architectural on every x86-64 CPU, and
    // clearing EM and AM changes no translation or protection the kernel
    // relies on (the kernel runs soft-float and never sets RFLAGS.AC at CPL 3);
    // clearing TS before any thread's state is loaded exposes no state.
    unsafe {
        write_cr0((read_cr0() & !(CR0_EM | CR0_AM | CR0_TS)) | CR0_MP | CR0_NE);
    }
}

/// Bytes of the XSAVE area for the components XCR0 currently enables on the
/// executing CPU (CPUID.0Dh:0.EBX): the per-thread save area [`save_to`]
/// writes, which sizes every Thread retype slot
/// (`crate::sched::thread_slot`). Valid once [`enable_xsave`] has written
/// XCR0.
#[cfg(not(test))]
fn xsave_area_bytes() -> u64
{
    u64::from(super::cpu::cpuid(0xD).1)
}

/// Byte offset of the x87 control word (`FCW`, 2 bytes) in the XSAVE legacy
/// region (Intel SDM Vol. 1 § 13.4.1).
const LEGACY_FCW_OFFSET: usize = 0;

/// Byte offset of `MXCSR` (4 bytes) in the XSAVE legacy region (Intel SDM
/// Vol. 1 § 13.4.1).
const LEGACY_MXCSR_OFFSET: usize = 24;

/// Bytes of the XSAVE legacy region, which holds both fields above; every
/// XSAVE area is longer.
const LEGACY_REGION_BYTES: usize = 512;

/// The x87 control word `FNINIT` sets, and so the one a component-initial
/// XRSTOR leaves: every x87 exception masked, double-extended precision,
/// round to nearest (Intel SDM Vol. 1 § 8.1.5). The System V AMD64 psABI
/// gives a new process this value.
const FCW_INIT: u16 = 0x037F;

/// `MXCSR`'s power-up value: every SIMD floating-point exception masked,
/// round to nearest, flush-to-zero and denormals-are-zero clear (Intel SDM
/// Vol. 1 § 10.2.3). The System V AMD64 psABI gives a new process this value.
const MXCSR_INIT: u32 = 0x1F80;

/// Write a new thread's initial extended state into its save area: the image
/// its first x87/SSE/AVX use restores ([`restore_from`]), and the one
/// `SYS_THREAD_READ_EXT_REGS` reads until the thread's first switch-out
/// after that use.
///
/// The area is zeroed, so `XSTATE_BV` and `XCOMP_BV` are 0: the standard
/// format, every component in its initial configuration (x87 as `FNINIT`
/// leaves it, the XMM registers and the YMM upper halves zero). `MXCSR` is
/// the exception: XRSTOR loads it from the legacy region whenever RFBM\[1\]
/// or RFBM\[2\] is set, whatever `XSTATE_BV` holds (Intel SDM Vol. 1
/// § 13.8.1), so a zero there would start the thread with every SIMD
/// floating-point exception unmasked, and its first inexact SSE result would
/// raise `#XM`. It is written as [`MXCSR_INIT`]. `FCW` is written as
/// [`FCW_INIT`], which XRSTOR ignores while `XSTATE_BV`\[0\] is clear, so
/// that every field of the image reads as the value the thread starts with.
///
/// # Safety
/// `area` must point at `bytes` bytes that the caller owns exclusively and
/// may write, `bytes` being at least the legacy region (the per-thread save
/// area of `crate::sched::thread_slot` is).
#[cfg(not(test))]
pub unsafe fn init_save_area(area: *mut u8, bytes: usize)
{
    debug_assert!(bytes >= LEGACY_REGION_BYTES);
    // SAFETY: the caller's contract gives `bytes` writable bytes at `area`.
    unsafe { core::ptr::write_bytes(area, 0, bytes) };
    let fcw = FCW_INIT.to_le_bytes();
    // SAFETY: FCW's 2 bytes lie inside the legacy region, which the area
    // holds (the caller's contract); the source is a local array.
    unsafe {
        core::ptr::copy_nonoverlapping(
            fcw.as_ptr(),
            area.wrapping_add(LEGACY_FCW_OFFSET),
            fcw.len(),
        );
    }
    let mxcsr = MXCSR_INIT.to_le_bytes();
    // SAFETY: MXCSR's 4 bytes lie inside the legacy region, which the area
    // holds (the caller's contract); the source is a local array.
    unsafe {
        core::ptr::copy_nonoverlapping(
            mxcsr.as_ptr(),
            area.wrapping_add(LEGACY_MXCSR_OFFSET),
            mxcsr.len(),
        );
    }
}

/// Report the BSP's per-thread save-area size, [`xsave_area_bytes`], which
/// sizes every Thread retype slot (`crate::sched::thread_slot`). Every CPU
/// enables the same XCR0 components ([`enable_xsave`]), and the standard
/// XSAVE layout of a given component set is architectural, so the BSP's size
/// holds on every CPU and only the BSP reports it. The arch contract's
/// `fpu::report_save_area`, called by Phase 5 after `percpu::init_bsp`.
///
/// # Safety
/// Must execute at ring 0 on the BSP, once, after `interrupts::init` ran
/// [`enable_xsave`] and before any Thread is created.
#[cfg(not(test))]
pub unsafe fn report_save_area()
{
    crate::sched::thread_slot::set_extended_bytes(xsave_area_bytes());
}

/// Save the live x87/SSE/AVX state of the executing CPU into `area`.
///
/// `area` must be 64-byte aligned and point at a writable XSAVE buffer of
/// at least the XCR0-enabled size (CPUID.0Dh:0.EBX) bytes, which XSAVE never
/// writes past. The component-mask passed in
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
/// publishes `context_saved`).
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
/// reloaded; the others reach their initial configuration. `MXCSR` is
/// loaded from the area whatever `XSTATE_BV` holds, which is why
/// [`init_save_area`] writes its initial value there.
///
/// # Safety
/// Must execute at ring 0 with CR0.TS clear. `area` must point at an XSAVE
/// buffer previously written by [`save_to`] or by [`init_save_area`]. Called
/// from `switch_in_restore` with interrupts disabled.
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
/// Saves the live extended-state registers of a user thread: when this CPU's
/// `fpu_owner` names `tcb`, which it does for every user thread that ran here
/// since its switch-in, XSAVE into `tcb`'s area. `fpu_owner` and the thread's
/// `fpu_cpu` are left naming each other, so a switch back to `tcb` on this CPU
/// with no other user thread between loads nothing. A thread this CPU's owner
/// does not name (kernel threads and idle, whose area is null) saves nothing.
///
/// Postcondition: `tcb`'s area holds its current state, for any CPU to XRSTOR
/// at its next switch-in.
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
    // SAFETY: tcb is valid (caller); `extended.area` is immutable after construction.
    let area = unsafe { (*tcb).extended.area };
    if area.is_null()
    {
        return;
    }
    let cpu = super::cpu::current_cpu() as usize;
    // SAFETY: `cpu` is the executing CPU's logical index, below CPU_COUNT.
    let owner =
        unsafe { crate::percpu::fpu_owner_for(cpu) }.load(core::sync::atomic::Ordering::Relaxed);
    if owner == tcb
    {
        // SAFETY: CR0.TS is clear; area satisfies XSAVE alignment and size; this
        // CPU's owner names tcb, so the live registers are tcb's.
        unsafe {
            save_to(area);
        }
    }
}

/// Context-switch hook called on switch-in of any thread, after the Acquire of
/// its `context_saved`.
///
/// For a user thread, XRSTOR its area unless this CPU's `fpu_owner` names it
/// and its `fpu_cpu` names this CPU (`sched::fpu_switch::in_use_action`), then
/// name it the owner and this CPU its `fpu_cpu`. A kernel thread or idle (null
/// area) loads nothing and leaves the owner as it is.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, after the outgoing thread's
/// `switch_out_save` and after this CPU's Acquire of `tcb`'s `context_saved`,
/// which orders the previous CPU's save of the area and its write of
/// `fpu_cpu` before the reads here. `tcb` must be a valid TCB pointer.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_in_restore(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::sched::fpu_switch::{InUseAction, Owner, in_use_action};

    // SAFETY: tcb is valid (caller); `extended` is a field of it.
    let ext = unsafe { &(*tcb).extended };
    if ext.area.is_null()
    {
        return;
    }
    let cpu = super::cpu::current_cpu();
    // SAFETY: `cpu` is the executing CPU's logical index, below CPU_COUNT.
    let owner_slot = unsafe { crate::percpu::fpu_owner_for(cpu as usize) };
    let owner = Owner::of(
        owner_slot
            .load(core::sync::atomic::Ordering::Relaxed)
            .cast_const(),
        tcb.cast_const(),
    );
    match in_use_action(
        owner,
        ext.fpu_cpu.load(core::sync::atomic::Ordering::Relaxed),
        cpu,
    )
    {
        InUseAction::Keep =>
        {}
        InUseAction::Load =>
        {
            // SAFETY: CR0.TS is clear; the area was written by init_save_area or
            // by this thread's own switch-out saves, the last of them ordered
            // before this read by the context_saved Acquire.
            unsafe {
                restore_from(ext.area);
            }
            owner_slot.store(tcb, core::sync::atomic::Ordering::Relaxed);
            ext.fpu_cpu
                .store(cpu, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}
