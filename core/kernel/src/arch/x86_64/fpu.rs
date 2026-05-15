// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/fpu.rs

//! x86-64 extended-state (x87 / SSE / AVX) control primitives.
//!
//! Concentrates the unsafe surface for FPU/SIMD state management:
//! CR0 access (TS bit for lazy-trap discipline), XSETBV/XCR0 setup, the
//! per-CPU XSAVE enablement performed at boot, and the per-thread XSAVE
//! area allocation plus save/restore used by the lazy save/restore path.

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

/// CR4.OSXSAVE bit. Setting this advertises XSAVE support to userspace via
/// CPUID and unmasks the XSETBV/XGETBV instructions.
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

    // Set CR4.OSXSAVE. This unmasks XSETBV/XGETBV.
    let cr4 = super::cpu::read_cr4();
    // SAFETY: CPUID confirmed XSAVE; setting OSXSAVE is the architected enable bit.
    unsafe {
        super::cpu::write_cr4(cr4 | CR4_OSXSAVE);
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

// ── Per-thread XSAVE area ─────────────────────────────────────────────────────

/// Per-thread XSAVE area size: 4 KiB.
///
/// Comfortably above the area size for the x87|SSE|AVX component set we
/// enable in XCR0 (typically 832 bytes). Leaves headroom for future
/// AVX-512 promotion. SEED-backed allocations are page-aligned, which
/// trivially satisfies XSAVE's 64-byte alignment requirement.
pub const XSAVE_AREA_BYTES: usize = 4096;

/// Allocate and zero-initialise a per-thread XSAVE area from the SEED
/// retype pool. Returns a page-aligned `*mut u8` of size [`XSAVE_AREA_BYTES`].
///
/// A zeroed area is XRSTOR-valid: it is equivalent to FINIT + zeroed XMM/YMM
/// per Intel SDM, so the first XRSTOR after a fresh allocation reaches the
/// architected initial state with no special-casing.
///
/// Returns null if SEED is exhausted; the caller (TCB constructor) records
/// the result in `ExtendedState::area`. A null area means lazy save/restore
/// is disabled for the thread; the lazy-trap handler skips XRSTOR in that
/// case and the user thread proceeds with whatever FPU state the hardware
/// happens to have. Until userspace targets actually emit SIMD this is
/// dormant; once they do, the allocator is the only failure mode and OOM
/// here would in practice halt the kernel via the SEED carve panic.
#[cfg(not(test))]
pub fn alloc_area() -> *mut u8
{
    match crate::cap::retype::alloc_seed_scratch(XSAVE_AREA_BYTES as u64)
    {
        Ok(ptr) =>
        {
            // SAFETY: ptr points at XSAVE_AREA_BYTES of freshly-carved SEED
            // scratch; zero-init makes the area XRSTOR-valid.
            unsafe {
                core::ptr::write_bytes(ptr, 0u8, XSAVE_AREA_BYTES);
            }
            ptr
        }
        Err(_) => core::ptr::null_mut(),
    }
}

/// Test stub: TCB construction is exercised in host unit tests for the
/// retype/dispatch arithmetic; never running asm there, so a null is fine.
#[cfg(test)]
pub fn alloc_area() -> *mut u8
{
    core::ptr::null_mut()
}

/// Reclaim a per-thread XSAVE area previously returned by [`alloc_area`].
///
/// # Safety
/// `area` must have been returned by [`alloc_area`] on this kernel build
/// and not previously freed. Null is allowed and is a no-op.
#[cfg(not(test))]
pub unsafe fn free_area(area: *mut u8)
{
    if area.is_null()
    {
        return;
    }
    crate::cap::retype::free_seed_scratch(area, XSAVE_AREA_BYTES as u64);
}

/// Test stub for [`free_area`].
#[cfg(test)]
pub unsafe fn free_area(_area: *mut u8) {}

/// Save the live x87/SSE/AVX state of the executing CPU into `area`.
///
/// Uses XSAVEOPT to skip components untouched since the last save.
/// `area` must be 64-byte aligned and point at a writable XSAVE buffer of
/// at least [`xsave_area_size`] bytes. The component-mask passed in
/// `EDX:EAX = 0xFFFF_FFFF_FFFF_FFFF` instructs XSAVEOPT to save every
/// component that XCR0 currently enables.
///
/// # Safety
/// Must execute at ring 0. `area` must satisfy the alignment and size
/// requirements above. Called from the context-switch path with
/// interrupts disabled and the scheduler lock held.
#[cfg(not(test))]
#[inline]
pub unsafe fn save_to(area: *mut u8)
{
    // SAFETY: caller's contract; XSAVEOPT requires OSXSAVE which the boot
    // path established. The component mask `0xFFFF_FFFF` (low 32 bits) is
    // intersected with XCR0 by hardware, so it saves exactly the enabled set.
    unsafe {
        core::arch::asm!(
            "xsaveopt [{area}]",
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

/// Context-switch hook called on switch-out of a user thread (the caller
/// supplies the non-null area pointer): XSAVEOPT the live x87/SSE/AVX
/// register file to the thread's per-TCB area and re-arm the `#NM` lazy
/// trap by setting CR0.TS.
///
/// XSAVEOPT performs hardware-tracked dirty filtering via the XINUSE bits
/// it maintains internally — components untouched since the last XRSTOR
/// are not written. The cost on a thread that has not dirtied any FPU
/// state since its last restore is ~50 cycles (instruction decode +
/// XINUSE check, no memory traffic). This is the discipline Linux and
/// most modern x86-64 kernels run.
///
/// # Safety
/// Must execute at ring 0 with interrupts disabled, before the scheduler
/// lock release that publishes this thread's state to other CPUs.
/// `area` must satisfy the alignment and size requirements of [`save_to`].
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_out_save(area: *mut u8)
{
    // SAFETY: caller's contract.
    unsafe {
        save_to(area);
        cr0_set_ts();
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_area: *mut u8) {}
