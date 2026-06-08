// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/interrupts.rs

//! x86-64 interrupt controller (xAPIC / x2APIC) and Phase 5 interrupt
//! initialisation.
//!
//! Orchestrates GDT, IDT, SMEP/SMAP, and the local APIC in the correct order:
//!
//! 1. Enable SMEP + SMAP (fatal if CPU lacks support).
//! 2. Carve IST stacks (2 × 8 KiB) out of the [`BSP_IST_STACKS`] BSS array.
//! 3. Load GDT + TSS with the IST stack pointers.
//! 4. Load IDT.
//! 5. Software-enable the local APIC: set SVR bit 8, spurious vector 255.
//! 6. Mask all LVT entries.
//!
//! Interrupts are **not** enabled here; `timer::init()` enables them after the
//! APIC timer is calibrated and configured.
//!
//! # Local APIC access
//! Two access modes share a single accessor pair ([`apic_read`] /
//! [`apic_write`]), gated on [`X2APIC_ENABLED`]:
//! - **xAPIC** (MMIO): registers live at `DIRECT_MAP_BASE + lapic_base() +
//!   offset`, where `lapic_base` comes from the bootloader through
//!   `BootInfo.kernel_mmio.lapic_base` (see [`super::platform::lapic_base`]).
//! - **x2APIC** (MSR): the CPU advertises x2APIC via CPUID.01H:ECX[21]; Phase
//!   5 sets `IA32_APIC_BASE.EXTD` and each register maps to MSR
//!   `0x800 + (offset >> 4)`. The ICR collapses to one 64-bit MSR write (see
//!   [`apic_send_icr`]). Enabling x2APIC disables the xAPIC MMIO window, so
//!   every local-APIC access must route through the accessor — the I/O APIC
//!   (separate hardware) is unaffected and stays MMIO.
//!
//! # Modification notes
//! - To handle a new device IRQ: call `register_handler(vec, handler)` and
//!   call `unmask(vec)`. Full routing is deferred to a later phase.

// cast_possible_truncation: u64→usize/u8 APIC address arithmetic; bounded by APIC layout.
// cast_lossless: u8→u32 vector casts are always widening.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

#[cfg(not(test))]
use super::{cpu, fpu, gdt, idt};
#[cfg(not(test))]
use crate::mm::paging::DIRECT_MAP_BASE;

// ── xAPIC constants ───────────────────────────────────────────────────────────

/// Spurious Interrupt Vector Register offset.
const APIC_SVR: usize = 0xF0;
/// End-of-Interrupt register offset (write 0 to acknowledge).
const APIC_EOI: usize = 0xB0;
/// LVT Timer register offset.
const APIC_LVT_TIMER: usize = 0x320;
/// LVT LINT0 register offset.
const APIC_LVT_LINT0: usize = 0x350;
/// LVT LINT1 register offset.
const APIC_LVT_LINT1: usize = 0x360;
/// LVT Error register offset.
const APIC_LVT_ERROR: usize = 0x370;
/// LVT Thermal monitor register offset.
const APIC_LVT_THERMAL: usize = 0x330;
/// LVT Performance counter register offset.
const APIC_LVT_PERF: usize = 0x340;

/// Bit to mask an LVT entry (prevent delivery).
const LVT_MASK: u32 = 1 << 16;

/// IST stack size: 8 KiB.
const IST_STACK_SIZE: usize = 8192;

/// BSP IST stacks, in BSS. The BSP installs these at Phase-5 init.
///
/// Two stacks: IST1 for double-fault, IST2 for NMI. AP IST stacks live in
/// [`crate::arch::x86_64::ap_trampoline::AP_IST_STACKS`].
///
/// `static mut` is written only at single-threaded boot init.
#[cfg(not(test))]
static mut BSP_IST_STACKS: [u8; IST_STACK_SIZE * 2] = [0u8; IST_STACK_SIZE * 2];

// ── x2APIC mode ───────────────────────────────────────────────────────────────

/// `IA32_APIC_BASE` MSR: bit 10 (EXTD) selects x2APIC mode, bit 11 (EN) is the
/// global APIC enable.
const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_GLOBAL_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC_ENABLE: u64 = 1 << 10;

/// `IA32_X2APIC_ICR` MSR. In x2APIC mode the ICR is a single 64-bit register:
/// destination in bits [63:32], command word in bits [31:0].
const IA32_X2APIC_ICR: u32 = 0x830;

/// CPUID.01H:ECX bit 21 — x2APIC supported.
const CPUID_ECX_X2APIC: u32 = 1 << 21;

/// True once the local APIC is driven through x2APIC MSRs rather than the
/// xAPIC MMIO window. Decided once on the BSP at Phase 5 from CPUID.01H:ECX[21];
/// each AP mirrors the mode by setting `IA32_APIC_BASE.EXTD` in [`init_ap`]
/// (EXTD is per-CPU MSR state). x2APIC support is uniform across a package, so a
/// single global flag is correct. The write happens before any AP exists, so
/// `Relaxed` ordering suffices.
#[cfg(not(test))]
static X2APIC_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether this CPU drives the APIC through x2APIC MSRs.
#[cfg(not(test))]
#[inline]
fn x2apic_enabled() -> bool
{
    X2APIC_ENABLED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Returns true when the CPU advertises x2APIC (CPUID.01H:ECX[21]).
#[cfg(not(test))]
fn x2apic_supported() -> bool
{
    let (_eax, _ebx, ecx, _edx) = cpu::cpuid(1);
    ecx & CPUID_ECX_X2APIC != 0
}

/// Switch the executing CPU into x2APIC mode by setting `IA32_APIC_BASE.EXTD`
/// (preserving the global-enable bit firmware already set).
///
/// # Safety
/// Ring 0. The CPU must advertise x2APIC (caller checks [`x2apic_supported`]).
#[cfg(not(test))]
unsafe fn enable_x2apic_this_cpu()
{
    // SAFETY: IA32_APIC_BASE exists on every x86-64 local APIC; ring 0.
    unsafe {
        let base = cpu::read_msr(IA32_APIC_BASE);
        cpu::write_msr(
            IA32_APIC_BASE,
            base | APIC_BASE_GLOBAL_ENABLE | APIC_BASE_X2APIC_ENABLE,
        );
    }
}

// ── APIC register access ──────────────────────────────────────────────────────

/// Write `val` to the local-APIC register at `offset` bytes from the xAPIC
/// base (an x2APIC MSR index of `0x800 + (offset >> 4)` in x2APIC mode).
///
/// The ICR is sent via [`apic_send_icr`] and must not pass through here.
///
/// # Safety
/// Must only be called after Phase 3 (direct map active) and with a valid
/// 16-byte-aligned APIC register offset.
#[cfg(not(test))]
pub(super) unsafe fn apic_write(offset: usize, val: u32)
{
    if x2apic_enabled()
    {
        // SAFETY: offset names a valid 16-byte-aligned APIC register; ring 0.
        unsafe { cpu::write_msr(0x800 + (offset >> 4) as u32, u64::from(val)) };
        return;
    }
    let vaddr = (DIRECT_MAP_BASE + super::platform::lapic_base()) as usize + offset;
    // SAFETY: vaddr is within the direct-mapped APIC MMIO region.
    unsafe {
        core::ptr::write_volatile(vaddr as *mut u32, val);
    }
}

/// Read the local-APIC register at `offset` bytes from the xAPIC base (an
/// x2APIC MSR index of `0x800 + (offset >> 4)` in x2APIC mode).
#[cfg(not(test))]
pub(super) fn apic_read(offset: usize) -> u32
{
    if x2apic_enabled()
    {
        // SAFETY: offset names a valid 16-byte-aligned APIC register; ring 0.
        return unsafe { cpu::read_msr(0x800 + (offset >> 4) as u32) as u32 };
    }
    let vaddr = (DIRECT_MAP_BASE + super::platform::lapic_base()) as usize + offset;
    // SAFETY: vaddr is within the direct-mapped APIC MMIO region.
    unsafe { core::ptr::read_volatile(vaddr as *const u32) }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise interrupt infrastructure for x86-64.
///
/// Must be called once during Phase 5, after the heap is active (Phase 4)
/// and before `timer::init()`.
///
/// # Safety
/// Must execute at ring 0 from a single-threaded context.
#[cfg(not(test))]
pub unsafe fn init()
{
    // 1. Enable SMEP + SMAP — fatal if CPU lacks support.
    // SAFETY: ring-0 single-threaded boot.
    unsafe {
        cpu::enable_smep_smap();
    }

    // 1a. Enable XSAVE (x87 | SSE | AVX in XCR0) and arm CR0.TS for lazy
    //     FPU/SIMD save-restore. Kernel never touches FP/SIMD (soft-float)
    //     so TS=1 is harmless until a user thread first uses XMM/YMM, at
    //     which point a #NM trap runs the lazy-restore path.
    // SAFETY: ring-0 boot; IDT is loaded a few steps below — until then a
    // CR4/XCR0 fault would triple-fault the boot CPU. enable_xsave only
    // executes architected register writes that succeed when CPUID
    // advertises XSAVE; we fatal cleanly if the advertisement is absent.
    unsafe {
        fpu::enable_xsave();
        fpu::cr0_set_ts();
    }

    // 2. Carve the BSP IST stacks out of [`BSP_IST_STACKS`] (BSS).
    let ist_base = core::ptr::addr_of_mut!(BSP_IST_STACKS) as u64;
    let ist1_top = ist_base + IST_STACK_SIZE as u64;
    let ist2_top = ist_base + (IST_STACK_SIZE * 2) as u64;

    // Derive the current kernel stack top from RSP for the initial TSS RSP0.
    // This is updated on each context switch in later phases.
    let rsp0: u64;
    // SAFETY: RSP is always readable at ring 0.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp0, options(nostack, nomem));
    }

    // 3. Load GDT + TSS.
    // SAFETY: single-threaded boot; IST stacks just allocated.
    unsafe {
        gdt::init(rsp0, ist1_top, ist2_top);
    }

    // 4. Load IDT.
    // SAFETY: GDT is loaded; KERNEL_CS selector is valid.
    unsafe {
        idt::init();
    }

    // 4a. Switch into x2APIC mode when the CPU advertises it, before any APIC
    //     register access below: once EXTD is set the xAPIC MMIO window is
    //     gone, so the SVR/LVT writes must route through the x2APIC MSRs.
    // SAFETY: ring-0 boot; the MSR write is gated on CPUID advertisement.
    unsafe {
        if x2apic_supported()
        {
            enable_x2apic_this_cpu();
            X2APIC_ENABLED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    }
    crate::kprintln!(
        "interrupts: local APIC mode = {}",
        if x2apic_enabled() { "x2APIC" } else { "xAPIC" }
    );

    // 5. Software-enable the local APIC.
    // Set SVR bit 8 (APIC Software Enable) and program spurious vector 255.
    // SAFETY: direct map / x2APIC MSRs active; SVR write is architecture-defined.
    unsafe {
        apic_write(APIC_SVR, apic_read(APIC_SVR) | 0x100 | 0xFF);
    }

    // 6. Mask all LVT entries to prevent unexpected interrupts before the
    //    timer is configured.
    // SAFETY: Local APIC MMIO base is valid kernel mapping; LVT mask writes are architecture-defined.
    unsafe {
        apic_write(APIC_LVT_TIMER, LVT_MASK);
        apic_write(APIC_LVT_LINT0, LVT_MASK);
        apic_write(APIC_LVT_LINT1, LVT_MASK);
        apic_write(APIC_LVT_ERROR, LVT_MASK);
        apic_write(APIC_LVT_THERMAL, LVT_MASK);
        apic_write(APIC_LVT_PERF, LVT_MASK);
    }

    // 7. Initialise the I/O APIC: discover entry count and mask all entries.
    // SAFETY: direct map is active; per-IOAPIC MMIO bases are mapped via the
    // arch platform layer's contribution to Phase 3 direct-map regions.
    unsafe {
        super::ioapic::init();
    }
}

/// No-op test stub: interrupt initialisation cannot run in host unit tests.
#[cfg(test)]
pub unsafe fn init() {}

// ── APIC ID and ICR ───────────────────────────────────────────────────────────

/// Local APIC ID register offset.
#[allow(dead_code)] // Used by lapic_id(), which is part of the arch interface for future SMP use.
const APIC_ID: usize = 0x20;
/// Interrupt Command Register low word (bits 31:0).
const APIC_ICR_LOW: usize = 0x300;
/// Interrupt Command Register high word (bits 63:32).
const APIC_ICR_HIGH: usize = 0x310;

/// ICR delivery pending bit (bit 12 of `ICR_LOW`).
const ICR_PENDING: u32 = 1 << 12;
/// ICR value for INIT IPI: level-assert, trigger=level, delivery=INIT.
const ICR_INIT_ASSERT: u32 = 0x0000_C500;
/// ICR value for INIT de-assert (clears INIT notification).
const ICR_INIT_DEASSERT: u32 = 0x0000_8500;
/// ICR base value for STARTUP IPI: delivery=STARTUP, vector in bits[7:0].
const ICR_SIPI_BASE: u32 = 0x0000_4600;
/// IPI vector for TLB shootdown requests.
pub const IPI_VECTOR_TLB_SHOOTDOWN: u8 = 250;
/// IPI vector for waking idle CPUs.
pub const IPI_VECTOR_WAKEUP: u8 = 251;

/// Per-CPU "dump backtrace from your NMI handler" request flag, set by the
/// synchronous-IPI watchdog before raising a vector-2 NMI at the stuck
/// target CPU. The target's NMI handler reads it, dumps the saved
/// `TrapFrame` to serial, and clears the flag. A hardware NMI with
/// the flag clear falls through to the existing fatal path.
///
/// Single-bit publication, no caller-side ordering beyond Release/Acquire
/// (the NMI itself is a serialising event for the target).
/// Base pointer for the per-CPU `[AtomicBool; cpu_count]` request slab,
/// allocated by [`init_nmi_backtrace_storage`] before AP bringup. Sized to
/// `cpu_count` rather than `MAX_CPUS` so it scales with the CPU count.
#[cfg(not(test))]
static NMI_BACKTRACE_PTR: core::sync::atomic::AtomicPtr<core::sync::atomic::AtomicBool> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU NMI-backtrace request slab sized to `cpu_count`,
/// zero-filled (each `AtomicBool` starts `false`). Called from
/// `sched::init_per_cpu_storage` before AP bringup.
#[cfg(not(test))]
pub fn init_nmi_backtrace_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    let bytes = cpu_count * core::mem::size_of::<core::sync::atomic::AtomicBool>();
    let ptr = crate::sched::alloc_zeroed_slab::<core::sync::atomic::AtomicBool>(
        bytes,
        allocator,
        "NMI_BACKTRACE",
    );
    NMI_BACKTRACE_PTR.store(ptr, core::sync::atomic::Ordering::Release);
}

/// Return CPU `cpu`'s NMI-backtrace request flag, or `None` if `cpu` is out of
/// range or the slab is not yet allocated.
#[cfg(not(test))]
pub fn nmi_backtrace_request(cpu: usize) -> Option<&'static core::sync::atomic::AtomicBool>
{
    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    if cpu >= cpu_count
    {
        return None;
    }
    let base = NMI_BACKTRACE_PTR.load(core::sync::atomic::Ordering::Acquire);
    if base.is_null()
    {
        return None;
    }
    // SAFETY: cpu < cpu_count; the slab covers cpu_count zero-initialised
    // AtomicBool slots.
    Some(unsafe { &*base.add(cpu) })
}

/// ICR delivery-mode + level encoding for an NMI IPI (`delivery_mode`=4 = NMI,
/// level=assert, trigger=edge, `dest_shorthand`=none, vector=0/ignored).
const ICR_NMI: u32 = 0x0000_4400;

/// Read this CPU's local APIC ID.
///
/// xAPIC packs the 8-bit ID in bits [31:24] of the APIC ID register; x2APIC
/// exposes the full 32-bit ID with no shift.
#[allow(dead_code)] // Part of the arch interface; will be used by future SMP topology code.
#[cfg(not(test))]
pub fn lapic_id() -> u32
{
    let raw = apic_read(APIC_ID);
    if x2apic_enabled() { raw } else { raw >> 24 }
}

/// No-op test stub.
#[cfg(test)]
pub fn lapic_id() -> u32
{
    0
}

/// Issue one ICR command targeting hardware APIC ID `dest`.
///
/// xAPIC mode writes `ICR_HIGH` (destination) then `ICR_LOW` (command); x2APIC
/// mode writes the single 64-bit `IA32_X2APIC_ICR` MSR with the full 32-bit
/// destination in the high dword. Callers serialise with [`wait_icr_idle`]
/// (a no-op in x2APIC, which has no delivery-status bit).
///
/// # Safety
/// Ring 0; `dest` must be a valid APIC ID and `cmd` a valid ICR command word.
#[cfg(not(test))]
unsafe fn apic_send_icr(dest: u32, cmd: u32)
{
    if x2apic_enabled()
    {
        // SAFETY: IA32_X2APIC_ICR is writable in x2APIC mode; ring 0.
        unsafe { cpu::write_msr(IA32_X2APIC_ICR, (u64::from(dest) << 32) | u64::from(cmd)) };
        return;
    }
    // SAFETY: APIC MMIO is valid; ICR_HIGH takes the destination in bits [31:24].
    unsafe {
        apic_write(APIC_ICR_HIGH, dest << 24);
        apic_write(APIC_ICR_LOW, cmd);
    }
}

/// Spin until the ICR delivery status bit clears (IPI accepted by hardware).
///
/// The bit clears within microseconds on a healthy LAPIC; 1M iterations
/// is far beyond any architectural timing. Exhaustion indicates a
/// hardware-level fault (stuck APIC, emulator bug) rather than a
/// schedulable race, so we fatal rather than return a status no caller
/// could act on. x2APIC has no delivery-status bit (the ICR
/// MSR write is not pipelined), so the wait is skipped in that mode.
#[cfg(not(test))]
unsafe fn wait_icr_idle()
{
    if x2apic_enabled()
    {
        return;
    }
    let mut n = 0u64;
    while apic_read(APIC_ICR_LOW) & ICR_PENDING != 0
    {
        core::hint::spin_loop();
        n += 1;
        if n >= 1_000_000
        {
            crate::fatal("wait_icr_idle: APIC ICR delivery-status stuck after 1M iters");
        }
    }
}

/// Send an INIT IPI to the AP identified by `target_apic_id`.
///
/// Follows the Intel SDM sequence: assert INIT, wait for delivery, then
/// de-assert INIT.
#[cfg(not(test))]
unsafe fn send_init_ipi(target_apic_id: u32)
{
    // SAFETY: ICR writes follow the Intel SDM INIT assert/de-assert sequence.
    unsafe {
        apic_send_icr(target_apic_id, ICR_INIT_ASSERT);
        wait_icr_idle();
        apic_send_icr(target_apic_id, ICR_INIT_DEASSERT);
        wait_icr_idle();
    }
}

/// Send a STARTUP IPI (SIPI) to the AP identified by `target_apic_id`.
///
/// `vector` is the SIPI vector byte: the AP starts executing at physical
/// address `vector << 12`. Must be < 256 (< 1 MiB physical address).
#[cfg(not(test))]
unsafe fn send_sipi(target_apic_id: u32, vector: u8)
{
    // SAFETY: ICR SIPI write follows the Intel SDM STARTUP sequence.
    unsafe {
        apic_send_icr(target_apic_id, ICR_SIPI_BASE | vector as u32);
        wait_icr_idle();
    }
}

/// Send a TLB shootdown IPI to a target CPU.
///
/// # Safety
/// - `target_apic_id` must be a valid APIC ID of an online CPU
/// - Caller must ensure the TLB shootdown protocol state is set up correctly
// Used by TLB shootdown implementation.
#[allow(dead_code)]
#[cfg(not(test))]
pub unsafe fn send_tlb_shootdown_ipi(target_apic_id: u32)
{
    // Wait for previous IPI to complete before sending a new one.
    // SAFETY: wait_icr_idle polls ICR_LOW until delivery status clears.
    unsafe { wait_icr_idle() };

    // SAFETY: fixed delivery mode (0), vector 250, level=0, trigger=edge.
    unsafe {
        apic_send_icr(target_apic_id, u32::from(IPI_VECTOR_TLB_SHOOTDOWN));
    }
}

/// Send a wakeup IPI to a target CPU.
///
/// Used to break an idle CPU out of `hlt` when work is enqueued on its run queue.
/// The handler itself just sends EOI; the interrupt breaks the halt state.
///
/// # Safety
/// `target_apic_id` must be a valid APIC ID of an online CPU.
#[cfg(not(test))]
pub unsafe fn send_wakeup_ipi(target_apic_id: u32)
{
    // Wait for previous IPI to complete before sending a new one.
    // SAFETY: wait_icr_idle polls ICR_LOW until delivery status clears.
    unsafe { wait_icr_idle() };

    // SAFETY: fixed delivery mode (0), vector 251, level=0, trigger=edge.
    unsafe {
        apic_send_icr(target_apic_id, u32::from(IPI_VECTOR_WAKEUP));
    }
}

/// Send an NMI (vector 2) to a target CPU. Used by the synchronous-IPI
/// watchdog at Phase C to coax a backtrace dump from a CPU that has not
/// acknowledged a sync IPI. The receiver's vector-2 handler consults
/// the per-CPU `nmi_backtrace_request` flag to distinguish a watchdog ping
/// from a real hardware NMI.
///
/// # Safety
/// `target_apic_id` must be a valid APIC ID of an online CPU.
#[cfg(not(test))]
pub unsafe fn send_nmi_to(target_apic_id: u32)
{
    // SAFETY: wait_icr_idle polls ICR_LOW until delivery status clears.
    unsafe { wait_icr_idle() };
    // SAFETY: ICR_NMI encodes delivery_mode=NMI (4), level=assert, trigger=edge.
    unsafe {
        apic_send_icr(target_apic_id, ICR_NMI);
    }
}

// ── Synchronous-IPI watchdog ──────────────────────────────────────────────────

/// Context passed to [`wait_for_ack`] by every synchronous IPI sender.
///
/// `op_name` and `target_cpu` are diagnostic-only (printed in the
/// watchdog dump and panic message). `resend` is called once at Phase B
/// to re-emit the IPI to whichever targets are still unacked; for a
/// broadcast operation like TLB shootdown the closure should fan out to
/// every CPU whose acknowledgement bit is still set, not the full
/// original mask.
pub struct IpiWaitCtx<'a>
{
    pub op_name: &'static str,
    pub target_cpu: usize,
    pub resend: &'a dyn Fn(),
}

/// TSC-bounded synchronous-IPI ack wait with re-send and NMI-backtrace
/// escalation. Phases (wall-clock via `timer::elapsed_us`):
/// - **A** (0 → ~250 ms): spin while `cond()` reports unacked.
/// - **B** (250 ms → ~750 ms): at the boundary, call `ctx.resend()` once,
///   then continue spinning. Recovers from a dropped IPI under
///   emulators with non-deterministic LAPIC delivery.
/// - **C** (750 ms → ~5 s): at the boundary, set
///   the `nmi_backtrace_request` flag for `ctx.target_cpu` and send a vector-2
///   NMI to that CPU. The receiver's handler dumps its
///   `TrapFrame` to serial so a subsequent panic is diagnosable.
/// - **D** (>5 s): print the context and fatal.
///
/// # Safety
/// Must be called at ring 0 with preemption disabled and `IF=1` — the
/// same envelope `mm::tlb_shootdown::shootdown` establishes. The caller
/// is responsible for the surrounding interrupt-state save / restore.
///
/// `cond` MUST be free of side effects beyond the atomic loads needed
/// to inspect the pending state; it is invoked many times per spin.
#[cfg(not(test))]
pub unsafe fn wait_for_ack(mut cond: impl FnMut() -> bool, ctx: &IpiWaitCtx<'_>)
{
    let start = super::timer::elapsed_us().unwrap_or(0);
    let mut resent = false;
    let mut nmi_sent = false;
    loop
    {
        if cond()
        {
            return;
        }
        core::hint::spin_loop();
        let Some(now) = super::timer::elapsed_us()
        else
        {
            continue;
        };
        let elapsed_ms = now.saturating_sub(start) / 1_000;
        if elapsed_ms >= 5_000
        {
            crate::kprintln!(
                "IPI WATCHDOG: target_cpu={} op={} elapsed_ms={} — never acked",
                ctx.target_cpu,
                ctx.op_name,
                elapsed_ms
            );
            crate::fatal("ipi: target CPU never acked");
        }
        if !nmi_sent && elapsed_ms >= 750
        {
            if let Some(flag) = nmi_backtrace_request(ctx.target_cpu)
            {
                flag.store(true, core::sync::atomic::Ordering::Release);
                // SAFETY: target_cpu is an online CPU index; apic_id_for is
                // read-only after init.
                let apic_id = unsafe { crate::percpu::apic_id_for(ctx.target_cpu) };
                // SAFETY: apic_id is a valid hardware LAPIC ID for an online CPU.
                unsafe {
                    send_nmi_to(apic_id);
                }
            }
            nmi_sent = true;
        }
        if !resent && elapsed_ms >= 250
        {
            (ctx.resend)();
            resent = true;
        }
    }
}

/// Start an AP using the INIT + 2×SIPI sequence (Intel SDM Vol. 3A §8.4.4.1).
///
/// Waits ~10 ms after INIT and ~200 µs after each SIPI.
/// `target_apic_id`: hardware LAPIC ID of the target AP.
/// `trampoline_phys`: 4 KiB-aligned physical address < 1 MiB of the AP trampoline.
///
/// # Safety
/// Must be called from the BSP with the IDT loaded and the APIC timer calibrated
/// (so `timer::delay_us` works). The trampoline page must have been set up via
/// `ap_trampoline::setup_trampoline` and `setup_ap_params`.
#[cfg(not(test))]
pub unsafe fn start_ap(target_apic_id: u32, trampoline_phys: u64)
{
    let vector = (trampoline_phys >> 12) as u8;
    // SAFETY: caller guarantees APIC is initialized, trampoline set up, and timer calibrated; INIT+SIPI sequence follows Intel SDM.
    unsafe {
        send_init_ipi(target_apic_id);
        super::timer::delay_us(10_000); // 10 ms after INIT (Intel SDM §8.4.4.1)
        send_sipi(target_apic_id, vector);
        super::timer::delay_us(200); // 200 µs after first SIPI
        send_sipi(target_apic_id, vector); // second SIPI per Intel spec
        super::timer::delay_us(200);
    }
}

/// Initialise the local APIC for an AP.
///
/// Software-enables the LAPIC and masks all LVT entries.
/// Call before `timer::init_ap` so the APIC is active before the timer starts.
///
/// # Safety
/// Ring 0. AP must have loaded its GDT and IDT before calling.
#[cfg(not(test))]
pub unsafe fn init_ap()
{
    // Per-CPU CR4/CR0/XCR0 setup. The AP trampoline only sets CR4.PAE; SMEP,
    // SMAP, OSXSAVE, and TS are per-CPU state that must be re-established on
    // each hart.
    // SAFETY: ring-0 AP boot; IDT loaded by caller (kernel_entry_ap); CPUID
    // gates each enable so a missing feature halts cleanly.
    unsafe {
        cpu::enable_smep_smap();
        fpu::enable_xsave();
        fpu::cr0_set_ts();
    }

    // Mirror the BSP's APIC mode: EXTD is per-CPU MSR state that must be set on
    // each CPU before any APIC register access. The mode is decided once on
    // the BSP in `init`.
    // SAFETY: ring-0 AP boot; only writes EXTD when the BSP chose x2APIC.
    unsafe {
        if x2apic_enabled()
        {
            enable_x2apic_this_cpu();
        }
    }

    // SAFETY: AP has loaded GDT/IDT; direct map / x2APIC MSRs active; SVR and LVT writes are architecture-defined.
    unsafe {
        apic_write(APIC_SVR, apic_read(APIC_SVR) | 0x100 | 0xFF);
        apic_write(APIC_LVT_TIMER, LVT_MASK);
        apic_write(APIC_LVT_LINT0, LVT_MASK);
        apic_write(APIC_LVT_LINT1, LVT_MASK);
        apic_write(APIC_LVT_ERROR, LVT_MASK);
        apic_write(APIC_LVT_THERMAL, LVT_MASK);
        apic_write(APIC_LVT_PERF, LVT_MASK);
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn init_ap() {}

/// Disable interrupts and return the previous IF state.
///
/// Returns `true` if interrupts were enabled before the call.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn disable() -> bool
{
    let rflags: u64;
    // SAFETY: pushfq/cli are always safe at ring 0; disables interrupts via x86 primitives.
    // `nostack` is intentionally absent: `pushfq` writes 8 bytes below RSP.
    // See `cpu::save_and_disable_interrupts` for the full rationale.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) rflags,
        );
    }
    rflags & (1 << 9) != 0 // IF is bit 9
}

/// Enable interrupts.
///
/// # Safety
/// IDT must be loaded before calling this function.
pub unsafe fn enable()
{
    // SAFETY: caller guarantees IDT is valid.
    unsafe {
        core::arch::asm!("sti", options(nostack, nomem));
    }
}

/// Return `true` if the interrupt flag (IF) is set in RFLAGS.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn are_enabled() -> bool
{
    let rflags: u64;
    // SAFETY: pushfq is always safe at ring 0; reads RFLAGS non-destructively.
    // `nostack` is intentionally absent: `pushfq` writes 8 bytes below RSP.
    // See `cpu::save_and_disable_interrupts` for the full rationale.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
        );
    }
    rflags & (1 << 9) != 0
}

/// Send the end-of-interrupt notification to the local APIC.
///
/// Must be called from within an interrupt handler before returning.
/// `_irq` is ignored (the local-APIC EOI register is level-independent).
#[cfg(not(test))]
pub fn acknowledge(_irq: u32)
{
    // SAFETY: direct map is active; APIC EOI write is always safe.
    unsafe {
        apic_write(APIC_EOI, 0);
    }
}

/// No-op test stub.
#[cfg(test)]
pub fn acknowledge(_irq: u32) {}

/// Mask (disable delivery of) GSI `irq` at the I/O APIC.
///
/// # Safety
/// Must be called after Phase 5 init (IOAPIC initialised).
#[cfg(not(test))]
pub fn mask(irq: u32)
{
    // SAFETY: IOAPIC is initialised in Phase 5 before any device IRQs fire.
    unsafe { super::ioapic::mask(irq) }
}

/// No-op test stub.
#[cfg(test)]
pub fn mask(_irq: u32) {}

/// Unmask (enable delivery of) GSI `irq` at the I/O APIC.
///
/// Call after `SYS_IRQ_REGISTER` routes the GSI and after `SYS_IRQ_ACK`
/// re-enables delivery following interrupt handling.
///
/// # Safety
/// Must be called after Phase 5 init and after the GSI has been routed
/// via [`ioapic::route`].
#[cfg(not(test))]
pub fn unmask(irq: u32)
{
    // SAFETY: IOAPIC is initialised in Phase 5.
    unsafe { super::ioapic::unmask(irq) }
}

/// No-op test stub.
#[cfg(test)]
pub fn unmask(_irq: u32) {}

/// Route device IRQ (GSI) `irq` to the BSP's local APIC, leaving the line
/// masked at the I/O APIC. The driver unmasks via `SYS_IRQ_ACK` once it has
/// registered a handler.
///
/// # Safety
/// Must be called after Phase 5 init (IOAPIC initialised) with a valid GSI.
// cast_possible_truncation: device GSIs are < 256, so the u32→u8 narrowing of
// the vector offset is exact.
#[allow(clippy::cast_possible_truncation)]
#[cfg(not(test))]
pub unsafe fn route_device_irq(irq: u32)
{
    // SAFETY: caller guarantees a valid GSI and post-Phase-5 IOAPIC. route()
    // installs the redirection entry masked; the driver unmasks via SYS_IRQ_ACK.
    unsafe {
        super::ioapic::route(irq, super::ioapic::DEVICE_VECTOR_BASE + irq as u8);
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn route_device_irq(_irq: u32) {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn apic_svr_offset()
    {
        assert_eq!(APIC_SVR, 0xF0);
    }

    #[test]
    fn apic_eoi_offset()
    {
        assert_eq!(APIC_EOI, 0xB0);
    }

    #[test]
    fn lvt_mask_bit()
    {
        assert_eq!(LVT_MASK, 1 << 16);
    }
}
