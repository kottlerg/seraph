// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/interrupts.rs

//! x86-64 interrupt controller (xAPIC) and Phase 5 interrupt initialisation.
//!
//! Orchestrates GDT, IDT, SMEP/SMAP, and the local APIC in the correct order:
//!
//! 1. Enable SMEP + SMAP (fatal if CPU lacks support).
//! 2. Allocate IST stacks (2 × 8 KiB) from the heap via `Box::leak`.
//! 3. Load GDT + TSS with the IST stack pointers.
//! 4. Load IDT.
//! 5. Software-enable the local APIC: set SVR bit 8, spurious vector 255.
//! 6. Mask all LVT entries.
//!
//! Interrupts are **not** enabled here; `timer::init()` enables them after the
//! APIC timer is calibrated and configured.
//!
//! # xAPIC layout
//! The local APIC is accessed at physical address `0xFEE0_0000`, which is
//! accessible via the kernel's direct physical map at `DIRECT_MAP_BASE + phys`.
//!
//! # Modification notes
//! - To handle a new device IRQ: call `register_handler(vec, handler)` and
//!   call `unmask(vec)`. Full routing is deferred to a later phase.
//! - To migrate to x2APIC: replace `apic_read`/`apic_write` with MSR accesses
//!   (`IA32_X2APIC_`*) and update the SVR/LVT offsets.

// cast_possible_truncation: u64→usize/u8 APIC address arithmetic; bounded by APIC layout.
// cast_lossless: u8→u32 vector casts are always widening.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
use alloc::boxed::Box;
#[cfg(not(test))]
use alloc::vec;

#[cfg(not(test))]
use super::{cpu, gdt, idt};
#[cfg(not(test))]
use crate::mm::paging::DIRECT_MAP_BASE;

// ── xAPIC constants ───────────────────────────────────────────────────────────

/// Physical base of the memory-mapped local APIC registers.
const APIC_BASE_PHYS: u64 = 0xFEE0_0000;

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

// ── APIC register access ──────────────────────────────────────────────────────

/// Write `val` to APIC register at `offset` bytes from the APIC base.
///
/// # Safety
/// Must only be called after Phase 3 (direct map active) and with a valid
/// APIC register offset.
#[cfg(not(test))]
unsafe fn apic_write(offset: usize, val: u32)
{
    let vaddr = (DIRECT_MAP_BASE + APIC_BASE_PHYS) as usize + offset;
    // SAFETY: vaddr is within the direct-mapped APIC MMIO region.
    unsafe {
        core::ptr::write_volatile(vaddr as *mut u32, val);
    }
}

/// Read an APIC register at `offset` bytes from the APIC base.
#[cfg(not(test))]
fn apic_read(offset: usize) -> u32
{
    let vaddr = (DIRECT_MAP_BASE + APIC_BASE_PHYS) as usize + offset;
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

    // 2. Allocate IST stacks from the heap.
    // 8 KiB each, leaked so they live for the rest of kernel execution.
    let ist1_stack = Box::leak(vec![0u8; IST_STACK_SIZE].into_boxed_slice());
    let ist2_stack = Box::leak(vec![0u8; IST_STACK_SIZE].into_boxed_slice());
    let ist1_top = ist1_stack.as_ptr() as u64 + IST_STACK_SIZE as u64;
    let ist2_top = ist2_stack.as_ptr() as u64 + IST_STACK_SIZE as u64;

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

    // 5. Software-enable the local APIC.
    // Set SVR bit 8 (APIC Software Enable) and program spurious vector 255.
    // SAFETY: direct map is active; APIC MMIO base is valid kernel mapping; SVR write is architecture-defined.
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
    // SAFETY: direct map is active; IOAPIC MMIO region is in MMIO_DIRECT_MAP_REGIONS.
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
/// ICR value for INIT de-assert (clears INIT signal).
const ICR_INIT_DEASSERT: u32 = 0x0000_8500;
/// ICR base value for STARTUP IPI: delivery=STARTUP, vector in bits[7:0].
const ICR_SIPI_BASE: u32 = 0x0000_4600;
/// IPI vector for TLB shootdown requests.
pub const IPI_VECTOR_TLB_SHOOTDOWN: u8 = 250;
/// IPI vector for waking idle CPUs.
pub const IPI_VECTOR_WAKEUP: u8 = 251;

/// Read this CPU's local APIC ID (bits [31:24] of the APIC ID register).
#[allow(dead_code)] // Part of the arch interface; will be used by future SMP topology code.
#[cfg(not(test))]
pub fn lapic_id() -> u32
{
    apic_read(APIC_ID) >> 24
}

/// No-op test stub.
#[cfg(test)]
pub fn lapic_id() -> u32
{
    0
}

/// Spin until the ICR delivery status bit clears (IPI accepted by hardware).
/// Returns false if it times out (bit still set after ~1M iterations).
#[cfg(not(test))]
unsafe fn wait_icr_idle() -> bool
{
    let mut n = 0u64;
    while apic_read(APIC_ICR_LOW) & ICR_PENDING != 0
    {
        core::hint::spin_loop();
        n += 1;
        if n >= 1_000_000
        {
            return false;
        }
    }
    true
}

/// Send an INIT IPI to the AP identified by `target_apic_id`.
///
/// Follows the Intel SDM sequence: assert INIT, wait for delivery, then
/// de-assert INIT.
#[cfg(not(test))]
unsafe fn send_init_ipi(target_apic_id: u32)
{
    // SAFETY: Local APIC MMIO base is valid kernel mapping; ICR writes follow Intel SDM INIT sequence.
    unsafe {
        apic_write(APIC_ICR_HIGH, target_apic_id << 24);
        apic_write(APIC_ICR_LOW, ICR_INIT_ASSERT);
        wait_icr_idle();
        apic_write(APIC_ICR_HIGH, target_apic_id << 24);
        apic_write(APIC_ICR_LOW, ICR_INIT_DEASSERT);
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
    // SAFETY: Local APIC MMIO base is valid kernel mapping; ICR SIPI write follows Intel SDM STARTUP sequence.
    unsafe {
        apic_write(APIC_ICR_HIGH, target_apic_id << 24);
        apic_write(APIC_ICR_LOW, ICR_SIPI_BASE | vector as u32);
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

    // SAFETY: APIC MMIO region is valid; ICR_HIGH takes destination in bits [31:24].
    unsafe {
        apic_write(APIC_ICR_HIGH, target_apic_id << 24);
    }

    // SAFETY: Delivery mode 0 (fixed), vector 250, level=0, trigger=edge.
    unsafe {
        apic_write(APIC_ICR_LOW, u32::from(IPI_VECTOR_TLB_SHOOTDOWN));
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

    // SAFETY: APIC MMIO region is valid; ICR_HIGH takes destination in bits [31:24].
    unsafe {
        apic_write(APIC_ICR_HIGH, target_apic_id << 24);
    }

    // SAFETY: Fixed delivery mode (0), vector 251, level=0, trigger=edge.
    unsafe {
        apic_write(APIC_ICR_LOW, u32::from(IPI_VECTOR_WAKEUP));
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
    // SAFETY: AP has loaded GDT/IDT; Local APIC MMIO base is valid kernel mapping; SVR and LVT writes are architecture-defined.
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
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) rflags,
            options(nostack),
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
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nostack),
        );
    }
    rflags & (1 << 9) != 0
}

/// Send the end-of-interrupt signal to the local APIC.
///
/// Must be called from within an interrupt handler before returning.
/// `_irq` is ignored for xAPIC (EOI register is level-independent).
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn apic_base_phys_constant()
    {
        // Ensure the constant matches the xAPIC fixed address.
        assert_eq!(APIC_BASE_PHYS, 0xFEE0_0000);
    }

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
