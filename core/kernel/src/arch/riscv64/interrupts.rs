// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/interrupts.rs

//! RISC-V trap handling and PLIC initialisation.
//!
//! Sets up the supervisor-mode trap infrastructure:
//! 1. Installs `trap_entry` in `stvec` (direct mode).
//! 2. Clears `sstatus.SIE`, `sstatus.SPP`, `sstatus.SUM` for a clean initial state.
//! 3. Enables `sie.SSIP` (IPIs), `sie.STIP` (timer), and `sie.SEIP` (external) bits.
//! 4. Initialises the PLIC: sets all source priorities to 1 and the boot hart's
//!    S-mode threshold to 0 (accept all above-threshold interrupts).
//!
//! The trap vector dispatches:
//! - Software interrupt (scause = 1 | MSB) → `handle_software_interrupt` (TLB shootdown /
//!   wakeup)
//! - Timer interrupt (scause = 5 | MSB) → `timer::handle_tick()`
//! - External interrupt (scause = 9 | MSB) → PLIC claim → `dispatch_external` (completes
//!   via `acknowledge`)
//! - U-mode illegal instruction on an F/D/V opcode (scause = 2) → lazy FP/V restore
//! - U-mode ecall (scause = 8) → `crate::syscall::dispatch`
//! - Other U-mode exceptions → spurious-TLB retry, the bound fault handler, or thread
//!   termination
//! - Other S-mode exceptions → `copy_user` fixup, else diagnostics + `fatal()`
//!
//! # PLIC layout
//! Base physical address is supplied by the bootloader through
//! `BootInfo.kernel_mmio.plic_base` (see [`super::platform::plic_base`]) and
//! accessed via the direct map. Register offsets follow the RISC-V PLIC spec:
//! - Priority registers: base + 4*source (sources `1..=platform::plic_ndev()`).
//! - Enable registers:  base + 0x2000 + 0x80*context + 4*word.
//! - Threshold:         base + `0x20_0000` + 0x1000*context.
//! - Claim/Complete:    the threshold register + 4.
//!
//! A hart's S-mode context is taken to be `hart*2 + 1`, numbered by the hardware
//! hart id (`percpu::apic_id_for`), never by the kernel's logical CPU index: the
//! boot hart need not be hart 0, and the two numberings differ wherever firmware
//! enumerates harts sparsely. The PLIC specification leaves the context-to-hart
//! mapping to the platform (a device tree states it in the PLIC's
//! `interrupts-extended`); `hart*2 + 1` is the layout of the platforms the kernel
//! targets (QEMU `virt` and SiFive-style PLICs), an assumption the kernel does
//! not read from firmware. `init` and `init_ap` halt the boot when a hart's
//! context registers would fall outside the PLIC window
//! (`super::platform::plic_size`).
//!
//! # Routing
//! Each routed source is enabled on one hart's S-mode context, its target, chosen at
//! route time ([`route_device_irq`], through `irq::next_target_cpu`): the harts in turn,
//! so device interrupts spread over the harts. One context per source avoids the PLIC
//! thundering herd, in which every enabled hart traps and all but one lose the claim.
//! The target is recorded per source (`SOURCE_TARGET`), so mask and unmask act on that
//! context, and the claim and complete run on the hart that took the trap.
//!
//! # Locking
//! [`plic_enable`] and [`plic_disable`] read-modify-write a 32-source enable word of
//! the source's target context, and [`acknowledge`] one of the claiming hart's own
//! context around its completion; all run on any hart (`SYS_IRQ_ACK`, the device-IRQ
//! dispatch in interrupt context, and the route changes `irq` makes), so each holds
//! `PLIC_LOCK`, a leaf lock taken with interrupts disabled, across its read and write;
//! otherwise two updates to sources sharing a word could lose one. `SOURCE_TARGET` is
//! written only by the route changes, which `irq` serialises under its routing lock.
//! [`init`] and [`init_ap`] write only the boot hart's or their own hart's context
//! before any IRQ is routed and take no lock; the claim register is per-context and
//! needs none.
//!
//! # Modification notes
//! - Device IRQs need no per-device code here: `route_device_irq` picks the source's
//!   target and leaves it masked, and `dispatch_external` forwards every claimed source
//!   to `crate::irq::dispatch_device_irq`.

use super::trap_frame::TrapFrame;
use crate::mm::paging::phys_to_virt;

// ── PLIC constants ────────────────────────────────────────────────────────────

/// PLIC priority register base: base + 4 * `source_id` (source 1..=`plic_ndev`).
const PLIC_PRIORITY_BASE: u64 = 0x0000;

/// PLIC S-mode context of the hart with hardware id `hart`.
///
/// Assumes the context layout of the targeted platforms (QEMU `virt`,
/// SiFive-style PLICs): M-mode = `hart*2`, S-mode = `hart*2+1`. The PLIC
/// specification leaves the mapping to the platform (module doc).
const fn plic_s_context(hart: u32) -> u64
{
    hart as u64 * 2 + 1
}

/// PLIC S-mode enable-bits base for the hart with hardware id `hart`:
/// 0x2000 + context * 0x80.
const fn plic_enable_base_for(hart: u32) -> u64
{
    0x2000 + plic_s_context(hart) * 0x80
}

/// PLIC S-mode threshold register offset for the hart with hardware id `hart`:
/// `0x20_0000 + context * 0x1000`. The claim/complete register follows at +4.
const fn plic_threshold_offset_for(hart: u32) -> u64
{
    0x0020_0000 + plic_s_context(hart) * 0x1000
}

/// Target hart of each PLIC source, plus one; 0 for an unrouted source, so the zeroed
/// table routes none. Indexed by source id over the specification's id space. Written
/// only by [`route_device_irq`] and [`unroute_device_irq`], which `irq` serialises under
/// its routing lock; read by [`plic_enable`] and [`plic_disable`].
#[cfg(not(test))]
static SOURCE_TARGET: [core::sync::atomic::AtomicU32; PLIC_MAX_SOURCES as usize + 1] =
    [const { core::sync::atomic::AtomicU32::new(0) }; PLIC_MAX_SOURCES as usize + 1];

/// Serialises the enable-word read-modify-writes of [`plic_enable`], [`plic_disable`]
/// and [`acknowledge`] (see the module doc's § Locking). A leaf lock: nothing is acquired
/// while it is held.
#[cfg(not(test))]
static PLIC_LOCK: crate::sync::Spinlock = crate::sync::Spinlock::new();

/// The hart id `source` is routed to, or `None` when it is unrouted (or out of range).
#[cfg(not(test))]
fn source_target(source: u32) -> Option<u32>
{
    SOURCE_TARGET
        .get(source as usize)?
        .load(core::sync::atomic::Ordering::Relaxed)
        .checked_sub(1)
}

/// Hardware hart id of the executing hart.
#[cfg(not(test))]
fn current_hart() -> u32
{
    let cpu = super::cpu::current_cpu() as usize;
    // SAFETY: `current_cpu()` is this hart's logical index, below `CPU_COUNT`;
    // `percpu::init_apic_ids` runs before Phase 5 (`kernel_entry`), ahead of every
    // caller (`init_ap` and the external-interrupt claim and complete).
    unsafe { crate::percpu::apic_id_for(cpu) }
}

/// Host-test stub: no hart identity exists off-target.
#[cfg(test)]
fn current_hart() -> u32
{
    0
}

/// Whether the S-mode context registers of the hart with hardware id `hart`
/// (its enable words and its threshold and claim/complete pair) lie inside the
/// PLIC window of `window` bytes.
///
/// Hart ids come from firmware and can be sparse or large; a context past the
/// window would turn a `plic_write` into a store to arbitrary physical memory
/// through the direct map.
const fn plic_context_in_window(hart: u32, window: u64) -> bool
{
    // With the standard register map the claim register always ends past the
    // enable words, so the enable-word test is defensive: it keeps the bound
    // correct should the enable span ever grow past the context block.
    let enable_end = plic_enable_base_for(hart) + enable_words(PLIC_MAX_SOURCES) as u64 * 4;
    let claim_end = plic_threshold_offset_for(hart) + 8;
    enable_end <= window && claim_end <= window
}

/// Halt the boot unless hart `hart`'s PLIC context lies inside the PLIC window.
#[cfg(not(test))]
fn require_plic_context(hart: u32)
{
    if !plic_context_in_window(hart, super::platform::plic_size())
    {
        crate::fatal("riscv64: a hart's PLIC S-mode context lies outside the PLIC window");
    }
}

/// PLIC claim/complete register offset for the executing hart's S-mode context.
fn plic_claim_complete_offset() -> u64
{
    plic_threshold_offset_for(current_hart()) + 4
}

/// Largest PLIC source id the RISC-V PLIC specification allows (sources 1..=1023;
/// source 0 is reserved).
pub const PLIC_MAX_SOURCES: u32 = 1023;

/// Number of 32-bit enable words a context needs for sources `0..=ndev`.
const fn enable_words(ndev: u32) -> u32
{
    (ndev + 1).div_ceil(32)
}

// ── PLIC access helpers ───────────────────────────────────────────────────────

fn plic_read(offset: u64) -> u32
{
    let vaddr = phys_to_virt(super::platform::plic_base() + offset);
    // SAFETY: PLIC base mapped via direct map; offset within PLIC MMIO range;
    // volatile read ensures ordering and prevents compiler reordering.
    unsafe { core::ptr::read_volatile(vaddr as *const u32) }
}

/// Write `val` to the PLIC register at `offset`, then order it before later MMIO stores.
///
/// # Safety
/// The direct physical map must be active and `offset` must lie inside the PLIC register
/// window.
unsafe fn plic_write(offset: u64, val: u32)
{
    let vaddr = phys_to_virt(super::platform::plic_base() + offset);
    // SAFETY: PLIC base mapped via direct map; offset within PLIC MMIO range;
    // volatile write ensures the access is not elided or reordered by the
    // compiler.
    unsafe { core::ptr::write_volatile(vaddr as *mut u32, val) };
    // RVWMO allows I/O-region writes to be reordered; a sequence of per-hart
    // enable-bit writes must be observed by the PLIC in program order, so we
    // emit an MMIO→MMIO fence after every store.
    mmio::mmio_to_mmio_barrier();
}

// ── Trap vector ───────────────────────────────────────────────────────────────

/// Naked trap entry point installed in `stvec`.
///
/// Handles traps from both U-mode (ecall, page faults) and S-mode (timer,
/// external interrupts). Saves all GPRs and CSRs to a [`TrapFrame`], calls
/// `trap_dispatch`, then restores and executes `sret`.
///
/// ## Stack switching invariant
///
/// `sscratch` encodes the trap source:
/// - S-mode: `sscratch = 0`
/// - U-mode: `sscratch = &PER_CPU[cpu]` (this hart's `PerCpuData`)
///
/// On U-mode trap entry the handler swaps `t0` with `sscratch` (`csrrw t0, sscratch, t0`),
/// installs the per-CPU pointer in `tp`, loads the kernel stack top from
/// `PerCpuData::kernel_rsp` (written by `cpu::set_kernel_trap_stack`), and switches to it
/// before building the [`TrapFrame`]. On a return to U-mode, `sscratch` is re-armed with
/// `tp` (`&PER_CPU`) before `sret`.
///
/// `context::return_to_user` arms `sscratch` the same way before the first `sret` to U-mode.
///
/// # Safety
/// Installed only in `stvec` by `install_trap_vector`; never called from Rust. Requires
/// `sscratch = 0` while in S-mode and `&PER_CPU` while in U-mode, `tp = &PER_CPU` in
/// S-mode, and `PerCpuData::kernel_rsp` set to the running thread's kernel stack top
/// before any return to U-mode.
// too_many_lines: trap_entry is a single naked-asm block; the register
// save/restore sequence cannot be meaningfully split.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn trap_entry()
{
    // Frame layout: 35 × 8 = 280 bytes (size asserted in `trap_frame::tests`).
    // Offsets: x1=0, x2=8, x3=16, x4=24, x5=32, …, x31=240,
    //          sepc=248, scause=256, stval=264, sstatus=272.
    //
    // sscratch convention:
    //   S-mode: sscratch = 0   (trap from S-mode, stack is already the kernel stack)
    //   U-mode: sscratch = &PER_CPU[cpu_id]   (tp value, always non-zero)
    //
    // tp (x4) convention: always = &PER_CPU[cpu_id] in S-mode.
    //   On U-mode entry the trap handler restores tp from sscratch and saves
    //   the user's tp to TrapFrame[tp] via PerCpuData::scratch.
    //   On U-mode return tp is overwritten with the user TLS value from the
    //   TrapFrame; sscratch is set to &PER_CPU before that restore so the
    //   next trap can recover tp.
    core::arch::naked_asm!(
        // ── Determine source privilege ──────────────────────────────────────────
        // Atomically swap t0 (x5) with sscratch:
        //   t0       = old sscratch (&PER_CPU if from U-mode, 0 if from S-mode)
        //   sscratch = old t0 (saved here temporarily)
        "csrrw t0, sscratch, t0",
        "bnez t0, 1f",              // t0 != 0 → came from U-mode

        // ── S-mode path ─────────────────────────────────────────────────────────
        // t0 = 0; sscratch = old_t0; sp = kernel_sp (already correct)
        // Restore t0: swap back so t0 = old_t0, sscratch = 0.
        "csrrw t0, sscratch, t0",
        // Allocate TrapFrame on the kernel stack.
        "addi sp, sp, -280",
        // Save t0 (x5) before reusing x5 as a temporary.
        "sd x5, 32(sp)",
        // Record original sp (= current sp + 280, the pre-allocation value).
        "addi x5, sp, 280",
        "sd x5, 8(sp)",
        // tp (x4) = &PER_CPU in S-mode; save it to the frame before common path.
        "sd x4, 24(sp)",
        "j 2f",

        // ── U-mode path ─────────────────────────────────────────────────────────
        // t0 (x5) = &PER_CPU; sscratch = old t0 (user's t0); sp = user_sp
        // x4 (tp) = user's tp (we must save it and replace with &PER_CPU)
        "1:",
        // Temporarily park user's tp in PerCpuData::scratch (offset 24 from t0).
        // t0 = &PER_CPU, x4 = user_tp at this point.
        "sd x4, 24(t0)",            // PerCpuData.scratch = user_tp (temporary)
        // Install kernel per-CPU pointer into tp.
        "mv x4, t0",                // tp = &PER_CPU (t0 is x5, x4 is tp)
        // Load kernel stack top from PerCpuData::kernel_rsp (offset 8 from tp).
        "ld t0, 8(x4)",             // t0 = kernel_stack_top
        // Allocate TrapFrame at the top of the kernel stack.
        "addi t0, t0, -280",        // t0 = TrapFrame base
        // Save user sp (x2) into the frame before overwriting sp.
        "sd x2, 8(t0)",
        // Switch to kernel stack.
        "mv sp, t0",                // sp = TrapFrame base
        // Retrieve user's t0 from sscratch; clear sscratch (now in S-mode).
        "csrrw t0, sscratch, x0",   // t0 = user_t0, sscratch = 0
        "sd t0, 32(sp)",            // frame.t0 = user t0
        // Retrieve user's tp from PerCpuData::scratch and save to the frame.
        // x4 (tp) = &PER_CPU at this point; user_tp was parked at offset 24.
        "ld t0, 24(x4)",            // t0 = user_tp (from PerCpuData.scratch)
        "sd t0, 24(sp)",            // frame.tp = user_tp
        // tp (x4) = &PER_CPU remains — common path must NOT save x4 again.

        // ── Save remaining registers (x2, x4, x5 already saved above) ──────────
        "2:",
        "sd x1,   0(sp)",           // ra
        // x2 (sp) saved above in both paths
        "sd x3,  16(sp)",           // gp
        // x4 (tp) saved by both paths above (kernel tp or user tp)
        // x5 (t0) saved by both paths above
        "sd x6,  40(sp)",
        "sd x7,  48(sp)",
        "sd x8,  56(sp)",
        "sd x9,  64(sp)",
        "sd x10, 72(sp)",           // a0
        "sd x11, 80(sp)",
        "sd x12, 88(sp)",
        "sd x13, 96(sp)",
        "sd x14,104(sp)",
        "sd x15,112(sp)",
        "sd x16,120(sp)",
        "sd x17,128(sp)",           // a7 (syscall number)
        "sd x18,136(sp)",
        "sd x19,144(sp)",
        "sd x20,152(sp)",
        "sd x21,160(sp)",
        "sd x22,168(sp)",
        "sd x23,176(sp)",
        "sd x24,184(sp)",
        "sd x25,192(sp)",
        "sd x26,200(sp)",
        "sd x27,208(sp)",
        "sd x28,216(sp)",
        "sd x29,224(sp)",
        "sd x30,232(sp)",
        "sd x31,240(sp)",
        // Save supervisor CSRs.
        "csrr t0, sepc",
        "sd   t0, 248(sp)",
        "csrr t0, scause",
        "sd   t0, 256(sp)",
        "csrr t0, stval",
        "sd   t0, 264(sp)",
        "csrr t0, sstatus",
        "sd   t0, 272(sp)",

        // ── Dispatch ────────────────────────────────────────────────────────────
        // tp (x4) = &PER_CPU throughout dispatch (compiler treats tp as reserved).
        "mv a0, sp",
        "call {dispatch}",

        // ── Restore sepc and sstatus ────────────────────────────────────────────
        // Restore sstatus FIRST so SPP and SPIE match the saved trap context.
        // Without this, a context switch during dispatch can leave sstatus.SPP
        // from a different thread's trap, causing sret to return at the wrong
        // privilege level.
        "ld t0, 272(sp)",
        "csrw sstatus, t0",
        "ld t0, 248(sp)",
        "csrw sepc, t0",

        // ── Restore sscratch and tp (privilege-dependent) ────────────────────────
        // Check sstatus.SPP (bit 8): 0 = return to U-mode, 1 = return to S-mode.
        // Reads the sstatus restored above (the trap context's SPP), not the CSR value
        // left by dispatch.
        "csrr t0, sstatus",
        "srli t0, t0, 8",
        "andi t0, t0, 1",
        "bnez t0, 3f",

        // U-mode return: set sscratch = &PER_CPU for the next U-mode trap,
        // then restore x4 from the TrapFrame (user TLS pointer).
        "csrw sscratch, x4",
        "ld x4,  24(sp)",
        "j 4f",

        // S-mode return: do NOT restore x4 (tp). tp is kernel-reserved and
        // already holds &PER_CPU[current_cpu]. The TrapFrame's x4 is stale
        // if schedule() migrated this thread to a different CPU during the
        // trap (e.g. timer preemption during a shootdown spin loop).
        "3:",

        // ── Restore remaining registers ──────────────────────────────────────────
        // x4 (tp): handled above — restored for U-mode, preserved for S-mode.
        // x2 (sp): restored last since it changes the addressing base.
        "4:",
        "ld x1,   0(sp)",
        // x2 restored last
        "ld x3,  16(sp)",
        // x4 already handled above
        "ld x5,  32(sp)",
        "ld x6,  40(sp)",
        "ld x7,  48(sp)",
        "ld x8,  56(sp)",
        "ld x9,  64(sp)",
        "ld x10, 72(sp)",
        "ld x11, 80(sp)",
        "ld x12, 88(sp)",
        "ld x13, 96(sp)",
        "ld x14,104(sp)",
        "ld x15,112(sp)",
        "ld x16,120(sp)",
        "ld x17,128(sp)",
        "ld x18,136(sp)",
        "ld x19,144(sp)",
        "ld x20,152(sp)",
        "ld x21,160(sp)",
        "ld x22,168(sp)",
        "ld x23,176(sp)",
        "ld x24,184(sp)",
        "ld x25,192(sp)",
        "ld x26,200(sp)",
        "ld x27,208(sp)",
        "ld x28,216(sp)",
        "ld x29,224(sp)",
        "ld x30,232(sp)",
        "ld x31,240(sp)",
        "ld x2,   8(sp)",           // restore sp last (user sp or original kernel sp)
        "sret",

        dispatch = sym trap_dispatch,
    );
}

/// TLB shootdown / wakeup IPI handler.
///
/// Services any per-CPU shootdown request that names this hart (flush + ack),
/// then returns. Wakeup IPIs carry no extra work beyond the SSIP clear.
#[cfg(not(test))]
fn handle_software_interrupt()
{
    // On RISC-V, both TLB shootdown and wakeup IPIs arrive as supervisor
    // software interrupts (scause=1); a wakeup-only IPI simply finds no
    // request naming this hart below.

    // Clear SSIP *before* servicing requests. This is critical for
    // correctness: if a new IPI arrives between our scan and sret, the
    // 0→1 transition on SSIP generates a fresh interrupt after sret.
    //
    // Clearing SSIP *after* the scan is racy: a wakeup IPI sets SSIP, we
    // enter and find no request (the shootdown store hasn't happened yet),
    // then the shootdown IPI arrives (SSIP already 1, no new edge), and
    // clear_sip_ssip wipes both notifications — the shootdown is never processed.
    // The initiator's SeqCst fence orders its slot store before the IPI, so
    // any IPI whose SSIP-set precedes our clear has a slot store visible to
    // the scan; any later IPI re-triggers via a fresh SSIP edge.
    //
    // SAFETY: sip.SSIP write clears supervisor software interrupt pending.
    unsafe {
        clear_sip_ssip();
    }

    let hart_id = super::cpu::current_cpu() as usize;
    // SAFETY: IPI-handler context on hart_id in S-mode; issuing sfence.vma here
    // is valid.
    unsafe {
        crate::mm::tlb_shootdown::service_shootdowns(hart_id);
    }

    // Wakeup IPIs carry no handler work beyond the SSIP acknowledgement above; the wake's
    // correctness rests on the producer-side `RESCHEDULE_PENDING` set in `enqueue_and_wake`
    // and the idle loop's check-and-halt (core/kernel/docs/scheduling-internals.md § Wake
    // Protocol Invariants).
}

/// Clear the supervisor software interrupt pending bit (SIP.SSIP).
///
/// # Safety
/// Must be called in supervisor mode.
#[cfg(not(test))]
unsafe fn clear_sip_ssip()
{
    // SAFETY: csrc sip, 2 clears bit 1 (SSIP) in supervisor interrupt pending register
    unsafe {
        core::arch::asm!(
            "csrc sip, {mask}",
            mask = in(reg) 2u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Main trap dispatch routine.
///
/// Called with interrupts disabled (sstatus.SIE is cleared on trap entry).
///
/// `frame` is the live frame `trap_entry` built on this hart's kernel stack.
/// It is held as a raw pointer, and each access derives a reference for that
/// access alone: the trap can block or be switched out (a syscall, a fault
/// delivery, a timer-tick preemption), during which other paths access the
/// same frame through the thread's published `trap_frame`
/// (`SYS_THREAD_READ_REGS` / `SYS_THREAD_WRITE_REGS`, the FS/VS clear in
/// `fpu::switch_out_save`), so no reference may live across those points
/// (core/kernel/docs/arch-interface.md § `trap_frame`).
#[cfg(not(test))]
// too_many_lines: the single scause dispatch (interrupt, syscall, user fault,
// kernel fault) stays one function so the trap-frame ownership and SIE
// discipline read in one place.
#[allow(clippy::too_many_lines)]
extern "C" fn trap_dispatch(frame: *mut TrapFrame)
{
    // SAFETY: trap_entry passes this hart's live, valid frame; these reads
    // end here, before anything can block (the same holds for every frame
    // access in this function: each is a single read or write, or a call that
    // cannot block).
    let (scause, sstatus_at_entry, stval) =
        unsafe { ((*frame).scause, (*frame).sstatus, (*frame).stval) };
    let is_interrupt = scause >> 63 != 0;
    let cause_code = scause & !(1u64 << 63);

    if is_interrupt
    {
        match cause_code
        {
            1 =>
            {
                // Supervisor software interrupt — TLB shootdown or wakeup IPI.
                handle_software_interrupt();
            }
            5 => super::timer::handle_tick(), // Supervisor timer interrupt
            9 =>
            {
                // Supervisor external interrupt: claim, then dispatch.
                // dispatch_external -> dispatch_device_irq calls acknowledge(irq),
                // which writes the PLIC claim/complete register. Do NOT write it
                // again here.
                //
                // `plic_enable` enables sources only on the BSP's S-mode context,
                // so only the BSP takes this trap; a claim that reads 0 (no source
                // pending for this context) dispatches nothing.
                let irq = plic_read(plic_claim_complete_offset());
                if irq != 0
                {
                    dispatch_external(irq);
                }
            }
            _ =>
            {
                // SAFETY: a single read of the live frame (see the top).
                let sepc = unsafe { (*frame).sepc };
                // `sepc` is a kernel VA when the interrupt lands in S-mode, and
                // `fatal` halts only this hart: serial only
                // (core/kernel/docs/cross-boundary-disclosure.md § Kernel
                // console diagnostics).
                crate::kprintln!("unknown interrupt: scause={:#x}", scause);
                crate::kprintln_serial!("  sepc={:#x}", sepc);
                crate::fatal("unhandled interrupt");
            }
        }
    }
    else if cause_code == 2
        && (sstatus_at_entry & (1 << 8)) == 0
        && super::fpu::is_fp_or_v_opcode(stval)
    {
        // U-mode illegal-instruction trap on an F/D/V opcode: lazy enable
        // by promoting sstatus.FS / sstatus.VS from Off to Initial, then
        // restore the F/D (and V) register file from the thread's per-TCB
        // area. lazy_restore_fp_v mirrors the resulting live FS/VS bits
        // into frame.sstatus so the trap_entry restore on sret keeps the
        // promotion — without that, sret would put FS = VS = Off back
        // into the live CSR and the trapping instruction would re-trap
        // forever. Returns without advancing sepc so the trapping
        // instruction is re-executed.
        // SAFETY: current_tcb returns this CPU's running thread; valid
        // here because we entered from a U-mode FP/V instruction.
        let area = unsafe {
            let tcb = crate::syscall::current_tcb();
            if tcb.is_null()
            {
                core::ptr::null()
            }
            else
            {
                (*tcb).extended.area.cast_const()
            }
        };
        // SAFETY: ring-0 trap context; lazy_restore_fp_v handles the null
        // area branch internally (no restore, just FS/VS promotion). The
        // frame reference lives only for the call, which cannot block.
        unsafe {
            super::fpu::lazy_restore_fp_v(area, &mut *frame);
        }
    }
    else if cause_code == 8
    {
        // U-mode ecall: dispatch via the kernel syscall table.
        // SAFETY: a single read of the live frame (see the top).
        let sepc_before = unsafe { (*frame).sepc };
        // SAFETY: frame is a valid TrapFrame on the kernel stack; trap_entry constructed
        // it with correct layout; pointer passed to syscall dispatcher.
        unsafe {
            crate::syscall::dispatch(frame);
        }
        // Advance sepc past the ecall instruction ONLY if dispatch did
        // not modify sepc. SYS_THREAD_WRITE_REGS may redirect a blocked
        // thread to a new instruction pointer; in that case sepc is
        // already the target address and must not be incremented. The
        // frame is re-read after the dispatch, which may have blocked.
        // SAFETY: single accesses of the live frame (see the top).
        unsafe {
            if (*frame).sepc == sepc_before
            {
                (*frame).sepc += 4;
            }
        }
    }
    else
    {
        let cpu = super::cpu::current_cpu();
        let satp_val: u64;
        let sstatus_val: u64;
        // SAFETY: reading CSRs is safe in S-mode.
        unsafe {
            core::arch::asm!("csrr {}, satp", out(reg) satp_val, options(nostack, nomem));
            core::arch::asm!("csrr {}, sstatus", out(reg) sstatus_val, options(nostack, nomem));
        }

        // Check if the fault came from U-mode (SPP bit 8 = 0) or S-mode (SPP = 1).
        let is_userspace = (sstatus_val & (1 << 8)) == 0;

        // Spurious stale-TLB retry: a U-mode page fault (instruction=12, load=13, store/AMO=15)
        // that the live tables already satisfy is a stale entry from an elided shootdown
        // (core/kernel/docs/memory-internals.md § SMP TLB Shootdown). Flush it locally and
        // re-execute the instruction (sepc not advanced); genuine faults fall through to the
        // kill path.
        if is_userspace && matches!(cause_code, 12 | 13 | 15)
        {
            let write = cause_code == 15;
            let instr = cause_code == 12;
            // SAFETY: S-mode; the faulting hart's satp is still active (no
            // context switch since trap entry — SIE is clear).
            if unsafe { super::paging::user_fault_is_spurious(stval, write, instr) }
            {
                // SAFETY: S-mode; drops the stale TLB entry so the retried
                // instruction re-walks the now-satisfying mapping.
                unsafe {
                    super::paging::flush_page(stval);
                }
                return;
            }
        }

        if is_userspace
        {
            // SAFETY: current_tcb() returns this CPU's running thread; valid
            // in exception context because we entered from a running user thread.
            let tcb = unsafe { crate::syscall::current_tcb() };

            // Redirect a kernel-unresolvable U-mode exception to the thread's
            // bound fault handler, if any. Page faults (cause 12/13/15) carry
            // `FAULT_KIND_VM`; every other U-mode exception carries
            // `FAULT_KIND_EXCEPTION` (see `fault_info_for`). On a resume reply the
            // trap returns and `sret` re-executes the faulting instruction (sepc
            // is not advanced for faults) or continues from a handler-modified
            // sepc.
            // SAFETY: tcb is the running user thread; has_handler only reads the
            // atomic fault_handler field.
            let handler_bound = !tcb.is_null() && unsafe { crate::ipc::fault::has_handler(tcb) };
            if handler_bound
            {
                // SAFETY: the shared reference lives only for the call, which
                // reads the frame and cannot block.
                let info = fault_info_for(cause_code, unsafe { &*frame });
                // SAFETY: frame is the live trap frame on this kernel stack; the
                // redirect points trap_frame at it for the handler's reg access
                // and returns whether to resume.
                if unsafe { redirect_user_fault(tcb, frame, &info) }
                {
                    return;
                }
                // Handler declined (Kill) — fall through to terminate the thread.
            }

            let tid = if tcb.is_null()
            {
                0u32
            }
            else
            {
                // SAFETY: tcb validated non-null.
                unsafe { (*tcb).thread_id }
            };

            crate::kprintln_serial!(
                "USERSPACE FAULT: tid={} cpu={} cause={} (scause={:#x})",
                tid,
                cpu,
                riscv_exception_name(cause_code),
                scause
            );
            // SAFETY: the shared reference lives only for these reads and the
            // dump, none of which can block; a declined fault delivery that
            // blocked has already returned.
            let live = unsafe { &*frame };
            crate::kprintln_serial!("  sepc={:#018x}  stval={:#018x}", live.sepc, live.stval);
            dump_riscv_regs(live);

            if !tcb.is_null()
            {
                // Commit Exited under all-CPU scheduler.locks. See
                // core/kernel/docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine.
                // The reason (`EXIT_FAULT_BASE + cause_code`) is written in the
                // same hold. A refusal means the thread is already `Exited` (an
                // object-teardown stop recorded `EXIT_KILLED`, or a
                // `dealloc_object(Thread)` committed `Exited`); the posts below
                // still carry the fault class (no death walk posts `EXIT_KILLED`).
                let reason = syscall::EXIT_FAULT_BASE + cause_code;
                // SAFETY: tcb validated non-null.
                let _ = unsafe { crate::sched::exit_under_all_locks(tcb, reason) };

                // Post death notification if bound (exit_reason = EXIT_FAULT_BASE + cause_code).
                // SAFETY: tcb validated non-null; exit_under_all_locks has marked it Exited and no
                // sched_lock is held.
                unsafe {
                    crate::sched::post_death_notification(tcb, reason);
                }

                // Terminal fault (no handler bound, or a Kill outcome: the handler
                // replied KILL or the episode was cancelled; see docs/fault-handling.md
                // § Delivery, Resume, and Kill): notify the faulting thread's
                // address-space observers with the fault class so procmgr can tear the
                // whole process down. Reached only on the terminal path; normal
                // thread_exit never lands here.
                // SAFETY: tcb validated non-null; address_space may be null for
                // kernel threads, which post_aspace_death_notification handles.
                unsafe {
                    crate::sched::post_aspace_death_notification((*tcb).address_space, reason);
                }
            }

            // SAFETY: schedule(Requeue::IfRunnable) context-switches away; the exited thread
            // is never re-enqueued.
            unsafe {
                crate::sched::schedule(crate::sched::Requeue::IfRunnable);
            }
            // Unreachable for an exited thread, but guard against schedule returning.
            loop
            {
                // SAFETY: wfi is a RISC-V instruction; waits for interrupt.
                unsafe {
                    core::arch::asm!("wfi", options(nomem, nostack));
                }
            }
        }
        else
        {
            // In-kernel user-copy fault recovery: an S-mode page fault (load=13,
            // store=15, instruction=12) whose sepc lies in the `copy_user` faultable
            // region is an unmapped or read-only user buffer. Redirect to the fixup
            // — which clears SUM and returns an error sentinel — instead of
            // panicking. An S-mode trap is taken by the kernel thread itself, so
            // no other path reaches this frame; the reference lives for the
            // trap's remaining, non-blocking work.
            // SAFETY: frame is the live frame (see the top); nothing below
            // blocks before `fatal` or the return.
            let live = unsafe { &mut *frame };
            if matches!(cause_code, 12 | 13 | 15)
                && let Some(fixup) = super::cpu::user_copy_fixup(live.sepc)
            {
                live.sepc = fixup;
                return;
            }

            crate::kprintln!(
                "KERNEL EXCEPTION: cpu={} cause={} (scause={:#x})",
                cpu,
                riscv_exception_name(cause_code),
                scause
            );
            // `sepc`, `stval`, `satp` and the register file can hold kernel VAs
            // or the kernel root's address, and `fatal` halts only this hart:
            // serial only (core/kernel/docs/cross-boundary-disclosure.md
            // § Kernel console diagnostics).
            crate::kprintln_serial!("  sepc={:#x}  stval={:#x}", live.sepc, live.stval);
            crate::kprintln!("  sstatus={:#x}", sstatus_val);
            crate::kprintln_serial!("  satp={:#x}", satp_val);
            dump_riscv_regs(live);
            crate::fatal("unhandled kernel exception");
        }
    }

    // Sanity check: if the trap was a U-mode ecall (scause == 8), the
    // post-dispatch sepc (ecall_pc + 4) must be in user range. A kernel
    // address here means the TrapFrame was corrupted — sret would jump
    // to kernel text in U-mode and immediately instruction-page-fault.
    // Bit-63 test: the kernel half has bit 63 set in every paging mode,
    // and no user sepc can (user_va_top <= 1 << 56). The frame is re-read
    // here, after whatever blocking the trap did.
    // SAFETY: the shared reference lives only for these reads, which cannot
    // block.
    let live = unsafe { &*frame };
    if live.scause == 8 && live.sepc >> 63 != 0
    {
        // The kernel-range `sepc` and the frame's `ra`/`sp` are kernel VAs, and
        // `fatal` halts only this hart: serial only
        // (core/kernel/docs/cross-boundary-disclosure.md § Kernel console
        // diagnostics).
        crate::kprintln!(
            "BUG: ecall return sepc in kernel range on cpu {}",
            super::cpu::current_cpu()
        );
        crate::kprintln_serial!(
            "  sepc={:#x} ra={:#x} sp={:#x} a7={:#x}",
            live.sepc,
            live.ra,
            live.sp,
            live.a7
        );
        crate::fatal("TrapFrame sepc corruption");
    }
}

/// Build the architecture-neutral [`FaultInfo`](crate::ipc::fault::FaultInfo) for
/// a U-mode exception `cause_code`. Page faults (12/13/15) become `FAULT_KIND_VM`
/// with access flags; every other cause becomes `FAULT_KIND_EXCEPTION` with a
/// normalized class and `stval` as the architecture auxiliary datum.
#[cfg(not(test))]
fn fault_info_for(cause_code: u64, frame: &TrapFrame) -> crate::ipc::fault::FaultInfo
{
    match cause_code
    {
        // scause: 12 = instruction page fault, 13 = load page fault, 15 =
        // store/AMO page fault. RISC-V does not encode present-vs-not-present in
        // scause, so the PRESENT flag is left unset (a handler that needs it
        // inspects its mappings).
        12 | 13 | 15 =>
        {
            let access = match cause_code
            {
                12 => syscall::FAULT_ACCESS_EXEC,
                15 => syscall::FAULT_ACCESS_WRITE,
                _ => syscall::FAULT_ACCESS_READ, // 13 = load
            };
            crate::ipc::fault::FaultInfo {
                kind: syscall::FAULT_KIND_VM,
                d1: frame.stval,
                d2: access,
                ip: frame.sepc,
            }
        }
        _ => crate::ipc::fault::FaultInfo {
            kind: syscall::FAULT_KIND_EXCEPTION,
            d1: normalize_riscv_exception(cause_code),
            d2: frame.stval,
            ip: frame.sepc,
        },
    }
}

/// Map a RISC-V exception cause code to the architecture-neutral
/// [`syscall::FAULT_EXC_UNKNOWN`]-family normalized code delivered in a
/// `FAULT_KIND_EXCEPTION` message. Page-fault causes (12/13/15) and `ecall`
/// (cause 8) are handled elsewhere and never reach here.
#[cfg(not(test))]
fn normalize_riscv_exception(cause: u64) -> u64
{
    match cause
    {
        0 | 4 | 6 => syscall::FAULT_EXC_ALIGNMENT, // instr / load / store misaligned
        1 | 5 | 7 => syscall::FAULT_EXC_ACCESS,    // instr / load / store access fault
        2 => syscall::FAULT_EXC_ILLEGAL_INSTRUCTION,
        3 => syscall::FAULT_EXC_BREAKPOINT,
        _ => syscall::FAULT_EXC_UNKNOWN,
    }
}

/// Redirect a genuine userspace fault to the faulting thread's bound fault
/// handler. Returns `true` if the handler resolved the fault and the thread
/// should resume (re-execute the faulting instruction, or continue from a
/// handler-modified sepc), `false` if the fault is terminal (the handler declined
/// or the binding was severed).
///
/// As on x86-64 (`x86_64/idt.rs::redirect_user_fault`), no frame copy is
/// needed: `(*tcb).trap_frame` is pointed at the live trap `frame` for the
/// duration of the block, so the handler's `SYS_THREAD_READ_REGS` /
/// `SYS_THREAD_WRITE_REGS` read and edit the faulting registers in place, and
/// `sret` restores the same frame on resume. `frame` is a raw pointer, and this
/// function forms no reference to it: the handler's edits land while this
/// thread blocks inside `fault_dispatch`.
///
/// # Safety
/// `tcb` is the current user thread and has a bound handler; `frame` is the live
/// trap frame on the current kernel stack; no lock is held.
#[cfg(not(test))]
unsafe fn redirect_user_fault(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    frame: *mut TrapFrame,
    info: &crate::ipc::fault::FaultInfo,
) -> bool
{
    // Point trap_frame at the live frame so the handler's register access targets
    // the faulting state; restore the previous pointer afterward.
    // SAFETY: tcb valid; frame is a valid live TrapFrame.
    let saved_tf = unsafe {
        (*tcb)
            .trap_frame
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    // SAFETY: tcb valid; trap_frame is the pointer the register syscalls read
    // while this thread is BlockedOnFault.
    unsafe {
        (*tcb)
            .trap_frame
            .store(frame, core::sync::atomic::Ordering::Relaxed);
    }

    // SAFETY: handler bound; trap_frame points at the live frame; no lock held.
    let outcome = unsafe { crate::ipc::fault::fault_dispatch(tcb, info) };

    // SAFETY: restore the previous trap_frame pointer.
    unsafe {
        (*tcb)
            .trap_frame
            .store(saved_tf, core::sync::atomic::Ordering::Relaxed);
    }

    matches!(outcome, crate::ipc::fault::FaultOutcome::Resume)
}

/// Enable PLIC `source` on its target hart's S-mode context; an unrouted source is left
/// disabled. Reached from `SYS_IRQ_ACK` through `irq::ack`, under `irq`'s routing lock,
/// so the target cannot be cleared between its read here and the enable.
#[cfg(not(test))]
pub fn plic_enable(source: u32)
{
    if let Some(hart) = source_target(source)
    {
        plic_update_enable_word(source, hart, |word, bit| word | bit);
    }
}

/// Disable PLIC `source` on its target hart's S-mode context (a no-op for an unrouted
/// source, which is enabled on no context).
#[cfg(not(test))]
pub fn plic_disable(source: u32)
{
    if let Some(hart) = source_target(source)
    {
        plic_update_enable_word(source, hart, |word, bit| word & !bit);
    }
}

/// Rewrite the enable word holding PLIC `source` in hart `hart`'s S-mode context to
/// `update(word, bit)`, where `bit` is the source's mask in that word, under
/// `PLIC_LOCK` (module doc § Locking). A source outside `1..=plic_ndev()` is ignored;
/// `irq::register` refuses such an id.
#[cfg(not(test))]
fn plic_update_enable_word(source: u32, hart: u32, update: impl FnOnce(u32, u32) -> u32)
{
    if source == 0 || source > super::platform::plic_ndev()
    {
        return;
    }
    let word_idx = source / 32;
    let bit = 1u32 << (source % 32);
    let offset = plic_enable_base_for(hart) + (u64::from(word_idx) * 4);
    // SAFETY: PLIC_LOCK is a leaf lock; lock_raw disables interrupts and is
    // paired with unlock_raw below on the only path out.
    let saved = unsafe { PLIC_LOCK.lock_raw() };
    let current = plic_read(offset);
    let updated = update(current, bit);
    // SAFETY: direct map active; PLIC MMIO is accessible; `offset` is an enable
    // word of a context `init` or `init_ap` checked to lie inside the window.
    unsafe { plic_write(offset, updated) };
    // SAFETY: paired with lock_raw above.
    unsafe { PLIC_LOCK.unlock_raw(saved) };
}

/// Mask (disable) PLIC source `irq`.
pub fn mask(irq: u32)
{
    #[cfg(not(test))]
    plic_disable(irq);
    #[cfg(test)]
    let _ = irq;
}

/// Unmask (enable) PLIC source `irq`.
pub fn unmask(irq: u32)
{
    #[cfg(not(test))]
    plic_enable(irq);
    #[cfg(test)]
    let _ = irq;
}

/// Route device IRQ (PLIC source) `irq`, leaving it masked at the controller: pick
/// its target hart (the next in turn, `irq::next_target_cpu`) and record it. The
/// driver unmasks via `SYS_IRQ_ACK` once it has registered a handler. A source routed
/// again is disabled on its old target first.
///
/// # Errors
/// `NoSuchLine` for a source outside `1..=plic_ndev()`.
///
/// # Safety
/// Must be called after PLIC init, under `irq`'s routing lock.
#[cfg(not(test))]
pub unsafe fn route_device_irq(irq: u32) -> Result<(), crate::irq::RouteError>
{
    if irq == 0 || irq > super::platform::plic_ndev()
    {
        return Err(crate::irq::RouteError::NoSuchLine);
    }
    let cpu = crate::irq::next_target_cpu(|_| true).ok_or(crate::irq::RouteError::Exhausted)?;
    // SAFETY: `next_target_cpu` returns an index below CPU_COUNT; the hart id slab
    // is read-only after boot.
    let hart = unsafe { crate::percpu::apic_id_for(cpu) };
    plic_disable(irq);
    SOURCE_TARGET[irq as usize].store(hart + 1, core::sync::atomic::Ordering::Relaxed);
    // Left disabled on the new target: unmask (SYS_IRQ_ACK) enables it, as the
    // x86-64 I/O APIC path leaves its entry masked.
    plic_disable(irq);
    Ok(())
}

/// No-op test stub.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn route_device_irq(_irq: u32) -> Result<(), crate::irq::RouteError>
{
    Ok(())
}

/// Release PLIC source `irq`'s route: disable it on its target and forget the target.
///
/// # Safety
/// Must be called after PLIC init, under `irq`'s routing lock.
#[cfg(not(test))]
pub unsafe fn unroute_device_irq(irq: u32)
{
    plic_disable(irq);
    if let Some(entry) = SOURCE_TARGET.get(irq as usize)
    {
        entry.store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

/// No-op test stub.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn unroute_device_irq(_irq: u32) {}

/// Number of interrupt lines the routing table covers: PLIC ids `0..=plic_ndev()` (id 0
/// reserved).
#[cfg(not(test))]
#[must_use]
pub fn irq_line_count() -> u32
{
    super::platform::plic_ndev() + 1
}

/// Dispatch an external interrupt from the PLIC to its registered notification.
///
/// Called from `trap_dispatch` after claiming the interrupt. Routing is
/// handled by [`crate::irq::dispatch_device_irq`], which masks the source
/// and sends EOI via [`acknowledge`].
///
/// Note: the PLIC complete write (EOI) is performed inside
/// `dispatch_device_irq` via `acknowledge(irq)`, so the caller (`trap_dispatch`)
/// must NOT also write the complete register.
#[cfg(not(test))]
fn dispatch_external(irq: u32)
{
    // SAFETY: called from trap_dispatch in interrupt context with sstatus.SIE clear;
    // irq claimed from PLIC; dispatcher will mask source and perform EOI via acknowledge().
    unsafe { crate::irq::dispatch_device_irq(irq) };
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Install `trap_entry` in this hart's `stvec` (direct mode).
///
/// `stvec` is per-hart: the BSP calls this from `init` (Phase 5), and each AP calls it from
/// `kernel_entry_ap` (through `idt::load` and `init_ap`).
///
/// # Safety
/// Must execute in supervisor mode with the direct physical map active.
#[cfg(not(test))]
pub unsafe fn install_trap_vector()
{
    // Install trap vector (direct mode: bit [1:0] = 00).
    // stvec is a per-hart CSR; called from both init() (BSP) and init_ap() (each AP).
    // SAFETY: trap_entry is a valid naked function at a known address; csrw stvec is
    // a privileged S-mode instruction; caller ensures execution in S-mode.
    unsafe {
        core::arch::asm!(
            "csrw stvec, {0}",
            in(reg) trap_entry as *const () as u64,
            options(nostack, nomem),
        );
    }
}

/// No-op stub for host tests.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn install_trap_vector() {}

/// Initialise supervisor trap infrastructure for the BSP.
///
/// # Safety
/// Must execute in supervisor mode with the direct physical map active, once,
/// on the BSP, after `percpu::init_apic_ids` (the BSP's PLIC context is that of
/// its hart id, `percpu::apic_id_for(0)`).
#[cfg(not(test))]
pub unsafe fn init()
{
    // Install trap vector (stvec is a per-hart CSR; also called from init_ap).
    // SAFETY: caller ensures execution in S-mode; trap_entry is valid.
    unsafe {
        install_trap_vector();
    }

    // Clear sscratch so trap_entry correctly identifies S-mode traps.
    // The UEFI firmware uses sscratch for its own trap handling and may leave
    // it non-zero after ExitBootServices (especially if keyboard interrupts
    // occurred during the firmware phase). A stale non-zero sscratch causes
    // trap_entry to take the U-mode path for an S-mode trap, writing the
    // TrapFrame to a bogus address and faulting.
    // SAFETY: csrw sscratch is a privileged S-mode instruction; caller ensures S-mode.
    unsafe {
        core::arch::asm!("csrw sscratch, zero", options(nostack, nomem));
    }

    // Clear sstatus.SIE (bit 1), sstatus.SPP (bit 8), sstatus.SUM (bit 18).
    // SIE: global interrupt enable — starts disabled, timer::init() enables it.
    // SPP: previous privilege (0 = U-mode return target).
    // SUM: clear outside the user-copy routines, which open their own window
    // (docs/memory-model.md § Kernel Isolation — SMEP and SMAP).
    // SAFETY: csrc sstatus is a privileged S-mode instruction that clears the
    // masked bits and touches no memory; caller ensures S-mode. `nomem` is
    // omitted as for `cpu::disable_interrupts`.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 8) | (1u64 << 18),
            options(nostack, preserves_flags),
        );
    }

    // Force sstatus.FS = sstatus.VS = 00 (Off). Kernel is soft-float
    // (RV64IMAC); any F/D or V instruction in U-mode now raises an illegal-
    // instruction trap, which the lazy save/restore path will use to
    // demand-restore extended state. cache_vlenb is BSP-only because the
    // RVA23 profile guarantees uniform VLEN across harts.
    // SAFETY: ring-0 boot; csrc sstatus is privileged S-mode.
    unsafe {
        super::fpu::enable_fpu_vector();
        super::fpu::cache_vlenb();
    }

    // Enable SSIP (bit 1), STIP (bit 5), and SEIP (bit 9) in sie.
    // SSIP: supervisor software interrupts — used for wakeup IPIs and TLB
    //   shootdown IPIs (both delivered via SBI IPI extension).
    // STIP: supervisor timer interrupts — scheduler preemption.
    // SEIP: supervisor external interrupts — PLIC device interrupts.
    // SAFETY: csrs sie is a privileged S-mode instruction; caller ensures S-mode.
    unsafe {
        core::arch::asm!(
            "csrs sie, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 9) | (1u64 << 5),
            options(nostack, nomem),
        );
    }

    // Allow U-mode to read the hardware cycle performance counter
    // (scounteren.CY = bit 0). Required for userspace cycle-count benchmarks
    // (equivalent to rdtsc on x86-64). The SBI firmware is responsible for
    // granting S-mode access via mcounteren.CY; this propagates it to U-mode.
    // SAFETY: csrs scounteren is a privileged S-mode instruction; caller ensures S-mode.
    unsafe {
        core::arch::asm!(
            "csrs scounteren, {cy}",
            cy = in(reg) 1u64,
            options(nostack, nomem),
        );
    }

    // Initialise PLIC:
    // - Set priority 1 for all sources (0 = disabled, 1 = lowest priority).
    // - Disable all source enables for BSP context (firmware may have enabled UART etc.).
    // - Set threshold to 0 for BSP S-mode context (accept all sources ≥ 1).
    //
    // The BSP's context is numbered by its hart id, which the boot protocol
    // does not fix at 0 (`BootInfo.cpu_ids[0]`, copied into the per-CPU id slab
    // before Phase 5). `current_cpu()` is not yet usable here (`tp` is installed
    // after this function), so the id is read for logical CPU 0 directly.
    // SAFETY: logical CPU 0 (the BSP) is below CPU_COUNT, and the caller ran
    // percpu::init_apic_ids first.
    let bsp_hart = unsafe { crate::percpu::apic_id_for(0) };
    require_plic_context(bsp_hart);
    let ndev = super::platform::plic_ndev();
    crate::kprintln!(
        "plic: {} sources (firmware reported {})",
        ndev,
        crate::platform::kernel_mmio().plic_ndev
    );
    // SAFETY: direct map active; PLIC MMIO region accessible; plic_write performs
    // volatile stores to valid PLIC register offsets (the BSP's context was
    // checked above to lie inside the PLIC window).
    unsafe {
        for src in 1..=ndev
        {
            plic_write(PLIC_PRIORITY_BASE + (u64::from(src) * 4), 1);
        }
        let bsp_enable_base = plic_enable_base_for(bsp_hart);
        for w in 0..enable_words(ndev)
        {
            plic_write(bsp_enable_base + u64::from(w) * 4, 0);
        }
        plic_write(plic_threshold_offset_for(bsp_hart), 0);
    }
}

/// Initialise supervisor trap infrastructure for an AP hart.
///
/// Called from `kernel_entry_ap` on each secondary hart. Mirrors the
/// per-hart subset of `init()` (no PLIC global setup — that is BSP-only).
///
/// # Safety
/// Must execute in supervisor mode on the AP being initialised.
#[cfg(not(test))]
pub unsafe fn init_ap()
{
    // SAFETY: caller (kernel_entry_ap) ensures execution in S-mode on the AP hart;
    // all CSR operations (stvec, sscratch, sstatus, sie, scounteren) are S-mode
    // privileged instructions; per-hart registers; no shared state.
    unsafe {
        // Clear SIE FIRST to prevent any stray interrupt from firing before
        // stvec and sscratch are configured. Firmware may leave SIE=1. The
        // write touches no memory; `nomem` is omitted as for
        // `cpu::disable_interrupts`.
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 8) | (1u64 << 18),
            options(nostack, preserves_flags),
        );

        // Install stvec — per-hart CSR, must be written on every hart.
        install_trap_vector();

        // Force sstatus.FS = sstatus.VS = 00 (Off) on this AP, mirroring
        // the BSP invariant. Per-hart CSR; must be re-established here.
        super::fpu::enable_fpu_vector();

        // Clear sscratch so trap_entry identifies S-mode traps correctly.
        core::arch::asm!("csrw sscratch, zero", options(nostack, nomem));

        // Enable SSIP, STIP, SEIP in sie (SIE is still 0; these only take
        // effect when SIE is re-enabled by the idle loop or sret).
        core::arch::asm!(
            "csrs sie, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 9) | (1u64 << 5),
            options(nostack, nomem),
        );

        // Allow U-mode performance-counter reads (per-hart; same as BSP init).
        core::arch::asm!(
            "csrs scounteren, {cy}",
            cy = in(reg) 1u64,
            options(nostack, nomem),
        );
    }

    // Set PLIC threshold to 0 for this hart's S-mode context and disable
    // all sources. Firmware may have left sources enabled (e.g. UART),
    // which would cause unhandled interrupt storms on secondary harts. The
    // context is this hart's (by hart id); percpu::init_ap installed `tp`
    // before this call, so current_cpu() is valid.
    let hart = current_hart();
    require_plic_context(hart);
    // SAFETY: direct map active; PLIC MMIO accessible; this hart's context,
    // checked above to lie inside the PLIC window.
    unsafe {
        plic_write(plic_threshold_offset_for(hart), 0);
        // Disable all source enable words for this hart's context.
        let enable_base = plic_enable_base_for(hart);
        for w in 0..enable_words(super::platform::plic_ndev())
        {
            plic_write(enable_base + u64::from(w) * 4, 0);
        }
    }
}

/// No-op stub for host tests.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn init_ap() {}

/// Disable supervisor interrupts. Returns previous SIE state.
// dead_code: required by the arch interface (core/kernel/docs/arch-interface.md § `interrupts`).
#[allow(dead_code)]
pub fn disable() -> bool
{
    let prev: u64;
    // SAFETY: csrrci sstatus is a privileged S-mode instruction that atomically
    // reads sstatus into the output register and clears bit 1 (SIE); it
    // touches no memory and clobbers no other register; kernel always runs in
    // S-mode. `nomem` is omitted so no memory operation is reordered across
    // the disable (see `cpu::disable_interrupts`).
    unsafe {
        core::arch::asm!(
            "csrrci {0}, sstatus, 0x2",
            out(reg) prev,
            options(nostack, preserves_flags),
        );
    }
    prev & (1 << 1) != 0 // SIE is bit 1 of sstatus
}

/// Enable supervisor interrupts.
///
/// # Safety
/// Trap vector must be installed before calling.
pub unsafe fn enable()
{
    // SAFETY: csrsi sstatus is a privileged S-mode instruction that sets bit 1
    // (SIE); it touches no memory and clobbers no register. Caller ensures the
    // trap vector is installed; kernel runs in S-mode. `nomem` is omitted so
    // no memory operation is reordered across the enable (see
    // `cpu::disable_interrupts`).
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2", options(nostack, preserves_flags));
    }
}

/// Return `true` if supervisor interrupts are currently enabled.
pub fn are_enabled() -> bool
{
    let sstatus: u64;
    // SAFETY: csrr sstatus is a privileged S-mode read-only instruction;
    // kernel always runs in S-mode.
    unsafe {
        core::arch::asm!(
            "csrr {0}, sstatus",
            out(reg) sstatus,
            options(nostack, nomem),
        );
    }
    sstatus & (1 << 1) != 0
}

/// Complete a PLIC external interrupt for `irq` on the executing hart's context,
/// the one that claimed it.
///
/// The PLIC ignores a completion for a source not enabled on the completing
/// context, and the dispatch masks (disables) the source before it completes
/// (`irq::deliver`), as a route change may also have done. So a disabled source
/// is enabled on this context for the completion and disabled again after it,
/// under `PLIC_LOCK`; without that the gateway never sees the completion and the
/// source never interrupts again.
#[cfg(not(test))]
pub fn acknowledge(irq: u32)
{
    let complete = plic_claim_complete_offset();
    if irq == 0 || irq > super::platform::plic_ndev()
    {
        // SAFETY: plic_write performs a volatile store to this context's
        // claim/complete register, inside the window init_ap checked.
        unsafe { plic_write(complete, irq) };
        return;
    }
    let word = plic_enable_base_for(current_hart()) + u64::from(irq / 32) * 4;
    let bit = 1u32 << (irq % 32);
    // SAFETY: PLIC_LOCK is a leaf lock; lock_raw disables interrupts and is
    // paired with unlock_raw below on the only path out.
    let saved = unsafe { PLIC_LOCK.lock_raw() };
    let enables = plic_read(word);
    // SAFETY: `word` is an enable word and `complete` the claim/complete register
    // of this hart's context, both inside the window init_ap checked; the
    // completion writes back the claimed id, as the PLIC protocol requires.
    unsafe {
        if enables & bit == 0
        {
            plic_write(word, enables | bit);
            plic_write(complete, irq);
            plic_write(word, enables);
        }
        else
        {
            plic_write(complete, irq);
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { PLIC_LOCK.unlock_raw(saved) };
}

/// No-op test stub.
#[cfg(test)]
pub fn acknowledge(_irq: u32) {}

// ── IPI infrastructure ────────────────────────────────────────────────────────

/// Send a TLB shootdown IPI to a target hart via SBI IPI.
///
/// Sends a supervisor software interrupt to the target hart. The
/// software-interrupt handler (scause=1) on the target clears SSIP, then services every
/// shootdown request naming it per core/kernel/docs/memory-internals.md § SMP TLB
/// Shootdown (flush, then clear its bit in `pending_cpus`).
///
/// Note: this uses SBI IPI (not RFENCE) because RFENCE is a blocking
/// firmware call that performs the flush internally without generating a
/// supervisor interrupt. The shootdown protocol requires the target to
/// clear its bit in `pending_cpus` via the handler.
///
/// # Safety
/// - `target_hart_id` must be a valid hart ID of an online hart
/// - Caller must ensure the TLB shootdown protocol state is set up correctly
pub unsafe fn send_tlb_shootdown_ipi(target_hart_id: u32)
{
    // SAFETY: caller guarantees the target hart is online (this function's
    // safety contract), satisfying sbi_send_ipi_to's contract.
    unsafe { sbi_send_ipi_to(target_hart_id) };
}

/// Send a wakeup IPI to a target hart.
///
/// Used to break an idle hart out of `wfi` when work is enqueued on its run queue.
/// On RISC-V this is implemented via the SBI IPI extension, which sends a supervisor
/// software interrupt to the target hart.
///
/// # Safety
/// `target_hart_id` must be a valid online hart ID.
#[cfg(not(test))]
pub unsafe fn send_wakeup_ipi(target_hart_id: u32)
{
    // SAFETY: caller guarantees the target hart is online (this function's
    // safety contract), satisfying sbi_send_ipi_to's contract.
    unsafe { sbi_send_ipi_to(target_hart_id) };
}

/// Split a hart ID into the SBI `(hart_mask, hart_mask_base)` pair.
///
/// The SBI hart-mask convention addresses a 64-hart window: `hart_mask_base`
/// is the first hart ID of the window and `hart_mask` is a bitmask relative
/// to that base, so any hart ID up to the platform limit is reachable.
fn sbi_hart_mask(target_hart_id: u32) -> (u64, u64)
{
    let base = u64::from(target_hart_id) & !63;
    let mask = 1u64 << (u64::from(target_hart_id) & 63);
    (mask, base)
}

/// Send a supervisor software interrupt to `target_hart_id` via the SBI IPI
/// extension (EID=0x735049 'sPI', FID=0 `SEND_IPI`).
///
/// # Safety
/// `target_hart_id` must be a valid hart ID of an online hart.
unsafe fn sbi_send_ipi_to(target_hart_id: u32)
{
    let (hart_mask, hart_mask_base) = sbi_hart_mask(target_hart_id);
    // SAFETY: SBI call with EID=sPI, FID=0; caller guarantees the target hart
    // is online.
    let err = unsafe { sbi_call_2(0x0073_5049, 0, hart_mask, hart_mask_base) };
    if err != 0
    {
        // A refused IPI is a silent lost wakeup; dying loudly here beats a
        // wedged hart. SEND_IPI errors are parameter-class, not transient.
        crate::fatal("sbi_send_ipi_to: SBI SEND_IPI returned an error");
    }
}

/// Send an NMI-equivalent to a target hart. RISC-V has no S-mode NMI
/// surface and SBI offers no analogue; this is provided for arch-
/// dispatch parity with x86-64's [`super::super::x86_64::interrupts::send_nmi_to`].
/// Calling it panics: the watchdog escalation that would invoke it on
/// x86-64 simply degrades to a logged warning before the eventual
/// Phase-D panic on RISC-V (see [`wait_for_ack`]).
///
/// # Safety
/// Arch-dispatch parity only; never invoked on RISC-V in practice.
// dead_code: arch-dispatch parity with x86_64; no caller on RISC-V.
#[allow(dead_code)]
#[cfg(not(test))]
pub unsafe fn send_nmi_to(_target_hart_id: u32)
{
    crate::fatal("send_nmi_to: RISC-V has no S-mode NMI surface");
}

/// Context passed to [`wait_for_ack`] by every synchronous IPI sender.
///
/// Identical shape to the x86-64 counterpart so shared call sites (e.g.
/// `mm::tlb_shootdown::shootdown`) compile on both arches; see the
/// x86-64 `IpiWaitCtx` rustdoc in `core/kernel/src/arch/x86_64/interrupts.rs` for the
/// per-field semantics (`op_name` and `target_cpu` are diagnostic-only;
/// `resend` is called once at Phase B to re-emit the IPI to whichever
/// targets are still unacked).
pub struct IpiWaitCtx<'a>
{
    pub op_name: &'static str,
    pub target_cpu: usize,
    pub resend: &'a dyn Fn(),
}

/// Wall-clock-bounded synchronous-IPI ack wait (`timer::elapsed_us`), escalating through
/// the four phases of core/kernel/docs/scheduling-internals.md § IPI Watchdog Ladder.
/// RISC-V has no S-mode NMI surface, so Phase C is a single logged warning.
///
/// # Safety
/// The calling envelope of core/kernel/docs/scheduling-internals.md § IPI Watchdog
/// Ladder: S-mode, preemption disabled, `sstatus.SIE = 1`, and a side-effect-free `cond`.
#[cfg(not(test))]
pub unsafe fn wait_for_ack(mut cond: impl FnMut() -> bool, ctx: &IpiWaitCtx<'_>)
{
    // A clock-less wait (`elapsed_us` not yet calibrated) falls back to the spin-count
    // estimate (`bounded_wait::WaitTimer`), so it is bounded too.
    let mut timer = crate::bounded_wait::WaitTimer::start(super::timer::elapsed_us());
    let mut resent = false;
    let mut warned = false;
    loop
    {
        if cond()
        {
            return;
        }
        core::hint::spin_loop();
        let elapsed_ms = timer.elapsed(super::timer::elapsed_us()) / 1_000;
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
        if !warned && elapsed_ms >= 750
        {
            crate::kprintln!(
                "IPI WATCHDOG: target_cpu={} op={} elapsed_ms={} — still unacked",
                ctx.target_cpu,
                ctx.op_name,
                elapsed_ms
            );
            warned = true;
        }
        if !resent && elapsed_ms >= 250
        {
            (ctx.resend)();
            resent = true;
        }
    }
}

/// Make SBI call with 2 arguments.
///
/// # Safety
/// Caller must ensure the SBI extension and function are valid.
unsafe fn sbi_call_2(ext_id: u64, fid: u64, arg0: u64, arg1: u64) -> u64
{
    let ret: u64;
    // SAFETY: SBI ecall convention, inputs in a7/a6/a0/a1, result in a0.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") ext_id,
            in("a6") fid,
            in("a0") arg0,
            in("a1") arg1,
            lateout("a0") ret,
            options(nostack),
        );
    }
    ret
}

// ── Fault diagnostics ────────────────────────────────────────────────────────

/// Human-readable name for a RISC-V exception cause code.
fn riscv_exception_name(cause: u64) -> &'static str
{
    match cause
    {
        0 => "instruction address misaligned",
        1 => "instruction access fault",
        2 => "illegal instruction",
        3 => "breakpoint",
        4 => "load address misaligned",
        5 => "load access fault",
        6 => "store address misaligned",
        7 => "store access fault",
        8 => "ecall from U-mode",
        9 => "ecall from S-mode",
        12 => "instruction page fault",
        13 => "load page fault",
        15 => "store/AMO page fault",
        _ => "unknown",
    }
}

/// Dump all general-purpose registers from a RISC-V trap frame (serial only:
/// the registers of a kernel trap can hold kernel VAs).
fn dump_riscv_regs(f: &super::trap_frame::TrapFrame)
{
    macro_rules! out {
        ($($arg:tt)*) => {
            crate::kprintln_serial!($($arg)*)
        };
    }
    out!(
        "  ra={:#018x}  sp={:#018x}  gp={:#018x}  tp={:#018x}",
        f.ra,
        f.sp,
        f.gp,
        f.tp
    );
    out!(
        "  t0={:#018x}  t1={:#018x}  t2={:#018x}  s0={:#018x}",
        f.t0,
        f.t1,
        f.t2,
        f.s0
    );
    out!(
        "  s1={:#018x}  a0={:#018x}  a1={:#018x}  a2={:#018x}",
        f.s1,
        f.a0,
        f.a1,
        f.a2
    );
    out!(
        "  a3={:#018x}  a4={:#018x}  a5={:#018x}  a6={:#018x}",
        f.a3,
        f.a4,
        f.a5,
        f.a6
    );
    out!(
        "  a7={:#018x}  s2={:#018x}  s3={:#018x}  s4={:#018x}",
        f.a7,
        f.s2,
        f.s3,
        f.s4
    );
    out!(
        "  s5={:#018x}  s6={:#018x}  s7={:#018x}  s8={:#018x}",
        f.s5,
        f.s6,
        f.s7,
        f.s8
    );
    out!(
        "  s9={:#018x}  s10={:#018x} s11={:#018x}",
        f.s9,
        f.s10,
        f.s11
    );
    out!(
        "  t3={:#018x}  t4={:#018x}  t5={:#018x}  t6={:#018x}",
        f.t3,
        f.t4,
        f.t5,
        f.t6
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn plic_context_registers_follow_the_hart_id()
    {
        // Hart 0: S-mode context 1.
        assert_eq!(plic_enable_base_for(0), 0x2080);
        assert_eq!(plic_threshold_offset_for(0), 0x0020_1000);
        // Hart 3: S-mode context 7, so a boot hart other than 0 gets its own
        // registers rather than hart 0's.
        assert_eq!(plic_enable_base_for(3), 0x2000 + 7 * 0x80);
        assert_eq!(plic_threshold_offset_for(3), 0x0020_0000 + 7 * 0x1000);
    }

    // Defect caught: a firmware hart id whose context lies past the PLIC window
    // being accepted, which would turn the context writes into stores outside it.
    #[test]
    fn plic_context_outside_the_window_is_refused()
    {
        // A 4 MiB window holds 512 contexts after the 2 MiB of priority, pending
        // and enable registers: the S-mode contexts of harts 0..=255 (context
        // 511's claim register ends at 0x3F_F008); hart 256's is context 513.
        assert!(plic_context_in_window(0, 0x40_0000));
        assert!(plic_context_in_window(255, 0x40_0000));
        assert!(!plic_context_in_window(256, 0x40_0000));
        assert!(!plic_context_in_window(u32::MAX, 0x40_0000));
    }

    // Defect caught: a default window too small for the hart ids the PLIC
    // specification admits, so a platform reporting no PLIC size halts the boot
    // on a hart id at or above 256.
    #[test]
    fn default_plic_window_holds_every_context_the_specification_admits()
    {
        // Context 15871, the specification's last, is hart 7935's S-mode context.
        let window = super::super::platform::DEFAULT_PLIC_SIZE;
        assert!(plic_context_in_window(256, window));
        assert!(plic_context_in_window(7935, window));
        assert!(!plic_context_in_window(7936, window));
    }

    #[test]
    fn sbi_hart_mask_windows()
    {
        assert_eq!(sbi_hart_mask(0), (1, 0));
        assert_eq!(sbi_hart_mask(63), (1 << 63, 0));
        assert_eq!(sbi_hart_mask(64), (1, 64));
        assert_eq!(sbi_hart_mask(65), (1 << 1, 64));
        assert_eq!(sbi_hart_mask(127), (1 << 63, 64));
        assert_eq!(sbi_hart_mask(128), (1, 128));
        assert_eq!(sbi_hart_mask(511), (1 << 63, 448));
    }
}
