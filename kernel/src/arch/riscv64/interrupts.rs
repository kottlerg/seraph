// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/interrupts.rs

//! RISC-V trap handling and PLIC initialisation.
//!
//! Sets up the supervisor-mode trap infrastructure:
//! 1. Installs `trap_entry` in `stvec` (direct mode).
//! 2. Clears `sstatus.SIE`, `sstatus.SPP`, `sstatus.SUM` for a clean initial state.
//! 3. Enables `sie.SEIP` (external) and `sie.STIP` (timer) bits.
//! 4. Initialises the PLIC: sets all source priorities to 1 and the hart 0
//!    S-mode threshold to 0 (accept all above-threshold interrupts).
//!
//! The trap vector dispatches:
//! - Timer interrupt (scause = 5 | MSB) → `timer::handle_tick()`
//! - External interrupt (scause = 9 | MSB) → PLIC claim → dispatch → PLIC complete
//! - U-mode ecall (scause = 8) → `syscall::syscall_stub()`
//! - All other exceptions → print diagnostics + `fatal()`
//!
//! # PLIC layout
//! Base physical address is supplied by the bootloader through
//! `BootInfo.kernel_mmio.plic_base` (see [`super::platform::plic_base`]) and
//! accessed via the direct map. Register offsets follow the RISC-V PLIC spec:
//! - Priority registers: base + 4*source (sources `1..=PLIC_NUM_SOURCES`).
//! - Enable registers:  base + 0x2080 + 4*word  (hart 0 S-mode context).
//! - Threshold:         base + `0x20_1000`.
//! - Claim/Complete:    base + `0x20_1004`.
//!
//! # Modification notes
//! - To add a new device IRQ: enable its PLIC source in the enable register
//!   and add a case in `dispatch_external`.
//! - To support additional harts: pass the hart ID and update the PLIC
//!   context register offsets (context = hart*2 + 1 for S-mode).

use super::trap_frame::TrapFrame;
use crate::mm::paging::DIRECT_MAP_BASE;

// ── PLIC constants ────────────────────────────────────────────────────────────

/// PLIC priority register base: base + 4 * `source_id` (source 1..=127).
const PLIC_PRIORITY_BASE: u64 = 0x0000;

/// Compute the PLIC enable register base for the current hart's S-mode context.
///
/// PLIC context = `hart_id * 2 + 1` (S-mode context for each hart).
/// Enable base = PLIC base + 0x2000 + context * 0x80.
///
/// Used only for per-hart cleanup at boot. Runtime device-IRQ routing is
/// pinned to the BSP (see [`BSP_S_CTX_ENABLE_BASE`]) so that enable/mask
/// pairs on the same source always target the same context, and only that
/// one hart takes the trap when the IRQ fires.
fn plic_enable_base() -> u64
{
    let ctx = u64::from(super::cpu::current_cpu()) * 2 + 1;
    0x2000 + ctx * 0x80
}

/// Compute the PLIC S-mode enable-bits base for the given hart.
///
/// Standard PLIC context numbering: M-mode = `hart*2`, S-mode = `hart*2+1`.
/// Enable base = 0x2000 + context * 0x80.
const fn plic_enable_base_for(hart: u32) -> u64
{
    0x2000 + (hart as u64 * 2 + 1) * 0x80
}

/// PLIC S-mode enable-bits base for hart 0 (the BSP).
///
/// All device IRQs are routed to the BSP's S-mode context — a single known
/// hart — so that only one hart takes the trap and there is no thundering-
/// herd claim race between multiple harts for the same source.
const BSP_S_CTX_ENABLE_BASE: u64 = plic_enable_base_for(0);

/// Compute the PLIC threshold register offset for the current hart's S-mode context.
fn plic_threshold_offset() -> u64
{
    let ctx = u64::from(super::cpu::current_cpu()) * 2 + 1;
    0x0020_0000 + ctx * 0x1000
}

/// Compute the PLIC claim/complete register offset for the current hart's S-mode context.
fn plic_claim_complete_offset() -> u64
{
    plic_threshold_offset() + 4
}

/// Conservative cap on the PLIC source number the kernel programs. The
/// RISC-V PLIC spec admits up to 1023 sources; every targeted platform
/// exposes far fewer, and the buddy-walked enable bitmap stays cheap at this
/// bound.
const PLIC_NUM_SOURCES: u32 = 127;

// ── PLIC access helpers ───────────────────────────────────────────────────────

fn plic_read(offset: u64) -> u32
{
    let vaddr = DIRECT_MAP_BASE + super::platform::plic_base() + offset;
    // SAFETY: PLIC base mapped via direct map; offset within PLIC MMIO range;
    // volatile read ensures ordering and prevents compiler reordering.
    unsafe { core::ptr::read_volatile(vaddr as *const u32) }
}

unsafe fn plic_write(offset: u64, val: u32)
{
    let vaddr = DIRECT_MAP_BASE + super::platform::plic_base() + offset;
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
/// `sscratch` encodes the current privilege:
/// - S-mode: `sscratch = 0`
/// - U-mode: `sscratch = kernel stack top for the current thread`
///
/// On U-mode trap entry the handler atomically reads the kernel stack top
/// from `sscratch` (via `csrrw t0, sscratch, t0`) and switches to it before
/// building the [`TrapFrame`]. On exit, `sscratch` is reloaded with the
/// kernel stack top before `sret` returns to U-mode.
///
/// `sscratch` must be initialised to the initial thread's kernel stack top
/// before the first `sret` to U-mode (done in `sched::enter`).
// too_many_lines: trap_entry is a single naked-asm block; the register
// save/restore sequence cannot be meaningfully split.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn trap_entry()
{
    // Frame layout: 35 × 8 = 280 bytes (verified by test below).
    // Offsets: x1=0, x2=8, x3=16, x4=24, x5=32, …, x31=240,
    //          sepc=248, scause=256, stval=264.
    //
    // sscratch convention (new):
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
        // Now reads from the restored sstatus, not the stale CSR.
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

/// Dispatch a trap to the appropriate handler.
///
/// `scause` bit 63 set = interrupt; clear = exception.
/// TLB shootdown IPI handler.
///
/// Reads the shootdown request from `TLB_SHOOTDOWN`, flushes the TLB for the
/// target address space, and acknowledges by clearing this hart's bit in the
/// pending mask.
#[cfg(not(test))]
fn handle_software_interrupt()
{
    // On RISC-V, both TLB shootdown and wakeup IPIs arrive as supervisor
    // software interrupts (scause=1). Distinguish by checking if our bit
    // is set in the shootdown pending mask.

    // Clear SSIP *before* checking pending_cpus. This is critical for
    // correctness: if a new IPI arrives between our check and sret, the
    // 0→1 transition on SSIP generates a fresh interrupt after sret.
    //
    // Clearing SSIP *after* the check is racy: a wakeup IPI sets SSIP,
    // we enter the handler and check pending_cpus (0 — shootdown store
    // hasn't happened yet), then the shootdown IPI arrives (SSIP already
    // 1, no new edge), and clear_sip_ssip wipes both signals. The
    // shootdown is never processed.
    //
    // SAFETY: sip.SSIP write clears supervisor software interrupt pending.
    unsafe {
        clear_sip_ssip();
    }

    let hart_id = super::cpu::current_cpu();
    let my_bit = 1u64 << hart_id;

    let pending = crate::mm::tlb_shootdown::TLB_SHOOTDOWN
        .pending_cpus
        .load(core::sync::atomic::Ordering::Acquire);

    if pending & my_bit != 0
    {
        // TLB shootdown request: flush the requested VA and acknowledge.
        // Per-VA sfence.vma avoids flushing kernel text iTLB entries, which
        // works around a QEMU TCG bug where full TLB flush (sfence.vma x0, x0)
        // can leave the instruction TLB in an inconsistent state.
        let va = crate::mm::tlb_shootdown::TLB_SHOOTDOWN
            .flush_va
            .load(core::sync::atomic::Ordering::Acquire);
        if va == u64::MAX
        {
            // Full flush requested.
            // SAFETY: sfence.vma x0, x0 flushes all TLB entries.
            unsafe {
                super::paging::flush_tlb_all();
            }
        }
        else
        {
            // SAFETY: sfence.vma with a specific VA flushes only that
            // translation. The VA is a user-range address from the
            // shootdown initiator.
            unsafe {
                core::arch::asm!(
                    "sfence.vma {}, zero",
                    in(reg) va,
                    options(nostack, preserves_flags),
                );
            }
        }

        // Clear our bit to acknowledge completion.
        // SAFETY: Release ordering ensures TLB flush is visible before bit clear.
        crate::mm::tlb_shootdown::TLB_SHOOTDOWN
            .pending_cpus
            .fetch_and(!my_bit, core::sync::atomic::Ordering::Release);
    }

    // Wakeup IPIs carry no handler work beyond the hardware-mandated SSIP
    // acknowledgement (performed by the caller via `clear_sip_ssip`). The
    // reschedule-pending flag is set producer-side in `enqueue_and_wake`,
    // so the handler does not need to touch it here.
    //
    // The IPI's purpose is purely to break the target hart out of `wfi`;
    // correctness of the wake is provided by the producer-side flag plus
    // the atomic check-and-halt in the idle loop. See
    // `kernel/src/sched/mod.rs` `RESCHEDULE_PENDING` doc.
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
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
extern "C" fn trap_dispatch(frame: &mut TrapFrame)
{
    let scause = frame.scause;
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
                // `plic_enable` enables the source on every hart's S-mode
                // context, so multiple harts may take this trap concurrently.
                // PLIC claim is atomic: only the first hart reads a non-zero
                // IRQ id; concurrent readers see 0 and fall through without
                // dispatching. This is the standard PLIC thundering-herd
                // behaviour and is safe.
                let irq = plic_read(plic_claim_complete_offset());
                if irq != 0
                {
                    dispatch_external(irq);
                }
            }
            _ =>
            {
                crate::kprintln!(
                    "unknown interrupt: scause={:#x} sepc={:#x}",
                    scause,
                    frame.sepc
                );
                crate::fatal("unhandled interrupt");
            }
        }
    }
    else if cause_code == 8
    {
        // U-mode ecall: dispatch via the kernel syscall table.
        let sepc_before = frame.sepc;
        // SAFETY: frame is a valid TrapFrame on the kernel stack; trap_entry constructed
        // it with correct layout; pointer passed to syscall dispatcher.
        unsafe {
            crate::syscall::dispatch(core::ptr::from_mut(frame));
        }
        // Advance sepc past the ecall instruction ONLY if dispatch did
        // not modify sepc. SYS_THREAD_WRITE_REGS may redirect a blocked
        // thread to a new instruction pointer; in that case sepc is
        // already the target address and must not be incremented.
        if frame.sepc == sepc_before
        {
            frame.sepc += 4;
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

        if is_userspace
        {
            // SAFETY: current_tcb() returns this CPU's running thread; valid
            // in exception context because we entered from a running user thread.
            let tcb = unsafe { crate::syscall::current_tcb() };
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
            crate::kprintln_serial!("  sepc={:#018x}  stval={:#018x}", frame.sepc, frame.stval);
            dump_riscv_regs(frame);

            if !tcb.is_null()
            {
                // SAFETY: tcb validated non-null; state field always valid.
                unsafe {
                    (*tcb).state = crate::sched::thread::ThreadState::Exited;
                }

                // Post death notification if bound (exit_reason = EXIT_FAULT_BASE + cause_code).
                // EXIT_FAULT_BASE = 0x1000 (matches syscall_abi::EXIT_FAULT_BASE).
                // SAFETY: tcb is valid; post_death_notification handles null check.
                unsafe {
                    crate::sched::post_death_notification(tcb, 0x1000 + cause_code);
                }
            }

            // SAFETY: schedule(false) context-switches away; the exited thread
            // is never re-enqueued.
            unsafe {
                crate::sched::schedule(false);
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
            crate::kprintln!(
                "KERNEL EXCEPTION: cpu={} cause={} (scause={:#x})",
                cpu,
                riscv_exception_name(cause_code),
                scause
            );
            crate::kprintln!("  sepc={:#x}  stval={:#x}", frame.sepc, frame.stval);
            crate::kprintln!("  sstatus={:#x}  satp={:#x}", sstatus_val, satp_val);
            dump_riscv_regs_console(frame);
            crate::fatal("unhandled kernel exception");
        }
    }

    // Sanity check: if the trap was a U-mode ecall (scause == 8), the
    // post-dispatch sepc (ecall_pc + 4) must be in user range. A kernel
    // address here means the TrapFrame was corrupted — sret would jump
    // to kernel text in U-mode and immediately instruction-page-fault.
    if frame.scause == 8 && frame.sepc >= 0xFFFF_8000_0000_0000
    {
        crate::kprintln!(
            "BUG: ecall return sepc={:#x} in kernel range on cpu {}",
            frame.sepc,
            super::cpu::current_cpu()
        );
        crate::kprintln!("  ra={:#x} sp={:#x} a7={:#x}", frame.ra, frame.sp, frame.a7);
        crate::fatal("TrapFrame sepc corruption");
    }
}

/// Enable PLIC `source` on the BSP's S-mode context.
///
/// Device IRQs are routed to a single hart (the BSP). Routing to one hart
/// avoids the PLIC thundering-herd: with N harts all enabled for the same
/// source, each trap fires on all N, N-1 of them lose the claim race
/// (`plic_claim` returns 0), and at QEMU SMP `cpus>1` the BQL contention
/// this causes between vCPU threads can leave the IRQ undelivered and the
/// driver's signal waiter blocked indefinitely. Pinning to a single context
/// makes IRQ delivery deterministic. This matches the `x86_64` side, which
/// programs every IOAPIC redirection entry for destination LAPIC ID 0 (see
/// `arch/x86_64/ioapic.rs::route`).
///
/// TODO: per-IRQ affinity. When the system grows multiple high-rate IRQ
/// sources (additional block devices, a NIC, more than one virtio queue
/// with per-queue MSI), concentrating all trap dispatch on hart 0 becomes
/// a bottleneck. Replace this with a per-source hart selector — either
/// round-robin at registration, user-supplied affinity, or a dynamic
/// rebalancer. The downstream `dispatch_device_irq` path is already
/// hart-agnostic (`acknowledge` uses `current_cpu`), so only the enable-bit
/// placement here needs to change. Same TODO applies to
/// `arch/x86_64/ioapic.rs::route`.
#[cfg(not(test))]
pub fn plic_enable(source: u32)
{
    if source == 0 || source > PLIC_NUM_SOURCES
    {
        return;
    }
    let word_idx = source / 32;
    let bit_idx = source % 32;
    let offset = BSP_S_CTX_ENABLE_BASE + (u64::from(word_idx) * 4);
    let current = plic_read(offset);
    // SAFETY: direct map active; PLIC MMIO is accessible.
    unsafe { plic_write(offset, current | (1 << bit_idx)) };
}

/// Disable PLIC `source` on the BSP's S-mode context.
///
/// Paired with [`plic_enable`]; both operate on the BSP only so that
/// mask/unmask is always symmetric against the one hart that actually
/// takes the trap.
#[cfg(not(test))]
pub fn plic_disable(source: u32)
{
    if source == 0 || source > PLIC_NUM_SOURCES
    {
        return;
    }
    let word_idx = source / 32;
    let bit_idx = source % 32;
    let offset = BSP_S_CTX_ENABLE_BASE + (u64::from(word_idx) * 4);
    let current = plic_read(offset);
    // SAFETY: direct map active; PLIC MMIO is accessible.
    unsafe { plic_write(offset, current & !(1 << bit_idx)) };
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

/// Dispatch an external interrupt from the PLIC to its registered signal.
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

/// Initialise trap handling and the PLIC.
///
/// Must be called once during Phase 5 from a single-threaded context.
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
#[cfg(test)]
pub unsafe fn install_trap_vector() {}

/// Initialise supervisor trap infrastructure for the BSP.
///
/// Must execute in supervisor mode with the direct physical map active.
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
    // SUM: permit S-mode to access U-mode pages (not needed; keep disabled).
    // SAFETY: csrc sstatus is a privileged S-mode instruction; caller ensures S-mode.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 8) | (1u64 << 18),
            options(nostack, nomem),
        );
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
    // (equivalent to rdtsc on x86-64). OpenSBI sets mcounteren.CY on QEMU
    // virt so S-mode access is already granted; this propagates it to U-mode.
    // Also enables the VDSO-style clock_gettime fast path in the future libc.
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
    // Uses hardcoded BSP context (hart 0 S-mode = context 1) because percpu
    // data is not yet available at this point in Phase 5.
    // SAFETY: direct map active; PLIC MMIO region accessible; plic_write performs
    // volatile stores to valid PLIC register offsets.
    unsafe {
        for src in 1..=PLIC_NUM_SOURCES
        {
            plic_write(PLIC_PRIORITY_BASE + (u64::from(src) * 4), 1);
        }
        let enable_words = PLIC_NUM_SOURCES.div_ceil(32);
        let bsp_enable_base = plic_enable_base_for(0);
        for w in 0..enable_words
        {
            plic_write(bsp_enable_base + u64::from(w) * 4, 0);
        }
        // BSP context 1: threshold = 0x200000 + 1*0x1000 = 0x201000
        plic_write(0x0020_1000, 0);
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
        // stvec and sscratch are configured. Firmware may leave SIE=1.
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 8) | (1u64 << 18),
            options(nostack, nomem),
        );

        // Install stvec — per-hart CSR, must be written on every hart.
        install_trap_vector();

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
    // which would cause unhandled interrupt storms on secondary harts.
    // SAFETY: direct map active; PLIC MMIO accessible; per-hart context.
    unsafe {
        plic_write(plic_threshold_offset(), 0);
        // Disable all source enable words for this hart's context.
        let enable_base = plic_enable_base();
        let enable_words = PLIC_NUM_SOURCES.div_ceil(32);
        for w in 0..enable_words
        {
            plic_write(enable_base + u64::from(w) * 4, 0);
        }
    }
}

/// No-op stub for host tests.
#[cfg(test)]
pub unsafe fn init_ap() {}

/// Disable supervisor interrupts. Returns previous SIE state.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn disable() -> bool
{
    let prev: u64;
    // SAFETY: csrrci sstatus is a privileged S-mode instruction that atomically
    // reads sstatus and clears bit 1 (SIE); kernel always runs in S-mode.
    unsafe {
        core::arch::asm!(
            "csrrci {0}, sstatus, 0x2",
            out(reg) prev,
            options(nostack, nomem),
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
    // SAFETY: csrsi sstatus is a privileged S-mode instruction that sets bit 1 (SIE);
    // caller ensures trap vector installed; kernel runs in S-mode.
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2", options(nostack, nomem));
    }
}

/// Return `true` if supervisor interrupts are currently enabled.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
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

/// Complete a PLIC external interrupt for `irq`.
///
/// Must be called after servicing the interrupt; called internally by the
/// trap dispatcher after `dispatch_external`.
pub fn acknowledge(irq: u32)
{
    // SAFETY: plic_write performs volatile store to PLIC claim/complete register;
    // irq value claimed from PLIC; EOI protocol requires writing back the IRQ number.
    unsafe {
        plic_write(plic_claim_complete_offset(), irq);
    }
}

// ── IPI infrastructure ────────────────────────────────────────────────────────

/// Send a TLB shootdown IPI to a target hart via SBI IPI.
///
/// Sends a supervisor software interrupt to the target hart. The
/// `handle_tlb_shootdown_ipi` handler (scause=1) on the target reads
/// the shootdown request, executes sfence.vma, clears its pending bit,
/// and clears SSIP.
///
/// Note: this uses SBI IPI (not RFENCE) because RFENCE is a blocking
/// firmware call that performs the flush internally without generating a
/// supervisor interrupt. The shootdown protocol requires the target to
/// clear its bit in `pending_cpus` via the handler.
///
/// # Safety
/// - `target_hart_id` must be a valid hart ID of an online hart
/// - Caller must ensure the TLB shootdown protocol state is set up correctly
// Used by TLB shootdown implementation.
#[allow(dead_code)]
pub unsafe fn send_tlb_shootdown_ipi(target_hart_id: u32)
{
    // SBI IPI extension (EID=0x735049 'sPI'), function SEND_IPI (fid=0).
    let hart_mask = 1u64 << target_hart_id;
    let hart_mask_base = 0u64;

    // SAFETY: SBI call sends a supervisor software interrupt to the target hart.
    unsafe {
        sbi_call_2(0x0073_5049, 0, hart_mask, hart_mask_base);
    }
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
    // SBI IPI extension (EID=0x735049 'sPI'), function SEND_IPI (fid=0).
    // Argument: hart_mask (bitmask of target harts).
    let hart_mask = 1u64 << target_hart_id;
    let hart_mask_base = 0u64; // hart_mask represents harts [0..63]

    // SAFETY: SBI call with EID=sPI, FID=0, sends an IPI to the target hart.
    // The target will receive a supervisor software interrupt, waking it from wfi.
    unsafe {
        sbi_call_2(0x0073_5049, 0, hart_mask, hart_mask_base);
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

/// Dump all general-purpose registers from a RISC-V trap frame (serial only).
fn dump_riscv_regs(f: &super::trap_frame::TrapFrame)
{
    dump_riscv_regs_to(f, false);
}

/// Dump all general-purpose registers to both serial and framebuffer (kernel faults).
fn dump_riscv_regs_console(f: &super::trap_frame::TrapFrame)
{
    dump_riscv_regs_to(f, true);
}

/// Inner register dump; `console` selects serial-only vs serial+framebuffer.
fn dump_riscv_regs_to(f: &super::trap_frame::TrapFrame, console: bool)
{
    macro_rules! out {
        ($($arg:tt)*) => {
            if console { crate::kprintln!($($arg)*); }
            else { crate::kprintln_serial!($($arg)*); }
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
    fn plic_threshold_offset()
    {
        assert_eq!(plic_threshold_offset(), 0x0020_1000);
    }

    #[test]
    fn plic_claim_complete_offset()
    {
        assert_eq!(plic_claim_complete_offset(), 0x0020_1004);
    }

    #[test]
    fn trap_frame_size()
    {
        // 31 regs × 8 + sepc + scause + stval + sstatus = 35 × 8 = 280 bytes.
        assert_eq!(core::mem::size_of::<TrapFrame>(), 280);
    }
}
