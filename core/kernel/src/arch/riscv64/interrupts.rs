// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/interrupts.rs

//! RISC-V trap handling and the external-interrupt controller's arch interface.
//!
//! Sets up the supervisor-mode trap infrastructure:
//! 1. Installs `trap_entry` in `stvec` (direct mode).
//! 2. Clears `sstatus.SIE`, `sstatus.SPP`, `sstatus.SUM` for a clean initial state.
//! 3. Enables `sie.SSIP` (IPIs), `sie.STIP` (timer), and `sie.SEIP` (external) bits.
//! 4. Brings up AIA ([`super::aia`]): the APLIC domain in MSI delivery mode and
//!    each hart's IMSIC interrupt file.
//!
//! The trap vector dispatches:
//! - Software interrupt (scause = 1 | MSB) → `handle_software_interrupt` (TLB shootdown /
//!   wakeup)
//! - Timer interrupt (scause = 5 | MSB) → `timer::handle_tick()`
//! - External interrupt (scause = 9 | MSB) → IMSIC claim (`aia::claim`) →
//!   `dispatch_external`
//! - U-mode illegal instruction on an F/D/V opcode (scause = 2) → lazy FP/V restore
//! - U-mode ecall (scause = 8) → `crate::syscall::dispatch`
//! - Other U-mode exceptions → spurious-TLB retry, the bound fault handler, or thread
//!   termination
//! - Other S-mode exceptions → the kernel spurious-TLB retry (load/store), the
//!   `copy_user` fixup, else diagnostics + `fatal()`
//!
//! # Device interrupts
//! The controller is AIA, whose mechanism [`super::aia`] holds: each routed APLIC
//! source is forwarded as a message to one hart's IMSIC file, its target, chosen at
//! route time ([`route_device_irq`], through `irq::next_target_cpu`): the harts in
//! turn, so device interrupts spread over the harts. The hart that takes the
//! external-interrupt trap claims the identity and dispatches the source its entry
//! names; masking and unmasking are APLIC register writes any hart can make.
//!
//! # Modification notes
//! - Device IRQs need no per-device code here: `route_device_irq` picks the source's
//!   target and leaves it masked, and `dispatch_external` forwards every claimed
//!   identity's entry to `crate::irq::dispatch_device_irq`.
//! - Message-signaled targets (`SYS_IRQ_MSG_ALLOC`, `irq::alloc_message`) take an
//!   identity of a hart's file through `alloc_message_target`, with no APLIC source;
//!   the identity's entry (`slot_entry`) anchors the target, and its claim dispatches
//!   it like a routed source.

use super::encoding::sbi_hart_mask;
use super::trap_frame::TrapFrame;
use crate::mm::paging::UserAccess;

/// Hardware hart id of the executing hart.
#[cfg(not(test))]
fn current_hart() -> u32
{
    let cpu = super::cpu::current_cpu() as usize;
    // SAFETY: `current_cpu()` is this hart's logical index, below `CPU_COUNT`;
    // `percpu::init_apic_ids` runs before Phase 5 (`kernel_entry`), ahead of its
    // caller (`init_ap`).
    unsafe { crate::percpu::apic_id_for(cpu) }
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
/// ## Kernel stack overflow
///
/// An S-mode trap pushes its frame on the stack it interrupts. Before the first
/// store the S-mode path compares the frame's base with the hart's
/// `PerCpuData::kernel_stack_floor` (one load, one compare-and-branch): a frame
/// that would land below the floor, in the guard page the direct map leaves
/// unmapped under every kernel stack (`mm::stack_guard`), is an overflow. The
/// path then switches to [`OVERFLOW_STACK`] and calls [`kernel_stack_overflow`],
/// which halts with a diagnostic, instead of faulting again on the guard with
/// each nested trap until the frames reach the memory below it. A floor of 0
/// disables the check.
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
        // Load this hart's stack floor and allocate the TrapFrame below sp; a
        // frame below the floor would land in the stack's guard page.
        "ld t0, {floor}(x4)",
        "addi sp, sp, -280",
        "bltu sp, t0, 5f",
        // Restore t0 = old_t0 and clear sscratch (the S-mode value).
        "csrrw t0, sscratch, zero",
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

        // ── Kernel stack overflow (never returns) ───────────────────────────────
        // sp = the frame base below the floor; t0 = the floor; sscratch = the
        // interrupted t0, abandoned. The first hart to get here takes the
        // overflow stack; any other parks.
        "5:",
        "mv a3, t0",                // a3 = floor
        "addi a2, sp, 280",         // a2 = the interrupted sp
        "la t0, {claim}",
        "li t1, 1",
        // The kernel target enables A, but the naked-asm assembler is not
        // handed it; enable it for this one instruction.
        ".option push",
        ".option arch, +a",
        "amoswap.w.aq t1, t1, (t0)",
        ".option pop",
        "bnez t1, 6f",
        "la sp, {overflow_stack}",
        "li t1, {overflow_bytes}",
        "add sp, sp, t1",
        "csrw sscratch, zero",
        "csrr a0, sepc",
        "csrr a1, stval",
        "call {overflow}",
        "6:",
        "wfi",
        "j 6b",

        dispatch = sym trap_dispatch,
        floor = const crate::percpu::PERCPU_KERNEL_STACK_FLOOR_OFFSET,
        claim = sym OVERFLOW_CLAIMED,
        overflow_stack = sym OVERFLOW_STACK,
        overflow_bytes = const OVERFLOW_STACK_BYTES,
        overflow = sym kernel_stack_overflow,
    );
}

/// Bytes of [`OVERFLOW_STACK`]: room for `kernel_stack_overflow`'s report and
/// `fatal`.
#[cfg(not(test))]
const OVERFLOW_STACK_BYTES: usize = 16 * 1024;

/// The stack a hart switches to when its S-mode trap entry finds a kernel
/// stack overflow (`trap_entry` § Kernel stack overflow). One for all harts:
/// the first to overflow claims it through [`OVERFLOW_CLAIMED`] and halts
/// there with its report; a later one parks without a report.
#[cfg(not(test))]
#[repr(C, align(16))]
struct OverflowStack([u8; OVERFLOW_STACK_BYTES]);

/// Storage of the overflow stack; written only by the asm in `trap_entry`
/// (through `sp`) after it claims [`OVERFLOW_CLAIMED`].
#[cfg(not(test))]
static mut OVERFLOW_STACK: OverflowStack = OverflowStack([0; OVERFLOW_STACK_BYTES]);

/// Nonzero once a hart has claimed [`OVERFLOW_STACK`].
#[cfg(not(test))]
static OVERFLOW_CLAIMED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Report a kernel stack overflow `trap_entry` caught and halt: the trap at
/// `sepc` (with `stval`) found the stack pointer `sp` within a frame of the
/// stack's floor `floor`. Runs on [`OVERFLOW_STACK`].
#[cfg(not(test))]
extern "C" fn kernel_stack_overflow(sepc: u64, stval: u64, sp: u64, floor: u64) -> !
{
    crate::kprintln!("KERNEL STACK OVERFLOW: cpu={}", super::cpu::current_cpu());
    // Kernel addresses; `fatal` halts: serial only
    // (core/kernel/docs/cross-boundary-disclosure.md § Kernel console
    // diagnostics).
    crate::kprintln_serial!(
        "  sepc={:#x}  stval={:#x}  sp={:#x}  floor={:#x}",
        sepc,
        stval,
        sp,
        floor
    );
    crate::fatal("kernel stack overflow");
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
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every read is of a field of this hart's live trap frame, which trap_entry \
                  passes and nothing else accesses before the reads end"
    )]
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
                // Supervisor external interrupt: this hart's IMSIC file has a
                // pending identity.
                dispatch_external();
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
        if sstatus_at_entry & (1 << 8) == 0
        {
            // The interrupt delivery point of an upcall posted with
            // UPCALL_ANY_INSTRUCTION (docs/fault-handling.md § Asynchronous
            // Upcalls): the interrupt is handled and completed, and the thread
            // it preempted (SPP = 0, U-mode) is about to return to U-mode.
            // SAFETY: U-mode origin, so frame is the interrupted thread's live
            // frame on its kernel stack; no lock is held, SIE = 0.
            unsafe { crate::ipc::upcall::deliver_at_interrupt(frame) };
        }
    }
    else if cause_code == 2
        && (sstatus_at_entry & (1 << 8)) == 0
        && super::encoding::is_fp_or_v_opcode(stval)
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
        // SAFETY: current_tcb returns this CPU's running thread.
        let tcb = unsafe { crate::syscall::current_tcb() };
        let area = if tcb.is_null()
        {
            core::ptr::null()
        }
        else
        {
            // SAFETY: a non-null tcb is this CPU's running thread, valid here
            // because we entered from a U-mode FP/V instruction.
            unsafe { (*tcb).extended.area.cast_const() }
        };
        // SAFETY: trap_entry passes this hart's live frame; the reference
        // lives only for the call below, which cannot block.
        let live = unsafe { &mut *frame };
        // SAFETY: ring-0 trap context; lazy_restore_fp_v handles the null
        // area branch internally (no restore, just FS/VS promotion).
        unsafe {
            super::fpu::lazy_restore_fp_v(area, live);
        }
    }
    else if cause_code == 8
    {
        // U-mode ecall: dispatch via the kernel syscall table.
        // SAFETY: a single read of the live frame (see the top).
        let sepc_before = unsafe { (*frame).sepc };
        // SAFETY: frame is a valid TrapFrame on the kernel stack; trap_entry constructed
        // it with correct layout; pointer passed to syscall dispatcher.
        let exit = unsafe { crate::syscall::dispatch(frame) };
        // Advance sepc past the ecall instruction ONLY if the syscall
        // completed and dispatch did not modify sepc. A restart re-executes
        // the ecall (core/kernel/docs/syscalls.md § Restartable Syscalls), and
        // SYS_THREAD_WRITE_REGS may redirect a blocked thread to a new
        // instruction pointer, which must not be incremented. The frame is
        // re-read after the dispatch, which may have blocked.
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to `sepc` of this hart's live trap frame, after the \
                      dispatch returned"
        )]
        // SAFETY: single accesses of the live frame (see the top).
        unsafe {
            if exit == crate::syscall::SyscallExit::Complete && (*frame).sepc == sepc_before
            {
                (*frame).sepc = (*frame).sepc.wrapping_add(4);
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
        }
        // SAFETY: as for satp: a CSR read in S-mode.
        unsafe {
            core::arch::asm!("csrr {}, sstatus", out(reg) sstatus_val, options(nostack, nomem));
        }

        // Check if the fault came from U-mode (SPP bit 8 = 0) or S-mode (SPP = 1).
        let is_userspace = (sstatus_val & (1 << 8)) == 0;

        // Spurious stale-TLB retry: a U-mode page fault (instruction=12, load=13, store/AMO=15)
        // that the live tables already satisfy is a stale entry from an elided shootdown
        // (core/kernel/docs/memory-internals.md § SMP TLB Shootdown). Flush it locally and
        // re-execute the instruction (sepc not advanced); genuine faults fall through to the
        // kill path.
        if is_userspace && let Some(access) = page_fault_access(cause_code)
        {
            // SAFETY: S-mode; the faulting hart's satp is still active (no
            // context switch since trap entry — SIE is clear).
            if unsafe { super::paging::user_fault_is_spurious(stval, access) }
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
            // SAFETY: the shared reference lives only for the call, which reads
            // the frame and cannot block.
            let info = fault_info_for(cause_code, unsafe { &*frame });
            // SAFETY: tcb is the running user thread; has_handler only reads the
            // atomic binding of the fault's class.
            let handler_bound =
                !tcb.is_null() && unsafe { crate::ipc::fault::has_handler(tcb, info.kind) };
            if handler_bound
            {
                // SAFETY: frame is the live trap frame on this kernel stack; the
                // redirect points trap_frame at it for the handler's reg access
                // and returns whether to resume.
                if unsafe { redirect_user_fault(tcb, frame, &info) }
                {
                    return;
                }
                // Handler declined (Kill) — fall through to terminate the thread.
            }
            else
            {
                // SAFETY: tcb is the running user thread or null.
                unsafe { crate::ipc::fault::report_unbound_kill(tcb) };
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

            // The hart printing, re-read: a declined delivery blocked above and
            // may have resumed this thread on another hart than the trap's.
            crate::kprintln_serial!(
                "USERSPACE FAULT: tid={} cpu={} cause={} (scause={:#x})",
                tid,
                super::cpu::current_cpu(),
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
                // An exception code is below 64, so the reason stays in the fault range.
                let reason = syscall::EXIT_FAULT_BASE.saturating_add(cause_code);

                // Terminal fault (no handler bound, or a Kill outcome: the handler
                // replied KILL or the episode was cancelled; see docs/fault-handling.md
                // § Delivery, Resume, and Kill): record it on the faulting thread's
                // address space before the `Exited` commit, so a holder that reads
                // the thread `Exited` also reads the space's terminal fault
                // (core/kernel/docs/syscalls.md § `SYS_CAP_INFO`); its observers
                // are posted below. Reached only on the terminal path; normal
                // thread_exit never lands here.
                // SAFETY: tcb validated non-null.
                let aspace = unsafe { (*tcb).address_space };
                // SAFETY: address_space may be null for kernel threads, which
                // record_aspace_terminal_fault handles; no death_lock is held.
                let aspace_post =
                    unsafe { crate::sched::record_aspace_terminal_fault(aspace, reason) };

                // SAFETY: tcb validated non-null.
                let _ = unsafe { crate::sched::exit_under_all_locks(tcb, reason) };

                // Post death notification if bound (exit_reason = EXIT_FAULT_BASE + cause_code).
                // SAFETY: tcb validated non-null; exit_under_all_locks has marked it Exited and no
                // sched_lock is held.
                unsafe {
                    crate::sched::post_death_notification(tcb, reason);
                }

                // Notify the address-space observers recorded above with the
                // fault class so procmgr can tear the whole process down.
                // SAFETY: aspace_post comes from this path's record, and the
                // thread has stayed on this hart since; it is now Exited and
                // no lock is held.
                unsafe {
                    crate::sched::post_aspace_death_notification(&aspace_post);
                }
            }

            // SAFETY: schedule(Requeue::IfRunnable) context-switches away; the exited thread
            // is never re-enqueued.
            unsafe {
                crate::sched::schedule(crate::sched::Requeue::IfRunnable);
            }
            // Unreachable for an exited thread, but guard against schedule returning.
            // infinite_loop: the other paths of `trap_dispatch` return to the
            // trap stub, so the function cannot be `-> !`; this branch never does.
            #[expect(clippy::infinite_loop)]
            loop
            {
                // SAFETY: wfi is a RISC-V instruction; waits for interrupt.
                unsafe {
                    core::arch::asm!("wfi", options(nomem, nostack));
                }
            }
        }
        // An S-mode trap is taken by the kernel thread itself, so no other
        // path reaches this frame; the reference lives for the trap's
        // remaining, non-blocking work.
        // SAFETY: frame is the live frame (see the top); nothing below
        // blocks before `fatal` or the return.
        let live = unsafe { &mut *frame };
        // Spurious stale-TLB retry for the kernel: a load or store fault
        // the kernel's tables already satisfy is an invalid entry this hart
        // cached before a closed direct-map hole (`mm::stack_guard`).
        // Flush it locally and re-execute. It runs before the user-copy
        // fixup, so a stale entry for a copy's kernel-side buffer retries
        // too; a user-half `stval` is never a kernel spurious fault.
        let access = match cause_code
        {
            13 => Some(super::paging::KernelAccess::Load),
            15 => Some(super::paging::KernelAccess::Store),
            _ => None,
        };
        if let Some(access) = access
        {
            // SAFETY: S-mode.
            if unsafe { super::paging::kernel_fault_is_spurious(live.stval, access) }
            {
                // SAFETY: S-mode; drops the stale entry for the retry.
                unsafe { super::paging::flush_page(live.stval) };
                return;
            }
        }

        // In-kernel user-copy fault recovery: an S-mode page fault (load=13,
        // store=15, instruction=12) whose sepc lies in the `copy_user` faultable
        // region is an unmapped or read-only user buffer. Redirect to the fixup
        // — which clears SUM and returns the bytes not copied — instead of
        // panicking.
        if let Some(access) = page_fault_access(cause_code)
            && let Some(fixup) = super::cpu::user_copy_fixup(live.sepc)
        {
            // A load or store fault the live tables already satisfy is a
            // stale entry (a hart may cache an invalid one), as for a
            // U-mode fault: flush it and retry the copy, so a page a fault
            // handler has just mapped is not failed or delivered again
            // (docs/fault-handling.md § Kernel Copies). A fetch fault at a
            // copy's sepc names a kernel VA, which is never spurious.
            // SAFETY: S-mode in the copying thread's context; its satp is
            // still active (SIE is clear).
            if unsafe { super::paging::user_fault_is_spurious(live.stval, access) }
            {
                // SAFETY: S-mode; drops the stale entry for the retry.
                unsafe { super::paging::flush_page(live.stval) };
                return;
            }
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
    match page_fault_access(cause_code)
    {
        // RISC-V does not encode present-vs-not-present in scause, so the
        // PRESENT flag is left unset (a handler that needs it inspects its
        // mappings).
        Some(access) => crate::ipc::fault::FaultInfo {
            kind: syscall::FAULT_KIND_VM,
            d1: frame.stval,
            d2: access.fault_access_bit(),
            ip: frame.sepc,
        },
        None => crate::ipc::fault::FaultInfo {
            kind: syscall::FAULT_KIND_EXCEPTION,
            d1: normalize_riscv_exception(cause_code),
            d2: frame.stval,
            ip: frame.sepc,
        },
    }
}

/// The access a page-fault `scause` reports (12 = instruction page fault,
/// 13 = load page fault, 15 = store/AMO page fault), or `None` for any other
/// cause.
fn page_fault_access(cause_code: u64) -> Option<UserAccess>
{
    match cause_code
    {
        12 => Some(UserAccess::Fetch),
        13 => Some(UserAccess::Load),
        15 => Some(UserAccess::Store),
        _ => None,
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
/// or the binding was severed), after printing its cause
/// (`ipc::fault::report_user_kill`) ahead of the kill path's diagnostic.
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

    match outcome
    {
        crate::ipc::fault::FaultOutcome::Resume => true,
        crate::ipc::fault::FaultOutcome::Kill(cause) =>
        {
            // SAFETY: tcb valid (this fn's contract); thread_id is fixed at
            // creation.
            crate::ipc::fault::report_user_kill(unsafe { (*tcb).thread_id }, cause);
            false
        }
    }
}

/// Mask (disable) APLIC source `irq` (`aia::mask`).
pub fn mask(irq: u32)
{
    #[cfg(not(test))]
    super::aia::mask(irq);
    #[cfg(test)]
    let _ = irq;
}

/// Unmask (enable) routed APLIC source `irq`, pending a level-sensitive source again
/// while it is still asserted (`aia::unmask`).
pub fn unmask(irq: u32)
{
    #[cfg(not(test))]
    super::aia::unmask(irq);
    #[cfg(test)]
    let _ = irq;
}

/// Route device IRQ (APLIC source) `irq`, leaving it masked at the controller: pick
/// its target hart (the next in turn with a free IMSIC identity,
/// `irq::next_target_cpu`), take an identity in that hart's file, and program the
/// source's trigger and polarity from `mode` (the `SYS_IRQ_ROUTE` word, which
/// `irq::route` validated and recorded) and its target (`aia::route`). The driver
/// unmasks via `SYS_IRQ_ACK` once it has registered a handler. Returns the hart and
/// identity. Called by `irq::route` for the source's first route holder; the route is
/// kept while a holder or a binding remains, and released (`unroute_device_irq`) when
/// neither does, so the source is not routed when this runs.
///
/// # Errors
/// `NoSuchLine` for a source outside `1..=aia::source_count()`; `Exhausted` when no
/// hart's file has a free identity.
///
/// # Safety
/// Must be called after `init`, under `irq`'s routing lock.
#[cfg(not(test))]
pub unsafe fn route_device_irq(
    irq: u32,
    mode: u32,
) -> Result<crate::irq::Target, crate::irq::RouteError>
{
    super::aia::route(irq, mode)
}

/// Test stub: routes every source to identity 1 of CPU 0.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the stub keeps the signature of the non-test item, which can fail"
)]
pub unsafe fn route_device_irq(
    _irq: u32,
    _mode: u32,
) -> Result<crate::irq::Target, crate::irq::RouteError>
{
    Ok(crate::irq::Target { cpu: 0, slot: 1 })
}

/// The kernel programs no interrupt remapping on riscv64: a device's message writes are
/// confined by the RISC-V IOMMU's translation of the interrupt files
/// (docs/device-management.md § IOMMU Discovery and Programming).
///
/// # Errors
/// Always `RemapError::NotSupported`.
#[cfg(not(test))]
pub fn set_remap(_remap: crate::irq::Remap) -> Result<(), crate::irq::RemapError>
{
    Err(crate::irq::RemapError::NotSupported)
}

/// No remapping entry exists on riscv64 ([`set_remap`]).
///
/// # Errors
/// Always `RemapError::NotSupported`.
#[cfg(not(test))]
pub fn remap_entry(_target: crate::irq::Target) -> Result<u64, crate::irq::RemapError>
{
    Err(crate::irq::RemapError::NotSupported)
}

/// No remapping table exists on riscv64 ([`set_remap`]).
///
/// # Errors
/// Always `RemapError::NotSupported`.
#[cfg(not(test))]
pub fn remap_handles() -> Result<u64, crate::irq::RemapError>
{
    Err(crate::irq::RemapError::NotSupported)
}

/// Release APLIC source `irq`'s route: disable it, make it inactive, and free its
/// identity in its target hart's file (`aia::unroute`, which reads the route it
/// recorded, so `_target` is not needed).
///
/// # Safety
/// Must be called after `init`, under `irq`'s routing lock.
#[cfg(not(test))]
pub unsafe fn unroute_device_irq(irq: u32, _target: crate::irq::Target)
{
    super::aia::unroute(irq);
}

/// No-op test stub.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn unroute_device_irq(_irq: u32, _target: crate::irq::Target) {}

/// Take an identity for a new message target in the next hart's IMSIC file in turn
/// with a free one, its row entry left `irq::Slot::Unbound` (`aia::alloc_message`).
/// Called by `irq::alloc_message` under `irq`'s routing lock.
///
/// # Errors
/// `Exhausted` when no hart's file has a free identity.
#[cfg(not(test))]
pub fn alloc_message_target() -> Result<crate::irq::Target, crate::irq::RouteError>
{
    super::aia::alloc_message()
}

/// Free the identity of the message target on `target`, whose row entry no binding
/// holds (`aia::free_message`). Called by `irq::free_message` under `irq`'s routing
/// lock.
#[cfg(not(test))]
pub fn free_message_target(target: crate::irq::Target)
{
    super::aia::free_message(target);
}

/// The slot entry of `target` (`irq::SlotEntry`): the entry of its identity in its
/// hart's EID row (`aia::slot_entry`), or `None` when the hart is past the boot CPUs
/// or the identity is not one its file implements.
#[cfg(not(test))]
#[must_use]
pub fn slot_entry(target: crate::irq::Target) -> Option<&'static crate::irq::SlotEntry>
{
    super::aia::slot_entry(target)
}

/// The physical address a device writes to raise `target`: its hart's
/// supervisor-level IMSIC file (`aia::message_address`).
#[cfg(not(test))]
#[must_use]
pub fn message_address(target: crate::irq::Target) -> Option<u64>
{
    super::aia::message_address(target)
}

/// The message data that raises `target`: its identity, which the device writes to
/// the file's `seteipnum_le` register.
#[cfg(not(test))]
#[must_use]
pub fn message_data(target: crate::irq::Target) -> u32
{
    target.slot
}

/// Number of interrupt lines the routing table covers: APLIC sources
/// `0..=aia::source_count()` (source 0 reserved).
#[cfg(not(test))]
#[must_use]
pub fn irq_line_count() -> u32
{
    // At most 1024: an APLIC has at most 1023 sources.
    super::aia::source_count().saturating_add(1)
}

/// Claim this hart's top pending IMSIC identity and dispatch it to the source its
/// entry in this hart's EID row names.
///
/// Called from `trap_dispatch` on a supervisor external interrupt. The claim
/// (`aia::claim`) clears the identity's pending bit and returns its entry; a claim
/// that finds nothing pending dispatches nothing, and a free identity's entry
/// signals nothing. A further pending identity keeps SEIP set and traps again.
/// Routing is handled by [`crate::irq::dispatch_device_irq`], which masks a wired
/// source and calls [`acknowledge`].
#[cfg(not(test))]
fn dispatch_external()
{
    if let Some(entry) = super::aia::claim()
    {
        // SAFETY: called from trap_dispatch in interrupt context with
        // sstatus.SIE clear; `entry` is a slot of this hart's row.
        unsafe { crate::irq::dispatch_device_irq(entry) };
    }
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
/// on the BSP, after `percpu::init_apic_ids` (the BSP's IMSIC file is that of its
/// hart id, `percpu::apic_id_for(0)`) and after Phase 4's per-CPU storage (the EID
/// rows, `aia::init_eid_storage`).
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
    // demand-restore extended state. The boot hart's vlenb, which sizes
    // every Thread's save area, is read later in Phase 5, once the per-CPU
    // pointer is installed (`fpu::report_save_area`); each AP checks its own
    // against it (`init_ap`) and halts the boot on a mismatch.
    // SAFETY: ring-0 boot; csrc sstatus is privileged S-mode.
    unsafe {
        super::fpu::enable_fpu_vector();
    }

    // Enable SSIP (bit 1), STIP (bit 5), and SEIP (bit 9) in sie.
    // SSIP: supervisor software interrupts — used for wakeup IPIs and TLB
    //   shootdown IPIs (both delivered via SBI IPI extension).
    // STIP: supervisor timer interrupts — scheduler preemption.
    // SEIP: supervisor external interrupts — this hart's IMSIC file (device
    //   interrupts, forwarded by the APLIC).
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

    // Bring up AIA: the APLIC domain (every source inactive and disabled,
    // whatever firmware left enabled) and the BSP's IMSIC file. The BSP's
    // file is that of its hart id, which the boot protocol does not fix at 0
    // (`BootInfo.cpu_ids[0]`, copied into the per-CPU id slab before Phase 5).
    // `current_cpu()` is not yet usable here (`tp` is installed after this
    // function), so the id is read for logical CPU 0 directly.
    // SAFETY: logical CPU 0 (the BSP) is below CPU_COUNT, and the caller ran
    // percpu::init_apic_ids first.
    let bsp_hart = unsafe { crate::percpu::apic_id_for(0) };
    // SAFETY: the BSP in S-mode, once, with the direct map active and SIE clear
    // (above); Phase 4's init_ap_percpu_storage allocated the EID rows.
    unsafe { super::aia::init_bsp(bsp_hart) };
}

/// Initialise supervisor trap infrastructure for an AP hart.
///
/// Called from `kernel_entry_ap` on each secondary hart. Mirrors the
/// per-hart subset of `init()` (no APLIC setup — that is BSP-only).
///
/// # Safety
/// Must execute in supervisor mode on the AP being initialised.
#[cfg(not(test))]
pub unsafe fn init_ap()
{
    // The CSR operations below on stvec, sscratch, sstatus, sie and scounteren
    // are S-mode privileged instructions on per-hart registers; the caller
    // (kernel_entry_ap) ensures execution in S-mode on the AP hart.

    // Clear SIE FIRST to prevent any stray interrupt from firing before
    // stvec and sscratch are configured. Firmware may leave SIE=1. The
    // write touches no memory; `nomem` is omitted as for
    // `cpu::disable_interrupts`.
    // SAFETY: S-mode on this AP (caller contract); sstatus is per-hart.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 8) | (1u64 << 18),
            options(nostack, preserves_flags),
        );
    }

    // Install stvec — per-hart CSR, must be written on every hart.
    // SAFETY: S-mode on this AP (caller contract), which runs on the kernel
    // page tables the trampoline's satp loaded, so the direct physical map is
    // active.
    unsafe { install_trap_vector() };

    // Force sstatus.FS = sstatus.VS = 00 (Off) on this AP, mirroring
    // the BSP invariant. Per-hart CSR; must be re-established here.
    // SAFETY: S-mode on this AP (caller contract).
    unsafe { super::fpu::enable_fpu_vector() };

    // Clear sscratch so trap_entry identifies S-mode traps correctly.
    // SAFETY: S-mode on this AP (caller contract); sscratch is per-hart.
    unsafe { core::arch::asm!("csrw sscratch, zero", options(nostack, nomem)) };

    // Every save area is sized from the boot hart's vlenb; halt the boot
    // on a hart whose vector registers are a different width. After the
    // sscratch clear: on a hart without V the vlenb read traps, and the
    // trap must take the S-mode path to the fatal handler.
    // SAFETY: S-mode on this AP, after the stvec install and the sscratch
    // clear above, with tp already installed by `percpu::init_ap` (the caller
    // runs it first). The vlenb read is of an unprivileged read-only CSR,
    // which needs sstatus.VS on (`fpu::read_vlenb` promotes it); the one
    // shared state read is the boot hart's cached vlenb, written once at BSP
    // init before any AP starts; the check may halt the boot.
    unsafe { super::fpu::check_ap_vlenb() };

    // Enable SSIP, STIP, SEIP in sie (SIE is still 0; these only take
    // effect when SIE is re-enabled by the idle loop or sret).
    // SAFETY: S-mode on this AP (caller contract); sie is per-hart.
    unsafe {
        core::arch::asm!(
            "csrs sie, {mask}",
            mask = in(reg) (1u64 << 1) | (1u64 << 9) | (1u64 << 5),
            options(nostack, nomem),
        );
    }

    // Allow U-mode performance-counter reads (per-hart; same as BSP init).
    // SAFETY: S-mode on this AP (caller contract); scounteren is per-hart.
    unsafe {
        core::arch::asm!(
            "csrs scounteren, {cy}",
            cy = in(reg) 1u64,
            options(nostack, nomem),
        );
    }

    // Initialise this hart's IMSIC file (by hart id; percpu::init_ap installed
    // `tp` before this call, so current_cpu() is valid). Firmware may have left
    // identities pending; the init clears them before enabling delivery.
    // SAFETY: this hart in S-mode with SIE clear (above); the EID rows were
    // allocated in Phase 4, before any AP started.
    unsafe { super::aia::init_hart(current_hart()) };
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

/// Acknowledge APLIC source `irq` at the controller after its dispatch: a no-op on
/// AIA. The claim (`aia::claim`) already cleared the identity's pending bit in the
/// hart's IMSIC file, which needs no completion, and the APLIC cleared the source's
/// pending bit when it forwarded it; a level-sensitive source still asserted is
/// pended again at its unmask ([`unmask`]), once its receivers have acknowledged.
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
