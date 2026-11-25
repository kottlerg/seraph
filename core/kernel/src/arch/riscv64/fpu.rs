// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/fpu.rs

//! RISC-V extended-state (F / D / V) control primitives.
//!
//! Concentrates the unsafe surface for FP and Vector state management. A user
//! thread's state is live in the registers whenever it runs in user mode, and no
//! other thread's is (`sched::fpu_switch`). `sstatus.FS` and `VS` are Off at
//! boot ([`enable_fpu_vector`]) and after every switch-out; a trap from user
//! mode leaves them as the thread had them, Clean or Dirty, until
//! [`switch_out_save`] reads and turns them Off. A save, a load or a scrub
//! here turns them on for its own instructions only. A user thread resumes with
//! the values its trap frame holds, which [`switch_in_restore`] and
//! [`first_use_trap`] write, since `trap_entry` restores `sstatus` from the
//! frame before `sret`.
//!
//! - [`switch_out_save`] saves the F/D file when `FS` is Dirty and the V file
//!   when `VS` is Dirty, turns both Off, and clears them in the thread's frame.
//!   This CPU's `fpu_owner` keeps naming the thread.
//! - [`switch_in_restore`] gives a thread that uses its state (its
//!   `ExtendedState::in_use`) that state: the registers already hold it when
//!   `fpu_owner` names the thread and its `fpu_cpu` names this CPU, else it loads
//!   the area and records both; the frame gets `FS`/`VS` Clean. A thread that
//!   has not used F/D or V keeps them Off, and when `fpu_owner` names a thread
//!   the registers are cleared first ([`scrub`]), so that no other thread's
//!   values sit in them while it runs.
//! - Such a thread's first F/D/V instruction raises an illegal-instruction trap
//!   (`scause = 2`) with `FS` Off ([`super::encoding::is_first_use_trap`]).
//!   [`first_use_trap`] marks it in use and gives it its state as switch-in
//!   would, once per thread. An F/D/V instruction that traps with the units on
//!   is the thread's illegal-instruction fault.

use super::encoding::{SSTATUS_FS_MASK, SSTATUS_VS_MASK};

/// Force `sstatus.FS = sstatus.VS = 00 (Off)` for the current hart.
///
/// After this returns, any U-mode F/D or V instruction raises an
/// illegal-instruction trap (`scause = 2`). The kernel never executes F/D/V
/// (soft-float target; see `docs/build-system.md` § Custom Targets), so the
/// kernel side itself never trips the trap.
///
/// Must be called once per hart at early init (BSP and each AP) before any
/// userspace runs.
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
#[inline]
pub unsafe fn enable_fpu_vector()
{
    // csrc clears the bits given in the mask. Clearing FS[14:13] and VS[10:9]
    // forces both fields to 00 (Off).
    // SAFETY: csrc sstatus is a privileged S-mode instruction; mask is constant
    // and architected.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (SSTATUS_FS_MASK | SSTATUS_VS_MASK),
            options(nostack, nomem),
        );
    }
}

/// No-op test stub: CSR access cannot run in host unit tests.
#[cfg(test)]
pub unsafe fn enable_fpu_vector() {}

/// Write a new thread's initial extended state into its save area: the image
/// its first load restores ([`first_use_trap`]), and the one
/// `SYS_THREAD_READ_EXT_REGS` reads until the thread's first switch-out
/// after that use.
///
/// The area is zeroed, and zero is the initial value of every field:
/// `f0`..`f31` +0.0; `fcsr` 0, rounding to nearest (ties to even) with no
/// flag accrued, and no field to unmask, since the F and D extensions never
/// trap on a floating-point exception; `vstart` 0; `vl` 0 with `vtype` 0
/// (SEW 8, LMUL 1, `vill` clear), a configuration one `vsetvl` restores, as
/// the V specification asks of the state at reset (it recommends `vill` set,
/// which differs only to a reader of `vtype`, since a program sets `vtype`
/// before a vector instruction that depends on it); `vcsr` 0 (`vxrm` round
/// to nearest up, `vxsat` clear); and `v0`..`v31` zero.
///
/// # Safety
/// `area` must point at `bytes` bytes that the caller owns exclusively and
/// may write.
#[cfg(not(test))]
pub unsafe fn init_save_area(area: *mut u8, bytes: usize)
{
    // SAFETY: the caller's contract gives `bytes` writable bytes at `area`.
    unsafe { core::ptr::write_bytes(area, 0, bytes) };
}

/// Turn `sstatus.FS` and `sstatus.VS` on (Dirty) on this hart, for a load or a
/// scrub of the register files; [`units_off`] turns them back Off.
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled, and be paired with
/// [`units_off`] before anything else runs on the hart.
#[cfg(not(test))]
#[inline]
unsafe fn units_on()
{
    // SAFETY: csrs sstatus is privileged S-mode; the mask is architected.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {mask}",
            mask = in(reg) (SSTATUS_FS_MASK | SSTATUS_VS_MASK),
            options(nostack, nomem),
        );
    }
}

/// Turn `sstatus.FS` and `sstatus.VS` Off on this hart: the state the kernel
/// runs in.
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
#[inline]
unsafe fn units_off()
{
    // SAFETY: csrc sstatus is privileged S-mode; the mask is architected.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (SSTATUS_FS_MASK | SSTATUS_VS_MASK),
            options(nostack, nomem),
        );
    }
}

/// Save the live F/D register file to `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller (`switch_out_save`)
/// verifies this by checking the field is `Dirty`.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at the thread's
/// per-thread save area (the pages after the TCB page of its Thread retype
/// slot, `crate::sched::thread_slot`). `sstatus.FS` must be non-Off.
#[cfg(not(test))]
#[inline]
unsafe fn save_fp_to(area: *mut u8)
{
    // .option arch, +d locally enables the D extension for the assembler
    // even though the kernel target is RV64IMAC. The CPU executes these
    // instructions only when FS is non-Off, which the caller enforces.
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fsd f0,    0({a})",
            "fsd f1,    8({a})",
            "fsd f2,   16({a})",
            "fsd f3,   24({a})",
            "fsd f4,   32({a})",
            "fsd f5,   40({a})",
            "fsd f6,   48({a})",
            "fsd f7,   56({a})",
            "fsd f8,   64({a})",
            "fsd f9,   72({a})",
            "fsd f10,  80({a})",
            "fsd f11,  88({a})",
            "fsd f12,  96({a})",
            "fsd f13, 104({a})",
            "fsd f14, 112({a})",
            "fsd f15, 120({a})",
            "fsd f16, 128({a})",
            "fsd f17, 136({a})",
            "fsd f18, 144({a})",
            "fsd f19, 152({a})",
            "fsd f20, 160({a})",
            "fsd f21, 168({a})",
            "fsd f22, 176({a})",
            "fsd f23, 184({a})",
            "fsd f24, 192({a})",
            "fsd f25, 200({a})",
            "fsd f26, 208({a})",
            "fsd f27, 216({a})",
            "fsd f28, 224({a})",
            "fsd f29, 232({a})",
            "fsd f30, 240({a})",
            "fsd f31, 248({a})",
            "csrr {tmp}, fcsr",
            "sd {tmp}, {fcsr}({a})",
            ".option pop",
            a = in(reg) area,
            fcsr = const syscall::EXT_REGS_RISCV64_FCSR_OFFSET,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Restore the F/D register file from `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller ([`load_area`]) has just
/// turned it on.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at a per-thread
/// F/D save area previously written by [`save_fp_to`] or by
/// [`init_save_area`] at thread creation.
#[cfg(not(test))]
#[inline]
unsafe fn restore_fp_from(area: *const u8)
{
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fld f0,    0({a})",
            "fld f1,    8({a})",
            "fld f2,   16({a})",
            "fld f3,   24({a})",
            "fld f4,   32({a})",
            "fld f5,   40({a})",
            "fld f6,   48({a})",
            "fld f7,   56({a})",
            "fld f8,   64({a})",
            "fld f9,   72({a})",
            "fld f10,  80({a})",
            "fld f11,  88({a})",
            "fld f12,  96({a})",
            "fld f13, 104({a})",
            "fld f14, 112({a})",
            "fld f15, 120({a})",
            "fld f16, 128({a})",
            "fld f17, 136({a})",
            "fld f18, 144({a})",
            "fld f19, 152({a})",
            "fld f20, 160({a})",
            "fld f21, 168({a})",
            "fld f22, 176({a})",
            "fld f23, 184({a})",
            "fld f24, 192({a})",
            "fld f25, 200({a})",
            "fld f26, 208({a})",
            "fld f27, 216({a})",
            "fld f28, 224({a})",
            "fld f29, 232({a})",
            "fld f30, 240({a})",
            "fld f31, 248({a})",
            "ld {tmp}, {fcsr}({a})",
            "csrw fcsr, {tmp}",
            ".option pop",
            a = in(reg) area,
            fcsr = const syscall::EXT_REGS_RISCV64_FCSR_OFFSET,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Context-switch hook called on switch-out of any thread: if `sstatus.FS` is
/// Dirty, save the live F/D state to the thread's save area, and if
/// `sstatus.VS` is Dirty the V register file. Then turn live `FS`/`VS` Off, the
/// state every switch leaves, and clear them in the thread's trap frame:
/// [`switch_in_restore`] sets the frame's at the thread's next switch-in. This
/// CPU's `fpu_owner` and the thread's `fpu_cpu` keep naming each other.
///
/// Dirty means the thread wrote the registers in user mode since its state was
/// made live, so they hold its state. Returns at once for a thread with no
/// extended-state area (kernel-only and idle threads).
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled, before the
/// outgoing thread's `switch()` publishes `context_saved = 1` (Release), which
/// orders the save before any other CPU's Acquire of it. `tcb` must be a valid
/// TCB pointer; when its `extended.area` is non-null, `trap_frame` must point
/// at the TCB's on-kernel-stack trap frame.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_out_save(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    // SAFETY: tcb validated by caller; area is owned by the TCB.
    let area = unsafe { (*tcb).extended.area };
    if area.is_null()
    {
        return;
    }
    let sstatus: u64;
    // SAFETY: csrr sstatus is a privileged S-mode read.
    unsafe {
        core::arch::asm!(
            "csrr {0}, sstatus",
            out(reg) sstatus,
            options(nostack, nomem),
        );
    }
    if sstatus & SSTATUS_FS_MASK == SSTATUS_FS_MASK
    {
        // SAFETY: FS = Dirty, so the FP register file is live and fsd
        // executes without trapping.
        unsafe {
            save_fp_to(area);
        }
    }
    if sstatus & SSTATUS_VS_MASK == SSTATUS_VS_MASK
    {
        // SAFETY: VS = Dirty, so the V register file is live and vs8r.v
        // executes without trapping.
        unsafe {
            save_v_to(area);
        }
    }
    // SAFETY: supervisor mode.
    unsafe {
        units_off();
    }
    // SAFETY: tcb validated by caller and its area is non-null, so its frame is
    // the user thread's (the caller's contract).
    unsafe { set_frame_units(tcb, 0) };
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// `FS` and `VS` Clean (10 each): the units on, the registers equal to the
/// area.
const SSTATUS_UNITS_CLEAN: u64 = (0x2 << 13) | (0x2 << 9);

/// Write `units` (`FS`/`VS` bits only) into the `sstatus` of `tcb`'s trap
/// frame, the value the thread's next `sret` to user mode takes.
///
/// # Safety
/// `tcb` must be a valid user TCB, switched out or this CPU's running thread,
/// with no live reference to its trap frame: `trap_dispatch`,
/// `redirect_user_fault` and the syscall dispatcher's `UserFrame` hold it as a
/// raw pointer and derive a reference only for an access that cannot block
/// (core/kernel/docs/arch-interface.md § `trap_frame`).
#[cfg(not(test))]
unsafe fn set_frame_units(tcb: *mut crate::sched::thread::ThreadControlBlock, units: u64)
{
    // SAFETY: tcb validated by caller; trap_frame is an atomic field of it.
    let tf = unsafe {
        (*tcb)
            .trap_frame
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    if !tf.is_null()
    {
        let mask = SSTATUS_FS_MASK | SSTATUS_VS_MASK;
        // SAFETY: tf is the TCB's on-kernel-stack trap frame, which the
        // caller's contract leaves unreferenced.
        let sstatus = unsafe { &mut (*tf).sstatus };
        *sstatus = (*sstatus & !mask) | (units & mask);
    }
}

/// Load the F/D and V register files from `area`, leaving the units Off.
///
/// The V load is skipped when [`vlenb`] is zero, which holds only before
/// [`cache_vlenb`] runs in Phase 5. Every hart is probed at boot: the boot hart
/// in [`cache_vlenb`], each secondary hart in [`check_ap_vlenb`], whose `vlenb`
/// read takes a fatal supervisor illegal-instruction trap on a hart without V
/// and which halts on a `vlenb` other than the boot hart's
/// (docs/platform-requirements.md § Boot-Time Feature Gate).
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled. `area` must be a
/// thread's save area, written by [`init_save_area`] or by its own switch-out
/// saves, the last of them ordered before this call.
#[cfg(not(test))]
unsafe fn load_area(area: *const u8)
{
    // SAFETY: supervisor mode with interrupts disabled; units_off follows.
    unsafe { units_on() };
    // SAFETY: FS is on; area is the thread's save area (caller's contract).
    unsafe { restore_fp_from(area) };
    if vlenb() != 0
    {
        // SAFETY: as for the F/D restore; VS is on.
        unsafe { restore_v_from(area) };
    }
    // SAFETY: supervisor mode.
    unsafe { units_off() };
}

/// Zero the F/D and V register files and `fcsr`, leaving the units Off: the
/// registers then hold no thread's state.
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled.
#[cfg(not(test))]
unsafe fn scrub()
{
    // SAFETY: supervisor mode with interrupts disabled; units_off follows.
    unsafe { units_on() };
    // SAFETY: FS is on, so the F instructions execute; they write only the F
    // registers and fcsr. `.option arch` enables D for them only.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fmv.d.x f0, zero",
            "fmv.d.x f1, zero",
            "fmv.d.x f2, zero",
            "fmv.d.x f3, zero",
            "fmv.d.x f4, zero",
            "fmv.d.x f5, zero",
            "fmv.d.x f6, zero",
            "fmv.d.x f7, zero",
            "fmv.d.x f8, zero",
            "fmv.d.x f9, zero",
            "fmv.d.x f10, zero",
            "fmv.d.x f11, zero",
            "fmv.d.x f12, zero",
            "fmv.d.x f13, zero",
            "fmv.d.x f14, zero",
            "fmv.d.x f15, zero",
            "fmv.d.x f16, zero",
            "fmv.d.x f17, zero",
            "fmv.d.x f18, zero",
            "fmv.d.x f19, zero",
            "fmv.d.x f20, zero",
            "fmv.d.x f21, zero",
            "fmv.d.x f22, zero",
            "fmv.d.x f23, zero",
            "fmv.d.x f24, zero",
            "fmv.d.x f25, zero",
            "fmv.d.x f26, zero",
            "fmv.d.x f27, zero",
            "fmv.d.x f28, zero",
            "fmv.d.x f29, zero",
            "fmv.d.x f30, zero",
            "fmv.d.x f31, zero",
            "fscsr zero",
            ".option pop",
            options(nostack, nomem),
        );
    }
    if vlenb() != 0
    {
        // SAFETY: VS is on, so the V instructions execute. `vsetvli` with a
        // destination register and rs1 = zero sets vl to VLMAX, so with SEW 8
        // and LMUL 8 the four moves write every element of v0..v31; `vcsr`
        // (`vxrm`, `vxsat`) is zeroed too. They change only the V registers,
        // vl, vtype, vstart and vcsr.
        unsafe {
            core::arch::asm!(
                ".option push",
                ".option arch, +v",
                "vsetvli {t}, zero, e8, m8, ta, ma",
                "vmv.v.i v0, 0",
                "vmv.v.i v8, 0",
                "vmv.v.i v16, 0",
                "vmv.v.i v24, 0",
                "csrw vcsr, zero",
                ".option pop",
                t = out(reg) _,
                options(nostack, nomem),
            );
        }
    }
    // SAFETY: supervisor mode.
    unsafe { units_off() };
}

/// Make `tcb`'s state live on this CPU, for a thread in use: load its area
/// unless this CPU's `fpu_owner` names it and its `fpu_cpu` names this CPU
/// (`sched::fpu_switch::in_use_action`), then record both. The caller gives
/// the thread's frame `FS`/`VS` Clean.
///
/// # Safety
/// Supervisor mode with interrupts disabled, on the CPU `tcb` runs on next or
/// runs on now, after the Acquire of its `context_saved` when it was switched
/// in; `tcb` a valid user TCB with a non-null area.
#[cfg(not(test))]
unsafe fn make_live(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::sched::fpu_switch::{InUseAction, Owner, in_use_action};

    // SAFETY: tcb is valid (caller); `extended` is a field of it.
    let ext = unsafe { &(*tcb).extended };
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
            // SAFETY: the caller's contract is load_area's.
            unsafe { load_area(ext.area) };
            owner_slot.store(tcb, core::sync::atomic::Ordering::Relaxed);
            ext.fpu_cpu
                .store(cpu, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Context-switch hook called on switch-in of any thread, after the Acquire of
/// its `context_saved`.
///
/// A thread that uses its state gets it live ([`make_live`]). A thread that has
/// not used F/D or V gets `FS`/`VS` Off in its frame, and when this CPU's
/// `fpu_owner` names a thread the registers are scrubbed and no owner is named
/// (`sched::fpu_switch::never_used_action`). A kernel thread or idle (null
/// area) loads nothing and leaves the owner as it is.
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled, after the outgoing
/// thread's `switch_out_save` and after this CPU's Acquire of `tcb`'s
/// `context_saved`, which orders the previous CPU's save of the area and its
/// writes of `fpu_cpu` and `in_use` before the reads here. `tcb` must be a
/// valid TCB pointer whose trap frame, when its area is non-null, is its
/// on-kernel-stack frame.
#[cfg(not(test))]
pub unsafe fn switch_in_restore(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::sched::fpu_switch::{NeverUsedAction, Owner, never_used_action};

    // SAFETY: tcb is valid (caller); `extended` is a field of it.
    let ext = unsafe { &(*tcb).extended };
    if ext.area.is_null()
    {
        return;
    }
    if ext.in_use.load(core::sync::atomic::Ordering::Relaxed)
    {
        // SAFETY: this function's contract is make_live's.
        unsafe { make_live(tcb) };
        // SAFETY: this function's contract is set_frame_units'.
        unsafe { set_frame_units(tcb, SSTATUS_UNITS_CLEAN) };
        return;
    }
    let cpu = super::cpu::current_cpu() as usize;
    // SAFETY: `cpu` is the executing CPU's logical index, below CPU_COUNT.
    let owner_slot = unsafe { crate::percpu::fpu_owner_for(cpu) };
    let owner = Owner::of(
        owner_slot
            .load(core::sync::atomic::Ordering::Relaxed)
            .cast_const(),
        tcb.cast_const(),
    );
    match never_used_action(owner)
    {
        NeverUsedAction::Scrub =>
        {
            // SAFETY: supervisor mode with interrupts disabled (caller).
            unsafe { scrub() };
            owner_slot.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Relaxed);
        }
        NeverUsedAction::Nothing =>
        {}
    }
    // SAFETY: the caller's contract.
    unsafe { set_frame_units(tcb, 0) };
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// The first-use trap: a user F/D/V instruction trapped with `FS` Off. Mark the
/// running thread in use and make its state live as switch-in would
/// ([`make_live`]), which writes `FS`/`VS` Clean into `frame`; the
/// instruction re-executes on `sret`. It runs once per thread: every later
/// switch-in gives the frame Clean, over the Off a register write
/// (`sanitize_for_user_resume`) leaves in a switched-out thread's frame.
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled, from the U-mode
/// illegal-instruction trap path, with `frame` the live frame of that trap, to
/// which no reference is held across this call.
#[cfg(not(test))]
pub unsafe fn first_use_trap(frame: *mut super::trap_frame::TrapFrame)
{
    // SAFETY: current_tcb returns this CPU's running thread, valid here because
    // the trap came from U-mode.
    let tcb = unsafe { crate::syscall::current_tcb() };
    // SAFETY: as above.
    let area = unsafe { (*tcb).extended.area };
    debug_assert!(!area.is_null(), "a thread in user mode has a save area");
    if area.is_null()
    {
        return;
    }
    // SAFETY: as above.
    unsafe { &(*tcb).extended }
        .in_use
        .store(true, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: supervisor mode with interrupts disabled, on the CPU tcb runs on;
    // tcb is a user TCB with an area.
    unsafe { make_live(tcb) };
    let mask = SSTATUS_FS_MASK | SSTATUS_VS_MASK;
    // SAFETY: frame is the live frame of this trap, unreferenced elsewhere
    // (caller).
    let sstatus = unsafe { &mut (*frame).sstatus };
    *sstatus = (*sstatus & !mask) | SSTATUS_UNITS_CLEAN;
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn first_use_trap(_frame: *mut super::trap_frame::TrapFrame) {}

// ── V (Vector) state save / restore ───────────────────────────────────────────

/// Cached value of CSR `vlenb` (vector length in bytes), populated at boot
/// by [`cache_vlenb`]. Zero only before that call, meaning not yet probed;
/// [`load_area`] and [`scrub`] then skip the V registers.
static VLENB: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Return the boot hart's cached `vlenb`, which every secondary hart shares
/// ([`check_ap_vlenb`]). Returns 0 only before [`cache_vlenb`] runs in Phase
/// 5 ([`report_save_area`]; docs/platform-requirements.md § Boot-Time Feature
/// Gate).
pub fn vlenb() -> u64
{
    VLENB.load(core::sync::atomic::Ordering::Relaxed)
}

/// Offset of `v0` in the save area: the 32 F/D registers and `fcsr` (264
/// bytes), then `vstart`, `vl`, `vtype` and `vcsr`, padded to 304. The
/// save area is the image `SYS_THREAD_READ_EXT_REGS` reads, so the ABI states
/// its layout (`syscall::EXT_REGS_RISCV64_*`). The save and restore asm
/// ([`save_fp_to`], [`save_v_to`] and their restores) takes those offsets as
/// `const` operands, and the area's size is computed from this one
/// ([`cache_vlenb`]), so the layout is stated once.
const V_REGS_OFFSET: u64 = syscall::EXT_REGS_RISCV64_V0_OFFSET as u64;

/// Largest `vlenb` the V specification allows (VLEN 65536). A hart reporting
/// more is not conforming; refusing it keeps the save-area arithmetic in range.
const VLENB_SPEC_MAX: u64 = 8192;

/// Read CSR `vlenb` on the running hart. The CSR access requires
/// `sstatus.VS != Off`; this function temporarily promotes VS to Initial,
/// reads `vlenb`, then restores VS = Off. On a hart without the V extension
/// the read takes an S-mode illegal-instruction trap, which the trap handler
/// treats as a fatal kernel exception: that is how such a hart is refused.
///
/// # Safety
/// Must execute in supervisor mode, with this hart's trap vector installed,
/// `sscratch` zero and its per-CPU pointer (`tp`) installed
/// (`percpu::init_bsp` / `percpu::init_ap`), so a trap on a hart without V
/// takes the S-mode path to the fatal handler, which reads `current_cpu()`.
#[cfg(not(test))]
unsafe fn read_vlenb() -> u64
{
    // Promote VS to Initial so the vlenb CSR read does not trap.
    // SAFETY: csrs sstatus is privileged S-mode.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {mask}",
            mask = in(reg) (1u64 << 9),
            options(nostack, nomem),
        );
    }
    let v: u64;
    // SAFETY: vlenb is a V-extension CSR; readable while VS != Off.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v",
            "csrr {0}, vlenb",
            ".option pop",
            out(reg) v,
            options(nostack, nomem),
        );
    }
    // Back to VS = Off, the boot state enable_fpu_vector set.
    // SAFETY: csrc sstatus is privileged S-mode.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) SSTATUS_VS_MASK,
            options(nostack, nomem),
        );
    }
    v
}

/// Read the boot hart's `vlenb`, cache it for the save-restore paths, and
/// report the per-thread save area it needs (the [`V_REGS_OFFSET`] prefix
/// and 32 vector registers, `crate::sched::thread_slot`), which sizes every
/// Thread retype slot. Must be called once at boot, before any Thread is
/// created.
///
/// Halts via [`crate::fatal`] if `vlenb` is zero, above [`VLENB_SPEC_MAX`],
/// or not a power of two (the Vector requirement is defined in
/// `docs/platform-requirements.md` § riscv64 Classification). Any other
/// `vlenb` is accepted: the save area grows with it.
///
/// # Safety
/// [`read_vlenb`]'s contract, on the boot hart.
#[cfg(not(test))]
unsafe fn cache_vlenb()
{
    // SAFETY: the caller's contract is `read_vlenb`'s, so a boot hart without
    // V halts in the trap handler at the read.
    let v = unsafe { read_vlenb() };
    if v == 0 || v > VLENB_SPEC_MAX || !v.is_power_of_two()
    {
        crate::fatal(
            "RISC-V vlenb is zero, above 8192, or not a power of two: the boot hart's Vector \
             extension is unusable",
        );
    }
    VLENB.store(v, core::sync::atomic::Ordering::Relaxed);
    // At most 304 + 32 * 8192 bytes: the bound above keeps it in range.
    crate::sched::thread_slot::set_extended_bytes(
        V_REGS_OFFSET.saturating_add(v.saturating_mul(32)),
    );
}

/// Read the boot hart's `vlenb` and report the per-thread save area it
/// needs ([`cache_vlenb`]). The arch contract's `fpu::report_save_area`,
/// called by Phase 5 after `percpu::init_bsp`.
///
/// # Safety
/// Must execute in supervisor mode on the boot hart, once, after
/// `interrupts::init` installed the trap vector and cleared `sscratch` and
/// `percpu::init_bsp` installed `tp` ([`read_vlenb`]), and before any Thread
/// is created.
#[cfg(not(test))]
pub unsafe fn report_save_area()
{
    // SAFETY: the caller's contract is `cache_vlenb`'s.
    unsafe { cache_vlenb() };
}

/// Halt the boot when this secondary hart's `vlenb` differs from the boot
/// hart's. Every Thread's save area is sized from the boot hart's `vlenb`,
/// while [`save_v_to`] and [`restore_v_from`] stride by the running hart's,
/// so a wider hart would write past the area (docs/platform-requirements.md
/// § riscv64 Classification requires uniform harts). Called once per AP
/// during its early init, after [`cache_vlenb`] ran on the boot hart.
///
/// # Safety
/// Must execute in supervisor mode, after this hart installed its trap
/// vector, cleared `sscratch` and installed `tp` ([`read_vlenb`]).
#[cfg(not(test))]
pub unsafe fn check_ap_vlenb()
{
    // SAFETY: the caller's contract, which `read_vlenb` needs: a hart without
    // V halts in the trap handler at the read.
    let v = unsafe { read_vlenb() };
    if v != vlenb()
    {
        crate::fatal("RISC-V: a secondary hart's vlenb differs from the boot hart's");
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn check_ap_vlenb() {}

/// Save V state (vstart, vl, vtype, vcsr and v0..v31) to `area`.
///
/// Layout offsets within `area` (`syscall::EXT_REGS_RISCV64_*`):
/// - 264..272: vstart
/// - 272..280: vl
/// - 280..288: vtype
/// - 288..296: vcsr
/// - 304..304+32*vlenb: v0..v31 contiguously (`vs8r.v` stores 8 regs each)
///
/// # Safety
/// Must execute in supervisor mode. `sstatus.VS` must be non-Off. `area`
/// must be the per-thread save area (`thread_slot::extended_area_bytes`).
#[cfg(not(test))]
#[inline]
unsafe fn save_v_to(area: *mut u8)
{
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v",
            "csrr {tmp}, vstart",
            "sd {tmp}, {vstart}({a})",
            "csrr {tmp}, vl",
            "sd {tmp}, {vl}({a})",
            "csrr {tmp}, vtype",
            "sd {tmp}, {vtype}({a})",
            "csrr {tmp}, vcsr",
            "sd {tmp}, {vcsr}({a})",
            "addi {p}, {a}, {off}",
            "csrr {stride}, vlenb",
            "slli {stride}, {stride}, 3",
            "vs8r.v v0, ({p})",
            "add {p}, {p}, {stride}",
            "vs8r.v v8, ({p})",
            "add {p}, {p}, {stride}",
            "vs8r.v v16, ({p})",
            "add {p}, {p}, {stride}",
            "vs8r.v v24, ({p})",
            ".option pop",
            a = in(reg) area,
            off = const V_REGS_OFFSET,
            vstart = const syscall::EXT_REGS_RISCV64_VSTART_OFFSET,
            vl = const syscall::EXT_REGS_RISCV64_VL_OFFSET,
            vtype = const syscall::EXT_REGS_RISCV64_VTYPE_OFFSET,
            vcsr = const syscall::EXT_REGS_RISCV64_VCSR_OFFSET,
            tmp = out(reg) _,
            p = out(reg) _,
            stride = out(reg) _,
            options(nostack),
        );
    }
}

/// Restore V state from `area`. Whole-register loads (`vl8re8.v`) ignore
/// `vl`/`vtype`/`vstart`, so the data registers are restored first. `vl`
/// and `vtype` are then restored exactly via `vsetvl` (AVL = saved `vl`),
/// after which `vcsr` and `vstart` are written back (`vsetvl` clears
/// `vstart`).
///
/// Restoring `vl`/`vtype` is required for correctness, not optional: a
/// thread that was preempted *between* its `vsetvli` and a dependent vector
/// memory op (`vle*`/`vse*`) resumes, after this load at its switch-in,
/// directly at that memory op, without re-executing the `vsetvli`. It must therefore observe
/// the `vl`/`vtype` it had set, not whatever values another thread left in
/// the live CSRs; otherwise the resumed `vle`/`vse` runs with the wrong
/// element count and silently mis-sizes the transfer.
///
/// # Safety
/// Must execute in supervisor mode. `sstatus.VS` must be non-Off. `area`
/// must be a save area previously written by [`save_v_to`] or by
/// [`init_save_area`].
#[cfg(not(test))]
#[inline]
unsafe fn restore_v_from(area: *const u8)
{
    // SAFETY: caller's contract. `vsetvl x0, vl, vtype` takes AVL from the
    // saved `vl` register (rs1 != x0), reproducing vl = min(saved_vl, vlmax)
    // = saved_vl for the saved vtype; rd = x0 discards the written length.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v",
            "addi {p}, {a}, {off}",
            "csrr {stride}, vlenb",
            "slli {stride}, {stride}, 3",
            "vl8re8.v v0, ({p})",
            "add {p}, {p}, {stride}",
            "vl8re8.v v8, ({p})",
            "add {p}, {p}, {stride}",
            "vl8re8.v v16, ({p})",
            "add {p}, {p}, {stride}",
            "vl8re8.v v24, ({p})",
            // Restore vtype + vl exactly (AVL = saved vl).
            "ld {vl}, {vl_at}({a})",
            "ld {vtype}, {vtype_at}({a})",
            "vsetvl x0, {vl}, {vtype}",
            // vsetvl clears vstart; restore vcsr then vstart from the area.
            "ld {tmp}, {vcsr_at}({a})",
            "csrw vcsr, {tmp}",
            "ld {tmp}, {vstart_at}({a})",
            "csrw vstart, {tmp}",
            ".option pop",
            a = in(reg) area,
            off = const V_REGS_OFFSET,
            vl_at = const syscall::EXT_REGS_RISCV64_VL_OFFSET,
            vtype_at = const syscall::EXT_REGS_RISCV64_VTYPE_OFFSET,
            vcsr_at = const syscall::EXT_REGS_RISCV64_VCSR_OFFSET,
            vstart_at = const syscall::EXT_REGS_RISCV64_VSTART_OFFSET,
            tmp = out(reg) _,
            vl = out(reg) _,
            vtype = out(reg) _,
            p = out(reg) _,
            stride = out(reg) _,
            options(nostack),
        );
    }
}
