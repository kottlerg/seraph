// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/fpu.rs

//! RISC-V extended-state (F / D / V) control primitives.
//!
//! Concentrates the unsafe surface for FP and Vector state management.
//! The boot invariant is `sstatus.FS = sstatus.VS = 00 (Off)`. Any F/D or V
//! instruction in U-mode raises an illegal-instruction trap (`scause = 2`);
//! the trap handler decodes the opcode (see
//! [`super::encoding::is_fp_or_v_opcode`]) and lazy-restores via
//! [`lazy_restore_fp_v`].
//!
//! The scheduler calls [`switch_out_save`] on switch-out of every user
//! thread. When `sstatus.FS == 11 (Dirty)` the live F/D register file is
//! saved to the thread's per-TCB area; when `sstatus.VS == 11 (Dirty)` the
//! V register file (plus vstart/vl/vtype/vcsr) is likewise saved. Live
//! `sstatus.FS/VS` are then forced back to `00 (Off)` to re-arm the lazy
//! trap, **and** the thread's trap-frame `sstatus.FS/VS` bits are also
//! cleared so the next `sret` for this thread leaves U-mode in `Off`. That
//! second update is essential: `trap_entry` restores `sstatus` from the
//! frame on exit, so any live-CSR change made during dispatch is otherwise
//! discarded across `sret`.

/// `sstatus.FS` field — bits [14:13]. Two-bit FP unit state: 00=Off,
/// 01=Initial, 10=Clean, 11=Dirty.
const SSTATUS_FS_MASK: u64 = 0x3 << 13;

/// `sstatus.VS` field — bits [10:9]. Two-bit Vector unit state, same encoding
/// as `FS`.
const SSTATUS_VS_MASK: u64 = 0x3 << 9;

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

/// Promote `sstatus.FS` and `sstatus.VS` from 00 (Off) to 01 (Initial) so the
/// next FP/V instruction executes without re-trapping.
///
/// Called by [`lazy_restore_fp_v`] on the illegal-instruction trap path at the
/// first user F/D/V touch. csrs only sets bits; from the Off boot invariant the
/// bit-13 and bit-9 sets move both fields to Initial. Once the user code writes
/// an F or V register, the hardware advances the field to Dirty. The per-thread
/// save-area restore happens in [`lazy_restore_fp_v`] after this returns.
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
#[inline]
pub unsafe fn lazy_enable_fp_v_initial()
{
    // sstatus.FS[14:13] and sstatus.VS[10:9]: setting only bit 13 / bit 9
    // turns each field from 00 (Off) into 01 (Initial).
    let mask = (1u64 << 13) | (1u64 << 9);
    // SAFETY: csrs sstatus is privileged S-mode; mask is architected.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {mask}",
            mask = in(reg) mask,
            options(nostack, nomem),
        );
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn lazy_enable_fp_v_initial() {}

/// Save the live F/D register file to `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller (`switch_out_save`)
/// verifies this by checking the field is `Dirty`.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at the thread's
/// per-thread F/D save area (page 6 of its Thread retype slot, zeroed by
/// `sys_cap_create_thread`). `sstatus.FS` must be non-Off.
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
            "sd {tmp}, 256({a})",
            ".option pop",
            a = in(reg) area,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Restore the F/D register file from `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller (`lazy_restore_fp_v`)
/// has just promoted FS to Initial.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at a per-thread
/// F/D save area previously written by [`save_fp_to`] or zero-initialised
/// at thread creation (`sys_cap_create_thread`; the zeroed area restores to
/// f0..f31 = 0.0 and fcsr = 0, matching the architected initial FP state).
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
            "ld {tmp}, 256({a})",
            "csrw fcsr, {tmp}",
            ".option pop",
            a = in(reg) area,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Context-switch hook: if `sstatus.FS == Dirty`, save the live F/D state
/// to the TCB's per-thread save area. If `sstatus.VS == Dirty`, also save
/// the V register file. Force live `sstatus.FS = sstatus.VS = 00 (Off)`
/// **and** clear the FS/VS fields of the TCB's trap-frame `sstatus` so
/// that the next `sret` for this thread leaves U-mode in Off and the
/// first F/D/V instruction lazy-traps.
///
/// Returns immediately if the TCB has no extended-state area (kernel-only
/// / idle threads).
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled. `tcb` must
/// be a valid TCB pointer; when its `extended.area` is non-null,
/// `trap_frame` must point at the TCB's on-kernel-stack trap frame.
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
    let fs = (sstatus >> 13) & 0x3;
    let vs = (sstatus >> 9) & 0x3;
    if fs == 0x3
    {
        // SAFETY: FS = Dirty, so the FP register file is live and fsd
        // executes without trapping.
        unsafe {
            save_fp_to(area);
        }
    }
    if vs == 0x3
    {
        // SAFETY: VS = Dirty, so the V register file is live and vs8r.v
        // executes without trapping.
        unsafe {
            save_v_to(area);
        }
    }
    // Force live FS = VS = Off to re-arm the lazy trap on this CPU.
    // SAFETY: csrc sstatus is privileged S-mode; mask is architected.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (SSTATUS_FS_MASK | SSTATUS_VS_MASK),
            options(nostack, nomem),
        );
    }
    // Also clear FS/VS in the trap frame so the next sret for this thread
    // resumes U-mode with FS = VS = Off — without this, trap_entry would
    // restore sstatus from the frame and undo the lazy-trap re-arm.
    // SAFETY: trap_frame points at the TCB's on-kernel-stack trap frame
    // and is non-null whenever extended.area is non-null (user threads). A
    // switch-out from a U-mode trap (syscall, preemption, or fault block)
    // leaves no live reference to this frame: trap_dispatch,
    // redirect_user_fault, and the syscall dispatcher's `UserFrame` hold it as
    // a raw pointer and derive a reference only for an access that cannot
    // block (core/kernel/docs/arch-interface.md § `trap_frame`).
    unsafe {
        let tf = (*tcb)
            .trap_frame
            .load(core::sync::atomic::Ordering::Relaxed);
        if !tf.is_null()
        {
            (*tf).sstatus &= !(SSTATUS_FS_MASK | SSTATUS_VS_MASK);
        }
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// No-op on RISC-V: the trap path's `lazy_restore_fp_v` already restores
/// extended state on the first U-mode FP/V instruction after switch-in.
/// The function exists for arch-dispatch symmetry with x86-64, where
/// the matching hook arms `CR0.TS=1` so the first FP op traps to `#NM`.
///
/// # Safety
/// Accepts the unified arch-dispatch signature; ring discipline is
/// enforced by the caller.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_in_restore(_tcb: *mut crate::sched::thread::ThreadControlBlock) {}

/// Lazy-trap handler body: promote live `sstatus.FS` and `sstatus.VS` from
/// Off to Initial, restore the F/D and V register files from `area` (when
/// non-null), then mirror the resulting live FS/VS bits into `frame.sstatus`
/// so the `sret` at the bottom of `trap_entry` resumes U-mode in the same
/// state (otherwise the frame restore would clobber the promotion and the
/// trapping instruction would re-trap forever).
///
/// The V restore is skipped when [`vlenb`] is zero, which holds only before
/// [`cache_vlenb`] runs in Phase 5. Every hart is probed at boot: the boot
/// hart in [`cache_vlenb`], each secondary hart in [`check_ap_vlenb`], whose
/// `vlenb` read takes a fatal supervisor illegal-instruction trap on a hart
/// without V and which halts on a `vlenb` other than the boot hart's
/// (docs/platform-requirements.md § Boot-Time Feature Gate).
///
/// # Safety
/// Must execute in supervisor mode from the illegal-instruction trap path.
#[cfg(not(test))]
#[inline]
pub unsafe fn lazy_restore_fp_v(area: *const u8, frame: &mut super::trap_frame::TrapFrame)
{
    // SAFETY: csrs sstatus is privileged S-mode; this is the architected
    // FS/VS promotion sequence.
    unsafe {
        lazy_enable_fp_v_initial();
    }
    if !area.is_null()
    {
        // SAFETY: area is a valid save area pointer or zero-initialised
        // (slot-resident allocation zeroes the page).
        unsafe {
            restore_fp_from(area);
            if vlenb() != 0
            {
                restore_v_from(area);
            }
        }
    }
    // Mirror live FS/VS into the trap frame: restore_fp_from / restore_v_from
    // executed write-class instructions on F and V registers, advancing the
    // live fields to Dirty. Reflect that in frame.sstatus so trap_entry's
    // `csrw sstatus, frame.sstatus` on the way back to U-mode keeps the
    // restored state (rather than wiping it back to Off and re-trapping).
    let live: u64;
    // SAFETY: csrr sstatus is a privileged S-mode read.
    unsafe {
        core::arch::asm!(
            "csrr {0}, sstatus",
            out(reg) live,
            options(nostack, nomem),
        );
    }
    let mask = SSTATUS_FS_MASK | SSTATUS_VS_MASK;
    frame.sstatus = (frame.sstatus & !mask) | (live & mask);
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn lazy_restore_fp_v(_area: *const u8, _frame: &mut super::trap_frame::TrapFrame) {}

// ── V (Vector) state save / restore ───────────────────────────────────────────

/// Cached value of CSR `vlenb` (vector length in bytes), populated at boot
/// by [`cache_vlenb`]. Zero only before that call, meaning not yet probed;
/// the lazy-trap path then skips V save/restore.
static VLENB: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Return the boot hart's cached `vlenb`, which every secondary hart shares
/// ([`check_ap_vlenb`]). Returns 0 only before [`cache_vlenb`] runs in Phase
/// 5 ([`report_save_area`]; docs/platform-requirements.md § Boot-Time Feature
/// Gate).
// dead_code fires only under `test`: `vlenb` is read only by non-test code
// (`lazy_restore_fp_v`, `check_ap_vlenb`); their `#[cfg(test)]` stubs do not
// reference it.
#[cfg_attr(test, allow(dead_code))]
pub fn vlenb() -> u64
{
    VLENB.load(core::sync::atomic::Ordering::Relaxed)
}

/// Offset of `v0` in the save area: the 32 F/D registers and `fcsr` (264
/// bytes), then `vstart`, `vl`, `vtype` and `vcsr`, padded to 304. The save
/// and restore asm ([`save_v_to`], [`restore_v_from`]) takes it as a `const`
/// operand, and the area's size is computed from it ([`cache_vlenb`]), so the
/// layout is stated once.
const V_REGS_OFFSET: u64 = 304;

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
    // Re-arm the lazy V trap: clear both bits of sstatus.VS.
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
    crate::sched::thread_slot::set_extended_bytes(V_REGS_OFFSET + 32 * v);
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
/// Layout offsets within `area`:
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
            "sd {tmp}, 264({a})",
            "csrr {tmp}, vl",
            "sd {tmp}, 272({a})",
            "csrr {tmp}, vtype",
            "sd {tmp}, 280({a})",
            "csrr {tmp}, vcsr",
            "sd {tmp}, 288({a})",
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
/// Restoring `vl`/`vtype` is required for correctness, not optional: the
/// kernel re-arms the lazy-trap on switch-out, so a thread that was
/// preempted *between* its `vsetvli` and a dependent vector memory op
/// (`vle*`/`vse*`) resumes — through this lazy-trap path — directly at that
/// memory op, without re-executing the `vsetvli`. It must therefore observe
/// the `vl`/`vtype` it had set, not whatever values another thread left in
/// the live CSRs; otherwise the resumed `vle`/`vse` runs with the wrong
/// element count and silently mis-sizes the transfer.
///
/// # Safety
/// Must execute in supervisor mode. `sstatus.VS` must be non-Off. `area`
/// must be a save area previously written by [`save_v_to`] or zero-init.
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
            "ld {vl}, 272({a})",
            "ld {vtype}, 280({a})",
            "vsetvl x0, {vl}, {vtype}",
            // vsetvl clears vstart; restore vcsr then vstart from the area.
            "ld {tmp}, 288({a})",
            "csrw vcsr, {tmp}",
            "ld {tmp}, 264({a})",
            "csrw vstart, {tmp}",
            ".option pop",
            a = in(reg) area,
            off = const V_REGS_OFFSET,
            tmp = out(reg) _,
            vl = out(reg) _,
            vtype = out(reg) _,
            p = out(reg) _,
            stride = out(reg) _,
            options(nostack),
        );
    }
}
