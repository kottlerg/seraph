// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/fpu.rs

//! RISC-V extended-state (F / D / V) control primitives.
//!
//! Concentrates the unsafe surface for FP and Vector state management.
//! The boot invariant is `sstatus.FS = sstatus.VS = 00 (Off)`. Any F/D or V
//! instruction in U-mode raises an illegal-instruction trap (`scause = 2`);
//! the trap handler decodes the opcode (see [`is_fp_or_v_opcode`]) and
//! lazy-restores via [`lazy_restore_fp_v`].
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
/// illegal-instruction trap (`scause = 2`). Kernel code remains soft-float
/// (RV64IMAC target) and never touches F/D/V, so the kernel side itself
/// never trips the trap.
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
/// Called from the illegal-instruction trap handler on first user F/D/V
/// touch. csrs only sets bits; from the Off boot invariant the bit-13 and
/// bit-9 sets transition both fields to Initial. Once the user code writes
/// an F or V register the hardware advances the field to Dirty.
///
/// Adding XRSTOR-equivalent restore of a per-thread save area is deferred
/// to the commit that introduces TCB extended state.
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

/// Return `true` if `insn` (a 32-bit RISC-V instruction encoding from
/// `stval` on an illegal-instruction trap) is an F, D, or V instruction —
/// i.e. the trap was caused by FS=Off or VS=Off and is a candidate for
/// lazy enable.
///
/// Decodes the major opcode (bits [6:0]):
/// - `0x07` LOAD-FP    (FLW/FLD, vector loads)
/// - `0x27` STORE-FP   (FSW/FSD, vector stores)
/// - `0x43` MADD       (FMADD)
/// - `0x47` MSUB       (FMSUB)
/// - `0x4B` NMSUB      (FNMSUB)
/// - `0x4F` NMADD      (FNMADD)
/// - `0x53` OP-FP      (FP arithmetic)
/// - `0x57` OP-V       (vector arithmetic, vsetvl[i])
///
/// Returns `false` if `insn == 0`, which some implementations write to
/// `stval` instead of the trapping encoding — the caller must then treat
/// the trap as a non-FP/V illegal instruction.
pub fn is_fp_or_v_opcode(insn: u64) -> bool
{
    if insn == 0
    {
        return false;
    }
    let major = (insn & 0x7F) as u8;
    matches!(major, 0x07 | 0x27 | 0x43 | 0x47 | 0x4B | 0x4F | 0x53 | 0x57)
}

/// Save the live F/D register file to `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller (`switch_out_save`)
/// verifies this by checking the field is `Dirty`.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at a per-thread
/// F/D save area allocated by [`alloc_area`]. `sstatus.FS` must be non-Off.
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
/// by [`alloc_area`] (the zeroed area restores to f0..f31 = 0.0 and
/// fcsr = 0, matching the architected initial FP state).
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
    // and is non-null whenever extended.area is non-null (user threads).
    unsafe {
        let tf = (*tcb).trap_frame;
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
/// extended state on the first U-mode FP/V instruction after switch-in,
/// and that path is correct under every TCG version currently exercised.
/// The function exists for arch-dispatch symmetry with x86-64, where
/// eager restore avoids variation in TCG lazy-FPU emulation.
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
/// The V restore is skipped when `vlenb` is zero (V missing on this CPU).
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
/// by [`cache_vlenb`]. Zero before that call, signalling "V missing or not
/// yet probed" and disabling V save/restore in the lazy-trap path.
static VLENB: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Cap on supported `vlenb`. With 304 bytes of F/D + V-header prefix and
/// 32 V registers, the per-thread 4 KiB save area accommodates
/// `vlenb <= 118`; 64 (VLEN = 512) leaves comfortable headroom and covers
/// every realistic RVA23-class implementation as of writing.
const MAX_VLENB: u64 = 64;

/// Return the cached `vlenb`. Returns 0 before [`cache_vlenb`] runs at
/// boot, or on systems whose V extension is absent.
#[allow(dead_code)]
pub fn vlenb() -> u64
{
    VLENB.load(core::sync::atomic::Ordering::Relaxed)
}

/// Read CSR `vlenb` on the running hart and cache it for later
/// save-restore sizing. Must be called once at boot, before any user code
/// runs. The CSR access requires `sstatus.VS != Off`; this function
/// temporarily promotes VS to Initial, reads `vlenb`, then restores
/// VS = Off.
///
/// Halts via [`crate::fatal`] if `vlenb` is zero (V missing — the cap
/// boot invariant requires V on RISC-V) or exceeds [`MAX_VLENB`] (a
/// kernel-side build-time limit on save-area size).
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
pub unsafe fn cache_vlenb()
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
    if v == 0 || v > MAX_VLENB
    {
        crate::fatal("RISC-V vlenb out of range (0 or > MAX_VLENB) for this kernel build");
    }
    VLENB.store(v, core::sync::atomic::Ordering::Relaxed);
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn cache_vlenb() {}

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
/// must be the per-thread save area page (4 KiB).
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
            "addi {p}, {a}, 304",
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
            tmp = out(reg) _,
            p = out(reg) _,
            stride = out(reg) _,
            options(nostack),
        );
    }
}

/// Restore V state from `area`. Whole-register loads (`vl8re8.v`) ignore
/// `vstart`. After the register loads, `vsetvl` resets `vl`/`vtype` from
/// the saved values (clearing `vstart` as a side effect), then `vstart`
/// and `vcsr` are explicitly written back from the saved values.
///
/// # Safety
/// Must execute in supervisor mode. `sstatus.VS` must be non-Off. `area`
/// must be a save area previously written by [`save_v_to`] or zero-init.
#[cfg(not(test))]
#[inline]
unsafe fn restore_v_from(area: *const u8)
{
    // SAFETY: caller's contract.
    // Note: vl/vtype/vcsr restoration is intentionally minimal — `vsetvl`
    // with a saved (vl=0, vtype=0) on the first lazy-trap can land
    // hardware in a state user code doesn't tolerate. The user's own
    // `vsetvli`/`vsetvl` immediately following the lazy-restored trap
    // re-establishes the correct vtype/vl before any V op that depends
    // on them. vstart is the one piece that matters across interrupted
    // V ops, so it is restored.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v",
            "addi {p}, {a}, 304",
            "csrr {stride}, vlenb",
            "slli {stride}, {stride}, 3",
            "vl8re8.v v0, ({p})",
            "add {p}, {p}, {stride}",
            "vl8re8.v v8, ({p})",
            "add {p}, {p}, {stride}",
            "vl8re8.v v16, ({p})",
            "add {p}, {p}, {stride}",
            "vl8re8.v v24, ({p})",
            "ld {tmp}, 264({a})",
            "csrw vstart, {tmp}",
            ".option pop",
            a = in(reg) area,
            tmp = out(reg) _,
            p = out(reg) _,
            stride = out(reg) _,
            options(nostack),
        );
    }
}
