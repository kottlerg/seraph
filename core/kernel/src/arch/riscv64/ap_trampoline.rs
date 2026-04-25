// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/ap_trampoline.rs

//! RISC-V AP startup trampoline (SBI HSM `hart_start`).
//!
//! On RISC-V, secondary harts are started via the SBI HSM extension
//! (EID = 0x48534D, FID = 0: `hart_start`). The BSP calls `hart_start` with:
//!   - `hartid`    = RISC-V hart ID of the AP to start
//!   - `start_pa`  = physical address of the trampoline page (paging off)
//!   - `opaque`    = physical address of per-AP startup parameters
//!
//! The AP starts in S-mode with paging disabled, a0 = `hart_id`, a1 = opaque.
//!
//! ## Trampoline page layout (4 KiB page at `trampoline_pa`)
//!
//! ```text
//! 0x000  Trampoline code (32 bytes, 8 PIC instructions)
//! 0x020  Zero padding
//! 0x040  Per-AP param slots: (cpu_count - 1) × PARAM_SLOT_SIZE (32) bytes
//!        Slot for cpu_idx N (1-based):  trampoline_pa + PARAMS_OFFSET + (N-1)*PARAM_SLOT_SIZE
//!          +0   satp:       u64   — Sv48 SATP value ((9<<60)|(root_pa>>12))
//!          +8   entry_virt: u64   — virtual address of kernel_entry_ap
//!          +16  stack_top:  u64   — kernel idle-thread stack top (loaded into sp)
//!          +24  cpu_id:     u64   — logical CPU index (overwrites hart_id in a0)
//! ```
//!
//! ## Trampoline code
//!
//! All instructions are position-independent (no PC-relative references), so
//! the code can be copied verbatim to any physical page and executes correctly.
//!
//! ```asm
//! _rv_ap_trampoline:
//!     ld   t0,  0(a1)    // satp value
//!     ld   t1,  8(a1)    // kernel_entry_ap VA
//!     ld   t2, 16(a1)    // kernel stack top
//!     ld   a0, 24(a1)    // cpu_id (overwrites hart_id)
//!     csrw satp, t0      // enable Sv48 paging
//!     sfence.vma x0, x0  // flush all TLB entries
//!     mv   sp, t2        // switch to kernel stack
//!     jr   t1            // jump to kernel_entry_ap
//! ```
//!
//! ## SBI HSM extension
//! Extension ID: `0x48534D` ("HSM"), Function ID: 0 (`hart_start`).
//! - a7 = EID = 0x48534D
//! - a6 = FID = 0
//! - a0 = target hart ID  (in: hart to start; out: SBI error code)
//! - a1 = start physical address
//! - a2 = opaque value (passed to AP in a1)

#[cfg(not(test))]
use crate::mm::paging::DIRECT_MAP_BASE;

// ── Trampoline page offsets ───────────────────────────────────────────────────

/// Byte offset within the trampoline page where per-AP params begin.
pub const PARAMS_OFFSET: usize = 0x40;

/// Size of one per-AP param slot in bytes.
pub const PARAM_SLOT_SIZE: usize = 32;

// Sub-offsets within each param slot (byte offsets, u64-aligned).
const PARAM_SATP: usize = 0; // u64: Sv48 SATP value
const PARAM_ENTRY: usize = 8; // u64: kernel_entry_ap virtual address
const PARAM_STACK: usize = 16; // u64: kernel idle stack top
const PARAM_CPU_ID: usize = 24; // u64: logical CPU index

// ── SBI HSM ───────────────────────────────────────────────────────────────────

/// SBI HSM extension ID: ASCII "HSM" = 0x0048534D.
const SBI_EXT_HSM: u64 = 0x0048_534D;

/// SBI HSM `hart_start` function ID (FID 0).
const SBI_FID_HART_START: u64 = 0;

/// Start a secondary hart via SBI HSM `hart_start`.
///
/// The AP will start at `start_pa` (physical address, paging off) in S-mode
/// with a0 = `hart_id` and a1 = `opaque`.
///
/// Returns `true` if SBI accepted the request (error code == `SBI_SUCCESS` = 0).
///
/// # Safety
/// - `start_pa` must be the physical address of a valid, executable trampoline
///   that has been set up by [`setup_trampoline`].
/// - `opaque` must be the physical address of a valid per-AP params block
///   written by [`setup_ap_params`].
#[cfg(not(test))]
pub unsafe fn sbi_hart_start(hart_id: u64, start_pa: u64, opaque: u64) -> bool
{
    let error_code: i64;
    // SAFETY: SBI ecall in S-mode; all arguments are caller-validated.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") hart_id => error_code,
            inout("a1") start_pa => _,
            inout("a2") opaque => _,
            inout("a6") SBI_FID_HART_START => _,
            inout("a7") SBI_EXT_HSM => _,
            options(nostack),
        );
    }
    error_code == 0
}

// ── Trampoline machine code ───────────────────────────────────────────────────

// The trampoline is assembled by the linker into a dedicated section so the
// assembler produces correct RISC-V machine code. The BSP copies these bytes
// to the physical trampoline page before sending hart_start.
core::arch::global_asm!(
    ".section .text.rv_ap_trampoline, \"ax\"",
    ".global _rv_ap_trampoline",
    ".global _rv_ap_trampoline_end",
    "_rv_ap_trampoline:",
    "    ld   t0,  0(a1)",   // satp value
    "    ld   t1,  8(a1)",   // kernel_entry_ap VA
    "    ld   t2, 16(a1)",   // kernel stack top
    "    ld   a0, 24(a1)",   // cpu_id (overwrite hart_id)
    "    csrw satp, t0",     // enable Sv48 paging
    "    sfence.vma x0, x0", // flush all TLB entries
    "    mv   sp, t2",       // switch to kernel stack
    "    jr   t1",           // jump to kernel_entry_ap
    "_rv_ap_trampoline_end:",
);

unsafe extern "C" {
    /// First byte of the AP trampoline code.
    static _rv_ap_trampoline: u8;
    /// First byte past the AP trampoline code.
    static _rv_ap_trampoline_end: u8;
}

// ── BSP setup ─────────────────────────────────────────────────────────────────

/// Copy the AP trampoline code to the physical trampoline page.
///
/// Must be called once before any [`sbi_hart_start`] call. Copies the
/// trampoline machine code from its link-time location into the physical page
/// at `trampoline_pa`, accessible via the direct map at
/// `DIRECT_MAP_BASE + trampoline_pa`.
///
/// # Safety
/// - Direct map must be active (Phase 3 complete).
/// - `trampoline_pa` must be the physical address of the 4 KiB page reported
///   in `BootInfo::ap_trampoline_page` and identity-mapped RWX by Phase 3.
/// - The code section must fit within the first [`PARAMS_OFFSET`] bytes of the
///   page (32 bytes of code, 32 bytes of padding). This is guaranteed by the
///   trampoline definition (8 × 4-byte RISC-V instructions = 32 bytes).
#[cfg(not(test))]
pub unsafe fn setup_trampoline(trampoline_pa: u64)
{
    let code_start = core::ptr::addr_of!(_rv_ap_trampoline) as usize;
    let code_end = core::ptr::addr_of!(_rv_ap_trampoline_end) as usize;
    let code_len = code_end - code_start;

    // SAFETY: direct map active; dst is valid writable memory for the page.
    let dst = (DIRECT_MAP_BASE + trampoline_pa) as *mut u8;
    // SAFETY: code_start is valid linker symbol; dst is direct-mapped trampoline page; len fits.
    unsafe {
        core::ptr::copy_nonoverlapping(code_start as *const u8, dst, code_len);
    }
}

/// Start one AP via SBI HSM `hart_start`.
///
/// Sets up per-AP params, constructs the Sv48 SATP value from the kernel root
/// page table, and calls `sbi_hart_start`. Returns `false` if SBI rejected the
/// request (e.g. invalid hart ID or implementation error).
///
/// # Parameters
/// - `trampoline_pa`: physical address of the trampoline page.
/// - `cpu_idx`: logical CPU index (1-based) for this AP.
/// - `hart_id`: RISC-V hart ID of the AP to start.
/// - `entry_fn`: virtual address of `kernel_entry_ap`.
/// - `stack_top`: kernel idle-thread stack top for this AP.
///
/// # Safety
/// - [`setup_trampoline`] must have been called.
/// - Phase 3–8 must be active (direct map, heap, scheduler state).
/// - `hart_id` must be a valid secondary hart listed in `BootInfo::cpu_ids`.
#[cfg(not(test))]
pub unsafe fn start_ap(
    trampoline_pa: u64,
    cpu_idx: u32,
    hart_id: u32,
    entry_fn: u64,
    stack_top: u64,
) -> bool
{
    // Sv48 SATP: mode=9 (bits[63:60]), ASID=0, PPN = root_pa >> 12.
    let root_pa = crate::mm::paging::kernel_pml4_pa();
    let satp = (9u64 << 60) | (root_pa >> 12);

    // SAFETY: setup_trampoline called; direct map active.
    unsafe {
        setup_ap_params(trampoline_pa, cpu_idx, satp, entry_fn, stack_top);
    }

    let params_pa =
        trampoline_pa + PARAMS_OFFSET as u64 + (u64::from(cpu_idx) - 1) * PARAM_SLOT_SIZE as u64;

    // SAFETY: trampoline_pa is identity-mapped RWX; params_pa is in the same page.
    unsafe { sbi_hart_start(u64::from(hart_id), trampoline_pa, params_pa) }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn start_ap(
    _trampoline_pa: u64,
    _cpu_idx: u32,
    _hart_id: u32,
    _entry_fn: u64,
    _stack_top: u64,
) -> bool
{
    false
}

/// Write per-AP startup parameters into the trampoline page.
///
/// Parameters are stored at `trampoline_pa + PARAMS_OFFSET + (cpu_idx-1)*PARAM_SLOT_SIZE`.
/// The AP receives the physical address of its slot in `a1` and loads all
/// four values before enabling paging.
///
/// # Safety
/// - Direct map must be active (Phase 3 complete).
/// - `trampoline_pa` must match the value passed to [`setup_trampoline`].
/// - `cpu_idx` must be in `1..cpu_count` (< 64); the param slot must lie
///   within the trampoline page.
#[cfg(not(test))]
pub unsafe fn setup_ap_params(
    trampoline_pa: u64,
    cpu_idx: u32,
    satp: u64,
    entry_virt: u64,
    stack_top: u64,
)
{
    let slot_off = PARAMS_OFFSET + (cpu_idx as usize - 1) * PARAM_SLOT_SIZE;
    let base = (DIRECT_MAP_BASE + trampoline_pa + slot_off as u64) as *mut u64;
    // SAFETY: direct map active; 4 × u64 stay within the 4 KiB page (slot_off ≤ 0x7E0).
    unsafe {
        base.add(PARAM_SATP / 8).write_volatile(satp);
        base.add(PARAM_ENTRY / 8).write_volatile(entry_virt);
        base.add(PARAM_STACK / 8).write_volatile(stack_top);
        base.add(PARAM_CPU_ID / 8)
            .write_volatile(u64::from(cpu_idx));
    }
}
