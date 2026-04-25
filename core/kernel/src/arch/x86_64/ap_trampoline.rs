// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/ap_trampoline.rs

//! AP (Application Processor) SIPI startup trampoline for x86-64.
//!
//! On x86-64, the SIPI instruction starts an AP in 16-bit real mode at the
//! physical address `vector << 12` (the SIPI vector in bits[7:0] of the ICR).
//! The trampoline transitions the AP through:
//!   real mode (16-bit) → protected mode (32-bit) → long mode (64-bit)
//! …then jumps to [`kernel_entry_ap`] in the kernel's direct-map virtual
//! address space.
//!
//! ## Trampoline page layout (4 KiB page at physical `AP_PAGE`)
//!
//! ```text
//! 0x000  Real-mode code  (24 bytes): cli, load GDTR, enable PE, far-jmp to PM32
//! 0x018  Padding
//! 0x020  RM far-jmp target (6 B): [u32: AP_PAGE+0x90, u16: 0x08]  — BSP-patched
//! 0x026  Padding
//! 0x040  GDTR descriptor (6 B): [u16: limit=0x1F, u32: base=AP_PAGE+0x48] — BSP-patched
//! 0x046  Padding
//! 0x048  GDT (32 bytes, 4 entries): null, code32, code64, data
//! 0x068  AP params (40 bytes): pml4_phys, cpu_id, stack_top, entry_fn, ist1_top, ist2_top
//! 0x090  PM32 code (95 bytes): set segs, COM1 diag, enable PAE/LME/PG, far-jmp to LM64
//! 0x0DD  Padding
//! 0x0F8  LM64 far-jmp target (6 B): [u32: AP_PAGE+0x100, u16: 0x10] — BSP-patched
//! 0x0FE  Padding
//! 0x100  LM64 relay stub (28 bytes): load RSP/args from params, jump to entry_fn
//! ```
//!
//! ## BSP patching
//! Before sending SIPI, the BSP calls [`setup_trampoline`] (once) and then
//! [`setup_ap_params`] (per AP). Both write through the kernel's direct physical
//! map at `DIRECT_MAP_BASE + AP_PAGE`.
//!
//! ## Adding / modifying
//! - To pass more per-AP arguments: extend the params area (0x68–0x8F) and
//!   update the LM64 relay stub encoding and `setup_ap_params`.
//! - If the trampoline binary changes, recompute byte offsets carefully and
//!   update `TRAMP_PATCH_*` constants. The host-side tests verify all offsets.

// cast_possible_truncation: u64→u32 trampoline vector shift; value < 256 by design.
#![allow(clippy::cast_possible_truncation)]

#[cfg(not(test))]
use crate::mm::paging::DIRECT_MAP_BASE;

// ── Trampoline byte offsets ───────────────────────────────────────────────────

/// Offset of the 6-byte far-jmp target used by real-mode code to jump to PM32.
/// Layout: [u32 little-endian: `AP_PAGE+0x90`, u16 little-endian: 0x0008].
pub const TRAMP_PATCH_RM_FAR_JMP: usize = 0x20;

/// Offset of the GDTR descriptor within the trampoline page.
/// Layout: [u16: GDT limit = 0x001F, u32: GDT linear base = `AP_PAGE+0x48`].
pub const TRAMP_PATCH_GDTR: usize = 0x40;

/// Offset of the GDT within the trampoline page (four 8-byte descriptors).
#[allow(dead_code)] // Documented layout constant; used as a reference even if not accessed directly
pub const TRAMP_GDT_OFFSET: usize = 0x48;

/// Byte offset of AP startup parameters within the trampoline page.
///
/// Layout (40 bytes):
/// ```text
/// +0  pml4_phys: u32   — physical address of kernel root page table
/// +4  cpu_id:    u32   — logical CPU index for this AP
/// +8  stack_top: u64   — kernel stack top (loaded into RSP before jumping)
/// +16 entry_fn:  u64   — virtual address of kernel_entry_ap
/// +24 ist1_top:  u64   — IST1 stack top (NMI handler)
/// +32 ist2_top:  u64   — IST2 stack top (double-fault handler)
/// ```
pub const TRAMP_PARAMS: usize = 0x68;

/// Offset of the `imm32` in `MOV ESP, imm32` (PM32 code), patched with
/// `AP_PAGE + 0xC0` (temporary stack for PM32 code).
pub const TRAMP_PATCH_PM32_STACK: usize = 0x9F;

/// Offset of the 6-byte far-jmp target used by PM32 code to enter LM64.
/// Layout: [u32 little-endian: `AP_PAGE+0x100`, u16 little-endian: 0x0010].
pub const TRAMP_PATCH_LM64_FAR_JMP: usize = 0xF8;

// ── Param sub-offsets (relative to TRAMP_PARAMS) ─────────────────────────────

const PARAM_PML4: usize = 0; // u32
const PARAM_CPU_ID: usize = 4; // u32
const PARAM_STACK: usize = 8; // u64
const PARAM_ENTRY_FN: usize = 16; // u64
const PARAM_IST1: usize = 24; // u64
const PARAM_IST2: usize = 32; // u64

// ── GDT descriptor constants ──────────────────────────────────────────────────

/// Null GDT descriptor (8 bytes, all zero).
const GDT_NULL: u64 = 0x0000_0000_0000_0000;

/// 32-bit flat code segment (ring 0, DPL=0, selector 0x08 in trampoline GDT).
/// Base=0, limit=4GiB, G=1, D=1, not L, exec/readable, present.
const GDT_CODE32: u64 = 0x00CF_9A00_0000_FFFF;

/// 64-bit code segment (ring 0, DPL=0, selector 0x10 in trampoline GDT).
/// Base=0, limit irrelevant in 64-bit, L=1, exec, present.
const GDT_CODE64: u64 = 0x0020_9A00_0000_0000;

/// Flat data segment (ring 0, DPL=0, selector 0x18 in trampoline GDT).
/// Base=0, limit=4GiB, G=1, D=1, data/writable, present.
const GDT_DATA: u64 = 0x00CF_9200_0000_FFFF;

// ── Trampoline machine-code template ─────────────────────────────────────────

/// Fixed-content trampoline bytes copied to the AP trampoline page.
///
/// Variable addresses (`AP_PAGE`, `pml4_phys`, etc.) are zeroed here and written
/// by [`setup_trampoline`] / [`setup_ap_params`] at runtime.
///
/// See module-level layout table for byte-offset annotations.
const TRAMPOLINE_TEMPLATE: [u8; 0x11C] = {
    let mut t = [0u8; 0x11C];

    // ── Real-mode code (0x00–0x17) ────────────────────────────────────────────
    // FA                 cli
    // 8C C8              mov ax, cs
    // 8E D8              mov ds, ax
    // 66 0F 01 16 40 00  data32 lgdt [0x0040]   ; load 6-byte GDTR from DS:0x40
    // 0F 20 C0           mov eax, cr0
    // 0C 01              or al, 1               ; set PE bit
    // 0F 22 C0           mov cr0, eax
    // 66 FF 2E 20 00     data32 jmp far [0x0020] ; jmp to [DS:0x0020] (PM32 target)
    let rm: [u8; 24] = [
        0xFA, // cli
        0x8C, 0xC8, // mov ax, cs
        0x8E, 0xD8, // mov ds, ax
        0x66, 0x0F, 0x01, 0x16, 0x40, 0x00, // data32 lgdt [0x0040]
        0x0F, 0x20, 0xC0, // mov eax, cr0
        0x0C, 0x01, // or al, 1
        0x0F, 0x22, 0xC0, // mov cr0, eax
        0x66, 0xFF, 0x2E, 0x20, 0x00, // data32 jmp far [0x0020]
    ];
    let mut i = 0;
    while i < rm.len()
    {
        t[i] = rm[i];
        i += 1;
    }
    // 0x18..0x1F: zero padding — far-jmp target written by setup_trampoline

    // ── GDTR limit (0x40–0x41): constant 0x001F ───────────────────────────────
    // GDT has 4 entries × 8 bytes = 32 bytes; limit = 32 − 1 = 31 = 0x1F.
    t[0x40] = 0x1F;
    t[0x41] = 0x00;
    // 0x42..0x45: GDTR base (AP_PAGE+0x48) written by setup_trampoline.

    // ── GDT entries (0x48–0x67) ───────────────────────────────────────────────
    let gdt_null = GDT_NULL.to_le_bytes();
    let gdt_c32 = GDT_CODE32.to_le_bytes();
    let gdt_c64 = GDT_CODE64.to_le_bytes();
    let gdt_data = GDT_DATA.to_le_bytes();
    let mut j = 0;
    while j < 8
    {
        t[0x48 + j] = gdt_null[j];
        j += 1;
    }
    j = 0;
    while j < 8
    {
        t[0x50 + j] = gdt_c32[j];
        j += 1;
    }
    j = 0;
    while j < 8
    {
        t[0x58 + j] = gdt_c64[j];
        j += 1;
    }
    j = 0;
    while j < 8
    {
        t[0x60 + j] = gdt_data[j];
        j += 1;
    }

    // ── AP params (0x68–0x8F): zeroed, filled by setup_ap_params ─────────────

    // ── PM32 code (0x90–0xEE) ─────────────────────────────────────────────────
    //
    // After the real-mode far jmp, CS=0x08 (32-bit flat code), EIP=AP_PAGE+0x90.
    //
    // 66 B8 18 00          mov ax, 0x18        ; data seg selector
    // 8E D8                mov ds, ax
    // 8E C0                mov es, ax
    // 8E E0                mov fs, ax
    // 8E E8                mov gs, ax
    // 8E D0                mov ss, ax
    // BC 00 00 00 00        mov esp, <AP_PAGE+0x200>  ; imm32 at +0x9F, BSP-patched
    //                                                 ; Must be above 0x11B (end of all
    //                                                 ; trampoline code) — the `call +0`
    //                                                 ; push goes to ESP-4; if ESP ≤ 0xC0
    //                                                 ; this overwrites PM32 code bytes.
    // [0xA3–0xB4: 18 NOPs — reserved for future diagnostics]
    // E8 00 00 00 00        call +0                   ; push EIP of next instr
    // 5B                   pop ebx                   ; EBX = AP_PAGE + offset
    // 81 E3 00 F0 FF FF     and ebx, 0xFFFFF000       ; EBX = AP_PAGE
    // 8B 43 68              mov eax, [ebx+0x68]       ; pml4_phys
    // 0F 22 D8              mov cr3, eax
    // 0F 20 E0              mov eax, cr4
    // 83 C8 20              or eax, 0x20              ; PAE
    // 0F 22 E0              mov cr4, eax
    // B9 80 00 00 C0        mov ecx, 0xC0000080       ; IA32_EFER MSR
    // 0F 32                 rdmsr
    // 0D 00 09 00 00        or eax, 0x900             ; LME (bit 8) + NXE (bit 11)
    // 0F 30                 wrmsr                     ; NXE required: kernel PTEs use
    //                                                 ; NO_EXECUTE (bit 63); without NXE
    //                                                 ; those bits are reserved and cause
    //                                                 ; a page fault (RSVD) → triple fault
    // 0F 20 C0              mov eax, cr0
    // 0D 00 00 01 80        or eax, 0x80010000        ; PG | WP
    // 0F 22 C0              mov cr0, eax
    // FF AB F8 00 00 00     jmp far [ebx + 0xF8]      ; → LM64 far-jmp target
    let pm32: [u8; 95] = [
        0x66, 0xB8, 0x18, 0x00, // mov ax, 0x18
        0x8E, 0xD8, // mov ds, ax
        0x8E, 0xC0, // mov es, ax
        0x8E, 0xE0, // mov fs, ax
        0x8E, 0xE8, // mov gs, ax
        0x8E, 0xD0, // mov ss, ax
        0xBC, 0x00, 0x00, 0x00, 0x00, // mov esp, imm32  (0x9E; imm32 at 0x9F)
        // ── 18 NOPs (0xA3–0xB4): reserved slot, preserves call +0 offset ──────
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 9 NOPs
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 9 NOPs
        // ─────────────────────────────────────────────────────────────────────
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
        0x5B, // pop ebx
        0x81, 0xE3, 0x00, 0xF0, 0xFF, 0xFF, // and ebx, 0xFFFFF000
        0x8B, 0x43, 0x68, // mov eax, [ebx+0x68]
        0x0F, 0x22, 0xD8, // mov cr3, eax
        0x0F, 0x20, 0xE0, // mov eax, cr4
        0x83, 0xC8, 0x20, // or eax, 0x20
        0x0F, 0x22, 0xE0, // mov cr4, eax
        0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080
        0x0F, 0x32, // rdmsr
        0x0D, 0x00, 0x09, 0x00, 0x00, // or eax, 0x900  ; LME (bit 8) + NXE (bit 11)
        0x0F, 0x30, // wrmsr
        0x0F, 0x20, 0xC0, // mov eax, cr0
        0x0D, 0x00, 0x00, 0x01, 0x80, // or eax, 0x80010000
        0x0F, 0x22, 0xC0, // mov cr0, eax
        0xFF, 0xAB, 0xF8, 0x00, 0x00, 0x00, // jmp far [ebx+0x000000F8]
    ];
    j = 0;
    while j < pm32.len()
    {
        t[0x90 + j] = pm32[j];
        j += 1;
    }
    // 0xEF..0xF7: zero padding

    // ── LM64 far-jmp target (0xF8–0xFD) ──────────────────────────────────────
    // [0xF8..0xFB]: u32 = AP_PAGE+0x100  (BSP-patched)
    // [0xFC..0xFD]: u16 = 0x0010        (64-bit code segment)
    t[0xFC] = 0x10;
    t[0xFD] = 0x00;

    // ── LM64 relay stub (0x100–0x113) ────────────────────────────────────────
    //
    // Entered at VA=AP_PAGE+0x100 (identity-mapped). Loads stack and args from
    // the params area (RIP-relative), then jumps to entry_fn in high VA space.
    //
    // 48 8D 1D 61 FF FF FF  lea rbx, [rip-0x9F]   ; rbx = AP_PAGE+0x68 (params)
    //                                              ; RIP_next = AP_PAGE+0x107
    //                                              ; disp = 0x68-0x107 = -0x9F
    // 48 8B 63 08           mov rsp, [rbx+8]       ; stack_top (PARAM_STACK=8)
    // 8B 7B 04              mov edi, [rbx+4]       ; cpu_id   (PARAM_CPU_ID=4)
    // 48 8B 73 18           mov rsi, [rbx+24]      ; ist1_top (PARAM_IST1=24)
    // 48 8B 53 20           mov rdx, [rbx+32]      ; ist2_top (PARAM_IST2=32)
    // 48 8B 43 10           mov rax, [rbx+16]      ; entry_fn (PARAM_ENTRY_FN=16)
    // FF E0                 jmp rax
    let lm64: [u8; 28] = [
        0x48, 0x8D, 0x1D, 0x61, 0xFF, 0xFF, 0xFF, // lea rbx, [rip-0x9F]
        0x48, 0x8B, 0x63, 0x08, // mov rsp, [rbx+8]
        0x8B, 0x7B, 0x04, // mov edi, [rbx+4]
        0x48, 0x8B, 0x73, 0x18, // mov rsi, [rbx+24]
        0x48, 0x8B, 0x53, 0x20, // mov rdx, [rbx+32]
        0x48, 0x8B, 0x43, 0x10, // mov rax, [rbx+16]
        0xFF, 0xE0, // jmp rax
    ];
    j = 0;
    while j < lm64.len()
    {
        t[0x100 + j] = lm64[j];
        j += 1;
    }

    t
};

// ── Helper: write a u32 at a byte offset within the direct-mapped trampoline ──

/// Write a little-endian `u32` at byte `offset` within the direct-mapped
/// trampoline page at `tramp_virt` (= `DIRECT_MAP_BASE + ap_trampoline_phys`).
///
/// Always writes byte-by-byte to handle unaligned offsets (e.g. the GDTR base
/// at page offset 0x42). This is boot code run once; byte writes are fine.
///
/// # Safety
/// `tramp_virt` must be a valid writable virtual address within the direct map.
#[cfg(not(test))]
unsafe fn write_u32(tramp_virt: u64, offset: usize, val: u32)
{
    let p = (tramp_virt + offset as u64) as *mut u8;
    let b = val.to_le_bytes();
    // SAFETY: `tramp_virt` is a valid writable virtual address within the direct map
    // (enforced by the caller), and `offset` is within the trampoline page bounds.
    unsafe {
        core::ptr::write_volatile(p.add(0), b[0]);
        core::ptr::write_volatile(p.add(1), b[1]);
        core::ptr::write_volatile(p.add(2), b[2]);
        core::ptr::write_volatile(p.add(3), b[3]);
    }
}

/// Write a little-endian `u16` at byte `offset`.
///
/// # Safety
/// `tramp_virt` must be a valid writable virtual address within the direct map.
#[cfg(not(test))]
unsafe fn write_u16(tramp_virt: u64, offset: usize, val: u16)
{
    let p = (tramp_virt + offset as u64) as *mut u8;
    let b = val.to_le_bytes();
    // SAFETY: `tramp_virt` is a valid writable virtual address within the direct map
    // (enforced by the caller), and `offset` is within the trampoline page bounds.
    unsafe {
        core::ptr::write_volatile(p.add(0), b[0]);
        core::ptr::write_volatile(p.add(1), b[1]);
    }
}

/// Write a little-endian `u64` at byte `offset`.
#[cfg(not(test))]
unsafe fn write_u64(tramp_virt: u64, offset: usize, val: u64)
{
    let p = (tramp_virt + offset as u64) as *mut u8;
    let b = val.to_le_bytes();
    // SAFETY: tramp_virt is valid direct-map address; offset within page; writes within bounds.
    unsafe {
        core::ptr::write_volatile(p.add(0), b[0]);
        core::ptr::write_volatile(p.add(1), b[1]);
        core::ptr::write_volatile(p.add(2), b[2]);
        core::ptr::write_volatile(p.add(3), b[3]);
        core::ptr::write_volatile(p.add(4), b[4]);
        core::ptr::write_volatile(p.add(5), b[5]);
        core::ptr::write_volatile(p.add(6), b[6]);
        core::ptr::write_volatile(p.add(7), b[7]);
    }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Copy the trampoline template to the AP trampoline page and patch all
/// address-dependent fields that are constant across all APs.
///
/// Must be called once before the first [`setup_ap_params`] / SIPI sequence.
///
/// # Safety
/// - Phase 3 must be active (direct physical map live).
/// - `ap_trampoline_phys` must be the physical address passed in [`BootInfo`].
#[cfg(not(test))]
pub unsafe fn setup_trampoline(ap_trampoline_phys: u64)
{
    let ap_page = ap_trampoline_phys;
    let virt = DIRECT_MAP_BASE + ap_page;

    // Copy the fixed template.
    // SAFETY: virt is within the direct map (Phase 3 active); 0x114 < 4096 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            TRAMPOLINE_TEMPLATE.as_ptr(),
            virt as *mut u8,
            TRAMPOLINE_TEMPLATE.len(),
        );
    }

    // Patch: real-mode far-jmp target at 0x20 → [u32: AP_PAGE+0x90, u16: 0x0008]
    // cast_possible_truncation: ap_page is a SIPI vector << 12, always < 1 MiB; fits u32
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: virt is direct-map address; write_u32/u16 write within page bounds.
    unsafe {
        write_u32(virt, TRAMP_PATCH_RM_FAR_JMP, (ap_page + 0x90) as u32);
        write_u16(virt, TRAMP_PATCH_RM_FAR_JMP + 4, 0x0008);
    }

    // Patch: GDTR base at 0x42 → AP_PAGE+0x48
    // cast_possible_truncation: ap_page is always < 1 MiB; fits u32
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: virt is direct-map address; write within page bounds.
    unsafe {
        write_u32(virt, TRAMP_PATCH_GDTR + 2, (ap_page + 0x48) as u32);
    }

    // Patch: PM32 temporary stack address at 0x9F → AP_PAGE+0x200.
    // Must be above all trampoline code (which ends at 0x11B) to avoid the
    // `call +0` push clobbering code bytes. 0x200 is well within the 4 KiB page.
    // cast_possible_truncation: ap_page is always < 1 MiB; fits u32
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: virt is direct-map address; write within page bounds.
    unsafe {
        write_u32(virt, TRAMP_PATCH_PM32_STACK, (ap_page + 0x200) as u32);
    }

    // Patch: LM64 far-jmp target at 0xF8 → [u32: AP_PAGE+0x100, u16: 0x0010]
    // cast_possible_truncation: ap_page is always < 1 MiB; fits u32
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: virt is direct-map address; writes within page bounds.
    unsafe {
        write_u32(virt, TRAMP_PATCH_LM64_FAR_JMP, (ap_page + 0x100) as u32);
        write_u16(virt, TRAMP_PATCH_LM64_FAR_JMP + 4, 0x0010);
    }
}

/// Write per-AP startup parameters into the trampoline page.
///
/// Must be called immediately before sending the SIPI for `cpu_id`.
/// Only one AP may use the trampoline at a time (the BSP serialises startup).
///
/// # Parameters
/// - `ap_trampoline_phys`: physical address of the trampoline page.
/// - `cpu_id`: logical CPU index (0-based) for this AP.
/// - `pml4_phys`: physical address of the kernel root page table.
/// - `stack_top`: kernel stack top for this AP's idle thread.
/// - `entry_fn`: virtual address of `kernel_entry_ap` to jump to.
/// - `ist1_top`: IST1 stack top (NMI).
/// - `ist2_top`: IST2 stack top (double-fault).
///
/// # Safety
/// Phase 3 must be active. `setup_trampoline` must have been called first.
#[cfg(not(test))]
pub unsafe fn setup_ap_params(
    ap_trampoline_phys: u64,
    cpu_id: u32,
    pml4_phys: u32,
    stack_top: u64,
    entry_fn: u64,
    ist1_top: u64,
    ist2_top: u64,
)
{
    let virt = DIRECT_MAP_BASE + ap_trampoline_phys;
    let base = virt + TRAMP_PARAMS as u64;

    // SAFETY: base is direct-map address; writes within parameter block bounds.
    unsafe {
        write_u32(base, PARAM_PML4, pml4_phys);
        write_u32(base, PARAM_CPU_ID, cpu_id);
        write_u64(base, PARAM_STACK, stack_top);
        write_u64(base, PARAM_ENTRY_FN, entry_fn);
        write_u64(base, PARAM_IST1, ist1_top);
        write_u64(base, PARAM_IST2, ist2_top);
    }
}

/// Start one AP: allocate IST stacks, write params, send INIT+SIPI.
///
/// Returns `true` unconditionally — SIPI delivery success is detected via
/// `APS_READY` after this call.
///
/// # Parameters
/// - `trampoline_pa`: physical address of the trampoline page (from `BootInfo`).
/// - `cpu_idx`: logical CPU index (1-based) for this AP.
/// - `apic_id`: local APIC ID of the target AP.
/// - `entry_fn`: virtual address of `kernel_entry_ap`.
/// - `stack_top`: kernel idle-thread stack top for this AP.
///
/// # Safety
/// - [`setup_trampoline`] must have been called.
/// - Phase 3–8 must be active (direct map, heap, IDT, scheduler state).
#[cfg(not(test))]
pub unsafe fn start_ap(
    trampoline_pa: u64,
    cpu_idx: u32,
    apic_id: u32,
    entry_fn: u64,
    stack_top: u64,
) -> bool
{
    // Allocate IST stacks (8 KiB each, leaked so they live for the CPU's lifetime).
    // SAFETY: heap is active (Phase 4); these are never freed.
    let ist1 = alloc::boxed::Box::leak(alloc::vec![0u8; 8192].into_boxed_slice());
    let ist1_top = ist1.as_ptr() as u64 + 8192;
    let ist2 = alloc::boxed::Box::leak(alloc::vec![0u8; 8192].into_boxed_slice());
    let ist2_top = ist2.as_ptr() as u64 + 8192;

    let pml4_pa = crate::mm::paging::kernel_pml4_pa() as u32;

    // SAFETY: setup_trampoline called; direct map active.
    unsafe {
        setup_ap_params(
            trampoline_pa,
            cpu_idx,
            pml4_pa,
            stack_top,
            entry_fn,
            ist1_top,
            ist2_top,
        );
        super::interrupts::start_ap(apic_id, trampoline_pa);
    }
    true
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn start_ap(
    _trampoline_pa: u64,
    _cpu_idx: u32,
    _apic_id: u32,
    _entry_fn: u64,
    _stack_top: u64,
) -> bool
{
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn trampoline_template_size()
    {
        // Template must fit within one 4 KiB page.
        assert!(TRAMPOLINE_TEMPLATE.len() <= 4096);
    }

    #[test]
    fn rm_code_starts_with_cli()
    {
        assert_eq!(
            TRAMPOLINE_TEMPLATE[0], 0xFA,
            "expected cli (0xFA) at offset 0"
        );
    }

    #[test]
    fn gdtr_limit_is_0x1f()
    {
        let limit = u16::from_le_bytes([TRAMPOLINE_TEMPLATE[0x40], TRAMPOLINE_TEMPLATE[0x41]]);
        assert_eq!(limit, 0x001F, "GDTR limit must be 31 (4 entries × 8 − 1)");
    }

    #[test]
    fn gdt_null_is_zero()
    {
        let null = u64::from_le_bytes(TRAMPOLINE_TEMPLATE[0x48..0x50].try_into().unwrap());
        assert_eq!(null, GDT_NULL);
    }

    #[test]
    fn gdt_code32_descriptor()
    {
        let c32 = u64::from_le_bytes(TRAMPOLINE_TEMPLATE[0x50..0x58].try_into().unwrap());
        assert_eq!(c32, GDT_CODE32);
    }

    #[test]
    fn gdt_code64_descriptor()
    {
        let c64 = u64::from_le_bytes(TRAMPOLINE_TEMPLATE[0x58..0x60].try_into().unwrap());
        assert_eq!(c64, GDT_CODE64);
        // L bit (bit 53 of raw descriptor = bit 21 of high dword) must be set.
        assert!(
            c64 & (1 << 53) != 0,
            "64-bit code segment must have L bit set"
        );
    }

    #[test]
    fn gdt_data_descriptor()
    {
        let data = u64::from_le_bytes(TRAMPOLINE_TEMPLATE[0x60..0x68].try_into().unwrap());
        assert_eq!(data, GDT_DATA);
    }

    #[test]
    fn lm64_stub_starts_at_0x100()
    {
        // First byte of LM64 relay stub: REX.W prefix (0x48) of lea rbx, [rip-...]
        assert_eq!(TRAMPOLINE_TEMPLATE[0x100], 0x48);
        assert_eq!(TRAMPOLINE_TEMPLATE[0x101], 0x8D);
        assert_eq!(TRAMPOLINE_TEMPLATE[0x102], 0x1D);
    }

    #[test]
    fn lm64_rip_disp_is_minus_0x9f()
    {
        // Bytes [0x103..0x107]: disp32 = -0x9F = 0xFFFFFF61 (little-endian: 61 FF FF FF)
        let disp = u32::from_le_bytes(TRAMPOLINE_TEMPLATE[0x103..0x107].try_into().unwrap());
        assert_eq!(disp, 0xFFFFFF61u32);
    }

    #[test]
    fn lm64_ends_with_jmp_rax()
    {
        // Last two bytes of the LM64 stub (at 0x11A–0x11B): FF E0 (jmp rax).
        // Stub layout: 7+4+3+4+4+4+2 = 28 bytes starting at 0x100 → ends at 0x11B.
        assert_eq!(TRAMPOLINE_TEMPLATE[0x11A], 0xFF);
        assert_eq!(TRAMPOLINE_TEMPLATE[0x11B], 0xE0);
    }

    #[test]
    fn lm64_selector_in_far_jmp_target()
    {
        // Bytes 0xFC–0xFD: u16 = 0x0010 (64-bit code segment selector)
        let sel = u16::from_le_bytes([TRAMPOLINE_TEMPLATE[0xFC], TRAMPOLINE_TEMPLATE[0xFD]]);
        assert_eq!(sel, 0x0010);
    }

    #[test]
    fn pm32_mov_esp_opcode()
    {
        // `mov esp, imm32` is `BC imm32`. Opcode must be 0xBC at 0x9E.
        assert_eq!(
            TRAMPOLINE_TEMPLATE[0x9E], 0xBC,
            "expected mov esp opcode (BC) at 0x9E"
        );
    }

    #[test]
    fn pm32_jmp_far_encoding()
    {
        // PM32 (95 bytes starting at 0x90) ends with `FF AB F8 00 00 00`
        // (jmp far [ebx+0xF8]). Last 6 bytes at page offset 0x90+89 = 0xE9.
        let end = &TRAMPOLINE_TEMPLATE[0xE9..0xEF];
        assert_eq!(end, &[0xFF, 0xAB, 0xF8, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tramp_param_offsets_fit_in_region()
    {
        // All params must lie within the 40-byte region [0x68..0x90).
        assert!(TRAMP_PARAMS + PARAM_IST2 + 8 <= 0x90);
    }
}
