// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/gdt.rs

//! Global Descriptor Table and Task State Segment.
//!
//! Sets up a minimal flat GDT for 64-bit kernel operation:
//! - Descriptor 0x00: null
//! - Descriptor 0x08: kernel CS (64-bit code, ring 0)
//! - Descriptor 0x10: kernel DS (data, ring 0)
//! - Descriptor 0x18: user DS  (data, ring 3)
//! - Descriptor 0x20: user CS  (64-bit code, ring 3)
//! - Descriptor 0x28: TSS low 64 bits  (first half of 128-bit system descriptor)
//! - Descriptor 0x30: TSS high 64 bits (second half)
//!
//! User DS appears before user CS because SYSRET loads:
//!   CS = STAR[63:48]+16, SS = STAR[63:48]+8
//! so the layout `user_ds(0x18), user_cs(0x20)` is required for SYSRET.
//!
//! IST stacks for double-fault and machine-check (IST1) and NMI (IST2) are
//! passed in by the caller: the BSP's are carved from the `BSP_IST_STACKS`
//! static in `interrupts`, and each AP's from the `AP_IST_STACKS` buddy slab in
//! `ap_trampoline`.
//!
//! # Modification notes
//! - To add a new ring-3 segment: insert it after `user_cs` and before the TSS
//!   pair; update the selector constants accordingly.
//! - To add more IST stacks: add IST fields to the TSS, pass the stack tops
//!   into `init`, and reference them in IDT gate descriptors.

// cast_possible_truncation: usize→u16 GDT/TSS limit casts; values are bounded by
// the struct sizes and array counts that are verified by the unit tests.
// cast_lossless: u8→u64 DPL shifts; u8 always fits in u64.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

// ── Selector constants ────────────────────────────────────────────────────────

/// Kernel code segment selector (ring 0, GDT index 1, RPL=0).
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data segment selector (ring 0, GDT index 2, RPL=0).
pub const KERNEL_DS: u16 = 0x10;
/// User data segment selector (ring 3, GDT index 3, RPL=3).
pub const USER_DS: u16 = 0x1B;
/// User code segment selector (ring 3, GDT index 4, RPL=3).
pub const USER_CS: u16 = 0x23;
/// TSS selector (GDT index 5, RPL=0). 128-bit descriptor spans 0x28–0x37.
pub const TSS_SEL: u16 = 0x28;

// ── GDT and TSS storage ───────────────────────────────────────────────────────

/// 64-bit Task State Segment — see Intel SDM Vol 3A §8.2.1.
///
/// `repr(C, packed)` is required: the hardware layout is fixed.
/// Size must be exactly 104 bytes.
///
/// Only fields used in Phase 5 are named; reserved fields are prefixed `_`.
#[repr(C, packed)]
pub struct Tss
{
    _reserved0: u32,
    /// Ring-0 stack pointer (loaded by the CPU on ring-3 → ring-0 transitions).
    pub rsp0: u64,
    _rsp1: u64,
    _rsp2: u64,
    _reserved1: u64,
    /// IST1 — used by the double-fault and machine-check gates.
    pub ist1: u64,
    /// IST2 — used by the NMI gate.
    pub ist2: u64,
    _ist3: u64,
    _ist4: u64,
    _ist5: u64,
    _ist6: u64,
    _ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    /// I/O permission bitmap offset (104 = no IOPB).
    pub iopb_offset: u16,
}

/// Size of the I/O Permission Bitmap in bytes (65536 ports / 8 bits each).
pub const IOPB_SIZE: usize = 8192;

/// `Tss::iopb_offset` while the CPU's TSS bitmap is current: the offset of
/// `TssWithIopb::iopb`.
const IOPB_OFFSET_VALID: u16 = core::mem::size_of::<Tss>() as u16;

/// `Tss::iopb_offset` that places the bitmap past the TSS limit, so every
/// ring-3 port access raises `#GP` until the CPU reloads its bitmap
/// ([`reload_invalidated_iopb`]).
const IOPB_OFFSET_INVALID: u16 = u16::MAX;

/// TSS extended with an I/O Permission Bitmap.
///
/// The hardware TSS is 104 bytes; immediately following it is the 8 KiB IOPB
/// bitmap (one bit per I/O port: 0 = permitted, 1 = denied) plus a mandatory
/// all-ones terminator byte (Intel SDM §8.5.3 requires the byte at IOPB limit
/// to be 0xFF).
///
/// The GDT TSS descriptor limit reaches the terminator:
///   limit = `offset_of!(TssWithIopb, terminator)`
///
/// `iopb_offset` in the `Tss` is [`IOPB_OFFSET_VALID`] (104, the offset of
/// `iopb` within this struct) while the CPU's bitmap is current, and
/// [`IOPB_OFFSET_INVALID`] after [`invalidate_all_iopbs`] until the CPU reloads
/// it. Every field has alignment 1 (`Tss` is packed), so `repr(C)` lays them
/// out with no padding; `align(2)` makes every instance, the per-CPU slab's
/// elements included, 2-byte aligned, so `iopb_offset` (at offset 102) is a
/// naturally aligned `u16` that another CPU can store atomically.
#[repr(C, align(2))]
pub struct TssWithIopb
{
    /// The base TSS (must be at offset 0).
    pub tss: Tss,
    /// I/O permission bitmap: bit N = port N. 0 = allow, 1 = deny.
    /// Initialised to all 0xFF (all ports denied) at boot.
    pub iopb: [u8; IOPB_SIZE],
    /// Mandatory terminator byte (must always be 0xFF per Intel SDM).
    pub terminator: u8,
}

// The AP_TSS slab is one buddy block (`alloc_zeroed_slab` rounds to a power
// of two), so it must fit the largest block even at the MAX_CPUS ceiling.
const _: () = assert!(
    crate::sched::MAX_CPUS * core::mem::size_of::<TssWithIopb>()
        <= (1 << crate::mm::buddy::MAX_ORDER) * crate::mm::PAGE_SIZE,
    "AP_TSS at MAX_CPUS exceeds the largest buddy block; raise MAX_ORDER"
);

/// The BSP's extended TSS + IOPB. Its static initializer fills the IOPB and
/// terminator with 0xFF (all ports denied) and sets `iopb_offset` to 104;
/// `init()` sets RSP0/IST1/IST2 and loads it. Boot code must call `init()`
/// before any user thread runs.
///
/// `static mut` is only written during single-threaded boot init or with
/// interrupts disabled during context switch.
#[cfg(not(test))]
static mut TSS: TssWithIopb = TssWithIopb {
    tss: Tss {
        _reserved0: 0,
        rsp0: 0,
        _rsp1: 0,
        _rsp2: 0,
        _reserved1: 0,
        ist1: 0,
        ist2: 0,
        _ist3: 0,
        _ist4: 0,
        _ist5: 0,
        _ist6: 0,
        _ist7: 0,
        _reserved2: 0,
        _reserved3: 0,
        iopb_offset: IOPB_OFFSET_VALID,
    },
    iopb: [0xFF; IOPB_SIZE], // all ports denied by default
    terminator: 0xFF,
};

/// GDT: 7 × 64-bit descriptors, in BSS.
#[cfg(not(test))]
static mut GDT: [u64; 7] = [0u64; 7];

/// Base pointer for the dynamically-sized per-CPU `[TssWithIopb; cpu_count]`
/// array. Allocated by [`init_ap_storage`] from the buddy in `sched::init_storage`
/// (Phase 4), before AP bringup. Slot `cpu_id` is the AP with that id; slot 0 is unused
/// (BSP has its own [`TSS`] static).
///
/// Each entry is ~8 KiB; the slab is sized to the boot CPU count
/// (`init_ap_storage`'s `cpu_count`) rather than `MAX_CPUS`.
///
/// Stored as an `AtomicPtr` set once by [`init_ap_storage`]. Slab entries are
/// written by `init_ap_storage` and by `init_ap` during single-threaded boot,
/// and afterwards by `set_rsp0` / `load_iopb` with interrupts disabled.
#[cfg(not(test))]
static AP_TSS_PTR: core::sync::atomic::AtomicPtr<TssWithIopb> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Number of entries in the [`AP_TSS_PTR`] slab (the boot CPU count), set
/// with it by [`init_ap_storage`].
#[cfg(not(test))]
static AP_TSS_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Base pointer for the dynamically-sized per-CPU `[[u64; 7]; cpu_count]`
/// AP-GDT array. Slot indexing matches [`AP_TSS_PTR`].
#[cfg(not(test))]
static AP_GDT_PTR: core::sync::atomic::AtomicPtr<[u64; 7]> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU AP TSS and GDT slabs sized to `cpu_count`. Called
/// from `sched::init_storage` (Phase 4, via `init_ap_percpu_storage`), before
/// any AP startup. Each slab is page-aligned and
/// zero-filled; `init_ap` overwrites the relevant fields per AP.
///
/// The IOPB region of every TSS is then filled with `0xFF` so all I/O-port
/// access is denied; `init_ap` re-applies on each AP for paranoia.
#[cfg(not(test))]
pub fn init_ap_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    let tss_bytes = cpu_count * core::mem::size_of::<TssWithIopb>();
    let tss_ptr = crate::sched::alloc_zeroed_slab::<TssWithIopb>(tss_bytes, allocator, "AP_TSS");
    // Initialise IOPB regions to 0xFF (all ports denied) for slots not yet
    // touched by init_ap. iopb_offset is u16 inside a packed struct, so use
    // write_unaligned. SAFETY: tss_ptr covers cpu_count entries.
    unsafe {
        for cpu in 0..cpu_count
        {
            let slot = tss_ptr.add(cpu);
            let iopb = core::ptr::addr_of_mut!((*slot).iopb);
            core::ptr::write_bytes(iopb.cast::<u8>(), 0xFF, IOPB_SIZE);
            let term = core::ptr::addr_of_mut!((*slot).terminator);
            core::ptr::write(term, 0xFF);
            let ofs = core::ptr::addr_of_mut!((*slot).tss.iopb_offset);
            core::ptr::write_unaligned(ofs, IOPB_OFFSET_VALID);
        }
    }
    AP_TSS_COUNT.store(cpu_count, core::sync::atomic::Ordering::Relaxed);
    AP_TSS_PTR.store(tss_ptr, core::sync::atomic::Ordering::Release);

    let gdt_bytes = cpu_count * core::mem::size_of::<[u64; 7]>();
    let gdt_ptr = crate::sched::alloc_zeroed_slab::<[u64; 7]>(gdt_bytes, allocator, "AP_GDT");
    AP_GDT_PTR.store(gdt_ptr, core::sync::atomic::Ordering::Release);
}

// ── GDTR ──────────────────────────────────────────────────────────────────────

/// Hardware GDTR format: limit (16-bit) followed immediately by base (64-bit).
///
/// Must be `packed` so there is no padding between `limit` and `base`.
#[repr(C, packed)]
struct Gdtr
{
    limit: u16,
    base: u64,
}

// ── Descriptor encoding ───────────────────────────────────────────────────────

/// Build a 64-bit long-mode code segment descriptor at `dpl` privilege level.
///
/// In 64-bit mode only P, DPL, S, type, and L matter:
/// - P=1: present
/// - S=1: code/data (not system)
/// - type=0b1010: execute/read, non-conforming
/// - L=1: 64-bit code segment
pub fn code_desc_64(dpl: u8) -> u64
{
    (1u64 << 47) // P
        | ((dpl as u64 & 3) << 45) // DPL
        | (1u64 << 44) // S
        | (0b1010u64 << 40) // type: execute+read
        | (1u64 << 53) // L
}

/// Build a 64-bit data segment descriptor at `dpl` privilege level.
///
/// In 64-bit mode data segments are nearly ignored but must be present.
/// - P=1, S=1, type=0b0010: data, writable
pub fn data_desc_64(dpl: u8) -> u64
{
    (1u64 << 47) // P
        | ((dpl as u64 & 3) << 45) // DPL
        | (1u64 << 44) // S
        | (0b0010u64 << 40) // type: data+writable
}

/// Encode the 128-bit TSS descriptor, split into two consecutive GDT entries.
///
/// Returns `(low, high)` where `low` goes into GDT\[5\] (0x28) and `high`
/// into GDT\[6\] (0x30).
///
/// Encoding:
/// - limit = offset of the terminator byte = 8296 (covers TSS + IOPB + terminator)
/// - type = 0x89: P=1, DPL=0, 64-bit TSS available
///
/// The limit must reach the terminator so the CPU can walk the I/O
/// permission bitmap when a user thread executes I/O instructions.
pub fn tss_desc(tss_addr: u64) -> (u64, u64)
{
    let limit: u64 = core::mem::offset_of!(TssWithIopb, terminator) as u64;

    let low: u64 = (limit & 0xFFFF) // [15:0]  limit[15:0]
        | ((tss_addr & 0x00FF_FFFF) << 16) // [39:16] base[23:0]
        | (0x89u64 << 40) // [47:40] P+type (TSS available)
        | (((limit >> 16) & 0xF) << 48) // [51:48] limit[19:16]
        | (((tss_addr >> 24) & 0xFF) << 56); // [63:56] base[31:24]

    let high: u64 = tss_addr >> 32; // [31:0]  base[63:32]

    (low, high)
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Populate and load the GDT and TSS, then reload all segment registers.
///
/// Called once during boot. Parameters:
/// - `kernel_stack_top`: initial RSP0 (ring-0 stack top for TSS).
/// - `ist1_top`: top of the 8 KiB IST stack shared by the double-fault and
///   machine-check gates.
/// - `ist2_top`: top of the 8 KiB NMI IST stack.
///
/// # Safety
/// Must execute at ring 0 from a single-threaded context. The `GDT` and `TSS`
/// statics must not be accessed concurrently.
#[cfg(not(test))]
pub unsafe fn init(kernel_stack_top: u64, ist1_top: u64, ist2_top: u64)
{
    // SAFETY: single-threaded boot phase; no concurrent access to static mut GDT.
    let gdt = unsafe { &mut *core::ptr::addr_of_mut!(GDT) };
    // SAFETY: single-threaded boot phase; no concurrent access to static mut TSS.
    let tss_with_iopb = unsafe { &mut *core::ptr::addr_of_mut!(TSS) };
    let tss = &mut tss_with_iopb.tss;

    // Configure TSS fields.
    tss.rsp0 = kernel_stack_top;
    tss.ist1 = ist1_top;
    tss.ist2 = ist2_top;
    // iopb_offset = 104 = offsetof(TssWithIopb, iopb) = size_of::<Tss>():
    // every TssWithIopb field has alignment 1 and Tss is exactly 104 bytes, so
    // iopb follows immediately.
    tss.iopb_offset = IOPB_OFFSET_VALID;

    // Fill GDT slots.
    gdt[0] = 0; // null
    gdt[1] = code_desc_64(0); // 0x08 kernel CS
    gdt[2] = data_desc_64(0); // 0x10 kernel DS
    gdt[3] = data_desc_64(3); // 0x18 user DS (RPL=3 via selector constant)
    gdt[4] = code_desc_64(3); // 0x20 user CS (RPL=3 via selector constant)
    // TSS descriptor limit must cover the full TssWithIopb struct.
    let tss_addr = core::ptr::addr_of!(*tss_with_iopb) as u64;
    let (tss_lo, tss_hi) = tss_desc(tss_addr);
    gdt[5] = tss_lo; // 0x28 TSS low
    gdt[6] = tss_hi; // 0x30 TSS high

    // Load GDTR.
    let gdtr = Gdtr {
        limit: (core::mem::size_of_val(gdt) - 1) as u16,
        base: gdt.as_ptr() as u64,
    };
    // SAFETY: lgdt is a privileged x86 instruction; GDT pointer is valid and
    // GDT table is static and properly aligned; executed at ring 0.
    unsafe {
        core::arch::asm!(
            "lgdt [{0}]",
            in(reg) core::ptr::addr_of!(gdtr),
            options(readonly, nostack, preserves_flags),
        );
    }

    // Reload CS by performing a far return into the kernel code segment.
    // This flushes the CPU's segment cache for CS.
    // SAFETY: KERNEL_CS references a valid GDT entry just loaded; far return
    // executed at ring 0 with valid stack and return address.
    //
    // `nostack` is intentionally absent: the body pushes twice and the
    // `retfq` pops twice (net RSP delta zero), but the asm transiently
    // writes [RSP-8] and [RSP-16]. Claiming `nostack` would license LLVM
    // to assume the red zone is untouched; only the kernel target's
    // `disable-redzone: true` makes this latent today. Be honest about
    // the body so a future target-spec change cannot break us silently.
    unsafe {
        core::arch::asm!(
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            cs  = in(reg) KERNEL_CS as u64,
            tmp = lateout(reg) _,
        );
    }

    // Reload data/stack segment registers.
    // SAFETY: KERNEL_DS references a valid GDT entry; segment selector loads
    // executed at ring 0; zeroing FS/GS is safe (GS-base is in MSR).
    unsafe {
        core::arch::asm!(
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            "xor {z:e}, {z:e}",
            "mov fs, {z:x}",
            "mov gs, {z:x}",
            ds = in(reg) KERNEL_DS,
            z  = lateout(reg) _,
            options(nostack, nomem),
        );
    }

    // Load the TSS selector.
    // SAFETY: ltr is a privileged x86 instruction; TSS_SEL references a valid
    // 128-bit TSS descriptor in the GDT just loaded; executed at ring 0.
    //
    // `nomem` is intentionally absent: `ltr` reads the 16-byte TSS
    // descriptor from the GDT in memory AND writes the descriptor's busy
    // bit back. Claiming `nomem` would license LLVM to reorder memory
    // ops across this asm, including a hypothetical future write to the
    // GDT itself; the latent hazard is real even though the GDT is
    // post-init read-only in practice today.
    unsafe {
        core::arch::asm!(
            "ltr {0:x}",
            in(reg) TSS_SEL,
            options(nostack),
        );
    }
}

/// Return the virtual address of the BSP's static TSS.
///
/// Used by `percpu::init_bsp()` to populate `(*per_cpu_ptr(0)).tss_ptr` so that
/// `set_rsp0` can locate the TSS via the GS-relative pointer regardless of
/// which CPU is executing.
#[cfg(not(test))]
pub fn bsp_tss_ptr() -> u64
{
    core::ptr::addr_of!(TSS) as u64
}

/// Update the ring-0 RSP stored in the current CPU's TSS.
///
/// Reads the current CPU's `PerCpuData::tss_ptr` via `gs:[32]` (`PERCPU_TSS_PTR_OFFSET`)
/// to locate the TSS without a global lookup. Safe to call after
/// `percpu::init_bsp()` / `percpu::init_ap()` installs GS-base.
///
/// Call before returning to ring-3 to ensure the correct kernel stack is used.
///
/// # Safety
/// Must be called at ring 0. GS-base must point to a valid `PerCpuData` with
/// `tss_ptr` set (by `percpu::init_bsp` on the BSP in Phase 5, by `init_ap`
/// on an AP during Phase 8 bringup).
#[cfg(not(test))]
pub unsafe fn set_rsp0(stack_top: u64)
{
    let tss_ptr: u64;
    // SAFETY: gs:[32] == PerCpuData::tss_ptr (PERCPU_TSS_PTR_OFFSET=32); valid
    // after percpu::init_bsp() / init_ap() sets GS-base and tss_ptr. TSS pointer
    // is valid and aligned; accessed at ring 0 with interrupts disabled during
    // context switch or from single-threaded boot context.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[32]",
            out(reg) tss_ptr,
            options(nostack, readonly, preserves_flags),
        );
        (*(tss_ptr as *mut Tss)).rsp0 = stack_top;
    }
}

/// Initialise and load a per-CPU GDT and TSS for an AP (Application Processor).
///
/// Configures the dynamic per-CPU `TssWithIopb` and `[u64; 7]` GDT slots
/// (allocated by [`init_ap_storage`] in `sched::init_storage`) with the same layout
/// as the BSP's static GDT, loads them via `lgdt` + `ltr`, and stores the
/// TSS pointer in `(*per_cpu_ptr(cpu_id)).tss_ptr`.
///
/// Called from `kernel_entry_ap` during AP startup, before `percpu::init_ap`
/// installs GS-base (the segment reload here zeroes the GS base). The BSP
/// calls `gdt::init()` (static [`GDT`] / [`TSS`]) — this function is only for APs.
///
/// # Safety
/// Must execute at ring 0 on the AP being initialised. `cpu_id` must be <
/// `CPU_COUNT`. [`init_ap_storage`] must have been called from `sched::init_storage`.
/// `percpu::init_storage` must have run so `(*per_cpu_ptr(cpu_id)).tss_ptr`
/// is writable; `percpu::init_ap(cpu_id)` runs after this function and
/// reinstalls GS-base.
#[cfg(not(test))]
pub unsafe fn init_ap(cpu_id: u32, rsp0: u64, ist1_top: u64, ist2_top: u64)
{
    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    debug_assert!(cpu_id < cpu_count);

    // Configure this AP's TSS slot in the dynamic per-CPU slab.
    // SAFETY: cpu_id < CPU_COUNT asserted; AP_TSS_PTR slab covers cpu_count
    // entries; this slot is exclusively owned by this AP during bringup.
    let tss_base = AP_TSS_PTR.load(core::sync::atomic::Ordering::Acquire);
    debug_assert!(!tss_base.is_null(), "init_ap: AP_TSS_PTR not initialised");
    // SAFETY: cpu_id < CPU_COUNT asserted; tss_base slab covers cpu_count entries.
    let tss_ptr_mut = unsafe { tss_base.add(cpu_id as usize) };
    let tss_addr = tss_ptr_mut as u64;
    // Packed-struct field writes via raw-pointer offsets — packed structs
    // forbid `&mut` to fields that aren't naturally aligned, but raw
    // pointer writes are sound.
    // SAFETY: tss_ptr_mut is unaliased; field writes stay within the struct.
    unsafe {
        let tss_inner = core::ptr::addr_of_mut!((*tss_ptr_mut).tss);
        core::ptr::write(
            tss_inner,
            Tss {
                _reserved0: 0,
                rsp0,
                _rsp1: 0,
                _rsp2: 0,
                _reserved1: 0,
                ist1: ist1_top,
                ist2: ist2_top,
                _ist3: 0,
                _ist4: 0,
                _ist5: 0,
                _ist6: 0,
                _ist7: 0,
                _reserved2: 0,
                _reserved3: 0,
                iopb_offset: IOPB_OFFSET_VALID,
            },
        );
        // The IOPB and terminator are pre-filled with 0xFF by
        // `init_ap_storage`. Re-deny on every init in case a prior
        // owner had granted ports — caller invariant says cpu_id is
        // exclusively owned, but explicit reset keeps the contract local.
        let iopb = core::ptr::addr_of_mut!((*tss_ptr_mut).iopb);
        core::ptr::write_bytes(iopb.cast::<u8>(), 0xFF, IOPB_SIZE);
    }

    // Configure this AP's GDT slot in the dynamic per-CPU slab.
    // SAFETY: cpu_id < CPU_COUNT asserted; AP_GDT_PTR slab covers cpu_count
    // entries; this slot is exclusively owned by this AP during bringup.
    let gdt_base = AP_GDT_PTR.load(core::sync::atomic::Ordering::Acquire);
    debug_assert!(!gdt_base.is_null(), "init_ap: AP_GDT_PTR not initialised");
    // SAFETY: cpu_id < CPU_COUNT asserted; gdt_base slab covers cpu_count entries.
    let gdt_ptr_mut = unsafe { gdt_base.add(cpu_id as usize) };
    // SAFETY: gdt_ptr_mut is unaliased; writes stay within the array.
    unsafe {
        (*gdt_ptr_mut)[0] = 0; // null
        (*gdt_ptr_mut)[1] = code_desc_64(0); // 0x08 kernel CS
        (*gdt_ptr_mut)[2] = data_desc_64(0); // 0x10 kernel DS
        (*gdt_ptr_mut)[3] = data_desc_64(3); // 0x18 user DS
        (*gdt_ptr_mut)[4] = code_desc_64(3); // 0x20 user CS
        let (tss_lo, tss_hi) = tss_desc(tss_addr);
        (*gdt_ptr_mut)[5] = tss_lo; // 0x28 TSS low
        (*gdt_ptr_mut)[6] = tss_hi; // 0x30 TSS high
    }

    let gdt_ptr: *const [u64; 7] = gdt_ptr_mut.cast_const();

    // Load GDTR.
    let gdtr = Gdtr {
        limit: (7 * 8 - 1) as u16,
        base: gdt_ptr as u64,
    };
    // SAFETY: lgdt is a privileged x86 instruction; GDT pointer is valid and
    // references a live, properly aligned GDT; executed at ring 0.
    unsafe {
        core::arch::asm!(
            "lgdt [{0}]",
            in(reg) core::ptr::addr_of!(gdtr),
            options(readonly, nostack, preserves_flags),
        );
    }

    // Reload CS via a far return into the kernel code segment.
    // SAFETY: KERNEL_CS references a valid GDT entry just loaded; far return
    // executed at ring 0 with valid stack and return address.
    // See `init` for why `nostack` is intentionally absent.
    unsafe {
        core::arch::asm!(
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            cs  = in(reg) KERNEL_CS as u64,
            tmp = lateout(reg) _,
        );
    }

    // Reload data/stack segment registers and zero FS/GS (GS-base is in MSR).
    // SAFETY: KERNEL_DS references a valid GDT entry; segment selector loads
    // executed at ring 0; zeroing FS/GS is safe (GS-base is in MSR).
    unsafe {
        core::arch::asm!(
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            "xor {z:e}, {z:e}",
            "mov fs, {z:x}",
            "mov gs, {z:x}",
            ds = in(reg) KERNEL_DS,
            z  = lateout(reg) _,
            options(nostack, nomem),
        );
    }

    // Load the TSS selector.
    // SAFETY: ltr is a privileged x86 instruction; TSS_SEL references a valid
    // 128-bit TSS descriptor in the GDT just loaded; executed at ring 0.
    // See `init` for why `nomem` is intentionally absent.
    unsafe {
        core::arch::asm!(
            "ltr {0:x}",
            in(reg) TSS_SEL,
            options(nostack),
        );
    }

    // Store TSS pointer directly in per-CPU data. GS-relative addressing is not
    // available here because the segment reload above (`mov gs, 0`) reset the
    // GS shadow-register base to 0; percpu::init_ap() reinstalls it afterward.
    // SAFETY: cpu_id < CPU_COUNT (caller guarantee); the PerCpuData slab entry
    // is not yet in use by any other CPU; single-CPU access during AP bringup.
    unsafe {
        let ptr = crate::percpu::per_cpu_ptr(cpu_id as usize);
        (*ptr).tss_ptr = tss_addr;
    }
}

/// The current CPU's `TssWithIopb`.
///
/// # Safety
/// GS-base must point to a valid `PerCpuData` with `tss_ptr` set.
#[cfg(not(test))]
unsafe fn current_tss() -> *mut TssWithIopb
{
    let tss_ptr: u64;
    // SAFETY: gs:[32] == PerCpuData::tss_ptr (PERCPU_TSS_PTR_OFFSET=32); valid
    // after percpu::init_bsp() / init_ap() sets GS-base and tss_ptr. The load
    // reads one GS-relative quadword, clobbers only the output register, and
    // leaves the flags and stack untouched.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[32]",
            out(reg) tss_ptr,
            options(nostack, readonly, preserves_flags),
        );
    }
    tss_ptr as *mut TssWithIopb
}

/// The `iopb_offset` field of `tss`, as an atomic another CPU may store to.
///
/// # Safety
/// `tss` points to a live `TssWithIopb`.
#[cfg(not(test))]
unsafe fn iopb_offset_of<'a>(tss: *mut TssWithIopb) -> &'a core::sync::atomic::AtomicU16
{
    // cast_ptr_alignment: `TssWithIopb` is `align(2)` and `iopb_offset` sits
    // at an even offset, so the field is 2-byte aligned.
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: caller contract; the field is a naturally aligned u16 (above),
    // and every access to it after boot goes through this atomic view.
    unsafe {
        &*core::ptr::addr_of_mut!((*tss).tss.iopb_offset).cast::<core::sync::atomic::AtomicU16>()
    }
}

/// Copy `iopb` into the TSS I/O Permission Bitmap for the current CPU and
/// mark the bitmap current.
///
/// If `iopb` is `Some`, the bitmap is copied from the thread's per-thread IOPB.
/// If `None`, the bitmap is filled with 0xFF (all ports denied).
///
/// Called on every context switch: for an incoming non-idle thread under its
/// `sched_lock`, in the hold that marks it running (with `None` when it has
/// no port bindings), and with `None` for the idle thread, which runs no
/// ring-3 code. Also called by the I/O-port bind syscall when it binds the
/// calling thread, and by [`reload_invalidated_iopb`].
///
/// # Safety
/// Must be called with interrupts disabled or from a single-CPU context.
/// GS-base must point to a valid `PerCpuData` with `tss_ptr` set.
#[cfg(not(test))]
pub unsafe fn load_iopb(iopb: Option<&[u8; IOPB_SIZE]>)
{
    // SAFETY: caller contract.
    let tss = unsafe { current_tss() };
    // SAFETY: tss points to the current CPU's TssWithIopb; interrupts disabled
    // by caller, so this CPU does not reload it concurrently; other CPUs only
    // store `iopb_offset`, atomically.
    let tss_iopb = unsafe { &mut *core::ptr::addr_of_mut!((*tss).iopb) };
    match iopb
    {
        Some(src) => tss_iopb.copy_from_slice(src),
        None => tss_iopb.fill(0xFF),
    }
    // Release: the bitmap bytes precede the offset that makes them live.
    // SAFETY: tss is live.
    unsafe { iopb_offset_of(tss) }.store(IOPB_OFFSET_VALID, core::sync::atomic::Ordering::Release);
}

/// Make every CPU reload its TSS I/O permission bitmap before its next ring-3
/// port access.
///
/// Called after a thread's bitmap changed while it may be running on another
/// CPU: an `IoPort` binding withdrawn
/// (`cap::ioport_bindings::withdraw_everywhere`), or a `SYS_IOPORT_BIND` of a
/// thread other than the caller. Sets every CPU's
/// `iopb_offset` to [`IOPB_OFFSET_INVALID`], so the next port access on each
/// raises `#GP`, whose handler reloads the running thread's current bitmap
/// ([`reload_invalidated_iopb`]) and retries the instruction. A CPU that
/// context-switches in the meantime loads its incoming thread's bitmap (the
/// all-denied one for a thread with no bindings) under that thread's
/// `sched_lock` and marks it current, which is equally fresh; only the idle
/// thread, which runs no ring-3 code, gets its all-denied bitmap outside a
/// thread lock.
/// The trailing fence makes the stores visible to every CPU before this
/// returns, so no port access after the return reads a stale bitmap.
#[cfg(not(test))]
pub fn invalidate_all_iopbs()
{
    use core::sync::atomic::Ordering;

    // SAFETY: the BSP TSS static is live for the kernel's lifetime.
    unsafe { iopb_offset_of(core::ptr::addr_of_mut!(TSS)) }
        .store(IOPB_OFFSET_INVALID, Ordering::Relaxed);
    let slab = AP_TSS_PTR.load(Ordering::Acquire);
    if !slab.is_null()
    {
        for cpu in 1..AP_TSS_COUNT.load(Ordering::Relaxed)
        {
            // SAFETY: the slab holds AP_TSS_COUNT live entries for the kernel's
            // lifetime.
            unsafe { iopb_offset_of(slab.add(cpu)) }.store(IOPB_OFFSET_INVALID, Ordering::Relaxed);
        }
    }
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// Reload the running thread's I/O permission bitmap into this CPU's TSS if
/// [`invalidate_all_iopbs`] invalidated it. Called from the `#GP` handler for
/// a fault taken in ring 3; returns `true` when it reloaded a bitmap, so the
/// faulting instruction should be retried, and `false` when the fault is to be
/// handled as a genuine one.
///
/// A retried instruction that faults again finds the offset current and is
/// handled as genuine, so a thread denied the port takes exactly one retry.
///
/// # Safety
/// `#GP` handler context for a ring-3 fault: interrupts disabled, no lock
/// held, the running thread is a user thread.
#[cfg(not(test))]
pub unsafe fn reload_invalidated_iopb() -> bool
{
    // SAFETY: GS-base is valid in exception context.
    let tss = unsafe { current_tss() };
    // SAFETY: tss is live.
    if unsafe { iopb_offset_of(tss) }.load(core::sync::atomic::Ordering::Relaxed)
        != IOPB_OFFSET_INVALID
    {
        return false;
    }
    // SAFETY: a ring-3 fault has a running user thread (contract).
    let tcb = unsafe { crate::syscall::current_tcb() };
    if tcb.is_null()
    {
        return false;
    }
    // The bitmap and its pointer are owned by the thread's sched_lock, which
    // the withdrawal walk holds while it rebuilds them.
    // SAFETY: tcb is the running thread; lock_raw/unlock_raw paired.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let iopb = (*tcb).iopb;
        let reloaded = !iopb.is_null();
        load_iopb(if reloaded { Some(&*iopb) } else { None });
        (*tcb).sched_lock.unlock_raw(saved);
        reloaded
    }
}

/// Set bits [base, base+count) to 0 in `iopb`, permitting those ports.
///
/// `base` and `count` are `u32` so the full 64K range (`base = 0`,
/// `count = 65536`) is expressible. Ports not covered by this call remain 1
/// (denied); existing permitted ranges are preserved, so multiple calls
/// accumulate permissions.
///
/// # Panics
/// Panics in debug mode if `base + count > 65536`.
pub fn permit_port_range(iopb: &mut [u8; IOPB_SIZE], base: u32, count: u32)
{
    if count == 0
    {
        return;
    }
    let end = base + count;
    debug_assert!(end <= 65536, "port range exceeds 0xFFFF");
    for port in base..end
    {
        let byte = (port / 8) as usize;
        let bit = port % 8;
        if byte < IOPB_SIZE
        {
            iopb[byte] &= !(1 << bit);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    // Hardware contract: on a ring-3 I/O instruction the CPU reads the bitmap
    // offset from the TSS (`iopb_offset`: IOPB_OFFSET_VALID while the CPU's
    // bitmap is current) and walks the I/O permission bitmap up to the TSS
    // descriptor's limit, which must reach the 0xFF terminator byte; an
    // offset past the limit (IOPB_OFFSET_INVALID) denies every port, which the
    // lazy reload after a withdrawal relies on. Another CPU stores the offset
    // atomically, so the field must be 2-byte aligned in every instance.
    #[test]
    fn tss_layout_and_descriptor_limit_cover_the_iopb_walk()
    {
        assert_eq!(core::mem::size_of::<Tss>(), 104);
        assert_eq!(
            core::mem::offset_of!(TssWithIopb, iopb),
            usize::from(IOPB_OFFSET_VALID)
        );
        let (lo, _hi) = tss_desc(0x1000);
        let limit = (lo & 0xFFFF) | (((lo >> 48) & 0xF) << 16);
        assert_eq!(
            limit,
            core::mem::offset_of!(TssWithIopb, terminator) as u64,
            "TSS descriptor limit must reach the IOPB terminator byte"
        );
        assert!(u64::from(IOPB_OFFSET_INVALID) > limit);
        assert_eq!(core::mem::align_of::<TssWithIopb>() % 2, 0);
        assert_eq!(core::mem::offset_of!(Tss, iopb_offset) % 2, 0);
    }

    #[test]
    fn tss_desc_encodes_available_tss_type_and_split_base()
    {
        let addr: u64 = 0x1234_5678_9ABC_DEF0;
        let (lo, hi) = tss_desc(addr);
        assert_eq!((lo >> 40) & 0xFF, 0x89, "P=1, DPL=0, 64-bit TSS available");
        assert_eq!((lo >> 16) & 0xFF_FFFF, addr & 0xFF_FFFF, "base[23:0]");
        assert_eq!((lo >> 56) & 0xFF, (addr >> 24) & 0xFF, "base[31:24]");
        assert_eq!(hi & 0xFFFF_FFFF, addr >> 32, "base[63:32]");
    }

    #[test]
    fn permit_port_range_clears_exactly_the_requested_ports()
    {
        let mut iopb = [0xFFu8; IOPB_SIZE];
        // Ports 3-10 span the tail of byte 0 and the head of byte 1.
        permit_port_range(&mut iopb, 3, 8);
        assert_eq!(iopb[0], 0x07, "ports 0-2 stay denied, 3-7 permitted");
        assert_eq!(iopb[1], 0xF8, "ports 8-10 permitted, 11-15 stay denied");
        assert!(
            iopb[2..].iter().all(|&b| b == 0xFF),
            "later ports untouched"
        );
    }

    #[test]
    fn permit_port_range_zero_count_is_nop()
    {
        let mut iopb = [0xFFu8; IOPB_SIZE];
        permit_port_range(&mut iopb, 100, 0);
        assert!(iopb.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn permit_port_range_reaches_the_last_port()
    {
        let mut iopb = [0xFFu8; IOPB_SIZE];
        // Port 65535 is the last valid port.
        permit_port_range(&mut iopb, 65535, 1);
        assert_eq!(iopb[IOPB_SIZE - 1], 0xFF & !(1 << 7));
        assert!(iopb[..IOPB_SIZE - 1].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn permit_port_range_covers_the_full_port_space()
    {
        let mut iopb = [0xFFu8; IOPB_SIZE];
        permit_port_range(&mut iopb, 0, 65536);
        assert!(iopb.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn permit_port_range_accumulates()
    {
        let mut iopb = [0xFFu8; IOPB_SIZE];
        permit_port_range(&mut iopb, 0, 4); // ports 0-3
        permit_port_range(&mut iopb, 4, 4); // ports 4-7
        assert_eq!(iopb[0], 0x00, "all 8 ports in byte 0 should be permitted");
    }

    #[test]
    fn kernel_cs_is_64bit_code_ring0()
    {
        let d = code_desc_64(0);
        assert!(d & (1 << 47) != 0, "P not set");
        assert!(d & (1 << 44) != 0, "S not set");
        assert!(d & (1 << 53) != 0, "L not set");
        assert_eq!((d >> 45) & 3, 0, "DPL should be 0");
    }

    #[test]
    fn user_cs_is_64bit_code_ring3()
    {
        let d = code_desc_64(3);
        assert!(d & (1 << 47) != 0, "P not set");
        assert!(d & (1 << 53) != 0, "L not set");
        assert_eq!((d >> 45) & 3, 3, "DPL should be 3");
    }

    #[test]
    fn kernel_ds_is_data_ring0_l_clear()
    {
        let d = data_desc_64(0);
        assert!(d & (1 << 47) != 0, "P not set");
        assert_eq!((d >> 45) & 3, 0, "DPL should be 0");
        assert_eq!(d & (1 << 53), 0, "L must be 0 for data");
    }

    #[test]
    fn user_ds_is_data_ring3()
    {
        let d = data_desc_64(3);
        assert_eq!((d >> 45) & 3, 3, "DPL should be 3");
    }
}
