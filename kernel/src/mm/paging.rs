// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/paging.rs

//! Kernel page table initialization (Phase 3).
//!
//! Establishes two permanent kernel mappings:
//! - **Direct physical map** at [`DIRECT_MAP_BASE`]: every 2 MiB chunk of RAM
//!   is mapped R/W- via 2 MiB large pages, so any physical address is
//!   accessible as `DIRECT_MAP_BASE + phys`.
//! - **Kernel image** at `0xFFFF_FFFF_8000_0000+`: `.text` as R-X, `.rodata`
//!   as R--, `.data`+`.bss` as RW- (W^X enforced per section).
//!
//! The boot stack's identity mapping is preserved so the CPU has a valid
//! stack immediately after `activate`.
//!
//! ## Bootstrap pool
//!
//! The buddy allocator returns physical addresses; writing to a freshly
//! allocated frame requires a virtual address — but the bootloader only
//! identity-maps specific regions, not all RAM. To avoid this chicken-and-egg
//! problem, a fixed array of [`BOOT_TABLE_POOL_SIZE`] × 4 KiB frames is placed
//! in `.bss` (zeroed, no binary bloat). Their virtual addresses are known at
//! compile time; their physical addresses are derived from the kernel VA/PA
//! offset in [`BootInfo`].
//!
//! 256 frames (1 MiB) supports direct-mapping ≈ 248 GiB of RAM. Systems that
//! exceed this limit halt with a clear fatal message.

// cast_possible_truncation: u64→usize page table index arithmetic; addresses bounded by canonical VA.
// cast_lossless: u32→u64 widening in page count arithmetic.
// inline_always: phys_to_virt/virt_to_phys are called on every memory access path; always-inline
//   avoids call overhead in these hot helpers.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::inline_always
)]

use boot_protocol::BootInfo;

// Production-only imports (linker symbols and arch paging are unavailable
// when running unit tests on the host).
#[cfg(not(test))]
use super::PAGE_SIZE;
#[cfg(not(test))]
use super::buddy::BuddyAllocator;
#[cfg(not(test))]
use crate::arch::current::paging as arch_paging;

// ── Kernel PML4 physical address ──────────────────────────────────────────────

/// Physical address of the kernel's root page table (PML4 on x86-64, Sv48 root on RISC-V).
///
/// Set once during Phase 3 by `init_kernel_page_tables`. APs load this into CR3
/// (x86-64) or `satp` (RISC-V) during the SMP startup sequence.
#[cfg(not(test))]
static KERNEL_PML4_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Return the physical address of the kernel root page table.
///
/// Returns 0 until `init_kernel_page_tables` completes (Phase 3).
#[cfg(not(test))]
pub fn kernel_pml4_pa() -> u64
{
    KERNEL_PML4_PA.load(core::sync::atomic::Ordering::Relaxed)
}

/// Test stub.
#[cfg(test)]
pub fn kernel_pml4_pa() -> u64
{
    0
}

// ── Public constants ──────────────────────────────────────────────────────────

/// Base virtual address of the direct physical map.
///
/// Every physical address `phys` is accessible at `DIRECT_MAP_BASE + phys`
/// after Phase 3 completes. The region occupies the upper half at PML4[256].
pub const DIRECT_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Size of a 2 MiB large page (used for the direct physical map).
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Convert a physical address to its direct-map virtual address.
#[inline(always)]
pub fn phys_to_virt(phys: u64) -> u64
{
    DIRECT_MAP_BASE + phys
}

/// Convert a direct-map virtual address back to a physical address.
#[inline(always)]
pub fn virt_to_phys(virt: u64) -> u64
{
    virt - DIRECT_MAP_BASE
}

// ── Error and flags types ─────────────────────────────────────────────────────

/// Errors that can occur during page table construction or modification.
#[derive(Debug, PartialEq, Eq)]
pub enum PagingError
{
    /// The static boot table pool is exhausted.
    ///
    /// Increase [`BOOT_TABLE_POOL_SIZE`] and rebuild, or reduce the amount of
    /// RAM being direct-mapped.
    OutOfFrames,
    /// The target virtual address is not mapped (used by protect/unmap walks).
    NotMapped,
}

/// Page permission flags for a mapping.
///
/// On x86-64, `readable` has no effect (all present pages are readable);
/// it is included for cross-architecture symmetry with RISC-V Sv48 which
/// has an explicit R bit.
// more_than_3_bools: PageFlags is a cross-arch PTE flag set; each bool is a distinct
// architectural attribute. A bitfield enum would need extra decode logic at every call site.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug)]
pub struct PageFlags
{
    /// Page is readable (relevant on RISC-V; has no dedicated bit on x86-64).
    // allow: x86-64 ignores this field; it is used by riscv64/paging.rs.
    #[allow(dead_code)]
    pub readable: bool,
    /// Page is writable.
    pub writable: bool,
    /// Page is executable (if `false`, the NX/X bit blocks instruction fetch).
    pub executable: bool,
    /// Force device/uncacheable memory type.
    ///
    /// On x86-64: sets PCD|PWT in the PTE (strong uncacheable).
    /// On RISC-V: QEMU virt MMIO regions are inherently device-ordered by
    /// physical address; this field is a documentation marker only.
    ///
    // TODO: On real RISC-V hardware with Svpbmt, set PTE bits
    // [62:61] = 01 (NC) when this is true. Pick up when targeting non-QEMU
    // RISC-V hardware.
    pub uncacheable: bool,
}

// ── Static boot table pool ────────────────────────────────────────────────────

/// Number of 4 KiB frames in the static boot table pool.
///
/// 256 frames = 1 MiB of BSS. Supports direct-mapping up to ≈ 248 GiB of RAM
/// (1 PML4 + 1 PDPT + 248 PDs) plus 6 frames for the kernel image and stack.
/// Increase this constant to support larger systems; rebuild is required.
pub const BOOT_TABLE_POOL_SIZE: usize = 256;

/// Contiguous 4 KiB-aligned block of zeroed BSS frames for boot page tables.
///
/// Placed in `.bss` so it occupies no space in the kernel binary.
#[cfg(not(test))]
#[repr(C, align(4096))]
struct BootTablePool
{
    frames: [[u8; 4096]; BOOT_TABLE_POOL_SIZE],
}

#[cfg(not(test))]
static mut BOOT_TABLE_POOL: BootTablePool = BootTablePool {
    frames: [[0u8; 4096]; BOOT_TABLE_POOL_SIZE],
};

// ── PoolState ─────────────────────────────────────────────────────────────────

/// Allocation state for the static boot table pool.
///
/// Handed to arch-specific mapping functions so they can allocate intermediate
/// page table frames and convert frame physical addresses back to virtual ones.
pub struct PoolState
{
    /// `kernel_virtual_base - kernel_physical_base` (wrapping arithmetic).
    ///
    /// Adding this offset to any pool frame's physical address yields its
    /// virtual address: `frame_va = frame_pa.wrapping_add(kv_minus_kp)`.
    kv_minus_kp: u64,
    pool_va_base: u64,
    pool_pa_base: u64,
    pool_capacity: usize,
    next: usize,
}

impl PoolState
{
    /// Construct for production use from [`BootInfo`].
    ///
    /// Pool physical base is derived from `BOOT_TABLE_POOL`'s virtual address
    /// and the kernel VA/PA offset supplied by the bootloader.
    ///
    /// # Safety
    /// Must be called from a single-threaded context (boot, before SMP).
    // similar_names: pool_va_base and pool_pa_base are the VA and PA of the same pool region.
    #[cfg(not(test))]
    #[allow(clippy::similar_names)]
    pub fn new(info: &BootInfo) -> Self
    {
        // SAFETY: BOOT_TABLE_POOL is in BSS; single-threaded boot access.
        let pool_va_base = core::ptr::addr_of!(BOOT_TABLE_POOL) as u64;
        let kv = info.kernel_virtual_base;
        let kp = info.kernel_physical_base;
        let pool_pa_base = pool_va_base.wrapping_sub(kv).wrapping_add(kp);
        Self {
            kv_minus_kp: kv.wrapping_sub(kp),
            pool_va_base,
            pool_pa_base,
            pool_capacity: BOOT_TABLE_POOL_SIZE,
            next: 0,
        }
    }

    /// Construct for unit tests with an explicit pool buffer.
    ///
    /// `pool_va == pool_pa` (identity mapping), so `phys_to_virt` is a no-op.
    /// `capacity` is the number of 4 KiB frames available in the buffer at
    /// `pool_va`. The buffer must remain live for the lifetime of this state.
    #[cfg(test)]
    pub fn new_for_test(pool_va: u64, capacity: usize) -> Self
    {
        Self {
            kv_minus_kp: 0,
            pool_va_base: pool_va,
            pool_pa_base: pool_va,
            pool_capacity: capacity,
            next: 0,
        }
    }

    /// Allocate one 4 KiB frame from the pool.
    ///
    /// Returns `(virtual_address, physical_address)`.
    ///
    /// # Errors
    /// `PagingError::OutOfFrames` when the pool is exhausted. Call
    /// `fatal()` in the caller if this is unacceptable.
    pub fn alloc_frame(&mut self) -> Result<(u64, u64), PagingError>
    {
        if self.next >= self.pool_capacity
        {
            return Err(PagingError::OutOfFrames);
        }
        let offset = (self.next * 4096) as u64;
        let va = self.pool_va_base + offset;
        let pa = self.pool_pa_base + offset;
        self.next += 1;
        Ok((va, pa))
    }

    /// Convert a pool frame physical address to its virtual address.
    ///
    /// Only valid for addresses that belong to the pool; the result is
    /// meaningless for arbitrary physical addresses.
    pub fn phys_to_virt(&self, phys: u64) -> u64
    {
        phys.wrapping_add(self.kv_minus_kp)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Scan the memory map for the highest `physical_base + size` across all
/// RAM-backed entries.
///
/// Only `Usable`, `Loaded`, `AcpiReclaimable`, and `Persistent` entries are
/// considered. `Reserved` entries are excluded because they may represent
/// high-address MMIO regions (`PCIe` BARs, firmware flash, LAPIC, etc.) whose
/// physical addresses can be in the hundreds-of-GiB range, which would
/// require far more page table frames than the boot pool provides.
///
/// MMIO ranges above the RAM ceiling are mapped on demand by device drivers
/// in later phases. The framebuffer, if it falls above this ceiling, is
/// handled separately by `map_framebuffer_if_needed`.
///
/// Returns 0 if the map contains no RAM entries.
pub fn compute_max_physical_address(info: &BootInfo) -> u64
{
    use boot_protocol::MemoryType;

    // SAFETY: Phase 0 validated that memory_map.entries is non-null and
    // count > 0; the region is identity-mapped by the bootloader.
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };
    entries
        .iter()
        .filter(|e| {
            matches!(
                e.memory_type,
                MemoryType::Usable
                    | MemoryType::Loaded
                    | MemoryType::AcpiReclaimable
                    | MemoryType::Persistent
            )
        })
        .map(|e| e.physical_base + e.size)
        .max()
        .unwrap_or(0)
}

// ── Page table initialization ─────────────────────────────────────────────────
// Excluded from unit test builds: references linker symbols and arch hardware.

#[cfg(not(test))]
unsafe extern "C" {
    /// Start of the kernel `.text` section (virtual address).
    static __text_start: u8;
    /// End of the kernel `.text` section (virtual address).
    static __text_end: u8;
    /// Start of the kernel `.rodata` section (virtual address).
    static __rodata_start: u8;
    /// End of the kernel `.rodata` section (virtual address).
    static __rodata_end: u8;
    /// Start of the kernel `.data` section (virtual address).
    static __data_start: u8;
    /// End of `.bss` (marks the end of the kernel's R/W region).
    static __bss_end: u8;
}

/// Initialize the kernel's own page tables and activate them (Phase 3).
///
/// After this function returns:
/// - Any physical address is accessible via `DIRECT_MAP_BASE + phys`.
/// - Kernel sections are mapped with W^X permissions.
/// - The boot stack remains accessible at its current virtual address.
///
/// `_alloc` is reserved for future phases that will allocate kernel objects
/// from the buddy allocator after page tables are active.
///
/// # Errors
/// `PagingError::OutOfFrames` if the 256-frame BSS pool is exhausted.
/// The caller should `fatal()` on this error; it indicates > 248 GiB of RAM.
///
/// In test builds this is a no-op stub so `main.rs` compiles unchanged.
#[cfg(test)]
pub fn init_kernel_page_tables(
    _info: &BootInfo,
    _alloc: &mut super::buddy::BuddyAllocator,
) -> Result<(), PagingError>
{
    Ok(())
}

// similar_names: root_va/root_pa and other va/pa pairs are VA/PA of the same frame.
#[cfg(not(test))]
#[allow(clippy::similar_names)]
pub fn init_kernel_page_tables(
    info: &BootInfo,
    _alloc: &mut BuddyAllocator,
) -> Result<(), PagingError>
{
    // Enable NX on x86-64 before we install tables with NX entries; a no-op
    // on RISC-V (X bit is always independently controllable).
    // SAFETY: single-threaded boot at ring 0 / S-mode.
    unsafe {
        arch_paging::enable_nx();
    }

    let mut pool = PoolState::new(info);

    // Allocate and zero the root page table.
    let (root_va, root_pa) = pool.alloc_frame()?;
    // SAFETY: root_va is a freshly allocated pool frame.
    unsafe {
        core::ptr::write_bytes(root_va as *mut u8, 0, 4096);
    }

    // Save the root page table physical address so APs can load it during startup.
    KERNEL_PML4_PA.store(root_pa, core::sync::atomic::Ordering::Relaxed);

    // Compute the highest physical address to determine direct map extent.
    let max_phys = compute_max_physical_address(info);
    let max_phys_rounded = (max_phys + LARGE_PAGE_SIZE - 1) & !(LARGE_PAGE_SIZE - 1);

    // ── Direct physical map ───────────────────────────────────────────────────
    // Map [0, max_phys_rounded) at DIRECT_MAP_BASE using 2 MiB large pages.
    // The framebuffer MMIO (if above max_phys) is handled separately below.
    let rw = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: false,
    };
    let mut phys: u64 = 0;
    while phys < max_phys_rounded
    {
        arch_paging::map_large_page(root_va, DIRECT_MAP_BASE + phys, phys, rw, &mut pool)?;
        phys += LARGE_PAGE_SIZE;
    }

    // ── Kernel image (W^X per section) ────────────────────────────────────────
    map_kernel_image(root_va, info, &mut pool)?;

    // ── Boot stack identity mapping ───────────────────────────────────────────
    map_boot_stack(root_va, info, &mut pool)?;

    // ── Framebuffer (only if above direct map range) ──────────────────────────
    map_framebuffer_if_needed(root_va, info, max_phys_rounded, &mut pool)?;

    // ── Architecture-specific MMIO regions ────────────────────────────────────
    // Map regions listed in arch::current::MMIO_DIRECT_MAP_REGIONS that fall
    // above max_phys_rounded (and thus outside the large-page direct map loop).
    for &(phys_base, size) in crate::arch::current::MMIO_DIRECT_MAP_REGIONS
    {
        if phys_base < max_phys_rounded
        {
            continue; // already covered by the large-page direct map
        }
        let page_mask = !(PAGE_SIZE as u64 - 1);
        let start = phys_base & page_mask;
        let end = (phys_base + size + PAGE_SIZE as u64 - 1) & page_mask;
        let rw = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };
        let mut phys = start;
        while phys < end
        {
            arch_paging::map_page(root_va, DIRECT_MAP_BASE + phys, phys, rw, &mut pool)?;
            phys += PAGE_SIZE as u64;
        }
    }

    // ── AP trampoline identity mapping (x86-64 SMP) ──────────────────────────
    // Map the AP trampoline page at its physical address as a 4 KiB identity
    // page (VA = PA). This allows APs to execute trampoline code immediately
    // after enabling paging (CR3 = kernel PML4) in the PM32 → LM64 transition,
    // before the first far jmp to the direct-map address.
    //
    // The trampoline page is physically < 1 MiB. The kernel's other mappings
    // are at high virtual addresses (DIRECT_MAP_BASE, kernel image), so the
    // low-VA identity mapping does not conflict.
    //
    // To add new low-VA trampoline pages: call map_page here with additional
    // addresses. One 4 KiB page is sufficient for the SIPI startup sequence.
    if info.ap_trampoline_page != 0
    {
        let tramp = info.ap_trampoline_page;
        // R/W/X: the trampoline page contains startup code AND writable patch areas.
        let rwx = PageFlags {
            readable: true,
            writable: true,
            executable: true,
            uncacheable: false,
        };
        arch_paging::map_page(root_va, tramp, tramp, rwx, &mut pool)?;
    }

    // Activate the new page tables. After this point the direct map is live.
    // SAFETY: we have mapped kernel code, stack, and all data accessed next.
    unsafe {
        arch_paging::activate(root_pa);
    }

    Ok(())
}

/// Map kernel image sections with W^X permissions using 4 KiB pages.
///
/// Physical addresses are derived from the kernel VA/PA offset in `info`.
#[cfg(not(test))]
fn map_kernel_image(root_va: u64, info: &BootInfo, pool: &mut PoolState)
-> Result<(), PagingError>
{
    let kv = info.kernel_virtual_base;
    let kp = info.kernel_physical_base;

    // Helper: map a virtual range [start, end) with given flags.
    // Physical address = virt - kv + kp.
    let map_range = |root_va: u64,
                     virt_start: u64,
                     virt_end: u64,
                     flags: PageFlags,
                     pool: &mut PoolState|
     -> Result<(), PagingError> {
        let mut virt = virt_start;
        while virt < virt_end
        {
            let pa = virt.wrapping_sub(kv).wrapping_add(kp);
            arch_paging::map_page(root_va, virt, pa, flags, pool)?;
            virt += PAGE_SIZE as u64;
        }
        Ok(())
    };

    // .text: readable + executable, not writable (W^X).
    let rx = PageFlags {
        readable: true,
        writable: false,
        executable: true,
        uncacheable: false,
    };
    let text_start = core::ptr::addr_of!(__text_start) as u64;
    let text_end = core::ptr::addr_of!(__text_end) as u64;
    map_range(root_va, text_start, text_end, rx, pool)?;

    // .rodata: readable only.
    let ro = PageFlags {
        readable: true,
        writable: false,
        executable: false,
        uncacheable: false,
    };
    let rodata_start = core::ptr::addr_of!(__rodata_start) as u64;
    let rodata_end = core::ptr::addr_of!(__rodata_end) as u64;
    map_range(root_va, rodata_start, rodata_end, ro, pool)?;

    // .data + .bss: readable + writable, not executable (W^X).
    let rw = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: false,
    };
    let data_start = core::ptr::addr_of!(__data_start) as u64;
    let bss_end = core::ptr::addr_of!(__bss_end) as u64;
    map_range(root_va, data_start, bss_end, rw, pool)?;

    Ok(())
}

/// Identity-map 64 KiB around the current stack pointer so it remains
/// accessible after the page table switch.
///
/// If the stack pointer is already within the kernel image mapping (unlikely
/// but possible), this is a no-op.
#[cfg(not(test))]
fn map_boot_stack(root_va: u64, info: &BootInfo, pool: &mut PoolState) -> Result<(), PagingError>
{
    let sp = arch_paging::read_stack_pointer();

    // Skip if SP already falls within the kernel image mapping.
    let kv = info.kernel_virtual_base;
    let kv_end = kv.wrapping_add(info.kernel_size);
    if sp >= kv && sp < kv_end
    {
        return Ok(());
    }

    // Identity-map 64 KiB aligned to 64 KiB around SP (VA == PA).
    let stack_base = sp & !0xFFFF;
    let rw = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: false,
    };
    let mut virt = stack_base;
    while virt < stack_base + 0x10000
    {
        arch_paging::map_page(root_va, virt, virt, rw, pool)?;
        virt += PAGE_SIZE as u64;
    }

    Ok(())
}

/// If the framebuffer's physical base is above `max_phys_rounded`, add
/// explicit 4 KiB mappings in the direct map region so it is accessible
/// after the switch. Frames within [0, `max_phys_rounded`) are already
/// covered by the large-page direct map loop.
#[cfg(not(test))]
fn map_framebuffer_if_needed(
    root_va: u64,
    info: &BootInfo,
    max_phys_rounded: u64,
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    let fb_phys = info.framebuffer.physical_base;
    if fb_phys == 0 || fb_phys < max_phys_rounded
    {
        return Ok(());
    }

    let fb_bytes = (info.framebuffer.stride * info.framebuffer.height) as u64;
    let page_mask = !(PAGE_SIZE as u64 - 1);
    let start = fb_phys & page_mask;
    let end = (fb_phys + fb_bytes + PAGE_SIZE as u64 - 1) & page_mask;

    let rw = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: false,
    };
    let mut phys = start;
    while phys < end
    {
        arch_paging::map_page(root_va, DIRECT_MAP_BASE + phys, phys, rw, pool)?;
        phys += PAGE_SIZE as u64;
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::{MemoryMapEntry, MemoryMapSlice, MemoryType};

    // ── phys_to_virt / virt_to_phys ──────────────────────────────────────────

    #[test]
    fn phys_to_virt_zero_equals_direct_map_base()
    {
        assert_eq!(phys_to_virt(0), DIRECT_MAP_BASE);
    }

    #[test]
    fn phys_to_virt_nonzero()
    {
        assert_eq!(phys_to_virt(0x1000), DIRECT_MAP_BASE + 0x1000);
    }

    #[test]
    fn phys_virt_roundtrip()
    {
        let phys: u64 = 0x8000_0000;
        assert_eq!(virt_to_phys(phys_to_virt(phys)), phys);
    }

    // ── compute_max_physical_address ─────────────────────────────────────────

    /// Construct a minimal [`BootInfo`] pointing to `entries` for testing.
    ///
    /// Valid only while `entries` is live in the caller's scope.
    fn boot_info_with_map(entries: &[MemoryMapEntry]) -> BootInfo
    {
        // SAFETY: entries is valid for the duration of the test scope.
        let mut info = unsafe { core::mem::zeroed::<BootInfo>() };
        info.memory_map = MemoryMapSlice {
            entries: entries.as_ptr(),
            count: entries.len() as u64,
        };
        info
    }

    #[test]
    fn max_phys_single_entry()
    {
        let entries = [MemoryMapEntry {
            physical_base: 0x0,
            size: 0x1000_0000, // 256 MiB
            memory_type: MemoryType::Usable,
        }];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x1000_0000);
    }

    #[test]
    fn max_phys_multiple_entries()
    {
        let entries = [
            MemoryMapEntry {
                physical_base: 0x0,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                physical_base: 0x4000_0000,
                size: 0x1000_0000,
                memory_type: MemoryType::Usable,
            },
        ];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x5000_0000);
    }

    #[test]
    fn max_phys_out_of_order_entries()
    {
        let entries = [
            MemoryMapEntry {
                physical_base: 0x8000_0000,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                physical_base: 0x1000,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
        ];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x8000_1000);
    }

    /// Reserved entries (e.g. PCIe MMIO BARs reported by OVMF under TCG) must
    /// not inflate max_phys. This is the scenario that causes pool exhaustion
    /// when running under QEMU with TCG (e.g. `--no-kvm`).
    #[test]
    fn max_phys_reserved_entries_are_excluded()
    {
        let entries = [
            MemoryMapEntry {
                physical_base: 0x0,
                size: 0x2000_0000, // 512 MiB of usable RAM
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                // Simulates a 64-bit PCIe MMIO window at 512 GiB — the kind
                // OVMF/Q35 exposes under TCG that caused pool exhaustion.
                physical_base: 0x80_0000_0000,
                size: 0x80_0000_0000,
                memory_type: MemoryType::Reserved,
            },
        ];
        let info = boot_info_with_map(&entries);
        // Only the Usable entry should be considered; the 512 GiB Reserved
        // entry must be ignored.
        assert_eq!(compute_max_physical_address(&info), 0x2000_0000);
    }

    #[test]
    fn max_phys_includes_loaded_acpi_persistent()
    {
        // Loaded, AcpiReclaimable, and Persistent are RAM-backed and must be
        // included in the max calculation.
        let entries = [
            MemoryMapEntry {
                physical_base: 0x0,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                physical_base: 0x1000_0000,
                size: 0x1000,
                memory_type: MemoryType::Loaded,
            },
            MemoryMapEntry {
                physical_base: 0x2000_0000,
                size: 0x1000,
                memory_type: MemoryType::AcpiReclaimable,
            },
            MemoryMapEntry {
                physical_base: 0x3000_0000,
                size: 0x1000,
                memory_type: MemoryType::Persistent,
            },
        ];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x3000_1000);
    }

    // ── PoolState ─────────────────────────────────────────────────────────────

    // Allocate a test pool buffer of `n` × 4 KiB frames aligned to 4 KiB.
    // The Vec must stay alive for the duration of the test.
    fn make_test_pool_buf(n: usize) -> Vec<u8>
    {
        // Over-allocate by one frame so we can find a 4 KiB-aligned start.
        let align = 4096usize;
        let total = n * align + align;
        vec![0u8; total]
    }

    fn aligned_start(buf: &[u8]) -> u64
    {
        let ptr = buf.as_ptr() as u64;
        (ptr + 4095) & !4095
    }

    #[test]
    fn pool_alloc_returns_sequential_frames()
    {
        let buf = make_test_pool_buf(4);
        let base = aligned_start(&buf);
        let mut pool = PoolState::new_for_test(base, 4);

        let (va0, pa0) = pool.alloc_frame().unwrap();
        let (va1, pa1) = pool.alloc_frame().unwrap();

        assert_eq!(va1, va0 + 4096);
        assert_eq!(pa1, pa0 + 4096);
    }

    #[test]
    fn pool_exhaustion_returns_err()
    {
        let buf = make_test_pool_buf(2);
        let base = aligned_start(&buf);
        let mut pool = PoolState::new_for_test(base, 2);

        assert!(pool.alloc_frame().is_ok());
        assert!(pool.alloc_frame().is_ok());
        assert_eq!(pool.alloc_frame(), Err(PagingError::OutOfFrames));
    }

    #[test]
    fn pool_phys_to_virt_identity_in_test_mode()
    {
        let buf = make_test_pool_buf(1);
        let base = aligned_start(&buf);
        let pool = PoolState::new_for_test(base, 1);
        // new_for_test uses kv_minus_kp = 0, so phys_to_virt is identity.
        assert_eq!(pool.phys_to_virt(base), base);
    }

    // ── PageFlags construction ────────────────────────────────────────────────

    #[test]
    fn page_flags_text_is_readable_executable_not_writable()
    {
        let f = PageFlags {
            readable: true,
            writable: false,
            executable: true,
            uncacheable: false,
        };
        assert!(f.readable);
        assert!(!f.writable);
        assert!(f.executable);
        assert!(!f.uncacheable);
    }

    #[test]
    fn page_flags_rodata_is_readable_only()
    {
        let f = PageFlags {
            readable: true,
            writable: false,
            executable: false,
            uncacheable: false,
        };
        assert!(f.readable);
        assert!(!f.writable);
        assert!(!f.executable);
    }

    #[test]
    fn page_flags_data_is_readable_writable_not_executable()
    {
        let f = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };
        assert!(f.readable);
        assert!(f.writable);
        assert!(!f.executable);
    }

    #[test]
    fn page_flags_uncacheable_default_false()
    {
        let f = PageFlags {
            readable: true,
            writable: false,
            executable: false,
            uncacheable: false,
        };
        assert!(!f.uncacheable);
    }

    #[test]
    fn page_flags_uncacheable_set()
    {
        let f = PageFlags {
            readable: true,
            writable: false,
            executable: false,
            uncacheable: true,
        };
        assert!(f.uncacheable);
    }
}
