// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/paging.rs

//! RISC-V page table construction for the bootloader, parameterized over
//! the negotiated paging mode.
//!
//! [`negotiate_paging`] picks the mode at boot: the DTB `mmu-type` claim
//! (or Sv57 when absent) is confirmed by a `satp` write-probe, falling back
//! mode by mode down to the Sv39 platform minimum. The negotiated mode fixes
//! the hierarchy depth (3/4/5 levels of 512-entry, 4 KiB tables) that
//! [`BootPageTable`] builds and the `satp.MODE` the handoff installs.
//!
//! Intermediate PTEs have V=1 with R=0, W=0, X=0. Leaf PTEs set the A bit
//! always and the D bit for writable mappings, to avoid hardware faults on
//! implementations that trap A/D updates. W^X is enforced: W=1 and X=1
//! together return [`MapError::WxViolation`].

use core::sync::atomic::{AtomicU8, Ordering};

use boot_protocol::riscv_paging::{PagingMode, level_stride, vpn_index};

use crate::error::BootError;
use crate::paging::{MapError, PageFlags, PageTableBuilder};
use crate::{bprintln, uefi};

// ── Mode negotiation ──────────────────────────────────────────────────────────

/// The paging mode negotiated by [`negotiate_paging`], as a raw `satp.MODE`
/// value. The bootloader is single-threaded; the Sv48 default only stands in
/// until negotiation runs (step 5), before any consumer (steps 6 and 10).
static NEGOTIATED_MODE: AtomicU8 = AtomicU8::new(PagingMode::Sv48 as u8);

/// The paging mode the bootloader builds tables for and installs at handoff.
pub(crate) fn negotiated_mode() -> PagingMode
{
    // The store site only writes PagingMode discriminants, so the decode
    // cannot fail.
    match PagingMode::from_satp_mode(u64::from(NEGOTIATED_MODE.load(Ordering::Relaxed)))
    {
        Some(mode) => mode,
        None => unreachable!(),
    }
}

/// Short lowercase name for boot diagnostics.
fn mode_name(mode: PagingMode) -> &'static str
{
    match mode
    {
        PagingMode::Sv39 => "sv39",
        PagingMode::Sv48 => "sv48",
        PagingMode::Sv57 => "sv57",
    }
}

/// Negotiate the paging mode: DTB `mmu-type` claim, confirmed by a `satp`
/// write-probe with fallback to the next-narrower mode on failure.
///
/// The candidate is the boot hart's DTB claim (Sv57 — the kernel's widest
/// supported mode — when the DTB is absent or silent). A candidate whose
/// `satp.MODE` bits do not stick falls back via [`PagingMode::next_lower`];
/// probe failure below Sv39 is fatal, since Sv39 is the RVA23 platform
/// minimum (docs/platform-requirements.md).
///
/// # Safety
/// Must run in S-mode before `ExitBootServices` (`bs` valid for the probe-root
/// frame allocation) and before step 6 builds the boot page tables.
/// `dtb_addr` must be zero or the physical address of an identity-mapped FDT.
pub unsafe fn negotiate_paging(
    bs: *mut uefi::EfiBootServices,
    dtb_addr: u64,
    boot_hart_id: u64,
) -> Result<(), BootError>
{
    let advertised = if dtb_addr != 0
    {
        // SAFETY: dtb_addr is a valid identity-mapped FDT (caller contract).
        unsafe { crate::dtb::parse_boot_cpu_mmu_type(dtb_addr, boot_hart_id) }
    }
    else
    {
        None
    };

    // SAFETY: bs is valid pre-ExitBootServices (caller contract).
    let probe_root = unsafe { uefi::allocate_pages(bs, 1)? };

    let mut candidate = advertised.unwrap_or(PagingMode::Sv57);
    loop
    {
        // SAFETY: probe_root is an exclusively-owned 4 KiB frame; S-mode.
        if unsafe { probe_satp_mode(probe_root, candidate) }
        {
            break;
        }
        candidate = candidate
            .next_lower()
            .ok_or(BootError::PagingModeUnsupported)?;
    }

    NEGOTIATED_MODE.store(candidate as u8, Ordering::Relaxed);
    match advertised
    {
        Some(adv) if adv != candidate => bprintln!(
            "[--------] boot: paging mode {} (dtb advertised {}; probe fallback)",
            mode_name(candidate),
            mode_name(adv)
        ),
        Some(_) => bprintln!("[--------] boot: paging mode {}", mode_name(candidate)),
        None => bprintln!(
            "[--------] boot: paging mode {} (no dtb mmu-type; probe only)",
            mode_name(candidate)
        ),
    }
    Ok(())
}

/// Probe whether the CPU implements `candidate` by writing `satp` and
/// reading it back: per the RISC-V Privileged ISA (§ satp, "Supervisor
/// Address Translation and Protection Register"), a write selecting an
/// unimplemented MODE has no effect, so the readback retains the prior
/// value. Same technique as Linux `set_satp_mode` (arch/riscv/mm/init.c).
///
/// `probe_root` becomes a one-entry probe table: a single root-level
/// identity *leaf* (V|R|X|A, no W — the probe window performs no data
/// accesses) covering the `level_stride`-aligned giant region around PC, so
/// instruction fetch stays valid while the candidate translation is live.
/// The sequence runs in one `asm!` block with S-mode interrupts masked
/// (firmware timer handlers would be unreachable under the probe root) and
/// restores the *live* `satp` afterwards — UEFI may be running with its own
/// translation active, so the old value is saved, never assumed Bare.
///
/// # Safety
/// Must run in S-mode. `probe_root` must be an exclusively-owned,
/// identity-mapped 4 KiB frame.
unsafe fn probe_satp_mode(probe_root: u64, candidate: PagingMode) -> bool
{
    // SAFETY: probe_root is an exclusively-owned frame (caller contract).
    unsafe {
        core::ptr::write_bytes(probe_root as *mut u8, 0, PAGE_SIZE_USIZE);
    }

    let pc = probe_satp_mode as *const () as u64;
    let top = candidate.levels() - 1;
    let base = pc & !(level_stride(top) - 1);
    // Root-level identity leaf covering the region around PC. The base is
    // stride-aligned, so the superpage PPN alignment rule holds.
    let leaf = PTE_V | PTE_R | PTE_X | PTE_A | ((base >> 12) << 10);
    // SAFETY: probe_root is a zeroed exclusively-owned table frame; the index
    // is within [0, 511].
    unsafe {
        let table = core::slice::from_raw_parts_mut(probe_root as *mut u64, TABLE_ENTRIES);
        table[vpn_index(top, pc)] = leaf;
    }

    let cand_satp = candidate.make_satp(probe_root, 0);
    let sstatus_save: u64;
    let satp_back: u64;
    // SAFETY: single asm block, register operands only — no memory access
    // can occur while the candidate translation is live, and instruction
    // fetch is covered by the identity leaf above. SIE is masked across the
    // window and restored below; the live satp is restored before the
    // trailing fence discards probe translations.
    unsafe {
        core::arch::asm!(
            "csrrci {sst}, sstatus, 0b10", // mask SIE, save prior state
            "csrr   {old}, satp",          // save the live translation regime
            "sfence.vma zero, zero",
            "csrw   satp, {cand}",         // ignored if MODE unimplemented
            "csrr   {back}, satp",
            "csrw   satp, {old}",
            "sfence.vma zero, zero",
            sst = out(reg) sstatus_save,
            old = out(reg) _,
            back = out(reg) satp_back,
            cand = in(reg) cand_satp,
            options(nostack),
        );
        if sstatus_save & 0b10 != 0
        {
            core::arch::asm!("csrsi sstatus, 0b10", options(nostack));
        }
    }

    satp_back >> 60 == candidate as u64
}

/// PTE bit: Valid.
const PTE_V: u64 = 1 << 0;
/// PTE bit: Readable.
const PTE_R: u64 = 1 << 1;
/// PTE bit: Writable.
const PTE_W: u64 = 1 << 2;
/// PTE bit: Executable.
const PTE_X: u64 = 1 << 3;
// Bit 4 (U) = 0: supervisor-only; never set in bootloader mappings.
// Bit 5 (G) = 0: not global.
/// PTE bit: Accessed. Set in all leaf PTEs to avoid A-flag faults on
/// implementations that trap rather than set A in hardware.
const PTE_A: u64 = 1 << 6;
/// PTE bit: Dirty. Set for writable leaf PTEs to avoid D-flag faults on
/// implementations that trap rather than set D in hardware.
const PTE_D: u64 = 1 << 7;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;
/// Page size as `usize` — 4096 always fits, cast is exact.
const PAGE_SIZE_USIZE: usize = 4096;
/// Number of entries in a single page table (all levels).
const TABLE_ENTRIES: usize = 512;

/// Capacity of the page-table frame log used for post-handoff reclamation.
///
/// Sized to cover the root plus every intermediate frame allocated
/// during identity mapping of kernel, init, modules, framebuffer, and
/// file-read buffers. Empirically a six-module seraph boot uses ~95
/// frames at four levels; Sv57 adds one intermediate level (roughly one
/// extra frame per distinct top-level chain), so this cap keeps >=25%
/// headroom above that. The reclaim array's backing page in `BootInfo`
/// holds up to `MAX_RECLAIM_RANGES` (256) entries, so this cap is the
/// binding limit; `alloc_table` returns `None` once exhausted,
/// propagating as `BootError::OutOfMemory` — diagnose by bumping this
/// constant rather than silently truncating.
const FRAME_LOG_CAP: usize = 160;

/// RISC-V page table builder for the negotiated paging mode.
///
/// Holds the physical address of the root table and the UEFI boot services
/// pointer used to allocate intermediate table frames on demand.
pub struct BootPageTable
{
    /// Physical address of the root table.
    root_phys: u64,
    /// Translation levels of the negotiated mode (3 / 4 / 5), captured from
    /// [`negotiated_mode`] at construction.
    levels: usize,
    /// UEFI boot services pointer for frame allocation.
    bs: *mut crate::uefi::EfiBootServices,
    /// Physical addresses of every frame allocated for this builder's tables
    /// (root + every intermediate frame). Recorded in `BootInfo.reclaim_ranges`
    /// so the kernel can reclaim them once Phase 3 has installed its own
    /// page tables.
    frame_log: [u64; FRAME_LOG_CAP],
    /// Number of valid entries in [`Self::frame_log`].
    frame_log_len: usize,
}

impl PageTableBuilder for BootPageTable
{
    fn new(bs: *mut crate::uefi::EfiBootServices) -> Option<Self>
    {
        // SAFETY: bs is valid pre-ExitBootServices; allocate_pages returns a
        // physical address of a freshly allocated EfiLoaderData region.
        let root_phys = unsafe { crate::uefi::allocate_pages(bs, 1).ok()? };
        // SAFETY: root_phys points to one PAGE_SIZE region of allocated memory.
        // Zeroing ensures all entries have V=0 (invalid), which is the correct
        // initial state for a page table at any level.
        unsafe {
            core::ptr::write_bytes(root_phys as *mut u8, 0, PAGE_SIZE_USIZE);
        }
        let mut frame_log = [0u64; FRAME_LOG_CAP];
        frame_log[0] = root_phys;
        Some(Self {
            root_phys,
            levels: negotiated_mode().levels(),
            bs,
            frame_log,
            frame_log_len: 1,
        })
    }

    fn map(&mut self, virt: u64, phys: u64, size: u64, flags: PageFlags) -> Result<(), MapError>
    {
        // W^X enforcement: reject before touching any table.
        if flags.writable && flags.executable
        {
            return Err(MapError::WxViolation);
        }

        // Round size up to a page boundary so callers with non-aligned sizes are
        // handled safely. Well-behaved callers always pass aligned sizes.
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        let mut offset: u64 = 0;
        while offset < aligned_size
        {
            self.map_4k_page(virt + offset, phys + offset, &flags)?;
            offset += PAGE_SIZE;
        }

        Ok(())
    }

    fn root_physical(&self) -> u64
    {
        self.root_phys
    }

    fn allocated_frames(&self) -> &[u64]
    {
        &self.frame_log[..self.frame_log_len]
    }
}

impl BootPageTable
{
    /// Map a single 4 KiB page at virtual address `virt` to physical address `phys`.
    ///
    /// Walks the negotiated mode's hierarchy from the root down, allocating
    /// intermediate table frames on demand. Writes the leaf PTE with the
    /// permissions encoded in `flags`.
    ///
    /// A PTE is a pointer to the next-level table when R=0, W=0, X=0, V=1,
    /// and a leaf when R=1 or X=1 (or both). This function always produces
    /// 4 KiB leaf PTEs at level 0.
    fn map_4k_page(&mut self, virt: u64, phys: u64, flags: &PageFlags) -> Result<(), MapError>
    {
        // SAFETY: root_phys is the physical address of a valid, zeroed 4 KiB
        // frame allocated in new().
        let mut table =
            unsafe { core::slice::from_raw_parts_mut(self.root_phys as *mut u64, TABLE_ENTRIES) };

        // Descend from the root (levels - 1) to level 1, resolving or
        // allocating the child table at each tier; every vpn_index is
        // within [0, 511].
        for level in (1..self.levels).rev()
        {
            let child_phys = self.ensure_table(&mut table[vpn_index(level, virt)])?;
            // SAFETY: frame from ensure_table is a valid, zeroed-or-live
            // 4 KiB table frame.
            table =
                unsafe { core::slice::from_raw_parts_mut(child_phys as *mut u64, TABLE_ENTRIES) };
        }
        let l0 = table;
        let l0_idx = vpn_index(0, virt);

        // Build the leaf PTE. The PPN field occupies bits [53:10]:
        // PPN = (phys >> 12) << 10.
        let ppn = (phys >> 12) << 10;

        // All leaf PTEs set R=1 (readable) and A=1 to avoid A-flag faults.
        let mut pte = PTE_V | PTE_R | PTE_A | ppn;
        if flags.writable
        {
            // Set W=1 and D=1 to avoid D-flag faults on writable pages.
            pte |= PTE_W | PTE_D;
        }
        if flags.executable
        {
            pte |= PTE_X;
        }

        l0[l0_idx] = pte;

        Ok(())
    }

    /// Ensure that an intermediate-level PTE points to a valid child table frame.
    ///
    /// If the entry is already valid (V=1), extracts and returns the child frame
    /// address from the PPN field. If the entry is invalid (V=0), allocates a new
    /// zeroed frame, writes an intermediate PTE (V=1, R=0, W=0, X=0), and returns
    /// the new frame address.
    ///
    /// Intermediate PTEs have only V=1 set (R=0, W=0, X=0), which signals to the
    /// hardware that this is a pointer to the next-level table, not a leaf.
    fn ensure_table(&mut self, entry: &mut u64) -> Result<u64, MapError>
    {
        if *entry & PTE_V != 0
        {
            // Extract the physical frame address from the PPN field (bits [53:10]).
            // PPN → phys: (pte >> 10) << 12.
            return Ok((*entry >> 10) << 12);
        }

        let frame = self.alloc_table().ok_or(MapError::OutOfMemory)?;
        // Intermediate PTE: V=1, R=0, W=0, X=0. Hardware treats this as a
        // pointer to the next-level table (not a leaf).
        let ppn = (frame >> 12) << 10;
        *entry = PTE_V | ppn;
        Ok(frame)
    }

    /// Allocate and zero one 4 KiB frame for use as an intermediate page table.
    ///
    /// Returns the physical address of the frame, or `None` on allocation failure
    /// (UEFI out-of-memory or [`FRAME_LOG_CAP`] exhausted).
    fn alloc_table(&mut self) -> Option<u64>
    {
        if self.frame_log_len >= FRAME_LOG_CAP
        {
            return None;
        }
        // SAFETY: self.bs is valid pre-ExitBootServices; allocate_pages returns a
        // physical address of a freshly allocated EfiLoaderData region.
        let frame = unsafe { crate::uefi::allocate_pages(self.bs, 1).ok()? };
        // SAFETY: frame points to one PAGE_SIZE region of allocated memory.
        // Zeroing ensures all entries have V=0 (invalid).
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE_USIZE);
        }
        self.frame_log[self.frame_log_len] = frame;
        self.frame_log_len += 1;
        Some(frame)
    }
}
