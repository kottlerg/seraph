// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/init-protocol/src/lib.rs

//! Init entry protocol — kernel-to-init handover contract.
//!
//! This crate defines the binary interface between the kernel (Phase 7/9) and
//! the init process. The kernel populates an [`InitInfo`] structure in a
//! read-only page mapped into init's address space at [`INIT_INFO_VADDR`] and
//! passes that address as init's sole entry argument (`rdi` on x86-64, `a0`
//! on RISC-V).
//!
//! # Versioning
//!
//! [`INIT_PROTOCOL_VERSION`] is incremented on any breaking change to the
//! `InitInfo` layout, field semantics, or `CSpace` population order. Init MUST
//! check `info.version == INIT_PROTOCOL_VERSION` before accessing any fields.
//!
//! # Rules
//! - `no_std`; builds in `no_std`.
//! - No inline assembly.
//! - All cross-boundary types are `#[repr(C)]` with stable layout.
//! - No dependencies outside `core`.

#![no_std]

// ── Protocol version ─────────────────────────────────────────────────────────

/// Init protocol version. Incremented on any breaking layout or semantic change.
///
/// v5: Range-cap semantics on `CapType::Interrupt` (`aux0 = start`,
///     `aux1 = count`). Dropped `CapType::PciEcam`. Added named
///     `InitInfo` slots for the root IRQ range cap and firmware-table
///     Frame caps (RSDP, ACPI reclaimable regions, DTB).
/// v4: Added `cspace_cap` slot for init's own `CSpace` cap.
/// v3: Added `cmdline_offset`, `cmdline_len`, and `sbi_control_cap` for kernel
///     command line passthrough and RISC-V SBI forwarding.
pub const INIT_PROTOCOL_VERSION: u32 = 6;

// ── Address space constants ──────────────────────────────────────────────────

/// Virtual address where the kernel maps the read-only [`InitInfo`] region.
///
/// The region spans one or more contiguous pages (as many as needed for the
/// header, [`CapDescriptor`] array, and command line). Placed below the stack.
pub const INIT_INFO_VADDR: u64 = 0x7FFF_FFFF_8000;

/// Virtual address of the top of init's user stack.
///
/// `INIT_STACK_PAGES` pages are mapped immediately below this address.
/// One additional guard page (unmapped) sits below the stack.
pub const INIT_STACK_TOP: u64 = 0x7FFF_FFFF_E000;

/// Number of 4 KiB pages in init's user stack (16 KiB total).
pub const INIT_STACK_PAGES: usize = 4;

/// Maximum number of 4 KiB pages the kernel may allocate for the
/// [`InitInfo`] region (header + [`CapDescriptor`] array + command line).
///
/// The kernel enforces this ceiling when assembling the region; init uses it
/// to bound descriptor-slice reads. Both sides must agree: changing this
/// constant is a protocol change — bump [`INIT_PROTOCOL_VERSION`].
pub const INIT_INFO_MAX_PAGES: usize = 4;

// ── InitInfo ─────────────────────────────────────────────────────────────────

/// Kernel-to-init handover structure.
///
/// Placed at [`INIT_INFO_VADDR`] (one or more pages, read-only). The fixed-size
/// header is followed by a variable-length [`CapDescriptor`] array; the array
/// starts at byte offset [`InitInfo::cap_descriptors_offset`] from the start
/// of this struct.
///
/// All slot indices refer to init's root `CSpace` (`CSpace` ID 0).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitInfo
{
    /// Protocol version. Must equal [`INIT_PROTOCOL_VERSION`].
    pub version: u32,

    /// Number of [`CapDescriptor`] entries in the descriptor array.
    pub cap_descriptor_count: u32,

    // ── Init's own resources ─────────────────────────────────────────────
    /// Slot index of init's own `AddressSpace` capability.
    pub aspace_cap: u32,

    /// Slot index of the `SchedControl` capability.
    pub sched_control_cap: u32,

    // ── CSpace slot ranges (contiguous) ──────────────────────────────────
    /// First slot index of usable physical memory `Frame` capabilities.
    pub memory_frame_base: u32,
    /// Number of usable memory `Frame` capabilities.
    pub memory_frame_count: u32,

    /// First slot index of init's ELF segment `Frame` capabilities.
    pub segment_frame_base: u32,
    /// Number of segment `Frame` capabilities.
    pub segment_frame_count: u32,

    /// First slot index of boot module `Frame` capabilities.
    ///
    /// Boot modules are ELF images for early services (procmgr, devmgr, etc.)
    /// loaded by the bootloader. Currently not populated (count = 0) until the
    /// boot protocol is extended with module metadata.
    pub module_frame_base: u32,
    /// Number of boot module `Frame` capabilities.
    pub module_frame_count: u32,

    /// First slot index of hardware resource capabilities (MMIO, IRQ, I/O port).
    pub hw_cap_base: u32,
    /// Number of hardware resource capabilities.
    pub hw_cap_count: u32,

    /// Byte offset from the start of this struct to the first [`CapDescriptor`].
    ///
    /// The descriptor array contains `cap_descriptor_count` entries, one per
    /// capability in the hardware resource and memory frame ranges. Init uses
    /// these to identify what each capability slot represents without probing.
    pub cap_descriptors_offset: u32,

    /// Slot index of init's own `Thread` capability (CONTROL right).
    ///
    /// Allows init to bind I/O port ranges to itself (`ioport_bind`), set its
    /// own priority and affinity, and delegate thread authority to child services.
    pub thread_cap: u32,

    // ── Command line (added in protocol version 3) ──────────────────────
    /// Byte offset from the start of this struct to the kernel command line.
    ///
    /// The command line is placed after the [`CapDescriptor`] array within the
    /// same 4 KiB page. Zero if no command line is present.
    pub cmdline_offset: u32,

    /// Length of the command line in bytes (no null terminator). Zero if absent.
    pub cmdline_len: u32,

    // ── RISC-V SBI forwarding (added in protocol version 3) ─────────────
    /// Slot index of the `SbiControl` capability (RISC-V only).
    ///
    /// Grants authority to forward SBI calls from userspace through the kernel.
    /// Zero on x86-64 (no SBI concept).
    pub sbi_control_cap: u32,

    /// Slot index of init's own `CSpace` capability.
    ///
    /// Init needs this to create threads bound to its own `CSpace` (e.g. a log
    /// thread that shares init's capability namespace). Added in protocol v4.
    pub cspace_cap: u32,

    // ── Root IRQ range + firmware-table caps (added in protocol v5) ─────
    /// Slot index of the root `Interrupt` range capability.
    ///
    /// Covers the full valid IRQ range for the target arch (x86-64: GSI
    /// 0..256; RISC-V: PLIC sources 0..N). Userspace splits this cap
    /// with `SYS_IRQ_SPLIT` to produce single-IRQ sub-caps for device
    /// drivers. Zero if no valid range could be determined at boot.
    pub irq_range_cap: u32,

    /// Slot index of the read-only `Frame` cap covering the 4 KiB page
    /// that contains the ACPI RSDP.
    ///
    /// RSDP commonly lives in firmware-reserved memory outside
    /// `AcpiReclaimable`, so it gets its own slot. Zero if no RSDP
    /// address was reported (pure-DTB platforms).
    pub acpi_rsdp_frame_cap: u32,

    /// First slot index of the read-only `Frame` caps covering each
    /// `MemoryType::AcpiReclaimable` region in the boot memory map.
    pub acpi_region_frame_base: u32,

    /// Number of ACPI reclaimable-region `Frame` caps.
    pub acpi_region_frame_count: u32,

    /// Slot index of the read-only `Frame` cap covering the DTB blob,
    /// or zero if no DTB was supplied (pure-ACPI platforms).
    pub dtb_frame_cap: u32,

    // ── Init self-reclaim cap surfaces (added in protocol v6) ───────────
    /// First slot index of init's user stack `Frame` caps.
    ///
    /// Each cap covers one 4 KiB stack page; init holds
    /// `init_stack_frame_count` consecutive caps starting at this slot.
    /// Used by init's reap-handoff (`procmgr.REGISTER_INIT_TEARDOWN`) to
    /// donate the stack pages back to memmgr's pool after init's
    /// `AddressSpace` is torn down. Zero if the kernel did not mint stack
    /// caps (legacy boot path).
    pub init_stack_frame_base: u32,
    /// Number of stack `Frame` caps (typically `INIT_STACK_PAGES = 4`).
    pub init_stack_frame_count: u32,

    /// First slot index of init's `InitInfo`-region `Frame` caps.
    ///
    /// Each cap covers one 4 KiB page of the kernel-allocated
    /// `InitInfo` region (header + `CapDescriptor` array + command
    /// line). Donated alongside the stack caps in init's reap-handoff.
    /// The cap range includes the page that contains this `InitInfo`
    /// struct itself — once init has read `InitInfo` at `_start`, the
    /// pages can be reclaimed safely. Zero if the kernel did not mint
    /// `InitInfo` caps (legacy boot path).
    pub init_info_frame_base: u32,
    /// Number of `InitInfo` `Frame` caps (1..=[`INIT_INFO_MAX_PAGES`]).
    pub init_info_frame_count: u32,

    /// Explicit 4-byte tail pad so `size_of::<InitInfo>()` stays 8-byte
    /// aligned. Consumers of `cap_descriptors_offset` rely on this: the
    /// `CapDescriptor` array that immediately follows contains u64
    /// fields and must start on an 8-byte boundary.
    #[doc(hidden)]
    pub _pad_tail: u32,
}

// ── CapDescriptor / CapType ──────────────────────────────────────────────────

/// Describes a single capability in init's root `CSpace`.
///
/// The kernel emits a variable-length array of these after the [`InitInfo`]
/// header. Each entry identifies the slot index, capability type, and
/// type-specific metadata so init can identify what each capability represents
/// without probing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapDescriptor
{
    /// `CSpace` slot index.
    pub slot: u32,

    /// Capability type discriminant. See [`CapType`].
    pub cap_type: CapType,

    /// Padding for alignment; must be zero.
    #[doc(hidden)]
    pub pad: [u8; 3],

    /// Type-specific primary metadata:
    /// - `Frame`: physical base address
    /// - `MmioRegion`: physical base address
    /// - `Interrupt`: starting IRQ line number (range cap; split via `SYS_IRQ_SPLIT`)
    /// - `IoPortRange`: I/O port base
    /// - `SchedControl`: 0 (unused)
    pub aux0: u64,

    /// Type-specific secondary metadata:
    /// - `Frame`: size in bytes
    /// - `MmioRegion`: size in bytes
    /// - `Interrupt`: number of consecutive IRQ lines covered by the cap
    /// - `IoPortRange`: port count
    /// - `SchedControl`: 0 (unused)
    pub aux1: u64,
}

/// Capability type discriminant for [`CapDescriptor`].
///
/// Discriminant values match the kernel's `CapTag` enum for the types that
/// appear in init's initial `CSpace` population. Types that are never present
/// at boot (Endpoint, Signal, Thread, etc.) are omitted.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapType
{
    /// Physical memory frame(s). Matches `CapTag::Frame = 1`.
    Frame = 1,
    /// Hardware interrupt range. Matches `CapTag::Interrupt = 6`.
    /// `aux0 = start`, `aux1 = count`. Use `SYS_IRQ_SPLIT` to narrow.
    Interrupt = 6,
    /// Memory-mapped I/O region. Matches `CapTag::MmioRegion = 7`.
    MmioRegion = 7,
    /// x86-64 I/O port range. Matches `CapTag::IoPortRange = 11`.
    IoPortRange = 11,
    /// Scheduling control authority. Matches `CapTag::SchedControl = 12`.
    SchedControl = 12,
    /// SBI forwarding authority (RISC-V only). Matches `CapTag::SbiControl = 13`.
    SbiControl = 13,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Return the kernel command line as a byte slice from the [`InitInfo`] page.
///
/// # Safety
/// `info` must point into the read-only [`InitInfo`] page mapped by the kernel
/// at [`INIT_INFO_VADDR`]. The page must contain at least
/// `info.cmdline_offset + info.cmdline_len` valid bytes.
#[must_use]
pub unsafe fn cmdline_bytes(info: &InitInfo) -> &[u8]
{
    if info.cmdline_len == 0 || info.cmdline_offset == 0
    {
        return &[];
    }
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: caller guarantees the InitInfo page contains valid cmdline data
    // at the specified offset and length, populated by the kernel in Phase 9.
    unsafe {
        core::slice::from_raw_parts(
            base.add(info.cmdline_offset as usize),
            info.cmdline_len as usize,
        )
    }
}
