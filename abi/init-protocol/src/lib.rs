// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/init-protocol/src/lib.rs

//! Init entry protocol — kernel-to-init handover contract.
//!
//! This crate defines the binary interface between the kernel (Phase 7/9) and
//! the init process. The kernel populates an [`InitInfo`] structure in a
//! read-only page mapped into init's address space at a kernel-chosen virtual
//! address (`choose_init_layout` in the kernel) and passes that address as
//! init's sole entry argument (`rdi` on x86-64, `a0` on RISC-V).
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
/// v3: Added `cmdline_offset`, `cmdline_len`, and `sbi_control_cap` for kernel
///     command line passthrough and RISC-V SBI forwarding.
/// v4: Added `cspace_cap` slot for init's own `CSpace` cap.
/// v5: Range-cap semantics on `CapType::Interrupt` (`aux0 = start`,
///     `aux1 = count`). Dropped `CapType::PciEcam`. Added named
///     `InitInfo` slots for the root IRQ range cap and firmware-table
///     `Memory` caps (RSDP, ACPI reclaimable regions, DTB).
/// v6: Added `init_stack_memory_*` / `init_info_memory_*` slot ranges for
///     init self-reclaim.
/// v7: Added a fixed-size [`InitInfo::module_names`] table so init can
///     map bundle-entry names (carried by the bootloader through
///     `BootModule.name`) to the kernel's `CSpace` slot index of each
///     module's `Memory` cap. The table lives in the `InitInfo` header so
///     it sits on the first `InitInfo` page; the [`CapDescriptor`] array
///     layout is unchanged. Removed `module_frame_base` /
///     `module_frame_count` (init now resolves modules by name via
///     `module_names`, not ordinal arithmetic), `cmdline_offset` /
///     `cmdline_len` (boot v8 removed the kernel command line surface
///     entirely), and the corresponding `cmdline_bytes` helper.
/// v8: Added [`InitInfo::framebuffer`] carrying the bootloader-discovered
///     GOP linear-framebuffer geometry. Authoritative runtime metadata
///     for the framebuffer dies with UEFI `ExitBootServices`; the kernel
///     forwards what the bootloader captured so devmgr can spawn the
///     userspace framebuffer driver (`services/drivers/framebuffer/`).
/// v9: Raised [`INIT_MAX_NAMED_MODULES`] from 8 to 12 — pure headroom for
///     near-roadmap bundle modules without further re-bumps. The current
///     bootstrap-essential set fits in 8 (#164 deliberately keeps the
///     per-arch RTC drivers off the bundle and on the rootfs); the
///     headroom accommodates upcoming non-RTC additions such as the
///     keyboard driver. Pure constant bump; the
///     [`InitInfo::module_names`] array grows in size but the field
///     layout is otherwise unchanged.
/// v10: Added [`InitInfo::system_ram_bytes`] and
///     [`InitInfo::kernel_reserved_bytes`] — immutable post-boot
///     memory-accounting facts (total usable RAM and the fixed kernel
///     reserve) that let the dynamic memory pool be reconciled against
///     the all-RAM-accounted identity. Both `u64`, placed before
///     `framebuffer` so that field remains last.
/// v11: Capability naming alignment (#184). `CapType::Frame` → `Memory`,
///     `MmioRegion` → `Mmio`, `IoPortRange` → `IoPort`; the `*_frame_*`
///     `InitInfo` slot-range fields renamed to `*_memory_*`. Source-level
///     rename only — discriminant values and field layout are unchanged.
/// v12: `SchedControl` carries a `[min, max]` priority range (#185). The
///     `SchedControl` [`CapDescriptor`] now reports `aux0 = min`, `aux1 = max`
///     (previously both 0). `Rights::ELEVATE` is removed: holding a
///     `SchedControl` cap plus its range is the authority. Field layout
///     unchanged; semantic change to the `SchedControl` descriptor only.
/// v13: Capability handles are generation-tagged (#349). Each [`CapDescriptor`]
///     slot is now a `(generation << CAP_INDEX_BITS) | index` handle, not a bare
///     slot index. Field layout is unchanged and every handover cap is a
///     never-recycled generation-0 slot, so the delivered values are
///     byte-identical; the semantic change is that the handle's high bits are
///     now meaningful and the kernel validates them on every use.
pub const INIT_PROTOCOL_VERSION: u32 = 13;

/// Length of [`InitModuleName::name`], matching
/// [`boot_protocol::BOOT_MODULE_NAME_LEN`] so the kernel copies the bundle
/// entry name straight through.
pub const INIT_MODULE_NAME_LEN: usize = 32;

/// Maximum number of named boot-module entries the kernel can publish in
/// [`InitInfo::module_names`]. Sized to comfortably cover the current
/// `procmgr, devmgr, memmgr, vfsd, virtio-blk, serial, framebuffer,
/// fatfs` bootstrap-essential set plus future modules (e.g. keyboard)
/// before the table fills. Non-bootstrap drivers (the per-arch RTC)
/// live on the rootfs and do not consume slots here.
pub const INIT_MAX_NAMED_MODULES: usize = 12;

// ── Address space constants ──────────────────────────────────────────────────
//
// The `InitInfo` region and init stack virtual addresses are not ABI constants:
// the kernel chooses them per-boot (see `choose_init_layout` in the kernel) and
// delivers the `InitInfo` page address to init in the entry register, exactly as
// procmgr does for `ProcessInfo` (#250). Only the page-count bounds below — which
// both the kernel and init must agree on — remain part of the protocol.

/// Number of 4 KiB pages in init's user stack (16 KiB total).
pub const INIT_STACK_PAGES: usize = 4;

/// Maximum number of 4 KiB pages the kernel may allocate for the
/// [`InitInfo`] region (header — which now includes the boot-module
/// name table — followed by the [`CapDescriptor`] array).
///
/// The kernel enforces this ceiling when assembling the region; init uses it
/// to bound descriptor-slice reads. Both sides must agree: changing this
/// constant is a protocol change — bump [`INIT_PROTOCOL_VERSION`].
pub const INIT_INFO_MAX_PAGES: usize = 4;

// ── InitInfo ─────────────────────────────────────────────────────────────────

/// Kernel-to-init handover structure.
///
/// Placed in one or more read-only pages at a kernel-chosen virtual address,
/// delivered to init in its entry register. The fixed-size header is followed by
/// a variable-length [`CapDescriptor`] array; the array starts at byte offset
/// [`InitInfo::cap_descriptors_offset`] from the start of this struct.
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
    /// First slot index of usable physical memory `Memory` capabilities.
    pub memory_base: u32,
    /// Number of usable memory `Memory` capabilities.
    pub memory_count: u32,

    /// First slot index of init's ELF segment `Memory` capabilities.
    pub segment_memory_base: u32,
    /// Number of segment `Memory` capabilities.
    pub segment_memory_count: u32,

    /// First slot index of hardware resource capabilities (MMIO, IRQ, I/O port).
    pub hw_cap_base: u32,
    /// Number of hardware resource capabilities.
    pub hw_cap_count: u32,

    /// Byte offset from the start of this struct to the first [`CapDescriptor`].
    ///
    /// The descriptor array contains `cap_descriptor_count` entries, one per
    /// capability in the hardware resource and memory cap ranges. Init uses
    /// these to identify what each capability slot represents without probing.
    pub cap_descriptors_offset: u32,

    /// Slot index of init's own `Thread` capability (CONTROL right).
    ///
    /// Allows init to bind I/O port ranges to itself (`ioport_bind`), set its
    /// own priority and affinity, and delegate thread authority to child services.
    pub thread_cap: u32,

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

    /// Slot index of the read-only `Memory` cap covering the 4 KiB page
    /// that contains the ACPI RSDP.
    ///
    /// RSDP commonly lives in firmware-reserved memory outside
    /// `AcpiReclaimable`, so it gets its own slot. Zero if no RSDP
    /// address was reported (pure-DTB platforms).
    pub acpi_rsdp_memory_cap: u32,

    /// First slot index of the read-only `Memory` caps covering each
    /// `MemoryType::AcpiReclaimable` region in the boot memory map.
    pub acpi_region_memory_base: u32,

    /// Number of ACPI reclaimable-region `Memory` caps.
    pub acpi_region_memory_count: u32,

    /// Slot index of the read-only `Memory` cap covering the DTB blob,
    /// or zero if no DTB was supplied (pure-ACPI platforms).
    pub dtb_memory_cap: u32,

    // ── Init self-reclaim cap surfaces (added in protocol v6) ───────────
    /// First slot index of init's user stack `Memory` caps.
    ///
    /// Each cap covers one 4 KiB stack page; init holds
    /// `init_stack_memory_count` consecutive caps starting at this slot.
    /// Used by init's reap-handoff (`procmgr.REGISTER_INIT_TEARDOWN`) to
    /// donate the stack pages back to memmgr's pool after init's
    /// `AddressSpace` is torn down. Zero if the kernel did not mint stack
    /// caps (legacy boot path).
    pub init_stack_memory_base: u32,
    /// Number of stack `Memory` caps (typically `INIT_STACK_PAGES = 4`).
    pub init_stack_memory_count: u32,

    /// First slot index of init's `InitInfo`-region `Memory` caps.
    ///
    /// Each cap covers one 4 KiB page of the kernel-allocated
    /// `InitInfo` region (header — which includes the boot-module name
    /// table — followed by the `CapDescriptor` array). Donated
    /// alongside the stack caps in init's reap-handoff.
    /// The cap range includes the page that contains this `InitInfo`
    /// struct itself — once init has read `InitInfo` at `_start`, the
    /// pages can be reclaimed safely. Zero if the kernel did not mint
    /// `InitInfo` caps (legacy boot path).
    pub init_info_memory_base: u32,
    /// Number of `InitInfo` `Memory` caps (1..=[`INIT_INFO_MAX_PAGES`]).
    pub init_info_memory_count: u32,

    // ── Boot-module name table (added in protocol version 7) ────────────
    /// Number of valid [`InitModuleName`] entries in [`module_names`].
    /// Indices `0..module_name_count` are populated; the rest are
    /// [`INIT_MODULE_NAME_EMPTY`].
    pub module_name_count: u32,

    /// Bundle-entry-name → `CSpace`-slot mapping for boot-module `Memory`
    /// caps. Lives inside the `InitInfo` header so it sits entirely on
    /// the first `InitInfo` page (the [`CapDescriptor`] array that
    /// follows the header may span pages).
    pub module_names: [InitModuleName; INIT_MAX_NAMED_MODULES],

    // ── Memory-accounting facts (added in protocol version 10) ─────────
    /// Total installed usable system RAM, in bytes. Immutable after boot.
    ///
    /// The full physical span the all-RAM-accounted identity covers:
    /// `system_ram_bytes == kernel_reserved_bytes + dynamic_pool_total`.
    pub system_ram_bytes: u64,

    /// RAM permanently held by the fixed kernel reserve, in bytes.
    /// Immutable after boot.
    ///
    /// The complement of all reclaimable RAM: kernel image, direct-map
    /// metadata, SEED reserve, kernel page tables, per-CPU/idle structures,
    /// retype metadata, and buddy residue. A reported quantity for
    /// accounting, never itself a capability.
    pub kernel_reserved_bytes: u64,

    // ── Framebuffer geometry (added in protocol version 8) ─────────────
    /// Bootloader-discovered framebuffer geometry. `physical_base == 0`
    /// indicates no framebuffer is present and devmgr skips the
    /// framebuffer-driver spawn.
    ///
    /// Last field by intent: `cap_descriptors_offset =
    /// size_of::<InitInfo>()` puts the `CapDescriptor` array
    /// immediately after this field, and [`InitFramebufferInfo`] is
    /// `u64 + 4×u32 = 24 B` so the total stays 8-byte aligned (the
    /// `u64` alignment the descriptor array needs). The compile-time
    /// assert below pins both invariants.
    pub framebuffer: InitFramebufferInfo,
}

// Compile-time invariants for the `InitInfo` layout. The kernel writes
// the `CapDescriptor` array at byte offset `cap_descriptors_offset =
// size_of::<InitInfo>()` and the entries contain `u64` fields, so the
// total size must be 8-byte aligned. The whole region must also fit
// within `INIT_INFO_MAX_PAGES`.
const _: () = assert!(
    core::mem::size_of::<InitInfo>().is_multiple_of(8),
    "InitInfo size must be 8-byte aligned so cap_descriptors_offset is 8-byte aligned",
);
const _: () = assert!(
    core::mem::size_of::<InitInfo>() <= INIT_INFO_MAX_PAGES * 4096,
    "InitInfo header must fit within INIT_INFO_MAX_PAGES",
);

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
    /// - `Memory`: physical base address
    /// - `Mmio`: physical base address
    /// - `Interrupt`: starting IRQ line number (range cap; split via `SYS_IRQ_SPLIT`)
    /// - `IoPort`: I/O port base
    /// - `SchedControl`: minimum priority level in the cap's range
    pub aux0: u64,

    /// Type-specific secondary metadata:
    /// - `Memory`: size in bytes
    /// - `Mmio`: size in bytes
    /// - `Interrupt`: number of consecutive IRQ lines covered by the cap
    /// - `IoPort`: port count
    /// - `SchedControl`: maximum priority level in the cap's range
    pub aux1: u64,
}

/// Named boot-module entry published in [`InitInfo::module_names`].
///
/// Maps a bundle-entry name (carried through
/// [`boot_protocol::BootModule::name`]) to the `CSpace` slot index of
/// the module's `Memory` capability. The table sits in the `InitInfo`
/// header so it always lives on the first `InitInfo` page and does not
/// interact with the variable-length [`CapDescriptor`] array, which
/// may span pages once `INIT_MAX_NAMED_MODULES` modules are minted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitModuleName
{
    /// `CSpace` slot index of the module's `Memory` cap.
    pub slot: u32,
    /// Explicit padding so `name` starts 8-byte aligned within the
    /// surrounding `[InitModuleName; N]` array.
    #[doc(hidden)]
    pub _pad: u32,
    /// Bundle entry name, NUL-padded to [`INIT_MODULE_NAME_LEN`] bytes.
    pub name: [u8; INIT_MODULE_NAME_LEN],
}

/// Empty / NUL-padded slot for an unused [`InitModuleName`] entry.
pub const INIT_MODULE_NAME_EMPTY: InitModuleName = InitModuleName {
    slot: 0,
    _pad: 0,
    name: [0u8; INIT_MODULE_NAME_LEN],
};

/// Pixel layout for a linear framebuffer. Discriminants are stable across
/// the kernel-to-init boundary; values match `boot_protocol::PixelFormat`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitPixelFormat
{
    /// Red–Green–Blue–Padding, 8 bits per channel.
    Rgbx8 = 0,
    /// Blue–Green–Red–Padding, 8 bits per channel.
    Bgrx8 = 1,
}

/// Framebuffer geometry forwarded to init.
///
/// Mirrors `boot_protocol::FramebufferInfo` but is redefined locally so
/// `init-protocol` retains its zero-dependency invariant. The kernel
/// converts between the two at the boundary. When `physical_base == 0`
/// no framebuffer is present.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InitFramebufferInfo
{
    /// Physical base address of the framebuffer. Zero if absent.
    pub physical_base: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row (may exceed `width × bytes_per_pixel`).
    pub stride: u32,
    /// Pixel format.
    pub pixel_format: InitPixelFormat,
}

impl InitFramebufferInfo
{
    /// Return a zeroed `InitFramebufferInfo` indicating no framebuffer.
    #[must_use]
    pub const fn empty() -> Self
    {
        Self {
            physical_base: 0,
            width: 0,
            height: 0,
            stride: 0,
            pixel_format: InitPixelFormat::Rgbx8,
        }
    }
}

/// Capability type discriminant for [`CapDescriptor`].
///
/// Discriminant values match the kernel's `CapTag` enum for the types that
/// appear in init's initial `CSpace` population. Types that are never present
/// at boot (Endpoint, Notification, Thread, etc.) are omitted.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapType
{
    /// Memory authority cap over a contiguous physical region — the
    /// retypable Untyped/map-as-memory object. Matches `CapTag::Memory = 1`.
    Memory = 1,
    /// Hardware interrupt range. Matches `CapTag::Interrupt = 6`.
    /// `aux0 = start`, `aux1 = count`. Use `SYS_IRQ_SPLIT` to narrow.
    Interrupt = 6,
    /// Memory-mapped I/O region. Matches `CapTag::Mmio = 7`.
    Mmio = 7,
    /// x86-64 I/O port range. Matches `CapTag::IoPort = 11`.
    IoPort = 11,
    /// Scheduling control authority. Matches `CapTag::SchedControl = 12`.
    SchedControl = 12,
    /// SBI forwarding authority (RISC-V only). Matches `CapTag::SbiControl = 13`.
    SbiControl = 13,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Trim a NUL-padded module-name buffer to its non-NUL prefix.
#[must_use]
pub fn module_name_str(name: &[u8; INIT_MODULE_NAME_LEN]) -> &[u8]
{
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    &name[..end]
}

/// Locate a boot-module `Memory` cap by its bundle-entry name.
///
/// Returns the `CSpace` slot index from the first matching
/// [`InitModuleName`] in [`InitInfo::module_names`], or `None` if no
/// entry carries the requested name.
#[must_use]
pub fn find_module_slot(info: &InitInfo, name: &[u8]) -> Option<u32>
{
    let count = (info.module_name_count as usize).min(INIT_MAX_NAMED_MODULES);
    for entry in &info.module_names[..count]
    {
        if module_name_str(&entry.name) == name
        {
            return Some(entry.slot);
        }
    }
    None
}
