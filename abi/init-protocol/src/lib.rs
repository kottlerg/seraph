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
//! `InitInfo` layout, field semantics, `CSpace` population order, or the
//! capacity the root `CSpace` carries for init. Init MUST check
//! `info.version == INIT_PROTOCOL_VERSION` before accessing any fields.
//!
//! # Rules
//! - `no_std`; builds in `no_std`.
//! - No inline assembly.
//! - Cross-boundary structs are `#[repr(C)]` and enums carry a fixed-width
//!   integer repr, all with stable layout.
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
/// v14: [`INIT_MAX_NAMED_MODULES`] rose from 12 to 85, one per boot module a
///     `BootInfo` can list; [`InitInfo::module_names`] grows with it, so every
///     field after it moves.
/// v15: the kernel sizes the [`InitInfo`] region from the boot's own
///     descriptor counts and maps all of it; [`InitInfo::init_info_memory_count`]
///     is its page count, which init reads to bound the descriptor slice.
///     [`INIT_INFO_MAX_PAGES`] rose from 4 to 64 and is now only the ceiling.
/// v16: Capability handles are 64-bit (#637). Every slot field of
///     [`InitInfo`] (each cap handle, range base, and slot count),
///     [`CapDescriptor::slot`], and [`InitModuleName::slot`] widen to `u64`;
///     [`InitInfo::cap_descriptors_offset`] and [`InitInfo::module_name_count`]
///     move up beside the other `u32` header fields so the header has no
///     implicit padding. Every field after [`InitInfo::cap_descriptor_count`]
///     moves.
/// v17: The root `CSpace` carries one body page, enough for init's first split,
///     not sixteen (#801). Init funds its own `CSpace` body arena from its RAM
///     with an augment-mode `cap_create_cspace` before it splits further; an
///     init that does not fund fails its later splits with `OutOfMemory`.
///     Field layout unchanged; semantic change to what the root `CSpace`
///     carries.
/// v18: Added [`CapType::EntropyControl`]: the root `CSpace` carries one
///     `EntropyControl` capability, on both architectures, named by its
///     [`CapDescriptor`] alone (no [`InitInfo`] field). Field layout
///     unchanged; an init built against v17 would read the new descriptor's
///     type byte as no [`CapType`] at all.
pub const INIT_PROTOCOL_VERSION: u32 = 18;

/// Length of [`InitModuleName::name`], matching
/// `boot_protocol::BOOT_MODULE_NAME_LEN` so the kernel copies the bundle
/// entry name straight through.
pub const INIT_MODULE_NAME_LEN: usize = 32;

/// Maximum number of named boot-module entries the kernel can publish in
/// [`InitInfo::module_names`]: one per boot module a `BootInfo` can list
/// (`boot_protocol::MAX_BOOT_MODULES`, 85, the entries of the bootloader's
/// one-page module array), so every module gets a name. This crate depends on
/// nothing outside `core`, so the kernel, which sees both crates, asserts the
/// two are equal. The table keeps the `InitInfo` header within its first page.
pub const INIT_MAX_NAMED_MODULES: usize = 85;

// ── Address space constants ──────────────────────────────────────────────────
//
// The `InitInfo` region and init stack virtual addresses are not ABI constants:
// the kernel chooses them per-boot (see `choose_init_layout` in the kernel) and
// delivers the `InitInfo` page address to init in the entry register, exactly as
// procmgr does for `ProcessInfo` (#250). Only the page-count bounds below — which
// both the kernel and init must agree on — remain part of the protocol.

/// Number of 4 KiB pages in init's user stack (16 KiB total).
///
/// The stack bounds only init's own call depth, which init's fixed code sets
/// and no hardware count grows.
pub const INIT_STACK_PAGES: usize = 4;

/// Ceiling on the 4 KiB pages of the [`InitInfo`] region (the header, which
/// includes the boot-module name table, followed by the [`CapDescriptor`]
/// array): 64 pages hold 8,079 descriptors past the header.
///
/// The kernel sizes each boot's region from that boot's own counts, one
/// descriptor per coalesced RAM extent, ACPI region, MMIO aperture, boot module
/// and reclaim range plus a few fixed caps, and reports the page count in
/// [`InitInfo::init_info_memory_count`]. Each of those counts is bounded by the
/// platform: coalesced RAM extents and ACPI regions by the firmware memory map,
/// apertures by the map and the firmware tables, modules by
/// `boot_protocol::MAX_BOOT_MODULES` (85), reclaim ranges by
/// `boot_protocol::MAX_RECLAIM_RANGES` (256). Real maps yield tens of
/// descriptors, so no platform comes near the ceiling; a boot that would pass
/// it halts by name. The ceiling sizes what must be fixed before init can
/// allocate: the virtual-address room the kernel leaves for the region and
/// init's orphan-cap table. Both sides must agree: changing this constant is a
/// protocol change — bump [`INIT_PROTOCOL_VERSION`].
pub const INIT_INFO_MAX_PAGES: usize = 64;

// ── InitInfo ─────────────────────────────────────────────────────────────────

/// Kernel-to-init handover structure.
///
/// Placed in one or more read-only pages at a kernel-chosen virtual address,
/// delivered to init in its entry register. The fixed-size header is followed by
/// a variable-length [`CapDescriptor`] array; the array starts at byte offset
/// [`InitInfo::cap_descriptors_offset`] from the start of this struct.
///
/// All slot fields refer to init's root `CSpace` (`CSpace` ID 0). Each slot
/// field holds a capability handle and each slot-count field a count of
/// consecutive slots; both are `u64`, the width of a capability handle. Every
/// handover cap sits in a never-recycled slot, so its handle is its bare slot
/// index and the caps of a range are `base..base + count`. The fields are laid
/// out with no implicit padding, so every byte of the header is a field's: the
/// kernel writes the fields in place into a zeroed page, and a header ever
/// written by value would carry a padding byte's kernel stack contents into
/// init's page.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitInfo
{
    /// Protocol version. Must equal [`INIT_PROTOCOL_VERSION`].
    pub version: u32,

    /// Number of [`CapDescriptor`] entries in the descriptor array.
    pub cap_descriptor_count: u32,

    /// Byte offset from the start of this struct to the first [`CapDescriptor`].
    ///
    /// The descriptor array contains `cap_descriptor_count` entries, one per
    /// Phase 7 and Phase 8 capability in init's `CSpace` (see
    /// `core/kernel/docs/capability-internals.md`). Init uses these to
    /// identify what each capability slot represents without probing.
    pub cap_descriptors_offset: u32,

    /// Number of valid [`InitModuleName`] entries in [`Self::module_names`].
    /// Indices `0..module_name_count` are populated; the rest are
    /// [`INIT_MODULE_NAME_EMPTY`].
    pub module_name_count: u32,

    // ── Init's own resources ─────────────────────────────────────────────
    /// Handle of init's own `AddressSpace` capability.
    pub aspace_cap: u64,

    /// Handle of the `SchedControl` capability.
    pub sched_control_cap: u64,

    // ── CSpace slot ranges (contiguous) ──────────────────────────────────
    /// First slot of usable physical memory `Memory` capabilities.
    pub memory_base: u64,
    /// Number of usable memory `Memory` capabilities.
    pub memory_count: u64,

    /// First slot of init's ELF segment `Memory` capabilities.
    pub segment_memory_base: u64,
    /// Number of segment `Memory` capabilities.
    pub segment_memory_count: u64,

    /// First slot of hardware resource capabilities (MMIO, IRQ, I/O port).
    pub hw_cap_base: u64,
    /// Number of hardware resource capabilities.
    pub hw_cap_count: u64,

    /// Handle of init's own `Thread` capability (CONTROL right).
    ///
    /// Allows init to bind I/O port ranges to itself (`ioport_bind`), set its
    /// own priority and affinity, and delegate thread authority to child services.
    pub thread_cap: u64,

    // ── RISC-V SBI forwarding (added in protocol version 3) ─────────────
    /// Handle of the `SbiControl` capability (RISC-V only).
    ///
    /// Grants authority to forward SBI calls from userspace through the kernel.
    /// Zero on x86-64 (no SBI concept).
    pub sbi_control_cap: u64,

    /// Handle of init's own `CSpace` capability.
    ///
    /// Init needs this to create threads bound to its own `CSpace` (e.g. a log
    /// thread that shares init's capability namespace). Added in protocol v4.
    pub cspace_cap: u64,

    // ── Root IRQ range + firmware-table caps (added in protocol v5) ─────
    /// Handle of the root `Interrupt` range capability.
    ///
    /// Covers the target arch's whole Interrupt id space (x86-64: GSIs
    /// 0..32768, `MAX_IOAPICS` I/O APICs of 256 pins each; RISC-V: the APLIC's
    /// 1024-id space, sources 1..1023); the cap's `CapDescriptor` `aux1` gives
    /// the count, and `SYS_IRQ_REGISTER` refuses an id no discovered
    /// controller implements. Userspace splits this cap with `SYS_IRQ_SPLIT`
    /// to produce single-IRQ sub-caps for device drivers.
    pub irq_range_cap: u64,

    /// Handle of the read-only `Memory` cap covering the 4 KiB page
    /// that contains the ACPI RSDP.
    ///
    /// RSDP commonly lives in firmware-reserved memory outside
    /// `AcpiReclaimable`, so it gets its own slot. Zero if no RSDP
    /// address was reported (pure-DTB platforms).
    pub acpi_rsdp_memory_cap: u64,

    /// First slot of the read-only `Memory` caps covering each
    /// `MemoryType::AcpiReclaimable` region in the boot memory map.
    pub acpi_region_memory_base: u64,

    /// Number of ACPI reclaimable-region `Memory` caps.
    pub acpi_region_memory_count: u64,

    /// Handle of the read-only `Memory` cap covering the DTB blob,
    /// or zero if no DTB was supplied (pure-ACPI platforms).
    pub dtb_memory_cap: u64,

    // ── Init self-reclaim cap surfaces (added in protocol v6) ───────────
    /// First slot of init's user stack `Memory` caps.
    ///
    /// Each cap covers one 4 KiB stack page; init holds
    /// `init_stack_memory_count` consecutive caps starting at this slot.
    /// Used by init's reap-handoff (`procmgr.REGISTER_INIT_TEARDOWN`) to
    /// donate the stack pages back to memmgr's pool after init's
    /// `AddressSpace` is torn down.
    pub init_stack_memory_base: u64,
    /// Number of stack `Memory` caps (typically `INIT_STACK_PAGES = 4`).
    pub init_stack_memory_count: u64,

    /// First slot of init's `InitInfo`-region `Memory` caps.
    ///
    /// Each cap covers one 4 KiB page of the kernel-allocated
    /// `InitInfo` region (header — which includes the boot-module name
    /// table — followed by the `CapDescriptor` array). Donated
    /// alongside the stack caps in init's reap-handoff.
    /// The cap range includes the page that contains this `InitInfo`
    /// struct itself — once init has read `InitInfo` at `_start`, the
    /// pages can be reclaimed safely.
    pub init_info_memory_base: u64,
    /// Number of `InitInfo` `Memory` caps (1..=[`INIT_INFO_MAX_PAGES`]),
    /// one per page of the region: the region's page count, which bounds the
    /// descriptor slice.
    pub init_info_memory_count: u64,

    // ── Boot-module name table (added in protocol version 7) ────────────
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
// total size must be 8-byte aligned. The header must also fit within the
// region's first page.
const _: () = assert!(
    core::mem::size_of::<InitInfo>().is_multiple_of(8),
    "InitInfo size must be 8-byte aligned so cap_descriptors_offset is 8-byte aligned",
);
const _: () = assert!(
    core::mem::size_of::<InitInfo>() <= 4096,
    "InitInfo header must fit within the region's first page",
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
    /// Capability handle of the slot.
    pub slot: u64,

    /// Capability type discriminant. See [`CapType`].
    pub cap_type: CapType,

    /// Padding for alignment; must be zero.
    #[doc(hidden)]
    pub pad: [u8; 7],

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
/// `boot_protocol::BootModule::name`) to the `CSpace` slot index of
/// the module's `Memory` capability. The table sits in the `InitInfo`
/// header so it always lives on the first `InitInfo` page and does not
/// interact with the variable-length [`CapDescriptor`] array, which
/// may span pages once `INIT_MAX_NAMED_MODULES` modules are minted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitModuleName
{
    /// Capability handle of the module's `Memory` cap.
    pub slot: u64,
    /// Bundle entry name, NUL-padded to [`INIT_MODULE_NAME_LEN`] bytes.
    pub name: [u8; INIT_MODULE_NAME_LEN],
}

/// Empty / NUL-padded slot for an unused [`InitModuleName`] entry.
pub const INIT_MODULE_NAME_EMPTY: InitModuleName = InitModuleName {
    slot: 0,
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
    /// Authority to mix bytes into the kernel entropy pool. Matches
    /// `CapTag::EntropyControl = 14`. `aux0 = aux1 = 0`.
    EntropyControl = 14,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Trim a NUL-padded module-name buffer to its non-NUL prefix.
#[must_use]
pub fn module_name_str(name: &[u8; INIT_MODULE_NAME_LEN]) -> &[u8]
{
    // `split` always yields a first item: the bytes before the first NUL, or
    // the whole name when it holds none.
    name.split(|&b| b == 0).next().unwrap_or(name)
}

/// Locate a boot-module `Memory` cap by its bundle-entry name.
///
/// Returns the capability handle from the first matching
/// [`InitModuleName`] in [`InitInfo::module_names`], or `None` if no
/// entry carries the requested name.
#[must_use]
pub fn find_module_slot(info: &InitInfo, name: &[u8]) -> Option<u64>
{
    let count = info.module_name_count as usize;
    for entry in info.module_names.iter().take(count)
    {
        if module_name_str(&entry.name) == name
        {
            return Some(entry.slot);
        }
    }
    None
}
