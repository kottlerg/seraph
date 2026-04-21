// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/lib.rs

//! Boot protocol types shared between the bootloader and kernel.
//!
//! Defines the [`BootInfo`] structure and associated types that form the
//! contract between the bootloader and the kernel entry point. See
//! `docs/boot-protocol.md` for the full specification.
//!
//! All types are `#[repr(C)]` with stable layout. The [`BOOT_PROTOCOL_VERSION`]
//! constant must match between the bootloader and kernel; the kernel halts at
//! entry if the versions differ.

#![no_std]

/// Current boot protocol version. Increment when `BootInfo` layout or the
/// CPU entry contract changes in a non-backwards-compatible way.
///
/// v4: Added `cpu_count`, `bsp_id`, `cpu_ids`, and `ap_trampoline_page` for
///     SMP bringup.
pub const BOOT_PROTOCOL_VERSION: u32 = 4;

// ── Memory map ───────────────────────────────────────────────────────────────

/// Classification of a physical memory region.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryType
{
    /// Available for use by the kernel.
    Usable = 0,
    /// In use by the kernel image or boot modules.
    Loaded = 1,
    /// Reserved by firmware or hardware; must not be used.
    Reserved = 2,
    /// ACPI reclaimable after userspace firmware parsing (devmgr) is complete.
    AcpiReclaimable = 3,
    /// Persistent memory (NVDIMM or similar).
    Persistent = 4,
}

/// A single entry in the physical memory map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemoryMapEntry
{
    /// Physical base address of the region.
    pub physical_base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Classification of the region.
    pub memory_type: MemoryType,
}

/// A slice of [`MemoryMapEntry`] values, passed by physical address.
///
/// Entries are sorted by `physical_base` in ascending order and do not overlap.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemoryMapSlice
{
    /// Physical address of the first entry. Null if `count` is zero.
    pub entries: *const MemoryMapEntry,
    /// Number of entries.
    pub count: u64,
}

// SAFETY: MemoryMapSlice contains raw pointers to boot-time physical memory.
// The bootloader guarantees these pointers are valid until the kernel explicitly
// reclaims the regions. Sharing across threads is safe because the boot sequence
// is single-threaded; the kernel reads the map before SMP is active.
unsafe impl Send for MemoryMapSlice {}
// SAFETY: Same rationale as Send; the map is read-only after population.
unsafe impl Sync for MemoryMapSlice {}

// ── Boot modules ─────────────────────────────────────────────────────────────

/// A boot module loaded by the bootloader (raw ELF image for early services).
///
/// The module set is configured via `boot.conf`. Each module is an ELF
/// executable for an early userspace service (procmgr, devmgr, drivers, etc.).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootModule
{
    /// Physical base address of the module data.
    pub physical_base: u64,
    /// Size of the module data in bytes (file size, not page-rounded size).
    pub size: u64,
}

/// A slice of [`BootModule`] values, passed by physical address.
///
/// Contains raw ELF images for early services. The module set is configurable
/// via `boot.conf`; minimum: procmgr, devmgr, one block driver, one FS driver,
/// VFS. Optionally: net stack and additional drivers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleSlice
{
    /// Physical address of the first entry. Null if `count` is zero.
    pub entries: *const BootModule,
    /// Number of entries.
    pub count: u64,
}

// SAFETY: Same rationale as MemoryMapSlice.
unsafe impl Send for ModuleSlice {}
// SAFETY: Same rationale as MemoryMapSlice.
unsafe impl Sync for ModuleSlice {}

// ── Init pre-parsed segments ──────────────────────────────────────────────────

/// Permission flags for a loaded ELF segment.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentFlags
{
    /// Readable, not writable, not executable (e.g. rodata).
    Read = 0,
    /// Readable and writable (e.g. data/bss).
    ReadWrite = 1,
    /// Readable and executable (e.g. text).
    ReadExecute = 2,
}

/// One pre-parsed ELF LOAD segment for init.
///
/// The bootloader pre-parses init's ELF and produces this array so the kernel
/// does not need an ELF parser to load init. The kernel maps each segment
/// directly from the provided physical addresses.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InitSegment
{
    /// Physical base address where this segment was loaded by the bootloader.
    pub phys_addr: u64,
    /// ELF virtual address this segment is mapped at.
    pub virt_addr: u64,
    /// Size of the segment in memory (`p_memsz`; may exceed file data).
    pub size: u64,
    /// Page permissions for this segment.
    pub flags: SegmentFlags,
}

/// Maximum number of ELF LOAD segments in init.
///
/// Must match the bootloader's segment array capacity.
pub const INIT_MAX_SEGMENTS: usize = 8;

/// Pre-parsed init ELF information provided by the bootloader.
///
/// The bootloader fully parses init's ELF and populates this structure so the
/// kernel can load init without containing an ELF parser. The kernel creates
/// init's address space by mapping each [`InitSegment`] directly.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InitImage
{
    /// Virtual entry point of init (`e_entry` from the ELF header).
    pub entry_point: u64,
    /// Pre-parsed LOAD segments. Valid entries occupy `[0..segment_count]`.
    pub segments: [InitSegment; INIT_MAX_SEGMENTS],
    /// Number of valid entries in `segments`.
    pub segment_count: u32,
}

// ── Framebuffer ──────────────────────────────────────────────────────────────

/// Pixel format of the framebuffer.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat
{
    /// Red–Green–Blue–Padding, 8 bits per channel.
    Rgbx8 = 0,
    /// Blue–Green–Red–Padding, 8 bits per channel.
    Bgrx8 = 1,
}

/// Framebuffer description provided by the bootloader.
///
/// When `physical_base` is zero, no framebuffer is available. The kernel and
/// early drivers must handle this case gracefully.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FramebufferInfo
{
    /// Physical base address of the framebuffer. Zero if no framebuffer.
    pub physical_base: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row (may exceed `width × bytes_per_pixel`).
    pub stride: u32,
    /// Pixel format.
    pub pixel_format: PixelFormat,
}

impl FramebufferInfo
{
    /// Return a zeroed `FramebufferInfo` indicating no framebuffer is present.
    #[must_use]
    pub const fn empty() -> Self
    {
        Self {
            physical_base: 0,
            width: 0,
            height: 0,
            stride: 0,
            pixel_format: PixelFormat::Rgbx8,
        }
    }
}

// ── Platform resources ───────────────────────────────────────────────────────

/// Discriminant identifying the kind of platform resource.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceType
{
    /// A memory-mapped I/O region.
    ///
    /// `base`+`size`: physical address range.
    /// `flags` bit 0: 0 = device (uncacheable), 1 = write-combine.
    /// `id`: opaque platform identifier (e.g. ACPI UID); zero if unknown.
    MmioRange = 0,

    /// A hardware interrupt line.
    ///
    /// `base`: unused (zero). `size`: unused (zero).
    /// `id`: interrupt number (GSI on x86-64, PLIC source on RISC-V).
    /// `flags` bit 0: 0 = level, 1 = edge triggered.
    /// `flags` bit 1: 0 = active-high, 1 = active-low.
    IrqLine = 1,

    /// A PCI Express ECAM window.
    ///
    /// `base`+`size`: physical ECAM MMIO range.
    /// `flags`: encoded bus range — bits 7:0 = start bus, bits 15:8 = end bus.
    /// `id`: segment group number (usually zero).
    PciEcam = 2,

    /// A firmware table region passed through to userspace as read-only.
    ///
    /// `base`+`size`: physical address range of the table.
    /// `flags`: reserved, zero.
    /// `id`: opaque identifier for the table type (platform-defined).
    PlatformTable = 3,

    /// An x86 I/O port range (x86-64 only).
    ///
    /// `base`: first port number. `size`: number of consecutive ports.
    /// `flags`: reserved, zero. `id`: opaque platform identifier; zero if unknown.
    IoPortRange = 4,

    /// An IOMMU unit's register range and scope.
    ///
    /// `base`+`size`: physical MMIO range of the IOMMU's registers.
    /// `flags`: reserved for future scope encoding; zero in protocol version 3.
    /// `id`: opaque platform identifier (e.g. ACPI DMAR unit index).
    IommuUnit = 5,
}

/// A structured descriptor for a platform hardware resource.
///
/// The array of `PlatformResource` entries in [`BootInfo`] is sorted by
/// `(resource_type, base)` in ascending order. Within a type, entries do not
/// overlap where overlap is nonsensical.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PlatformResource
{
    /// Discriminant identifying the kind of resource.
    pub resource_type: ResourceType,
    /// Type-specific flags (see [`ResourceType`] documentation).
    pub flags: u32,
    /// Physical base address of the resource (zero for [`ResourceType::IrqLine`]).
    pub base: u64,
    /// Size of the resource in bytes (zero for [`ResourceType::IrqLine`]).
    pub size: u64,
    /// Opaque, type-specific identifier. Do not compare across resource types.
    pub id: u64,
}

/// A slice of [`PlatformResource`] values, passed by physical address.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PlatformResourceSlice
{
    /// Physical address of the first entry. Null if `count` is zero.
    pub entries: *const PlatformResource,
    /// Number of entries.
    pub count: u64,
}

// SAFETY: Same rationale as MemoryMapSlice.
unsafe impl Send for PlatformResourceSlice {}
// SAFETY: Same rationale as MemoryMapSlice.
unsafe impl Sync for PlatformResourceSlice {}

// ── BootInfo ─────────────────────────────────────────────────────────────────

/// Boot information structure populated by the bootloader and passed to the
/// kernel entry point.
///
/// All pointer and address fields hold **physical addresses**. The kernel
/// converts them via its direct physical map once paging is fully established.
///
/// The `version` field must equal [`BOOT_PROTOCOL_VERSION`]; the kernel halts
/// if it does not.
#[repr(C)]
#[derive(Debug)]
pub struct BootInfo
{
    /// Protocol version. Must equal [`BOOT_PROTOCOL_VERSION`].
    pub version: u32,

    /// Physical memory map describing all address ranges.
    pub memory_map: MemoryMapSlice,

    /// Physical base address of the loaded kernel image.
    pub kernel_physical_base: u64,
    /// ELF virtual base address of the kernel image.
    pub kernel_virtual_base: u64,
    /// Total span of the kernel ELF LOAD segments in bytes.
    pub kernel_size: u64,

    /// Pre-parsed init ELF information.
    ///
    /// The bootloader fully parses init's ELF and provides the entry point and
    /// segment array so the kernel can map init without an ELF parser.
    pub init_image: InitImage,

    /// Additional boot modules (raw ELF images for early services).
    ///
    /// The set of modules is configured via `boot.conf`.
    pub modules: ModuleSlice,

    /// Framebuffer, if available. `physical_base == 0` means no framebuffer.
    pub framebuffer: FramebufferInfo,

    /// Physical address of the ACPI RSDP (x86-64). Zero on RISC-V or if absent.
    ///
    /// Passed through for userspace consumption (`devmgr`). The kernel does
    /// not parse ACPI tables.
    pub acpi_rsdp: u64,

    /// Physical address of the Device Tree blob (RISC-V). Zero on x86-64 or if absent.
    ///
    /// Passed through for userspace consumption (`devmgr`). The kernel does
    /// not parse the Device Tree.
    pub device_tree: u64,

    /// Structured platform resource descriptors extracted from firmware tables.
    ///
    /// The kernel mints initial capabilities from these entries. Sorted by
    /// `(resource_type, base)` in ascending order.
    pub platform_resources: PlatformResourceSlice,

    /// Physical address of a null-terminated kernel command line string.
    ///
    /// May point to a single null byte if no command line was specified.
    pub command_line: *const u8,
    /// Length of the command line string in bytes, excluding the null terminator.
    pub command_line_len: u64,

    // ── SMP fields (added in protocol version 4) ──────────────────────────────
    /// Number of logical CPUs present and usable.
    ///
    /// On x86-64: count of enabled LAPIC entries from the ACPI MADT.
    /// On RISC-V: count of enabled RINTC (MADT type 0x18) entries, or hart
    /// count from the DTB if ACPI is absent.
    /// Always at least 1 (the BSP).
    pub cpu_count: u32,

    /// Hardware identifier of the bootstrap processor (BSP).
    ///
    /// On x86-64: APIC ID of the BSP (read from CPUID.01H:EBX[31:24]).
    /// On RISC-V: hart ID of the booting hart (from `EFI_RISCV_BOOT_PROTOCOL`).
    pub bsp_id: u32,

    /// Hardware identifiers for all CPUs, indexed by logical CPU index.
    ///
    /// `cpu_ids[0]` is always the BSP (`bsp_id`). `cpu_ids[1..cpu_count]` are
    /// the APs in discovery order. Entries beyond `cpu_count` are zero.
    ///
    /// On x86-64: APIC IDs. On RISC-V: hart IDs.
    pub cpu_ids: [u32; 64],

    /// Physical address of the AP startup trampoline page (x86-64 only).
    ///
    /// On x86-64: a 4 KiB frame below 1 MiB reserved by the bootloader before
    /// `ExitBootServices` for use as the SIPI real-mode entry point. The kernel
    /// writes AP startup code here before sending INIT/SIPI IPIs.
    ///
    /// On RISC-V (or when no trampoline is needed): zero.
    pub ap_trampoline_page: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// `empty()` must signal "no framebuffer" via physical_base == 0.
    #[test]
    fn framebuffer_info_empty_physical_base_is_zero()
    {
        assert_eq!(FramebufferInfo::empty().physical_base, 0);
    }

    /// All dimension fields are zero, confirming the struct is fully zeroed.
    #[test]
    fn framebuffer_info_empty_dimensions_are_zero()
    {
        let fb = FramebufferInfo::empty();
        assert_eq!(fb.width, 0);
        assert_eq!(fb.height, 0);
        assert_eq!(fb.stride, 0);
    }

    /// pixel_format defaults to Rgbx8 (discriminant 0), which equals the
    /// zeroed bit pattern for the PixelFormat repr(u32).
    #[test]
    fn framebuffer_info_empty_pixel_format_is_rgbx8()
    {
        assert_eq!(FramebufferInfo::empty().pixel_format, PixelFormat::Rgbx8);
    }

    /// BOOT_PROTOCOL_VERSION must be 4 after the SMP cpu_count addition.
    #[test]
    fn protocol_version_is_4()
    {
        assert_eq!(BOOT_PROTOCOL_VERSION, 4);
    }

    /// InitImage segment_count field must fit within INIT_MAX_SEGMENTS.
    #[test]
    fn init_image_segment_count_fits_max()
    {
        assert!(INIT_MAX_SEGMENTS <= u32::MAX as usize);
    }
}
