// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/lib.rs

//! Boot protocol types shared between the bootloader and kernel.
//!
//! Defines the [`BootInfo`] structure and associated types that form the
//! contract between the bootloader and the kernel entry point. The crate
//! source is the authoritative layout specification; this module-level
//! comment is an index, not the contract.
//!
//! All types are `#[repr(C)]` with stable layout. The [`BOOT_PROTOCOL_VERSION`]
//! constant must match between the bootloader and kernel; the kernel halts at
//! entry if the versions differ.
//!
//! See [`README.md`](../README.md) for the compliant-bootloader policy and
//! `boot/docs/kernel-handoff.md` for the CPU-state contract at kernel entry.

#![no_std]

pub mod bundle;
pub mod riscv_paging;
pub mod role_guids;

/// Current boot protocol version. Increment when `BootInfo` layout or the
/// CPU entry contract changes in a non-backwards-compatible way.
///
/// The kernel enforces **strict equality** against this constant at entry:
/// any mismatch — including a bootloader that is layout-compatible but
/// announces a higher version — is rejected. The rationale is TCB
/// minimization: the kernel refuses to interpret a `BootInfo` whose exact
/// layout it was not compiled against. A protocol bump therefore requires
/// the bootloader and kernel to be updated together in the same commit.
///
/// v4: Added `cpu_count`, `bsp_id`, `cpu_ids`, and `ap_trampoline_page` for
///     SMP bringup.
/// v5: Raised `cpu_ids` to `[u32; 512]`; removed `IommuUnit` from
///     `ResourceType` (IOMMU discovery is userspace-only, done by `devmgr`).
/// v6: Replaced per-device `PlatformResource` array with two narrower
///     descriptors: `kernel_mmio` (arch-specific struct carrying the small
///     MMIO bases the kernel itself consumes) and `mmio_apertures` (coarse
///     non-RAM physical ranges from which the kernel mints MMIO caps).
/// v7: Added `reclaim_ranges: ReclaimSlice` so the bootloader can hand the
///     kernel a list of scratch pages (`BootInfo` page, module descriptor
///     array, memory-map entry array, MMIO aperture array, the
///     reclaim-array page itself, and the bootloader's own transient
///     page-table frames) that are safe to reclaim once
///     the kernel's Phase-7 capability system has consumed them. The
///     slice is backed by a dedicated 4 KiB scratch page; that page is
///     itself the final entry in the array so the kernel reclaims it
///     last. The kernel mints reclaimable Memory caps over each range
///     inside `populate_cspace` so the pages reach userspace through
///     the same `CapDescriptor` path as boot modules.
///     Renamed `ReclaimRange.reserved` to `ReclaimRange.flags` (no
///     on-wire layout change); bit 0 ([`RECLAIM_FLAG_LATE`]) marks an
///     entry as deferred to the kernel's post-SMP-bringup late-reclaim
///     pass (the AP SIPI trampoline page is the only such entry
///     today). All other bits remain reserved (producers MUST write
///     zero).
/// v8: Removed `command_line` / `command_line_len` from `BootInfo` —
///     boot-time configuration moves to GPT type-GUID partition discovery
///     (vfsd-side) and compile-time defaults (ktest options). Added a
///     `name: [u8; 32]` field to [`BootModule`] (NUL-padded) so init can
///     match boot modules by identity instead of ordinal. Introduced the
///     [`bundle`] module: bootloader-loaded modules and init are now
///     packed into a single `\EFI\seraph\bootstrap.bundle` file on the
///     ESP, identified inside the bundle by the same name string carried
///     in `BootModule.name`. The entry named `"init"` is special-cased by
///     the bootloader and pre-parsed as an ELF into [`BootInfo::init_image`];
///     every other entry is exposed verbatim through `BootInfo::modules`.
/// v9: Added `boot_entropy_seed: [u8; 32]` and `boot_entropy_len: u32` so the
///     bootloader can hand the kernel a conditioned early-boot entropy seed
///     obtained from UEFI `EFI_RNG_PROTOCOL` while boot services are live. The
///     kernel absorbs it into the entropy pool at Phase 5, narrowing the
///     boot-time entropy hole before any early consumer (KASLR/ASLR) draws
///     randomness. `boot_entropy_len` is `0` when no source was available, in
///     which case the kernel degrades to timing jitter alone.
/// v10: [`InitImage`] gained `flags: u32` (bit 0 = [`INIT_IMAGE_FLAG_PIE`]:
///     init is `ET_DYN`; the kernel chooses a load bias and applies the
///     image's `RELATIVE` relocations before mapping), plus `rela_phys: u64`
///     and `rela_size: u64` — the physical address and byte size of the
///     pre-located `.rela.dyn` table — and `relro_vaddr: u64` /
///     `relro_size: u64` — the `PT_GNU_RELRO` span (unbiased link VAs) the
///     kernel maps read-only once relocations are applied. All four are
///     zero when absent. `ET_EXEC` init images carry `flags = 0` and zeroed
///     relocation/RELRO fields and load exactly as before.
/// v11: The riscv64 [`KernelMmio`] variant gained `timebase_freq: u64` (the
///     `time` CSR frequency in Hz, from ACPI RHCT or the DTB `/cpus`
///     `timebase-frequency` property; zero when undiscovered) and
///     `hart_caps: u64` (ISA-capability bits the bootloader positively
///     confirmed on every enabled hart; bit 0 = [`HART_CAP_SSTC`]). The
///     kernel timer refuses to boot without Sstc and a discovered
///     timebase; there is no compiled-in frequency fallback.
pub const BOOT_PROTOCOL_VERSION: u32 = 11;

// ── Memory map ───────────────────────────────────────────────────────────────

/// Classification of a physical memory region.
///
/// This enum intentionally collapses the ~15 UEFI `EFI_MEMORY_TYPE` values
/// into a small, consumer-facing set. Distinctions within each variant below
/// are not preserved; downstream code MUST NOT assume any sub-kind.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryType
{
    /// Available for use by the kernel.
    ///
    /// Subsumes `EfiConventionalMemory`, and — after `ExitBootServices` —
    /// `EfiBootServicesCode` and `EfiBootServicesData`.
    Usable = 0,
    /// In use by the kernel image or boot modules.
    ///
    /// Subsumes `EfiLoaderCode` and `EfiLoaderData` for the regions the
    /// bootloader deliberately staged for kernel consumption.
    Loaded = 1,
    /// Reserved by firmware or hardware; must not be used.
    ///
    /// Subsumes every UEFI variant that is not safely writable by the
    /// kernel after exit: `EfiRuntimeServicesCode`, `EfiRuntimeServicesData`,
    /// `EfiACPIMemoryNVS`, `EfiMemoryMappedIO`, `EfiMemoryMappedIOPortSpace`,
    /// `EfiPalCode`, `EfiUnusableMemory`, and anything unknown to the
    /// translator. The kernel cannot distinguish genuine device MMIO from
    /// firmware-exclusive regions via this enum; MMIO intended for driver
    /// use is delivered separately via [`MmioApertureSlice`].
    Reserved = 2,
    /// ACPI reclaimable after userspace firmware parsing (devmgr) is complete.
    ///
    /// Subsumes `EfiACPIReclaimMemory`.
    AcpiReclaimable = 3,
    /// Persistent memory (NVDIMM or similar).
    ///
    /// Subsumes `EfiPersistentMemory`.
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
/// Entries are sorted by `physical_base` in ascending order and do not
/// overlap — the kernel may rely on both invariants without
/// re-validating. The kernel must not write to `Reserved` regions;
/// `Loaded` regions containing boot modules may be reclaimed once the
/// kernel has consumed them.
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

/// Maximum length of a [`BootModule::name`] (NUL-padded; the NUL terminator
/// is part of the array, so usable name length is up to 32 bytes with no
/// terminator implied beyond the array bound).
///
/// Matches [`bundle::BundleEntryHeader::name`] so the bootloader can copy
/// the bundle entry's name verbatim into `BootModule.name`.
pub const BOOT_MODULE_NAME_LEN: usize = 32;

/// A boot module loaded by the bootloader (raw ELF image for early services).
///
/// The module set is sourced from the `\EFI\seraph\bootstrap.bundle` file
/// on the ESP (see [`bundle`]). Each module is an ELF executable for an
/// early userspace service (procmgr, devmgr, drivers, etc.). `name`
/// carries the bundle entry's identifier so init can match modules by
/// identity instead of position in the array.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootModule
{
    /// Identifier copied verbatim from the bundle entry header, NUL-padded
    /// to [`BOOT_MODULE_NAME_LEN`] bytes. The bundle's entry named `"init"`
    /// is consumed by the bootloader as the userspace init image and does
    /// not appear here; every other entry is exposed as a `BootModule`.
    pub name: [u8; BOOT_MODULE_NAME_LEN],
    /// Physical base address of the module data.
    pub physical_base: u64,
    /// Size of the module data in bytes (file size, not page-rounded size).
    pub size: u64,
}

/// A slice of [`BootModule`] values, passed by physical address.
///
/// Contains raw ELF images for early services. The module set is determined
/// by the contents of `\EFI\seraph\bootstrap.bundle` minus the special
/// `"init"` entry the bootloader consumes for [`BootInfo::init_image`].
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
///
/// Read permission is implied for every loaded segment — there is no
/// execute-only or write-only variant. A producer encountering an ELF
/// segment whose ELF `p_flags` bits express `PF_X` without `PF_R` MUST
/// map it as [`ReadExecute`](Self::ReadExecute) (read is necessary for
/// instruction fetch to be observable alongside other accesses and for
/// the kernel's page-table builder to encode a coherent PTE). Similarly,
/// `PF_W` without `PF_R` is mapped as [`ReadWrite`](Self::ReadWrite).
/// `W^X` (simultaneous `PF_W` and `PF_X`) MUST be rejected by the
/// producer, not silently collapsed.
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

/// Maximum number of logical CPUs representable in [`BootInfo::cpu_ids`].
///
/// Sizes the fixed array at the ABI boundary. Producers MUST cap
/// `cpu_count` at this value and diagnose truncation; consumers may assume
/// `cpu_count <= MAX_CPUS` and `cpu_ids[cpu_count..]` is zero.
pub const MAX_CPUS: usize = 512;

/// [`InitImage::flags`] bit 0: init is a position-independent executable
/// (`ET_DYN`). The kernel chooses a load bias, applies the image's
/// `RELATIVE` relocations (located by [`InitImage::rela_phys`] /
/// [`InitImage::rela_size`]), and biases every segment VA and the entry
/// point before mapping.
pub const INIT_IMAGE_FLAG_PIE: u32 = 1 << 0;

/// Pre-parsed init ELF information provided by the bootloader.
///
/// The bootloader fully parses init's ELF and populates this structure so the
/// kernel can load init without containing an ELF parser. The kernel creates
/// init's address space by mapping each [`InitSegment`] directly.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InitImage
{
    /// Virtual entry point of init (`e_entry` from the ELF header). For a
    /// PIE image this is the unbiased link-VA entry; the kernel adds its
    /// chosen load bias.
    pub entry_point: u64,
    /// Pre-parsed LOAD segments. Valid entries occupy `[0..segment_count]`.
    /// For a PIE image the `virt_addr` fields are unbiased link VAs.
    pub segments: [InitSegment; INIT_MAX_SEGMENTS],
    /// Number of valid entries in `segments`.
    pub segment_count: u32,
    /// Image flags; see [`INIT_IMAGE_FLAG_PIE`]. All other bits are
    /// reserved (producers MUST write zero).
    pub flags: u32,
    /// Physical address of the image's `.rela.dyn` table within the loaded
    /// segment bytes; zero when the image carries no relocations.
    pub rela_phys: u64,
    /// Byte size of the `.rela.dyn` table; zero when absent.
    pub rela_size: u64,
    /// Link VA of the `PT_GNU_RELRO` region (unbiased); zero when absent.
    /// The kernel maps the covered pages read-only after applying
    /// relocations.
    pub relro_vaddr: u64,
    /// Byte size of the `PT_GNU_RELRO` region; zero when absent.
    pub relro_size: u64,
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

    /// Size of the serialised form in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Serialise into `buf`. Returns `None` if the buffer is shorter than
    /// [`Self::SIZE`].
    #[must_use]
    pub fn to_bytes(&self, buf: &mut [u8]) -> Option<()>
    {
        if buf.len() < Self::SIZE
        {
            return None;
        }
        // SAFETY: buf has sufficient length; Self is repr(C) POD.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(self).cast::<u8>(),
                buf.as_mut_ptr(),
                Self::SIZE,
            );
        }
        Some(())
    }

    /// Deserialise from a byte slice. Returns `None` if `bytes` is shorter
    /// than [`Self::SIZE`] or carries a `pixel_format` discriminant outside
    /// the known set.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self>
    {
        if bytes.len() < Self::SIZE
        {
            return None;
        }
        // Parse field-by-field. Constructing a `PixelFormat` whose
        // discriminant is outside its declared variants is UB; validate
        // before materialising the enum.
        let physical_base = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let width = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let height = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let stride = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let pf_raw = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let pixel_format = match pf_raw
        {
            0 => PixelFormat::Rgbx8,
            1 => PixelFormat::Bgrx8,
            _ => return None,
        };
        Some(Self {
            physical_base,
            width,
            height,
            stride,
            pixel_format,
        })
    }
}

/// Schema version of the [`FramebufferInfo`] payload exchanged via
/// devmgr's `QUERY_DEVICE_INFO`. Bump whenever the struct layout
/// changes; callers verify this value before deserialising.
pub const FRAMEBUFFER_INFO_VERSION: u32 = 1;

// ── Kernel MMIO (arch-specific) ──────────────────────────────────────────────
//
// `KernelMmio` carries the small set of platform facts the kernel itself
// reads during its own operation (interrupts, timer). It is **not** a
// capability surface — the kernel consumes it directly and does not mint
// caps from it. The `mmio_apertures` slice below is the capability-minting
// surface.
//
// Shape is arch-specific: each arch's fields are the values that arch's
// kernel actually uses.

/// One I/O APIC instance description (x86-64).
///
/// ACPI MADT type 1 (`IOAPIC`) supplies `id`, `phys_base`, and `gsi_base`
/// for each I/O APIC. Real systems typically have one; the array in
/// [`KernelMmio`] admits up to [`MAX_IOAPICS`].
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoApicEntry
{
    /// APIC ID reported by the MADT record.
    pub id: u32,
    /// Physical base address of the I/O APIC register window.
    pub phys_base: u64,
    /// Global system interrupt number of the first pin on this IOAPIC.
    pub gsi_base: u32,
}

/// Maximum number of I/O APICs the bootloader records.
///
/// Oversize MADTs are truncated at this bound with a diagnostic; real
/// systems with more than eight IOAPICs are out of the targeted envelope.
#[cfg(target_arch = "x86_64")]
pub const MAX_IOAPICS: usize = 8;

/// Kernel-facing MMIO bases on x86-64.
///
/// Fields are what `kernel/src/arch/x86_64/` needs to reach the interrupt
/// controllers today. The COM1 UART is I/O-port-mapped (not MMIO) and is
/// not included.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelMmio
{
    /// Physical base of the local APIC register window. On Q35 / every
    /// currently targeted host this is `0xFEE0_0000`, but MADT
    /// `LocalApicAddress` or the later `LocalApicAddressOverride` entry
    /// may relocate it.
    pub lapic_base: u64,
    /// Number of valid entries in [`Self::ioapics`].
    pub ioapic_count: u32,
    /// I/O APIC instances discovered in the MADT. `[ioapic_count..]` is zeroed.
    pub ioapics: [IoApicEntry; MAX_IOAPICS],
}

#[cfg(target_arch = "x86_64")]
impl KernelMmio
{
    /// Zeroed `KernelMmio` for bootloaders that cannot populate it (e.g.
    /// ACPI tables absent). The kernel falls back to its hardcoded
    /// constants when the corresponding field is zero.
    #[must_use]
    pub const fn zero() -> Self
    {
        Self {
            lapic_base: 0,
            ioapic_count: 0,
            ioapics: [IoApicEntry {
                id: 0,
                phys_base: 0,
                gsi_base: 0,
            }; MAX_IOAPICS],
        }
    }
}

/// Kernel-facing platform description on RISC-V 64: the MMIO bases plus the
/// two non-MMIO hart facts (`timebase_freq`, `hart_caps`) the kernel's own
/// initialization consumes before any userspace exists.
///
/// Fields are what `kernel/src/arch/riscv64/` needs today. CLINT is not
/// included because S-mode arms the timer through the Sstc `stimecmp` CSR,
/// not CLINT MMIO.
#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelMmio
{
    /// Physical base of the PLIC register window.
    pub plic_base: u64,
    /// Size of the PLIC register window in bytes.
    pub plic_size: u64,
    /// Physical base of the kernel console UART (ns16550-compatible).
    pub uart_base: u64,
    /// Size of the UART register window in bytes.
    pub uart_size: u64,
    /// Frequency of the `time` CSR in Hz, from the ACPI RHCT
    /// `TimeBaseFrequency` field or the DTB `/cpus` `timebase-frequency`
    /// property. Zero when neither source provided it; the kernel timer
    /// treats an undiscovered timebase as fatal (no compiled-in default).
    pub timebase_freq: u64,
    /// ISA-capability bits the bootloader positively confirmed on every
    /// enabled hart (bit 0 = [`HART_CAP_SSTC`]). Each firmware source ORs
    /// in the bits it can confirm; zero means undiscovered or absent.
    pub hart_caps: u64,
}

/// [`KernelMmio::hart_caps`] bit 0: every enabled hart implements Sstc
/// (the `stimecmp` supervisor timer CSR).
#[cfg(target_arch = "riscv64")]
pub const HART_CAP_SSTC: u64 = 1 << 0;

#[cfg(target_arch = "riscv64")]
impl KernelMmio
{
    /// Zeroed `KernelMmio` for bootloaders that cannot populate it. The
    /// kernel falls back to its hardcoded constants when the corresponding
    /// MMIO field is zero; a zero `timebase_freq` or `hart_caps` is fatal
    /// at timer initialization instead.
    #[must_use]
    pub const fn zero() -> Self
    {
        Self {
            plic_base: 0,
            plic_size: 0,
            uart_base: 0,
            uart_size: 0,
            timebase_freq: 0,
            hart_caps: 0,
        }
    }
}

// ── MMIO apertures ───────────────────────────────────────────────────────────

/// A coarse-grained MMIO physical range covering some subset of the
/// platform's non-RAM address space.
///
/// Each entry is a region from which the kernel mints exactly one
/// `Mmio` capability (MAP | WRITE) and hands it to init. Userspace
/// narrows these to per-device ranges via `mmio_split` (not in this
/// protocol revision) and distributes them to drivers. Apertures are
/// intentionally coarse; device-level enumeration is `devmgr`'s job from
/// ACPI / DTB passthrough.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MmioAperture
{
    /// Physical base address of the aperture (page-aligned).
    pub phys_base: u64,
    /// Size of the aperture in bytes (page-aligned, non-zero).
    pub size: u64,
}

/// Maximum number of MMIO apertures the bootloader records.
///
/// Derived from `EfiMemoryMappedIO` / `EfiMemoryMappedIOPortSpace`
/// regions of the UEFI memory map, unioned with firmware-advertised PCI
/// apertures (MCFG on x86-64, `/soc ranges` on RISC-V), then
/// sorted-and-merged. Platforms with more than sixteen disjoint
/// non-RAM regions are out of the targeted envelope.
pub const MAX_APERTURES: usize = 16;

/// A slice of [`MmioAperture`] values, passed by physical address.
///
/// Entries are sorted by `phys_base` ascending and do not overlap.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MmioApertureSlice
{
    /// Physical address of the first entry. Null if `count` is zero.
    pub entries: *const MmioAperture,
    /// Number of entries.
    pub count: u64,
}

// SAFETY: Same rationale as MemoryMapSlice — boot-time physical memory,
// produced pre-ExitBootServices and read-only after handoff.
unsafe impl Send for MmioApertureSlice {}
// SAFETY: Same rationale as MemoryMapSlice.
unsafe impl Sync for MmioApertureSlice {}

// ── Reclaimable bootloader scratch ───────────────────────────────────────────

/// A contiguous range of physical pages the bootloader allocated for its own
/// scratch use and which becomes reclaim-safe once the kernel's Phase-7
/// capability system has consumed it.
///
/// The kernel walks the [`ReclaimSlice`] in [`BootInfo`] inside
/// `populate_cspace`, mints one reclaimable `MemoryObject` cap per range, and
/// inserts each into the root `CSpace` so the cap reaches userspace through
/// the standard `CapDescriptor` path. Once `populate_cspace` returns, the
/// kernel MUST NOT dereference any address inside a recorded range.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReclaimRange
{
    /// Page-aligned physical base address.
    pub phys_base: u64,
    /// Number of 4 KiB pages covered. Non-zero.
    pub page_count: u32,
    /// Per-entry flags. See [`RECLAIM_FLAG_LATE`]. All other bits are
    /// reserved; producers MUST write zero for them.
    pub flags: u32,
}

/// `ReclaimRange.flags` bit: defer minting to a kernel-side "late reclaim"
/// pass that runs after SMP bringup and any required identity-mapping
/// teardown. Used today for the AP SIPI trampoline page: both supported
/// arches (x86-64 and RISC-V) install a low-VA identity-RWX mapping over
/// the trampoline page so the AP can continue fetching instructions at
/// its PA after enabling paging, and the kernel must retire that mapping
/// via TLB shootdown before handing the page to userspace as a Memory cap.
pub const RECLAIM_FLAG_LATE: u32 = 1;

/// Maximum number of [`ReclaimRange`] entries one 4 KiB reclaim-array page
/// can hold. The bootloader allocates a dedicated 4 KiB page for the array
/// and indexes into it; 256 × 16 B = 4 KiB exactly.
///
/// A typical seraph boot produces between fifteen and fifty entries (one
/// per fixed scratch allocation plus one per bootloader transient
/// page-table frame). The bootloader diagnoses overflow as a sizing bug
/// rather than truncating.
pub const MAX_RECLAIM_RANGES: usize = 256;

/// A slice of [`ReclaimRange`] values, passed by physical address.
///
/// Stored in `BootInfo` as a `(*const ReclaimRange, u64)` slice so the
/// underlying array lives in its own dedicated 4 KiB scratch page,
/// avoiding inline pressure on the `BootInfo` page-fit budget. The
/// array's backing page is itself one of the recorded entries — the
/// kernel reclaims it via `cap::mint_reclaim_memory_caps` once the
/// scan completes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReclaimSlice
{
    /// Physical address of the first entry. Null if `count` is zero.
    pub entries: *const ReclaimRange,
    /// Number of entries.
    pub count: u64,
}

// SAFETY: Same rationale as MemoryMapSlice — boot-time physical memory,
// produced pre-ExitBootServices and read-only after handoff.
unsafe impl Send for ReclaimSlice {}
// SAFETY: Same rationale as MemoryMapSlice.
unsafe impl Sync for ReclaimSlice {}

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
    /// The set of modules is sourced from the bootloader's
    /// `bootstrap.bundle`; see the [`bundle`] module for the wire
    /// format and the `init` entry name special-cased by the bootloader.
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

    /// Arch-specific platform facts the kernel itself consumes.
    ///
    /// Not a capability surface. The kernel reads these values directly
    /// during its own initialisation (interrupt controller, timer). Fields
    /// not populated by the bootloader are zero; per-field docs on
    /// [`KernelMmio`] state whether the kernel falls back to a compiled-in
    /// default or refuses to boot.
    pub kernel_mmio: KernelMmio,

    /// Coarse-grained MMIO apertures from which the kernel mints
    /// `Mmio` capabilities.
    ///
    /// One cap minted per entry, handed to init, narrowed and distributed
    /// by userspace. Replaces the per-device `PlatformResource` array from
    /// protocol versions 4 and 5.
    pub mmio_apertures: MmioApertureSlice,

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
    /// On x86-64: APIC IDs (LAPIC `ApicId` field from ACPI MADT).
    /// On RISC-V: hart IDs.
    ///
    /// The fixed array length is [`MAX_CPUS`] (512), chosen to cover
    /// current dual-socket high-end server hardware (e.g. 192-core ×
    /// 2-socket EPYC without SMT = 384; 128-core × 2-socket × 2-thread
    /// Intel = 512) while keeping `BootInfo` inside a single 4 KiB page.
    /// Producers that discover more enabled CPUs MUST cap at this length
    /// and MUST diagnose the truncation.
    pub cpu_ids: [u32; MAX_CPUS],

    /// Physical address of a 4 KiB page reserved for the AP startup
    /// trampoline. The kernel writes AP startup code into this page before
    /// bringing secondary processors online.
    ///
    /// Arch-specific constraints on the physical address:
    /// - **x86-64**: MUST be below 1 MiB. The SIPI vector encodes the
    ///   real-mode start address in bits `[19:12]` of the IPI ICR, so the
    ///   trampoline must live in the first megabyte.
    /// - **RISC-V**: any 4 KiB frame. SBI HSM (`HART_START`) accepts any
    ///   physical address for the entry point, so no placement constraint
    ///   applies beyond page alignment.
    ///
    /// Zero if the bootloader could not reserve a trampoline page (SMP will
    /// then be unavailable; the kernel continues BSP-only).
    pub ap_trampoline_page: u64,

    // ── Reclaimable scratch (added in protocol version 7) ─────────────────────
    /// Bootloader scratch ranges the kernel reclaims into the cap surface
    /// inside `populate_cspace`. The slice's backing array lives in its
    /// own dedicated 4 KiB scratch page; that page is itself one of the
    /// recorded entries, so the kernel reclaims it last. Reading or
    /// writing any address in a recorded range after the Phase-7 cap
    /// system has been initialised is undefined behaviour from the
    /// kernel's perspective.
    pub reclaim_ranges: ReclaimSlice,

    // ── Boot entropy seed (added in protocol version 9) ───────────────────────
    /// Conditioned early-boot entropy seed obtained by the bootloader from UEFI
    /// `EFI_RNG_PROTOCOL`. Valid only for the first `boot_entropy_len` bytes;
    /// the remainder is zero. The kernel absorbs it into the entropy pool at
    /// Phase 5, then **scrubs it from this page** (`boot_entropy_seed`/`_len`
    /// zeroed) before Phase 7 — this page is a reclaim range donated to
    /// userspace, so the secret seed must not outlive boot.
    ///
    /// This is already a conditioned (DRBG) output, not a raw source, so the
    /// kernel absorbs it directly without the raw-source health gating.
    pub boot_entropy_seed: [u8; 32],

    /// Number of valid leading bytes in `boot_entropy_seed`. `0` means the
    /// bootloader found no entropy source; the kernel then degrades to timing
    /// jitter alone (no regression).
    pub boot_entropy_len: u32,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    // FramebufferInfo::empty() is the "no framebuffer" sentinel: the kernel treats
    // physical_base == 0 as absent and disregards the remaining fields.
    #[test]
    fn empty_signals_no_framebuffer()
    {
        let fb = FramebufferInfo::empty();
        assert_eq!(fb.physical_base, 0);
        assert_eq!(fb.width, 0);
        assert_eq!(fb.height, 0);
        assert_eq!(fb.stride, 0);
        assert_eq!(fb.pixel_format, PixelFormat::Rgbx8);
    }

    // ABI contract: the bootloader writes these structures into the BootInfo page and
    // the kernel reads them back by offset, so their sizes are part of
    // BOOT_PROTOCOL_VERSION. A size change is a boot-protocol break, not a refactor.
    #[test]
    fn boot_protocol_struct_sizes_are_stable()
    {
        assert_eq!(core::mem::size_of::<ReclaimRange>(), 16);
        assert_eq!(core::mem::size_of::<MmioApertureSlice>(), 16);
        assert_eq!(core::mem::size_of::<MmioAperture>(), 16);
        assert_eq!(FramebufferInfo::SIZE, 24);
        assert!(core::mem::size_of::<BootInfo>() <= 4096);
    }

    /// Round-trip: a populated `FramebufferInfo` survives `to_bytes` then
    /// `from_bytes` with every field intact.
    #[test]
    fn framebuffer_info_round_trip()
    {
        let fb = FramebufferInfo {
            physical_base: 0xFD00_0000,
            width: 1024,
            height: 768,
            stride: 4096,
            pixel_format: PixelFormat::Bgrx8,
        };
        let mut buf = [0u8; FramebufferInfo::SIZE];
        fb.to_bytes(&mut buf).expect("to_bytes");
        let parsed = FramebufferInfo::from_bytes(&buf).expect("from_bytes");
        assert_eq!(parsed.physical_base, fb.physical_base);
        assert_eq!(parsed.width, fb.width);
        assert_eq!(parsed.height, fb.height);
        assert_eq!(parsed.stride, fb.stride);
        assert_eq!(parsed.pixel_format, fb.pixel_format);
    }

    /// `from_bytes` rejects an invalid `PixelFormat` discriminant rather
    /// than materialising an enum value outside its declared variants
    /// (which is undefined behaviour in Rust).
    #[test]
    fn framebuffer_info_from_bytes_rejects_invalid_pixel_format()
    {
        let mut buf = [0u8; FramebufferInfo::SIZE];
        // Discriminant 2 is outside {0, 1}.
        buf[20..24].copy_from_slice(&2u32.to_le_bytes());
        assert!(FramebufferInfo::from_bytes(&buf).is_none());
        // 0xFFFFFFFF should also reject.
        buf[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(FramebufferInfo::from_bytes(&buf).is_none());
    }

    /// `from_bytes` rejects a buffer shorter than `SIZE`.
    #[test]
    fn framebuffer_info_from_bytes_rejects_short_buffer()
    {
        let short = [0u8; FramebufferInfo::SIZE - 1];
        assert!(FramebufferInfo::from_bytes(&short).is_none());
    }

    /// `to_bytes` rejects a buffer shorter than `SIZE`.
    #[test]
    fn framebuffer_info_to_bytes_rejects_short_buffer()
    {
        let fb = FramebufferInfo::empty();
        let mut short = [0u8; FramebufferInfo::SIZE - 1];
        assert!(fb.to_bytes(&mut short).is_none());
    }
}
