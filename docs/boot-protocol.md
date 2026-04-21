# Boot Protocol

Seraph uses a custom UEFI-native boot protocol. The bootloader loads the kernel,
establishes a known CPU and memory state, and jumps to the kernel entry point. The
kernel MUST NOT assume anything about the environment beyond what this document
guarantees.

The bootloader in `boot/` is the reference implementation. Any compliant bootloader
that satisfies this contract MAY be used in its place. Shared types are in
`abi/boot-protocol/` (crate: `boot-protocol`).

---

## Boot Flow

The authoritative enumeration of bootloader execution — ten bootloader
steps from UEFI entry through kernel handoff — lives in
[`boot/docs/boot-flow.md`](../boot/docs/boot-flow.md). This document
specifies the contract at the boundary only: the CPU state, memory state,
and `BootInfo` layout established by the time the kernel entry point
runs. UEFI runtime services are not used by the kernel; the firmware is
considered done once the bootloader has completed its steps.

---

## Kernel Entry Point

The kernel must export a single entry point symbol. The bootloader jumps to this
address after establishing the CPU state described below.

**Signature:**

```rust
#[no_mangle]
pub extern "C" fn kernel_entry(boot_info: *const BootInfo) -> ! {
    ...
}
```

The entry point receives a single argument: a pointer to the boot information
structure (see below). The pointer is valid and the structure is fully populated
before the jump occurs.

The entry point must not return. The bootloader does not provide a return address
in any meaningful context.

---

## CPU State at Entry

The following state is guaranteed by the bootloader on both architectures.
The kernel must not assume anything beyond what is listed here.

### x86-64

| Item | Guaranteed state |
|---|---|
| Mode | 64-bit long mode |
| Interrupts | Disabled (`IF` = 0) |
| Direction flag | Clear (`DF` = 0) |
| Paging | Enabled; kernel mapped at intended virtual addresses |
| Stack | Valid; at least 64 KiB available |
| `rdi` | Physical address of `BootInfo` structure |
| Floating point | Not initialised; kernel must not use SSE/AVX before enabling |
| GDT | Bootloader-provided; kernel replaces it during early initialisation |
| IDT | Not loaded; interrupts must remain disabled until the kernel installs its own |

### RISC-V (RV64GC)

| Item | Guaranteed state |
|---|---|
| Privilege level | Supervisor mode |
| Interrupts | Disabled (`sstatus.SIE` = 0) |
| MMU | Enabled (Sv48); kernel mapped at intended virtual addresses |
| Stack | Valid; at least 64 KiB available |
| `a0` | Physical address of `BootInfo` structure |
| `a1` | Hart ID of the booting hart (obtained via `EFI_RISCV_BOOT_PROTOCOL`) |
| Floating point | Not initialised |

On RISC-V, secondary harts are held in a spin loop by the bootloader and are
released by the kernel when it is ready to bring them up.

---

## Page Table State at Entry

The bootloader establishes a minimal page table sufficient for the kernel to begin
executing at its intended virtual addresses. This table includes:

- The kernel image mapped at its ELF-specified virtual addresses (text, rodata,
  data, bss), with permissions matching each segment (W^X enforced)
- An identity map of the physical memory region containing the `BootInfo` structure
  and all boot modules, so the kernel can read them before establishing its own
  mappings
- The bootloader's own stack, mapped at the address in use at entry

The kernel is expected to replace this table with its own during early
initialisation. The bootloader's page table is not intended to be permanent.

---

## Boot Information Structure

The `BootInfo` structure is allocated in physical memory by the bootloader and
remains valid until the kernel explicitly reclaims or unmaps the region. All
pointer fields within the structure refer to physical addresses unless otherwise
noted — the kernel converts these using its direct physical map once paging is
fully established.

```rust
#[repr(C)]
pub struct BootInfo {
    /// Protocol version. Must match the kernel's expected version.
    pub version: u32,

    /// Physical memory map describing all address ranges.
    pub memory_map: MemoryMapSlice,

    /// Physical and virtual base addresses of the loaded kernel image.
    pub kernel_physical_base: u64,
    pub kernel_virtual_base: u64,
    pub kernel_size: u64,

    /// Pre-parsed init ELF information.
    ///
    /// The bootloader fully parses init's ELF and provides the entry point
    /// and segment array. The kernel maps init directly from these segments
    /// without needing an ELF parser.
    pub init_image: InitImage,

    /// Additional boot modules (raw ELF images for early services).
    ///
    /// The module set is configured via `boot.conf`. Typical set:
    /// procmgr, devmgr, one block driver, one FS driver, VFS.
    /// Net stack is optional; it may be included for network-backed filesystems.
    pub modules: ModuleSlice,

    /// Framebuffer, if available. Used for early debug output.
    pub framebuffer: FramebufferInfo,

    /// ACPI RSDP physical address. Zero if the UEFI configuration table does
    /// not contain `EFI_ACPI_20_TABLE_GUID`.
    ///
    /// Passed through for userspace consumption (devmgr). The kernel does
    /// not parse ACPI tables; it reads structured platform resources from
    /// `platform_resources` instead. May be non-zero on any architecture
    /// that exposes ACPI via UEFI.
    pub acpi_rsdp: u64,

    /// Device tree blob physical address. Zero if the UEFI configuration
    /// table does not contain `EFI_DTB_TABLE_GUID`.
    ///
    /// Passed through for userspace consumption (devmgr). The kernel does
    /// not parse the Device Tree; it reads structured platform resources
    /// from `platform_resources` instead. May be non-zero on any
    /// architecture that exposes a DTB via UEFI.
    pub device_tree: u64,

    /// Structured platform resource descriptors extracted from firmware tables
    /// by the bootloader. The kernel mints initial capabilities from these entries.
    /// See `PlatformResource` for the per-entry layout.
    pub platform_resources: PlatformResourceSlice,

    /// Null-terminated kernel command line string. May be empty.
    pub command_line: *const u8,
    pub command_line_len: u64,
}
```

### Init Segments

```rust
#[repr(u32)]
pub enum SegmentFlags {
    /// Readable, not writable, not executable (e.g. rodata).
    Read = 0,
    /// Readable and writable (e.g. data/bss).
    ReadWrite = 1,
    /// Readable and executable (e.g. text).
    ReadExecute = 2,
}

#[repr(C)]
pub struct InitSegment {
    /// Physical base address where this segment was loaded by the bootloader.
    pub phys_addr: u64,
    /// ELF virtual address this segment is mapped at.
    pub virt_addr: u64,
    /// Size of the segment in memory (p_memsz; may exceed file data).
    pub size: u64,
    /// Page permissions for this segment.
    pub flags: SegmentFlags,
}

pub const INIT_MAX_SEGMENTS: usize = 8;

#[repr(C)]
pub struct InitImage {
    /// Virtual entry point of init (e_entry from the ELF header).
    pub entry_point: u64,
    /// Pre-parsed LOAD segments. Valid entries occupy [0..segment_count].
    pub segments: [InitSegment; INIT_MAX_SEGMENTS],
    /// Number of valid entries in segments.
    pub segment_count: u32,
}
```

The bootloader fully parses init's ELF and populates `InitImage`. The kernel maps
each segment directly from `phys_addr` to `virt_addr` with the given permissions.
No ELF parsing occurs in the kernel. This is distinct from the other boot modules
(`modules` slice), which are raw ELF images that init's built-in parser handles.

### Memory Map

```rust
#[repr(C)]
pub struct MemoryMapSlice {
    pub entries: *const MemoryMapEntry,
    pub count: u64,
}

#[repr(C)]
pub struct MemoryMapEntry {
    pub physical_base: u64,
    pub size: u64,
    pub memory_type: MemoryType,
}

#[repr(u32)]
pub enum MemoryType {
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
```

The memory map is sorted by `physical_base` in ascending order. Entries do not
overlap. The kernel must not write to `Reserved` regions. `Loaded` regions
containing boot modules may be reclaimed once the kernel has consumed them.

### Boot Modules

```rust
#[repr(C)]
pub struct ModuleSlice {
    pub entries: *const BootModule,
    pub count: u64,
}

#[repr(C)]
pub struct BootModule {
    pub physical_base: u64,
    pub size: u64,
}
```

Each module is a raw ELF image for an early userspace service. The set of modules
loaded is configured via `boot.conf` under the `modules` key. The kernel passes the
module slice to init via the initial CSpace; init uses its built-in ELF parser to
start procmgr from the first module, then delegates the remaining modules to procmgr
for startup.

Minimum module set: procmgr, devmgr, one block driver, one FS driver, vfsd.
netd may be included as a module when network-backed filesystems are needed.

### Framebuffer

```rust
#[repr(C)]
pub struct FramebufferInfo {
    /// Physical base address of the framebuffer. Zero if no framebuffer.
    pub physical_base: u64,
    pub width: u32,
    pub height: u32,
    /// Bytes per row (may be larger than width × bytes_per_pixel).
    pub stride: u32,
    pub pixel_format: PixelFormat,
}

#[repr(u32)]
pub enum PixelFormat {
    Rgbx8 = 0,
    Bgrx8 = 1,
}
```

The framebuffer is provided on a best-effort basis. The kernel must handle the case
where `physical_base` is zero and no framebuffer is available. This is the expected
state in headless or virtual environments without a display.

### Platform Resources

```rust
#[repr(C)]
pub struct PlatformResourceSlice {
    /// Pointer to the first entry. Null if `count` is zero.
    pub entries: *const PlatformResource,
    pub count: u64,
}

#[repr(C)]
pub struct PlatformResource {
    /// Discriminant identifying the kind of resource.
    pub resource_type: ResourceType,

    /// Type-specific flags (see ResourceType documentation for interpretation).
    pub flags: u32,

    /// Physical base address of the resource (zero for IrqLine).
    pub base: u64,

    /// Size of the resource in bytes (zero for IrqLine).
    pub size: u64,

    /// Opaque, type-specific identifier. Interpretation depends on `resource_type`.
    /// Do not compare `id` values across resource types.
    pub id: u64,
}

#[repr(u32)]
pub enum ResourceType {
    /// A memory-mapped I/O region.
    ///
    /// `base`+`size`: physical address range.
    /// `flags` bit 0: 0 = device (uncacheable), 1 = write-combine.
    /// `id`: opaque platform identifier (e.g. ACPI UID); zero if unknown.
    MmioRange = 0,

    /// A hardware interrupt line.
    ///
    /// `base`: unused (zero).
    /// `size`: unused (zero).
    /// `id`: interrupt number (GSI on x86-64, PLIC source on RISC-V).
    /// `flags` bit 0: 0 = level, 1 = edge triggered.
    /// `flags` bit 1: 0 = active-high, 1 = active-low.
    IrqLine = 1,

    /// A PCI Express ECAM (Enhanced Configuration Access Mechanism) window.
    ///
    /// `base`+`size`: physical ECAM MMIO range.
    /// `flags`: encoded bus range — bits 7:0 = start bus, bits 15:8 = end bus.
    /// `id`: segment group number (usually zero).
    PciEcam = 2,

    /// A firmware table region to be passed through to userspace as read-only.
    ///
    /// `base`+`size`: physical address range of the table (e.g. ACPI table body).
    /// `flags`: reserved, zero.
    /// `id`: opaque identifier for the table type (platform-defined).
    PlatformTable = 3,

    /// An x86 I/O port range (x86-64 only).
    ///
    /// `base`: first port number in the range.
    /// `size`: number of consecutive ports.
    /// `flags`: reserved, zero.
    /// `id`: opaque platform identifier; zero if unknown.
    IoPortRange = 4,

    /// An IOMMU unit's register range and scope.
    ///
    /// `base`+`size`: physical MMIO range of the IOMMU's registers.
    /// `flags`: reserved for future scope encoding; zero in protocol version 2.
    /// `id`: opaque platform identifier (e.g. ACPI DMAR unit index).
    IommuUnit = 5,
}
```

The `platform_resources` array is sorted by `(resource_type, base)` in ascending
order. Within a type, entries do not overlap where overlap is nonsensical (MMIO
ranges, port ranges). `IrqLine` entries are sorted by interrupt number.

`PlatformTable` entries are read-only by contract — the kernel creates read-only
frame capabilities for these regions. Userspace must not write to them.

The bootloader populates this array by parsing the UEFI memory map plus the platform
firmware tables (ACPI/MADT/MCFG on x86-64; Device Tree on RISC-V). It must not
include resources that are inaccessible or reserved for firmware exclusive use.

---

## Protocol Version

The `version` field in `BootInfo` must be checked by the kernel on entry. If the
version does not match the expected value, the kernel must halt rather than proceed
with a potentially incompatible structure. This prevents silent corruption from
a mismatched bootloader.

The current protocol version is `3`. This value is incremented whenever the
`BootInfo` structure or CPU entry contract changes in a non-backwards-compatible way.

Version history:
- **1** — initial protocol.
- **2** — added `platform_resources` field to `BootInfo`; clarified `acpi_rsdp`
  and `device_tree` as userspace passthrough fields.
- **3** — added `init_image` (`InitImage`) field to `BootInfo`; changed `modules`
  from "first entry is init" to "configurable early service modules"; the kernel
  no longer parses init's ELF.

---

## Bootloader Responsibilities

The bootloader must, before jumping to the kernel entry point:

- Verify that the kernel ELF is valid and has a recognisable entry point
- Load all ELF LOAD segments into allocated physical memory
- Zero BSS segments
- Respect ELF segment permissions (readable, writable, executable) when establishing
  page table entries
- Obtain the final UEFI memory map after all allocations are complete
- Call `ExitBootServices` successfully before jumping to the kernel
- Guarantee that the `BootInfo` structure and all referenced data remain mapped
  and readable at kernel entry

The bootloader must not:

- Leave UEFI boot services active at kernel entry
- Map any region as both writable and executable
- Assume anything about the kernel's internal layout beyond the ELF headers

---

## Summarized By

[Architecture Overview](architecture.md), [init](../init/README.md)
