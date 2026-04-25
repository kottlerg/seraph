# Boot Flow

This document describes the bootloader's execution from `efi_main` to kernel handoff.
The contract at handoff is defined in [kernel-handoff.md](kernel-handoff.md)
(CPU state and register contents) and in the
[`abi/boot-protocol/`](../../../abi/boot-protocol/) crate (`BootInfo` layout
and version); this document covers how the bootloader fulfils that contract.

---

## Boot Sequence

The following ten steps correspond to the bootloader's execution order. Each step is
described briefly here; detailed implementation is in the referenced document.

### Step 1: UEFI Protocol Discovery

`efi_main` receives an `EFI_HANDLE image_handle` and a pointer to the UEFI system
table. The first act is to locate the protocols needed for the rest of the boot:

- `EFI_LOADED_IMAGE_PROTOCOL` — to find the device handle for the boot volume
- `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` — to open the EFI System Partition filesystem
- `EFI_GRAPHICS_OUTPUT_PROTOCOL` — to record the framebuffer, if present

Protocol handles are resolved via `BootServices->HandleProtocol` and
`BootServices->LocateProtocol`. Failure to locate a required protocol is fatal.

Detail: [uefi-environment.md](uefi-environment.md)

### Step 2: Load Boot Configuration

The bootloader opens `\EFI\seraph\boot.conf` on the ESP and reads it into a
4096-byte stack buffer. The file is parsed line by line for `key=value` entries.
`#` comments and blank lines are ignored; unknown keys are skipped for forward
compatibility.

**File format:**

```
# Seraph boot configuration
path=\EFI\seraph
kernel=kernel
init=init
modules=procmgr, devmgr, vfsd, fat
cmdline=placeholder
```

- `path` — required. Base ESP directory. Prepended (with `\`) to kernel, init,
  and all module names to form full ESP paths.
- `kernel` — required. Kernel filename, resolved against `path`.
- `init` — required. Init filename, resolved against `path`.
- `modules` — optional. Comma-separated module filenames resolved against `path`.
  Whitespace around names is trimmed; empty tokens are skipped. Absent or empty
  means no additional modules.
- `cmdline` — optional. Kernel command line passed verbatim via
  `BootInfo.command_line`. Absent means empty string.

Missing `path`, `kernel`, or `init` keys, or a malformed line (missing `=`), are
fatal errors (`InvalidConfig`). The parsed paths are used in all subsequent
file-open operations.

Detail: [uefi-environment.md](uefi-environment.md)

### Step 3: Load Kernel ELF

The kernel ELF is loaded from the path specified by the `kernel` key in
`boot.conf` (default: `\EFI\seraph\seraph-kernel`). The ELF header is validated,
LOAD segments are mapped into physical memory allocated via `AllocatePages`, and
the kernel virtual addresses and entry point are recorded.

W^X is enforced during loading: any ELF segment requesting both writable and
executable permissions is a fatal error.

Detail: [elf-loading.md](elf-loading.md)

### Step 4: Load Init ELF and Boot Modules

**Init** is loaded from the path resolved from the `init` key in `boot.conf`. It
receives full ELF treatment: header validation, W^X check, and per-segment loading.
Each `PT_LOAD` segment is allocated at any available physical address via
`AllocateAnyPages` (not at `p_paddr`, which conflicts with UEFI low-memory use),
file data is copied in, and the BSS tail is zeroed. The result is an `InitImage`
containing the virtual entry point and one `InitSegment` per LOAD segment, each
recording its physical allocation address, ELF virtual address, size, and
permissions. This is stored in `BootInfo.init_image`.

**Boot modules** are flat binary images listed in `boot.conf` under the `modules`
key. Each module path is resolved as `path\<name>`. For each module: the file is
read into a temporary UEFI-allocated buffer, `load_module()` copies the data into a
persistent physical allocation, and a `BootModule` entry recording `physical_base`
and `size` is stored in a local array. The descriptors are written into the
pre-allocated modules page in step 9. The bootloader does not inspect or interpret
module content; what the modules are and in what order they are started is entirely
init's concern. Typical modules: procmgr, devmgr, block driver, FS driver, vfsd.

Both the module file read buffers and the loaded module physical regions are tracked
for identity mapping so they remain accessible after page table switch.

Detail: [elf-loading.md](elf-loading.md)

### Step 5: Firmware Discovery and CPU Topology

The UEFI configuration table is scanned for two GUIDs:
- `EFI_ACPI_20_TABLE_GUID` → physical address of the ACPI RSDP
- `EFI_DTB_TABLE_GUID` → physical address of the Device Tree blob

Both GUIDs are searched unconditionally; absent entries produce a zero field in
`BootInfo`. Whichever tables are present are passed through to userspace as
opaque physical addresses (`BootInfo.acpi_rsdp`, `BootInfo.device_tree`).

The bootloader also extracts two narrow views from the firmware tables for
the kernel's own consumption:

- **CPU topology** — MADT `LocalApic` / `RINTC` entries (ACPI) and `/cpus`
  nodes (DTB) populate `BootInfo.cpu_count`, `bsp_id`, and `cpu_ids`.
- **`kernel_mmio`** — arch-specific MMIO bases: LAPIC / IOAPIC on x86-64
  (from MADT), PLIC / UART on RISC-V (from MADT `PLIC` type or DTB
  compatible nodes).

A third extraction produces **seed entries** for `mmio_apertures` —
coarse `{phys_base, size}` regions the kernel mints as `MmioRegion`
capabilities. The seed covers LAPIC / IOAPIC / PLIC / ECAM / BAR
windows / `virtio,mmio` transports from the firmware tables and is
merged with the UEFI memory map's `MemoryMappedIO` regions in step 8.

Detail: [firmware-parsing.md](firmware-parsing.md)

### Step 6: Allocate and Build Page Tables

Initial page tables are constructed for the kernel. All page table frames are
allocated from UEFI before `ExitBootServices`. The tables map:

- The kernel ELF segments at their ELF virtual addresses, with segment permissions
- An identity map of the `BootInfo` structure, all boot modules, and the bootloader's
  own stack, so the kernel can read them before replacing the page tables

W^X is verified during construction: no PTE has both writable and executable bits.

Detail: [page-tables.md](page-tables.md)

### Step 7: Query Final Memory Map

The UEFI memory map is queried immediately before `ExitBootServices`. Every UEFI
allocation performed after the previous query invalidates the map key; this final
query must be the last allocation-generating action before the exit call. The map is
translated from UEFI memory types to the `MemoryType` values defined in the boot
protocol and sorted by `physical_base`.

Detail: [uefi-environment.md](uefi-environment.md)

### Step 8: ExitBootServices

`ExitBootServices` is called with the map key from step 7. If the call fails due to
a stale key (indicating that UEFI performed allocations between the query and the
call), the memory map is re-queried and the call is retried once. After a successful
exit, UEFI boot services are unavailable; no further UEFI calls are made.

Detail: [uefi-environment.md](uefi-environment.md)

### Step 9: Populate BootInfo

`BootInfo` is populated in-place in a physical memory region allocated before step 8.
All pointer and address fields hold physical addresses; no virtual addresses appear in
`BootInfo`. The `version` field is set to `BOOT_PROTOCOL_VERSION` (currently `6`).
Fields are populated as follows:

| Field | Source |
|---|---|
| `version` | `BOOT_PROTOCOL_VERSION` constant from `boot-protocol` crate |
| `memory_map` | Translated UEFI memory map from step 7 |
| `kernel_physical_base` | Physical address of kernel LOAD segments from step 3 |
| `kernel_virtual_base` | ELF virtual base address from step 3 |
| `kernel_size` | Total span of kernel ELF LOAD segments from step 3 |
| `init_image` | Pre-parsed init ELF segments and entry point from step 4 |
| `modules` | Physical base and size of each additional boot module from step 4; empty if none configured |
| `framebuffer` | GOP framebuffer from step 1 (zeroed if GOP is absent) |
| `acpi_rsdp` | Physical address of ACPI RSDP from step 5; zero if GUID absent |
| `device_tree` | Physical address of DTB from step 5; zero if GUID absent |
| `kernel_mmio` | Arch-specific MMIO bases extracted from firmware tables in step 5 (see `firmware-parsing.md`). Fields the extractor cannot populate stay zero and the kernel falls back to its compiled-in defaults. |
| `mmio_apertures` | Coarse `{phys_base, size}` array from step 8 (UEFI MMIO regions merged with firmware-table seeds). Empty if no MMIO regions were reported. |
| `command_line` | Physical address of null-terminated ASCII string; may be empty |
| `cpu_count` | Enabled LAPIC count from MADT (x86-64) or enabled RINTC / DTB hart count (RISC-V); always ≥ 1 |
| `bsp_id` | APIC ID of the BSP (x86-64) or boot hart ID from `EFI_RISCV_BOOT_PROTOCOL` (RISC-V) |
| `cpu_ids` | Per-CPU hardware identifiers; `cpu_ids[0] == bsp_id`; entries beyond `cpu_count` are zero |
| `ap_trampoline_page` | 4 KiB physical frame for AP startup code. x86-64: below 1 MiB (SIPI vector constraint). RISC-V: any 4 KiB page (SBI HSM has no placement constraint). Zero if allocation failed (SMP disabled). |

All arrays pointed to by `BootInfo` fields reside in physical memory that the UEFI
memory map marks as `Loaded` or `Usable`, ensuring they survive until the kernel
reclaims or remaps them.

### Step 10: Kernel Handoff

CPU state is established per the boot protocol and the kernel entry point is called.
This step is the point of no return: the bootloader has no code to execute after the
jump, and `kernel_entry` is declared `-> !`.

The architecture-specific CPU-state contract and register-setup sequence are owned
by [kernel-handoff.md](kernel-handoff.md).

---

## BootInfo Population Details

Every pointer in `BootInfo` is a physical address. The kernel cannot dereference
these pointers through its own virtual address space until its direct physical map is
active (Phase 3 of kernel initialisation). Before that point, the kernel accesses
`BootInfo` fields through the identity mapping established in step 5.

The `BootInfo` structure itself must not be placed in a region the kernel will
reclaim before reading all fields. In practice this means placing it in a range the
memory map marks as `Loaded`, which the kernel treats as in-use until it explicitly
chooses to reclaim it.

Slices within `BootInfo` (`memory_map`, `modules`, `mmio_apertures`) point to
separately allocated physical regions. These regions must also remain readable until
the kernel has consumed them.

---

## Summarized By

[boot/README.md](../README.md)
