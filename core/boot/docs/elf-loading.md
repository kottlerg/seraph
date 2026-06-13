# ELF Loading

The bootloader loads and validates three categories of binaries from the EFI System
Partition: kernel ELF, init ELF, and boot modules.

---

## Categories

- **Kernel ELF** — fully validated and loaded as a single contiguous span at a
  bootloader-chosen physical base, preserving the ELF's relative segment offsets.
- **Init ELF** — fully validated and ELF-parsed; segments allocated at any available
  physical address. Result is an `InitImage` passed to the kernel in `BootInfo.init_image`.
- **Boot modules** — opaque flat binaries loaded verbatim into physical memory and
  passed to the kernel via `BootInfo.modules`. The bootloader does not inspect or
  interpret their content; what they are is init's concern.

All loading occurs before `ExitBootServices`. W^X is enforced for the kernel and
init ELFs at load time: any `PT_LOAD` segment with both write and execute permissions
is a fatal error.

---

## File Paths

Files are opened via `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` on the ESP volume. The
bootloader carries two hardcoded ESP path constants in
[`boot/src/main.rs`](../src/main.rs) (see
[uefi-environment.md](uefi-environment.md)):

| File | Hardcoded ESP path |
|---|---|
| Kernel | `\EFI\seraph\kernel` |
| Bootstrap bundle | `\EFI\seraph\bootstrap.bundle` |

All paths use backslash separators as required by the UEFI file
protocol. There is no per-file extension mechanism: the bundle is a
single composed artifact carrying the userspace `init` entry plus every
module init needs to bootstrap the system, parsed by the bundle module
in [`abi/boot-protocol/src/bundle.rs`](../../../abi/boot-protocol/src/bundle.rs).
Adding a new boot module is therefore a bundle-composer change in
[`xtask/src/bundle.rs`](../../../xtask/src/bundle.rs), not a bootloader
change.

---

## ELF Validation

ELF-header and program-header *format* validation is performed by the shared ELF crate;
the ruleset (magic, class, data encoding, version, type, machine, program-header
geometry) is owned by
[`shared/elf/README.md`](../../../shared/elf/README.md). Any
`elf::ElfError` returned by the shared crate is surfaced by the bootloader as
[`BootError::InvalidElf`](../src/error.rs).

The kernel image carries an additional *placement* ruleset enforced by the bootloader
(`validate_kernel_layout` in [`boot/src/elf.rs`](../src/elf.rs)), because the image is
relocated to a dynamically chosen base and the relocation is sound only if it holds:
every `PT_LOAD` segment is 4 KiB-aligned in both `p_vaddr` and `p_paddr`, all segments
share one `p_vaddr → p_paddr` offset, no two segments' physical ranges overlap, and the
entry point lies within a `PT_LOAD` segment. A violation is surfaced as
`BootError::InvalidElf`.

The same validation applies to the kernel ELF and the init ELF. Boot modules (the
`BootInfo.modules` slice) are not ELF-validated by the bootloader — they are loaded
as opaque flat binaries. Their validation and execution is init's responsibility.

---

## LOAD Segment Processing

Once [`shared/elf`](../../../shared/elf/README.md) has yielded the validated
`PT_LOAD` program-header array, the bootloader layers UEFI-specific placement
on each segment:

1. Enforce W^X: a segment with both `PF_W` and `PF_X` is rejected when its
   first page is mapped and surfaced as [`BootError::WxViolation`](../src/error.rs).
2. Allocate physical frames via `AllocatePages`, classified `EfiLoaderData`:
   - **Kernel ELF** — one `AllocateAnyPages` span covering the whole image at
     any free physical base; each segment is copied to
     `span_base + (p_paddr - link_phys)`, preserving the ELF's relative
     offsets. The chosen base is recorded in `BootInfo.kernel_physical_base`.
   - **Init ELF** — `AllocateAnyPages` per segment, preserving the in-page
     byte offset of `p_vaddr` so the kernel can identity-map each segment
     without a second copy.
3. Copy `p_filesz` bytes from the file into the allocated region.
4. Zero the BSS tail (`p_memsz - p_filesz` bytes).

The page-table builder ([page-tables.md](page-tables.md)) consumes the
recorded `(phys_base, virt_base, size, flags)` per segment. Every mapping
is implicitly readable; only the writable / executable bits come from
`p_flags`:

| `p_flags` | Page table flags |
|---|---|
| `PF_R` (only) | Readable |
| `PF_R | PF_W` | Readable, Writable |
| `PF_R | PF_X` | Readable, Executable |
| `PF_R | PF_W | PF_X` | Rejected (`WxViolation`) |

A pure BSS segment (`p_filesz == 0`, `p_memsz > 0`) incurs no file read;
the entire allocation is produced by step 4.

---

## Entry Point

The kernel entry point is `e_entry` from the ELF header — a virtual address recorded as
[`KernelInfo.entry_virtual`](../src/elf.rs). The bootloader installs the kernel's initial
page tables ([page-tables.md](page-tables.md)) before transferring control, so the jump
target is always this virtual address; no physical entry address is computed or used.
`validate_kernel_layout` confirms `e_entry` falls within a `PT_LOAD` segment.

---

## Init ELF Loading

Init is loaded and pre-parsed into an `InitImage` for the kernel. Like the kernel
image, init segments are allocated via `AllocateAnyPages` (init is a userspace ELF
whose `p_paddr` values fall in low memory already occupied by UEFI firmware). Unlike
the kernel — placed as one contiguous span — each init segment is allocated
independently and the in-page byte offset of `p_vaddr` is preserved, so the kernel
can identity-map each segment without a second copy.

```
For each PT_LOAD segment:
1. AllocatePages(AllocateAnyPages, EfiLoaderData, page_count, &phys_base).
   page_count = ceil(p_memsz / PAGE_SIZE).
2. Copy p_filesz bytes from file offset p_offset into phys_base.
3. Zero the BSS tail: memset(phys_base + p_filesz, 0, p_memsz - p_filesz).
4. Record an InitSegment { phys_addr, virt_addr: p_vaddr, size: p_memsz, flags }.
```

`flags` is derived from `p_flags`: `ReadExecute` if `PF_X` is set, `ReadWrite` if
`PF_W` is set (and `PF_X` is not), otherwise `Read`. The resulting `InitImage`
(entry point + segment array) is stored in `BootInfo.init_image`. The kernel uses
the `phys_addr`/`virt_addr` pairs to build init's page tables without an ELF parser.

---

## Boot Module Loading

Boot modules are flat binary images for early userspace services (e.g.
procmgr, devmgr). The bootloader does not open per-module files —
every module body is already inside the bundle that step 2 loads. Per
module, the bootloader's bundle walker:

```
1. Iterate bundle entry headers from `boot_protocol::bundle::parse_header`.
2. Skip the entry literally named "init" (that body becomes init's
   ELF source, parsed separately).
3. For every other entry, record a `BootModule { name, physical_base,
   size }` where `physical_base = bundle_phys + entry.offset` and
   `size = entry.size` (the file-byte size, not the body's rounded
   allocation).
```

Bundle bodies are 4 KiB-aligned per `BODY_ALIGNMENT`, so
`physical_base` is page-aligned and a downstream consumer that needs
a page-rounded allocation (the kernel's `mint_module_memory_caps`,
which rounds `size` up to the next page boundary for the Memory cap)
does not need to copy or relocate bytes. Init receives the module
slice via its initial `CSpace` and is responsible for validating and
starting each service.

---

## Extensibility

The bundle is the single boot-module container. Adding a new boot
module is a bundle-composer change in
[`xtask/src/bundle.rs`](../../../xtask/src/bundle.rs); the bootloader
binary needs no change. `BootInfo.modules.count` accurately reflects
the bundle's non-`init` entry count; the kernel and init iterate it
without assuming a fixed count or fixed ordering, and init looks
modules up by name via `InitInfo::module_names` rather than by
ordinal.

---

## Summarized By

[boot/README.md](../README.md)
