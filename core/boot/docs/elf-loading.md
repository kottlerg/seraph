# ELF Loading

The bootloader loads and validates three categories of binaries from the EFI System
Partition: kernel ELF, init ELF, and boot modules.

---

## Categories

- **Kernel ELF** — fully validated and loaded at ELF-specified physical addresses.
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

Files are opened via `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` on the ESP volume. Paths
come from `\EFI\seraph\boot.conf`, parsed before any file loading occurs (see
[uefi-environment.md](uefi-environment.md)):

| File | Config key | Default path on ESP |
|---|---|---|
| Kernel | `kernel` | `\EFI\seraph\seraph-kernel` |
| Init binary | `init` | `\EFI\seraph\init` |
| Boot modules | future `boot.conf` keys | — |

All paths use backslash separators as required by the UEFI file protocol. The kernel
and init keys are required; their absence is a fatal error. Additional module paths
are an extension point via new keys in `boot.conf`; the parser silently skips
unknown keys, so old bootloader binaries are unaffected by additions.

---

## ELF Validation

ELF-header and program-header validation is performed by the shared ELF crate; the
ruleset (magic, class, data encoding, version, type, machine, program-header
geometry, entry-point-in-LOAD) is owned by
[`shared/elf/README.md`](../../shared/elf/README.md). Any
`elf::ElfError` returned by the shared crate is surfaced by the bootloader as
[`BootError::InvalidElf`](../src/error.rs).

The same validation applies to the kernel ELF and the init ELF. Boot modules (the
`BootInfo.modules` slice) are not ELF-validated by the bootloader — they are loaded
as opaque flat binaries. Their validation and execution is init's responsibility.

---

## LOAD Segment Processing

Once [`shared/elf`](../../shared/elf/README.md) has yielded the validated
`PT_LOAD` program-header array, the bootloader layers UEFI-specific placement
on each segment:

1. Enforce W^X: a segment with both `PF_W` and `PF_X` is rejected when its
   first page is mapped and surfaced as [`BootError::WxViolation`](../src/error.rs).
2. Allocate physical frames via `AllocatePages`, classified `EfiLoaderData`:
   - **Kernel ELF** — `AllocateAddress` at `p_paddr` (the kernel chooses its
     own load address).
   - **Init ELF** — `AllocateAnyPages`, preserving the in-page byte offset
     of `p_vaddr` so the kernel can identity-map each segment without a
     second copy.
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

## Entry Point Extraction

The kernel entry point is `e_entry` from the ELF header. This is a virtual address.
The corresponding physical address (needed for the initial jump before paging is
active) is computed by finding the LOAD segment whose virtual range contains `e_entry`
and applying the `p_vaddr → p_paddr` offset for that segment:

```
physical_entry = e_entry - segment.p_vaddr + segment.p_paddr
```

Both the virtual and physical entry point addresses are recorded. The bootloader jumps
to the physical address if paging is not yet enabled; it jumps to the virtual address
after page tables are installed.

In practice, the page tables are installed in the bootloader before the jump
([page-tables.md](page-tables.md)), so the jump target is the ELF virtual address.

---

## Init ELF Loading

Init is loaded and pre-parsed into an `InitImage` for the kernel. The procedure
differs from kernel loading in one key respect: init is a userspace ELF whose
`p_paddr` values are in low memory already occupied by UEFI firmware, so segments
are allocated at any available physical address via `AllocateAnyPages` rather than
`AllocateAddress`.

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

Boot modules are flat binary images for early userspace services (e.g. procmgr,
devmgr). The bootloader loads whatever files `boot.conf` specifies; it does not
interpret their purpose.

```
1. Open the module file and query its size via EFI_FILE_INFO.
2. AllocatePages(AllocateAnyPages, EfiLoaderData, page_count, &phys_base).
   page_count = ceil(file_size / PAGE_SIZE).
3. Read the entire file into the allocated region.
4. The allocated region may be larger than the file if the file size is not
   page-aligned; the extra bytes at the end are unused (not explicitly zeroed).
5. Record phys_base and file_size in a BootModule entry in BootInfo.modules.
```

`BootModule.size` records the exact file size (not the rounded allocation size).
Init receives the module slice via its initial CSpace and is responsible for
validating and starting each service.

---

## Extensibility

All file paths come from `\EFI\seraph\boot.conf`, not hard-coded in the bootloader
binary. Adding boot modules requires only new keys in `boot.conf`; the parser
silently skips unknown keys, so existing bootloader binaries are unaffected.
`BootInfo.modules.count` accurately reflects however many modules were loaded; the
kernel and init iterate it without assuming a fixed count or fixed ordering.

---

## Summarized By

[boot/README.md](../README.md)
