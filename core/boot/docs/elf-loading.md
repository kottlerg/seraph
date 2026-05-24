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

ELF-header and program-header validation is performed by the shared ELF crate; the
ruleset (magic, class, data encoding, version, type, machine, program-header
geometry, entry-point-in-LOAD) is owned by
[`shared/elf/README.md`](../../../shared/elf/README.md). Any
`elf::ElfError` returned by the shared crate is surfaced by the bootloader as
[`BootError::InvalidElf`](../src/error.rs).

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
a page-rounded allocation (the kernel's `mint_module_frame_caps`,
which rounds `size` up to the next page boundary for the Frame cap)
does not need to copy or relocate bytes. Init receives the module
slice via its initial `CSpace` and is responsible for validating and
starting each service.

---

## Extensibility

The bundle replaces both the per-module file enumeration and the
configuration file that used to point at it. Adding a new boot
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
