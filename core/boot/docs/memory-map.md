# Memory Map Translation

Invariants for converting the UEFI memory map into
`BootInfo.memory_map`. Higher-level flow (when the map is queried
during the boot sequence) is owned by
[uefi-environment.md](uefi-environment.md) §"Memory Map Acquisition";
this document owns the translation policy and the invariants the kernel
can rely on at handoff.

The implementation lives in [`core/boot/src/memory_map.rs`](../src/memory_map.rs).

---

## UEFI Memory Type → `MemoryType`

| UEFI `EFI_MEMORY_TYPE` | `MemoryType` | Rationale |
|---|---|---|
| `EfiConventionalMemory` | `Usable` | Free RAM. |
| `EfiBootServicesCode` / `EfiBootServicesData` | `Usable` | No longer in use after `ExitBootServices`. |
| `EfiLoaderCode` / `EfiLoaderData` | `Loaded` | Every bootloader allocation and the bootloader's own loaded image (enumerated in § Allocation-Class Classification). |
| `EfiACPIReclaimMemory` | `AcpiReclaimable` | Firmware tables; exposed to userspace read-only as Map-only Memory caps (up to eight regions) and never returned to the allocator; see [initialization.md § Phase 7](../../kernel/docs/initialization.md#phase-7-capability-system). |
| `EfiACPIMemoryNVS` | `Reserved` | Firmware-reserved. |
| `EfiRuntimeServicesCode` / `EfiRuntimeServicesData` | `Reserved` | Seraph does not use UEFI runtime services; treat as off-limits. |
| `EfiMemoryMappedIO` / `EfiMemoryMappedIOPortSpace` | `Reserved` | Device space, not RAM. |
| `EfiPersistentMemory` | `Persistent` | NVDIMM or similar. |
| Any unrecognised type | `Reserved` | Conservative default. |

`EfiBootServices*` → `Usable` is deliberate: those regions are dead
after `ExitBootServices` and represent the largest usable reclaim on a
typical system. `EfiRuntimeServices*` → `Reserved` keeps firmware runtime
code and data out of every allocator and reclaim path even though Seraph never
calls into it.

---

## Post-Translation Invariants

The translated array passed in `BootInfo.memory_map` satisfies the
invariants documented in the boot-protocol contract — sorted ascending
by `physical_base`, no overlap between entries, stable classification
per the table above. The kernel may rely on these without
re-validation.

Contiguous same-type UEFI entries are **not** coalesced by the
bootloader. The translated array mirrors the UEFI descriptor sequence
1:1 (after sorting) up to the capacity of the `MemoryMapEntry` array
(`MEM_MAP_ENTRY_PAGES` pages, about 680 entries); `translate_memory_map` drops
descriptors beyond it without a diagnostic; any consolidation of adjacent
regions into a single larger entry is left to the kernel if it wants a denser
representation.

The bootloader makes no allocation after the final memory-map query; a
firmware allocation in the window before `ExitBootServices` invalidates the
map key, and the retry path in
[uefi-environment.md](uefi-environment.md) §"ExitBootServices" ensures
the map key and the map body agree at exit time.

### Sort Algorithm

Sorting is performed in place by an O(n²) insertion sort. The translated
map is tiny in practice — UEFI firmware on target hardware reports well
under one hundred entries — so the algorithm class is immaterial and an
in-place, no-allocation, no-recursion implementation is preferred.

---

## Allocation-Class Classification

Every bootloader allocation uses `EfiLoaderCode` or `EfiLoaderData` and
therefore surfaces as `MemoryType::Loaded`. The kernel never hands
`Loaded` regions to its buddy allocator. Three `Loaded` sets return to the
pool, each through reclaimable Memory caps that the kernel hands to init;
init hands those caps to procmgr, which donates them to memmgr when it reaps
init (see [process-lifecycle.md](../../../docs/process-lifecycle.md) §"Init reap"):

- The bootloader-scratch subset recorded in `BootInfo.reclaim_ranges`, minted
  in Phase 7 (the AP trampoline page is late-minted in Phase 8). See
  [initialization.md](../../kernel/docs/initialization.md) §"Phase 7: Capability System",
  and §"Phase 3: Kernel Page Tables" step 7 for the bootloader page-table
  frames.
- The boot-module bodies, minted by `mint_module_memory_caps` in Phase 7.
- The init image LOAD segments, one reclaimable Memory cap per `InitImage`
  segment (Phase 9's RELRO seal splits a writable segment in two when the
  RELRO range ends inside it) minted in Phase 9. See
  [initialization.md](../../kernel/docs/initialization.md)
  §"Phase 9: Init Creation and Scheduler Entry".

Every other `Loaded` page is permanent: the bootloader's own loaded image
(firmware-allocated as `EfiLoaderCode` / `EfiLoaderData`; it contains the
handoff trampoline), the kernel image, the kernel handoff stack (kept as the
BSP boot stack), the kernel ELF file read buffer, the raw UEFI memory-map
buffer, and, on riscv64, the paging-mode probe page. The read buffer and the raw map
buffer are dead once consumed; freeing or reclaiming them is
[#442](https://github.com/kottlerg/seraph/issues/442).

The `Loaded` allocations are:

- The bootloader's own loaded image (firmware-allocated as `EfiLoaderCode` /
  `EfiLoaderData`; it contains the handoff trampoline).
- Kernel image LOAD segments, placed in one contiguous `AllocateAnyPages` span at a
  firmware-chosen address.
- Kernel ELF file read buffer.
- Init image LOAD segments, placed at any free physical address.
- Bundle blob: one allocation holding the bundle header and entry table,
  every boot-module body, and the init ELF source.
- `BootInfo` structure page.
- `BootInfo.modules` descriptor page.
- `MmioAperture` array page (`mmio_apertures.entries`).
- Raw UEFI memory-map buffer (the `GetMemoryMap` output).
- Translated `MemoryMapEntry` array (`BootInfo.memory_map`).
- Reclaim-array page (the `BootInfo.reclaim_ranges` backing).
- AP trampoline page, when allocated.
- Kernel handoff stack (`KERNEL_STACK_PAGES`, 64 KiB).
- Page-table frames allocated for the initial mapping (see
  [page-tables.md](page-tables.md)).
- riscv64 only: the paging-mode probe page.

---

## Sizing the Map Buffer

The acquisition sequence that sizes and fills the map buffer, including
its slack margin, is owned by
[uefi-environment.md](uefi-environment.md) §"Memory Map Acquisition".

---

## Consumer: KASLR direct-map base

Step 9 selects the KASLR direct-map base from this translated map: the highest
RAM address (`boot_protocol::layout::max_ram_address` over the `Usable` /
`Loaded` / `AcpiReclaimable` / `Persistent` entries) plus any framebuffer /
kernel-MMIO regions above it form the direct-map ceiling
(`boot_protocol::layout::direct_map_ceiling`), and, when KASLR entropy is
present and the `nokaslr` knob is absent, the base is drawn 1 GiB-aligned in
the gap between the mode's kernel-half floor and the kernel image (less the
ceiling and `DIRECT_MAP_GUARD`); otherwise, or when that gap holds fewer than
two slots, the base is the kernel-half floor. The kernel re-derives the same
ceiling from the same helper at Phase 3 to guard the mapping, so bootloader
and kernel cannot disagree. See
[boot-flow.md](boot-flow.md) step 9 and [initialization.md](../../kernel/docs/initialization.md)
§"Phase 3: Kernel Page Tables". The direct-map placement rule is owned by
[memory-model.md](../../../docs/memory-model.md) § Virtual Address Space Layout.

## What Lives Elsewhere

- The `ExitBootServices` retry protocol and its stale-key semantics
  are owned by [uefi-environment.md](uefi-environment.md).
- Per-region sort/no-overlap invariants as contract requirements are
  owned by the boot-protocol specification; see the crate
  [`abi/boot-protocol/src/lib.rs`](../../../abi/boot-protocol/src/lib.rs).
- The page-table identity-map region list (what the bootloader maps so
  the kernel can read `BootInfo` at entry) is owned by
  [page-tables.md](page-tables.md).

---

## Summarized By

[Boot Flow](boot-flow.md), [UEFI Environment](uefi-environment.md)
