# Memory Map Translation

Invariants for converting the UEFI memory map into
`BootInfo.memory_map`. Higher-level flow (when the map is queried
during the boot sequence) is owned by
[uefi-environment.md](uefi-environment.md) §"Memory Map Acquisition";
this document owns the translation policy and the invariants the kernel
can rely on at handoff.

The implementation lives in [`boot/src/memory_map.rs`](../src/memory_map.rs).

---

## UEFI Memory Type → `MemoryType`

| UEFI `EFI_MEMORY_TYPE` | `MemoryType` | Rationale |
|---|---|---|
| `EfiConventionalMemory` | `Usable` | Free RAM. |
| `EfiBootServicesCode` / `EfiBootServicesData` | `Usable` | No longer in use after `ExitBootServices`. |
| `EfiLoaderCode` / `EfiLoaderData` | `Loaded` | Every bootloader allocation (kernel image, modules, init segments, `BootInfo`, `mmio_apertures` page, memory-map buffer, stack). |
| `EfiACPIReclaimMemory` | `AcpiReclaimable` | Reclaimable by the kernel after `devmgr` has finished firmware parsing. |
| `EfiACPIMemoryNVS` | `Reserved` | Firmware-reserved. |
| `EfiRuntimeServicesCode` / `EfiRuntimeServicesData` | `Reserved` | Seraph does not use UEFI runtime services; treat as off-limits. |
| `EfiMemoryMappedIO` / `EfiMemoryMappedIOPortSpace` | `Reserved` | Device space, not RAM. |
| `EfiPersistentMemory` | `Persistent` | NVDIMM or similar. |
| Any unrecognised type | `Reserved` | Conservative default. |

`EfiBootServices*` → `Usable` is deliberate: those regions are dead
after `ExitBootServices` and represent the largest usable reclaim on a
typical system. `EfiRuntimeServices*` → `Reserved` prevents accidental
reclamation of firmware code that remains mapped in the identity region
even though Seraph does not call into it.

---

## Post-Translation Invariants

The translated array passed in `BootInfo.memory_map` satisfies the
invariants documented in the boot-protocol contract — sorted ascending
by `physical_base`, no overlap between entries, stable classification
per the table above. The kernel may rely on these without
re-validation.

Contiguous same-type UEFI entries are **not** coalesced by the
bootloader. The translated array mirrors the UEFI descriptor sequence
1:1 (after sorting); any consolidation of adjacent regions into a single
larger entry is left to the kernel if it wants a denser representation.

Bootloader allocations made between the memory-map query and
`ExitBootServices` are already accounted for by the UEFI-side map
refresh; the retry path in
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
`Loaded` regions to its buddy allocator. The bootloader-scratch subset
recorded in `BootInfo.reclaim_ranges` is minted as reclaimable Memory caps
in Phase 7 (the AP trampoline page is late-minted in Phase 8), and init
donates those caps to memmgr at reap; kernel-image and init-segment pages
are never reclaimed. See
[initialization.md](../../kernel/docs/initialization.md) §"Phase 7: Capability System",
and §"Phase 3: Kernel Page Tables" step 7 for the bootloader page-table
frames. The `Loaded` allocations are:

- Kernel image LOAD segments, placed in a bootloader-chosen contiguous span.
- Init image LOAD segments, placed at any free physical address.
- Boot-module file buffers, placed at any free physical address.
- `BootInfo` structure page.
- `MmioAperture` array page (`mmio_apertures.entries`).
- Memory-map buffer itself.
- Kernel handoff stack (`KERNEL_STACK_PAGES`, 64 KiB), allocated by the
  bootloader as `EfiLoaderData`.
- Page-table frames allocated for the initial mapping (see
  [page-tables.md](page-tables.md)).

The `BootInfo.modules` descriptor page is similarly `Loaded` and is a
`BootInfo.reclaim_ranges` entry; the module bodies get Memory caps from
`mint_module_memory_caps`. The kernel mints both in Phase 7, before init
exists, and hands them to init (see
[initialization.md](../../kernel/docs/initialization.md) §"Phase 7: Capability System").
The pages return to the pool only when init donates those caps to memmgr at
reap (see [process-lifecycle.md](../../../docs/process-lifecycle.md) §"Init reap").

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
(`boot_protocol::layout::direct_map_ceiling`), and the base is drawn
1 GiB-aligned in the gap between the mode's kernel-half floor and the kernel
image. The kernel re-derives the same ceiling from the same helper at Phase 3
to guard the mapping, so bootloader and kernel cannot disagree. See
[boot-flow.md](boot-flow.md) step 9 and [initialization.md](../../kernel/docs/initialization.md)
§"Phase 3: Kernel Page Tables".

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
