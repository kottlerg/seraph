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
therefore surfaces as `MemoryType::Loaded`. The kernel treats `Loaded`
regions as in-use until it explicitly reclaims them in Phase 3 (kernel
page-table replacement). Specifically:

- Kernel image LOAD segments, placed at ELF `p_paddr`.
- Init image LOAD segments, placed at any free physical address.
- Boot-module file buffers, placed at any free physical address.
- `BootInfo` structure page.
- `MmioAperture` array page (`mmio_apertures.entries`).
- Memory-map buffer itself.
- Bootloader stack region (mapped by UEFI at boot; classified by
  firmware, not by the bootloader).
- Page-table frames allocated for the initial mapping (see
  [page-tables.md](page-tables.md)).

The `BootInfo.modules` slice and its backing page are similarly
`Loaded`; the kernel only reclaims them after init has copied whatever
is needed.

---

## Sizing the Map Buffer

The UEFI map query is racy with allocation: each `AllocatePages` call
can grow the map by one entry. The buffer size is taken from the
first, size-query call and padded with extra slack for the map-buffer
allocation itself. The exact slack constant is internal to
[`boot/src/memory_map.rs`](../src/memory_map.rs); it is sized so the
post-allocation map fits without reallocation under every supported
firmware implementation.

---

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

[boot/README.md](../README.md)
