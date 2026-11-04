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
| `EfiACPIReclaimMemory` | `AcpiReclaimable` | Firmware tables; exposed to userspace read-only as Map-only Memory caps (one per region) and never returned to the allocator; see [initialization.md § Phase 7](../../kernel/docs/initialization.md#phase-7-capability-system). |
| `EfiACPIMemoryNVS` | `Reserved` | Firmware-reserved. |
| `EfiRuntimeServicesCode` / `EfiRuntimeServicesData` | `Reserved` | Seraph does not use UEFI runtime services; treat as off-limits. |
| `EfiMemoryMappedIO` / `EfiMemoryMappedIOPortSpace` | `Reserved` | Device space, not RAM. |
| `EfiPersistentMemory` | `Persistent` | NVDIMM or similar. |
| Any unrecognised type | `Reserved` | Conservative default. |

`EfiBootServices*` → `Usable` is deliberate: those regions are dead
after `ExitBootServices` and represent the largest usable reclaim on a
typical system. They still hold what firmware and the bootloader left there
(the UEFI stack the bootloader runs on is `EfiBootServicesData`), so the kernel
zeroes every page it drains from them before minting it to userspace
([initialization.md § Phase 7](../../kernel/docs/initialization.md#phase-7-capability-system)).
`EfiRuntimeServices*` → `Reserved` keeps firmware runtime
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
1:1 (after sorting); its capacity follows the firmware's map
(§ Sizing the Entry Array). Any consolidation of adjacent regions into a
single larger entry is left to the kernel if it wants a denser
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

Every bootloader allocation still held at `ExitBootServices` uses `EfiLoaderCode` or
`EfiLoaderData` and therefore surfaces as `MemoryType::Loaded`. The kernel never hands
`Loaded` regions to its buddy allocator. Three `Loaded` sets return to the
pool, each through reclaimable Memory caps that the kernel hands to init;
init hands those caps to procmgr, which donates them to memmgr when it reaps
init (see [process-lifecycle.md](../../../docs/process-lifecycle.md) §"Init reap"):

- The bootloader-scratch subset recorded in `BootInfo.reclaim_ranges` (the raw UEFI
  memory-map buffer among it, zeroed after its last read in step 9), minted
  in Phase 7 (the AP trampoline page is late-minted in Phase 8) and zeroed
  whole by the kernel in Phase 9, before init runs. See
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
handoff trampoline), the kernel image, and the kernel handoff stack with its guard page
(the stack is kept as the BSP boot stack).

Two scratch allocations never reach the final map: the kernel ELF file read
buffer, freed in step 3 once `load_kernel` has copied the image out, and, on
riscv64, the paging-mode probe page, freed once the mode is negotiated. Both are
zeroed and returned with `FreePages` before `ExitBootServices`, so their frames
surface as `Usable` (or back a later bootloader allocation); a free the firmware
refuses leaves the allocation `Loaded` and permanent, with a console diagnostic.

The `Loaded` allocations are:

- The bootloader's own loaded image (firmware-allocated as `EfiLoaderCode` /
  `EfiLoaderData`; it contains the handoff trampoline).
- Kernel image LOAD segments, placed in one contiguous span at a firmware-chosen
  address (`AllocateAnyPages` on riscv64; `AllocateMaxAddress` below 4 GiB on x86-64).
- Init image LOAD segments, placed at any free physical address.
- Bundle blob: one allocation holding the bundle header and entry table,
  every boot-module body, and the init ELF source.
- `BootInfo` structure page.
- `BootInfo.modules` descriptor page.
- `MmioAperture` array pages (`mmio_apertures.entries`).
- CPU-id pages (`BootInfo.cpu_ids`).
- Raw UEFI memory-map buffer (the `GetMemoryMap` output).
- Translated `MemoryMapEntry` array (`BootInfo.memory_map`).
- Reclaim-array page (the `BootInfo.reclaim_ranges` backing).
- AP trampoline page, when allocated.
- Kernel handoff stack (`KERNEL_STACK_PAGES`, 64 KiB) and the guard page below it.
- Page-table frames allocated for the initial mapping (see
  [page-tables.md](page-tables.md)).
- The x86-64 LA57 toggle page (`EfiLoaderCode`), when the handoff changes the paging
  depth; it is reclaimed with the page-table frames.

---

## Sizing the Map Buffer

The acquisition sequence that sizes and fills the map buffer, including
its slack margin, is owned by
[uefi-environment.md](uefi-environment.md) §"Memory Map Acquisition".

---

## Sizing the Entry Array

The translated `MemoryMapEntry` array is allocated in step 6, before the final
map exists, so it is sized from the firmware's map at that point: step 6 reads
the descriptor count and stride with a `GetMemoryMap` size query before its first
allocation. The array holds every descriptor that the buffer step 7 would allocate
for a map `MEM_MAP_SLACK_ENTRIES` (32) descriptors larger could hold at the
smallest stride the UEFI contract allows (`EFI_MEMORY_DESCRIPTOR`'s 40 bytes):
`uefi::map_buffer_descriptor_reach` of `uefi::map_buffer_bytes`, the map plus the
buffer's own 16 descriptors of slack, in whole pages
([uefi-environment.md](uefi-environment.md) § Memory Map Acquisition). Each
allocation after the query (the bootloader's own in steps 6 and 7) adds at most two
descriptors, and the rest of the slack absorbs the firmware's own housekeeping
allocations in that window (§ ExitBootServices in
[uefi-environment.md](uefi-environment.md)), which nothing bounds, so the slack is
a first guess, not a proof.

The guess is checked before `ExitBootServices`: when the reach of step 7's map
buffer exceeds the array, the bootloader frees every allocation of steps 6
and 7, the page-table frame pool included (the AP trampoline page, the CPU-id
pages and the x86-64 LA57 toggle page are earlier steps' and stay), and runs both
again with twice the slack. The redo counts the map after those frees, so its count
includes what the firmware itself allocated during the first window. After
`MEM_MAP_ATTEMPTS` (3) attempts a buffer that still reaches past its array fails
the boot with `BootError::MemoryMapKeptGrowing`; only firmware that outgrows twice
the slack in the second window reaches a third.

The check bounds the buffer, not the map in it, because a map can still grow after
step 7: when `ExitBootServices` refuses a stale key, step 8 re-queries the map into
the same buffer, and a map past the buffer fails that re-query. Translation reads
no descriptor past the buffer, so every map step 9 translates fits the array and no
descriptor is lost.

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

[Boot Flow](boot-flow.md), [UEFI Environment](uefi-environment.md)
