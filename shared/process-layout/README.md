# shared/process-layout

Per-process bootstrap virtual-address layout for Seraph process creators.

---

## Overview

`no_std`, no allocation, no I/O; depends only on `process-abi` (for stack policy
bounds), and builds inside std's dependency graph through the `rustc-dep-of-std`
feature. Owns the choice of where a new process's four bootstrap surfaces are
placed — the `ProcessInfo` handover page, the main-thread stack, the main-thread
TLS block, and the main-thread IPC buffer — so that choice lives in one place
instead of being pinned as ABI constants in `process-abi`.

Used by `init` (lays out memmgr and procmgr) and `procmgr` (lays out all other
processes). The creator draws entropy, calls `choose_process_layout` once per
process, and writes the result into the handover surface and the entry register;
the created process reads the addresses back rather than assuming fixed values
(see [docs/process-lifecycle.md](../../docs/process-lifecycle.md) § Handover-page addresses).

Each surface is drawn independently inside a fixed per-region `VaWindow`
(ASLR, [#39](https://github.com/kottlerg/seraph/issues/39)): 2^21 page-aligned
slots on 9 GiB strides, the whole fixed tier below `LAYOUT_VA_CEILING` (2^38, the
smallest supported user half — riscv64 Sv39) so one static layout is canonical
under every paging mode on both architectures, with disjointness, region
ordering, and the stack guard gap holding for every possible draw. The crate is
pure: entropy is injected as pre-drawn bytes, and a creator whose entropy draw
failed passes `None` to fall back to the deterministic `DEFAULT_*` addresses.
The zone map and draw windows are specified in
[docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) § Bootstrap
Cross-Boundary VAs; the `DEFAULT_*` fallback addresses are this crate's own constants
(see § Surface).
The kernel reuses the `INIT_*` windows for init's per-boot layout, and the
`IMAGE_WINDOW` constants parameterise ET_DYN load-bias placement.

The crate also sizes the zones a process places itself: `growth_zones(user_va_top)` gives the
byte-heap and reservation-arena zones ruststd draws in, and the image zone procmgr validates its
children against, for the process's user half (below the bootstrap windows under Sv39, above the
whole fixed tier and growing with the half otherwise; see
[docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) § Growth Zones). Its
zones are const-asserted disjoint and inside the address space for every supported paging mode.

---

## Surface

| Item | Purpose |
|---|---|
| `ProcessLayout` | The four bootstrap base VAs for one new process. |
| `choose_process_layout(Option<&[u8; LAYOUT_ENTROPY_BYTES]>) -> ProcessLayout` | Draw the layout from injected entropy; `None` degrades to defaults. |
| `VaWindow` | A fixed randomisation window: power-of-two page slots at a constant base. |
| `MAIN_TLS_WINDOW`, `IPC_BUFFER_WINDOW`, `PROCESS_INFO_WINDOW`, `STACK_GUARD_WINDOW` | Per-surface draw windows used by `choose_process_layout`. |
| `INIT_INFO_WINDOW`, `INIT_STACK_GUARD_WINDOW` | Kernel-side windows for init's per-boot layout. |
| `IMAGE_WINDOW`, `IMAGE_MAX_SPAN`, `choose_image_bias`, `validate_image_placement` | ET_DYN load-bias window and fixed-tier placement validation (`IMAGE_MAX_SPAN` derived, 28 GiB). |
| `FIXED_IMAGE_ZONE_END`, `image_max_span`, `validate_image_placement_below` | Image-zone end of the fixed tier, the span an image zone holds, and validation against any zone end. |
| `MAX_WINDOW_REGION_PAGES` | Largest region hanging off a window draw (1 GiB stride gap); bounds the stack reservation and the main TLS block. |
| `GrowthZone`, `AddressSpaceZones`, `SV39_ZONES`, `growth_zones(u64) -> AddressSpaceZones` | Heap, arena, and image zones sized to a user half; the Sv39 zones also serve an unknown size. |
| `LAYOUT_ENTROPY_BYTES` | Entropy bytes one layout draw consumes. |
| `main_stack_growth(u64, u64, u64) -> Option<(u64, u64)>` | The demand-growth range below a main-thread stack's committed pages, inside the stack reservation; ruststd's `_start` registers it with the pager. |
| `DEFAULT_PROCESS_INFO_VA`, `DEFAULT_STACK_TOP`, `DEFAULT_MAIN_TLS_VA`, `DEFAULT_IPC_BUFFER_VA` | Degraded-fallback addresses (outside the draw windows by design, each with its window's region tail). |
| `LAYOUT_VA_CEILING` | Exclusive ceiling of the fixed tier (every draw window and `DEFAULT_*` fallback): the smallest supported user half (Sv39, 2^38). |

Page counts are not part of the layout: stack size comes from the binary's
`.note.seraph.stack` ELF note and TLS size from its `PT_TLS` segment, both
resolved by the creator (see [abi/process-abi/README.md](../../abi/process-abi/README.md)).

---

## Source Layout

```
process-layout/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs      # ProcessLayout, choose_process_layout, VaWindow and the per-surface
                    #   windows, image-bias placement, DEFAULT_* fallbacks, growth zones,
                    #   const-asserted zone disjointness, host tests
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Three-surface VA model; "Bootstrap Cross-Boundary VAs"; zone map |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Handover discipline; `ProcessInfo`/`InitInfo` fields |
| [abi/process-abi/README.md](../../abi/process-abi/README.md) | `ProcessInfo` handover struct that records the chosen VAs |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[Process Lifecycle](../../docs/process-lifecycle.md),
[Userspace Memory Model](../../docs/userspace-memory-model.md),
[runtime/ruststd/README.md](../../runtime/ruststd/README.md)
