# Device Tree Parsing

Flat Device Tree (FDT/DTB) walk invariants for the bootloader's
structured-resource extraction on RISC-V. Higher-level flow (how ACPI
and DTB parsing plug into Step 5 of the boot sequence) is owned by
[firmware-parsing.md](firmware-parsing.md); this document owns only the
invariants internal to DTB parsing itself.

The implementation lives in [`core/boot/src/dtb.rs`](../src/dtb.rs).

---

## Scope

The bootloader extracts a minimal set of platform resources from the
DTB: MMIO-backed peripherals matched by known `compatible` strings,
PLIC interrupt controllers, PCI host bridges, the `/cpus` hart IDs (the
CPU-topology fallback when no ACPI is present), the `/cpus` hart
capabilities (`timebase-frequency` and the `HART_CAP_*` bits) and the
boot hart's `mmu-type` claim for paging-mode negotiation. It also
extracts the `/chosen/rng-seed` boot-entropy fallback and scrubs the
property in place while the blob is still writable (before
`ExitBootServices`), since the same blob is later handed to userspace;
which firmware exposes which entropy source is documented in
[boot-flow.md](boot-flow.md). The `rng-seed` reader is a flat scan that
takes the first property of that name anywhere in the tree. The DTB's
physical address is passed through unchanged in `BootInfo.device_tree`
because device-level discovery, IOMMU topology included, is a userspace
concern; `devmgr`'s own firmware-table parsing is specified under
Parse firmware tables in
[`services/devmgr/docs/responsibilities.md`](../../../services/devmgr/docs/responsibilities.md#responsibilities).
See [`docs/device-management.md`](../../../docs/device-management.md) for
the system-scope IOMMU model.

The bootloader does **not** resolve `interrupt-map` tables, complex
`ranges` translations, phandle graphs, or node-tree semantics beyond a
flat walk. Driver binding and property-evaluation logic belong to
`devmgr` (see [`docs/device-management.md`](../../../docs/device-management.md)).

---

## Header Validation

The DTB header is validated before any parsing. A blob that fails
validation yields no resources (the walkers return `None` or zero) and
the bootloader proceeds without DTB-derived resources; the
`BootInfo.device_tree` passthrough is unaffected. The bootloader never
halts on a rejected blob. The kernel falls back to its compiled-in
defaults for any zero MMIO base, but on a RISC-V platform whose only hart
facts come from the DTB (no ACPI RHCT), a rejected blob leaves
`timebase_freq` zero and `hart_caps` empty, which halts the kernel at
Phase 5 (see [boot-flow.md](boot-flow.md) §"Step 9").

Validation checks:
- `magic == 0xD00DFEED` (big-endian per the FDT spec).
- `off_dt_struct + size_dt_struct` and `off_dt_strings + size_dt_strings`
  (overflow-checked) do not exceed `totalsize`.

All header fields and struct-block tokens are big-endian per the FDT
specification, regardless of target CPU byte order.

---

## Cell-Size Assumptions

The compatible-node walker (`Fdt::walk_compatible`) assumes
`#address-cells = 2` and `#size-cells = 2`; the CPU-node walker
(`Fdt::walk_cpu_nodes`) reads each `/cpus` child's `reg` as one
big-endian u32 hart ID (`#address-cells = 1`, `#size-cells = 0`). The
2/2 assumption is the standard for RISC-V QEMU virt and every production
RISC-V platform targeted. Nodes that override these with different
values are parsed as if the defaults applied; any resulting
misinterpretation is bounded (the node's `reg` entries become garbage; a
garbage first entry with non-zero size still becomes an `MmioAperture`
seed and, for a PLIC or UART node, the corresponding `kernel_mmio`
base). Full cell-inheritance support belongs to `devmgr` (design intent,
not yet implemented: devmgr's DTB reader likewise assumes
`#address-cells = 2` and `#size-cells = 2`).

Walker limits: `MAX_DEPTH = 8` for node nesting, `MAX_REG_ENTRIES = 8`
for `reg` tuples per node, `MAX_IRQ_ENTRIES = 4` for `interrupts`
values, `MAX_RANGES_ENTRIES = 4` for PCI `ranges`. Nodes exceeding
these bounds truncate silently — the bootloader does not need
exhaustive coverage, because device-level discovery is a userspace
concern (see Responsibilities in
[`services/devmgr/docs/responsibilities.md`](../../../services/devmgr/docs/responsibilities.md#responsibilities)).

---

## Compatible-String Matching

MMIO peripherals are matched by an exact entry in the node's
`compatible` string list (`ns16550a`, `virtio,mmio`, …). A match
contributes its first `reg` entry as an `MmioAperture` seed; PCI host
bridges additionally contribute their MMIO `ranges` windows. Unknown
`compatible` strings are skipped
without warning; `devmgr` is responsible for identifying every other
device (see [`docs/device-management.md`](../../../docs/device-management.md)).

PCI host bridges match `pci-host-ecam-generic`.
A node's raw `interrupts` values are collected alongside its `reg`
entries; the bootloader does not resolve `interrupt-parent`; associating
lines with a PLIC belongs to `devmgr` (design intent, not yet
implemented; see Parse firmware tables in
[`services/devmgr/docs/responsibilities.md`](../../../services/devmgr/docs/responsibilities.md#responsibilities)).

---

## Error Handling

Malformed nodes are skipped; partial results are returned. An
unreadable or unknown token ends the walk with the partial results
collected so far. A bad header aborts DTB parsing entirely (see
§Header Validation). Nothing is logged for skipped nodes, and the
bootloader never halts on a DTB parse error.

---

## What Lives Elsewhere

- Aperture merging / sort / cap-at-`MAX_APERTURES` invariants are owned
  by [firmware-parsing.md](firmware-parsing.md)
  §"`mmio_apertures` construction" and implemented by
  `derive_mmio_apertures` in
  [`core/boot/src/memory_map.rs`](../src/memory_map.rs).
- The DTB physical address is discovered from the UEFI configuration
  table in [`core/boot/src/firmware.rs`](../src/firmware.rs);
  [firmware-parsing.md](firmware-parsing.md) §"Architecture Dispatch"
  covers the dispatch invariants.
- Per-hart count discovery overlaps with SMP fields in `BootInfo`;
  [boot-flow.md](boot-flow.md) §"Step 9" owns the `BootInfo`
  population invariants.

---

## Summarized By

[Boot Flow](boot-flow.md), [Early Console](console.md)
