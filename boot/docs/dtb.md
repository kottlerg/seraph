# Device Tree Parsing

Flat Device Tree (FDT/DTB) walk invariants for the bootloader's
structured-resource extraction on RISC-V. Higher-level flow (how ACPI
and DTB parsing plug into Step 5 of the boot sequence) is owned by
[firmware-parsing.md](firmware-parsing.md); this document owns only the
invariants internal to DTB parsing itself.

The implementation lives in [`boot/src/dtb.rs`](../src/dtb.rs).

---

## Scope

The bootloader extracts a minimal set of platform resources from the
DTB: MMIO-backed peripherals matched by known `compatible` strings,
PLIC interrupt controllers, PCI host bridges, and IOMMU units. The
full DTB is additionally recorded as a single `PlatformTable` entry so
`devmgr` can perform its own complete walk.

The bootloader does **not** resolve `interrupt-map` tables, complex
`ranges` translations, phandle graphs, or node-tree semantics beyond a
flat walk. Driver binding and property-evaluation logic belong to
`devmgr`.

---

## Header Validation

The DTB header is validated before any parsing. Validation failures
zero the `BootInfo.device_tree` field and leave the resource count at
zero; the bootloader then proceeds without a DTB. On RISC-V platforms
this reduces available hardware to what the kernel can infer directly,
but it is not fatal at boot time.

Validation checks:
- `magic == 0xD00DFEED` (big-endian per the FDT spec).
- `version >= 17`.
- `last_comp_version <= 17`.
- `totalsize > sizeof(fdt_header)`.
- Struct-block and strings-block offsets fall within `totalsize`.

All header fields and struct-block tokens are big-endian per the FDT
specification, regardless of target CPU byte order.

---

## Cell-Size Assumptions

The walker assumes `#address-cells = 2` and `#size-cells = 2`, which is
the standard for RISC-V QEMU virt and every production RISC-V platform
targeted. Nodes that override these with different values are parsed as
if the defaults applied; any resulting misinterpretation is bounded
(the node's `reg` entries become garbage but no invariant outside the
node is violated). Full cell-inheritance support is a `devmgr`-side
concern.

Walker limits: `MAX_DEPTH = 8` for node nesting, `MAX_REG_ENTRIES = 8`
for `reg` tuples per node, `MAX_IRQ_ENTRIES = 4` for `interrupts`
values, `MAX_RANGES_ENTRIES = 4` for PCI `ranges`. Nodes exceeding
these bounds truncate silently — the bootloader does not need
exhaustive coverage; `devmgr` re-parses the full DTB.

---

## Compatible-String Matching

MMIO peripherals are matched by `compatible` string containing known
substrings (`ns16550`, `virtio`, `sifive`, …). Matches emit an
`MmioRange` per `reg` entry. Unknown `compatible` strings are skipped
without warning; `devmgr` is responsible for identifying every other
device.

PCI host bridges match `pci-host-ecam-generic` (and close variants).
IOMMU units match `riscv,iommu` and close variants. Interrupt lines
come from `interrupts` values on nodes whose `interrupt-parent`
resolves to a PLIC node.

---

## Error Handling

Malformed nodes are skipped; partial results are returned. An
out-of-bounds token offset aborts the walk for the current subtree but
not the whole tree. A bad header aborts DTB parsing entirely (see
§Header Validation). Warnings are logged for skipped nodes; the
bootloader never halts on DTB parse error.

---

## What Lives Elsewhere

- Aperture merging / sort / cap-at-`MAX_APERTURES` invariants are owned
  by [`boot/src/memory_map.rs`](../src/memory_map.rs); see
  [memory-map.md](memory-map.md) §"MMIO Aperture Derivation".
- The DTB physical address is discovered from the UEFI configuration
  table in [`boot/src/firmware.rs`](../src/firmware.rs);
  [firmware-parsing.md](firmware-parsing.md) §"Architecture Dispatch"
  covers the dispatch invariants.
- Per-hart count discovery overlaps with SMP fields in `BootInfo`;
  [boot-flow.md](boot-flow.md) §"Step 9" owns the `BootInfo`
  population invariants.

---

## Summarized By

[boot/README.md](../README.md)
