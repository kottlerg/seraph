# ACPI Parsing

ACPI table-walk invariants for the bootloader's narrow extractors.
Higher-level flow (how ACPI parsing feeds the boot sequence) is owned by
[firmware-parsing.md](firmware-parsing.md); this document owns the
invariants internal to the ACPI walker itself.

The implementation lives in [`boot/src/acpi.rs`](../src/acpi.rs).

---

## Scope

The bootloader parses a minimal subset of ACPI: the RSDP, XSDT, MADT,
MCFG, and (RISC-V only) SPCR. Every other XSDT-linked table (FADT,
SSDT, DSDT, BERT, EINJ, DMAR, …) is left untouched; its address
remains reachable from the RSDP via the passthrough
`BootInfo.acpi_rsdp` pointer, and any userspace component that needs
it re-parses the tree itself.

SPCR is consumed only on RISC-V and only for the UART base address:
once by the pre-Step-1 serial-init path (see [console.md](console.md))
and once by the `kernel_mmio` extractor (Step 5). No other SPCR field
is extracted. SPCR is not walked on x86-64 because the x86-64 console
path uses a fixed-convention COM1 I/O-port UART that requires no
discovery.

The bootloader does **not** evaluate AML. It reads static table fields
only; ACPI namespace evaluation, `_CRS`/`_HID`/`_PRT` resolution, device
binding, and IOMMU-topology discovery are userspace concerns.

---

## Revision Gating

Only ACPI 2.0 and later are supported. The RSDP revision byte at
offset 15 must be ≥ 2; otherwise the bootloader skips ACPI entirely.
ACPI 1.0 (RSDT-only) systems are outside the targeted platform set.

The XSDT pointer at RSDP offset 24 is the authoritative table root; the
32-bit `RsdtAddress` at offset 16 is ignored.

---

## Tables Consumed

| Table | Signature | Extracted into |
|---|---|---|
| MADT | `"APIC"` | `BootInfo.cpu_count` / `cpu_ids` via LAPIC (type 0) and RINTC (type 0x18). On x86-64: `BootInfo.kernel_mmio` LAPIC base (MADT header + type-5 override) and IOAPIC entries (type 1). On RISC-V: `BootInfo.kernel_mmio.plic_base` / `plic_size` from the first PLIC entry (type 0x1B). Aperture seeds for LAPIC, IOAPIC, and RISC-V PLIC. |
| MCFG | `"MCFG"` | Aperture seeds for each ECAM window and the derived 32-bit / 64-bit PCI BAR windows (QEMU-layout heuristic; see `firmware-parsing.md` for the real-hardware `_CRS` note). |
| SPCR | `"SPCR"` | RISC-V only: `BootInfo.kernel_mmio.uart_base` (from the Generic Address Structure when the address-space identifier is MMIO). `uart_size` is set to the ns16550a conventional 0x100 (SPCR does not carry a region size; if DTB also advertises the UART, DTB's explicit `reg` size overrides). The pre-Step-1 serial-init path uses the same walk to pick up a UART base for early diagnostics. |

Every other signature is ignored by the bootloader. Userspace consumes
the remaining ACPI tree via `BootInfo.acpi_rsdp`.

---

## Error Handling

Malformed tables are skipped, not fatal:
- A bad XSDT length or a short read yields empty extractor output.
- An MADT entry with an impossible length byte stops the walk early.
- Unknown MADT / MCFG entry types are silently skipped.

A warning is logged on hard failure; the bootloader proceeds with
whatever it successfully extracted and lets the kernel fall back to its
compile-time defaults for any zero fields.

---

## What Lives Elsewhere

- Aperture merging / sort / cap-at-`MAX_APERTURES` invariants are owned
  by [`boot/src/memory_map.rs`](../src/memory_map.rs); see
  [memory-map.md](memory-map.md) §"MMIO Aperture Derivation".
- The ACPI RSDP physical address is discovered from the UEFI
  configuration table in [`boot/src/firmware.rs`](../src/firmware.rs);
  [firmware-parsing.md](firmware-parsing.md) §"Architecture Dispatch"
  covers the dispatch invariants.
- CPU-count / CPU-ID population interacts with the SMP fields in
  `BootInfo`; [boot-flow.md](boot-flow.md) §"Step 9" owns the final
  population invariants.

---

## Summarized By

[boot/README.md](../README.md)
