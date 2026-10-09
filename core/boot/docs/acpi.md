# ACPI Parsing

ACPI table-walk invariants for the bootloader's narrow extractors.
Higher-level flow (how ACPI parsing feeds the boot sequence) is owned by
[firmware-parsing.md](firmware-parsing.md); this document owns the
invariants internal to the ACPI walker itself.

The implementation lives in [`core/boot/src/acpi.rs`](../src/acpi.rs), with the arch-specific
extractors in
[`core/boot/src/arch/x86_64/acpi_kernel_mmio.rs`](../src/arch/x86_64/acpi_kernel_mmio.rs),
[`core/boot/src/arch/riscv64/acpi_kernel_mmio.rs`](../src/arch/riscv64/acpi_kernel_mmio.rs), and
[`core/boot/src/arch/riscv64/acpi_spcr.rs`](../src/arch/riscv64/acpi_spcr.rs).

---

## Scope

The bootloader parses a minimal subset of ACPI: the RSDP, XSDT, MADT,
MCFG, (RISC-V only) SPCR and RHCT, and every SSDT, which it scans for
the QEMU VMGENID `VGIA` named DWORD without evaluating AML. Every other
table (FADT, DSDT, BERT, EINJ, DMAR, …) is left untouched; it remains
reachable from the RSDP via the passthrough `BootInfo.acpi_rsdp`
pointer, and any userspace component that needs it re-parses the tree
itself (see [firmware-parsing.md](firmware-parsing.md)).

SPCR is consumed only on RISC-V and only for the UART base address:
once by the pre-Step-1 serial-init path (see [console.md](console.md))
and once by the `kernel_mmio` extractor (Step 9, `populate_kernel_mmio`). No other SPCR field
is extracted. SPCR is not walked on x86-64 because the x86-64 console
path uses a fixed-convention COM1 I/O-port UART that requires no
discovery.

The bootloader does **not** evaluate AML. It reads static table fields
only; ACPI namespace evaluation, `_CRS`/`_HID`/`_PRT` resolution, device
binding, and IOMMU-topology discovery are userspace concerns; see
[firmware-parsing.md](firmware-parsing.md) §"Parsing Depth".

---

## Revision Gating

Only ACPI 2.0 and later are supported. The RSDP revision byte at
offset 15 must be ≥ 2; otherwise every bootloader ACPI walker returns
empty output (the RSDP address is still passed through in `BootInfo.acpi_rsdp`).
ACPI 1.0 (RSDT-only) systems are outside the targeted platform set.

The XSDT pointer at RSDP offset 24 is the authoritative table root; the
32-bit `RsdtAddress` at offset 16 is ignored.

---

## Tables Consumed

| Table | Signature | Extracted into |
|---|---|---|
| MADT | `"APIC"` | `BootInfo.cpu_count` / `cpu_ids` via LAPIC (type 0), Local x2APIC (type 9, 32-bit IDs), and RINTC (type 0x18). On x86-64: `BootInfo.kernel_mmio` LAPIC base (MADT header + type-5 override) and IOAPIC entries (type 1). On RISC-V: `BootInfo.kernel_mmio.plic_base` / `plic_size` from the first PLIC entry (type 0x1B). Aperture seeds for LAPIC, IOAPIC, and RISC-V PLIC. |
| MCFG | `"MCFG"` | Aperture seeds for each ECAM window and the derived 32-bit / 64-bit PCI BAR windows (QEMU-layout heuristic: real hardware advertises these windows through the host bridge's `_CRS`, which the bootloader does not evaluate; see [firmware-parsing.md](firmware-parsing.md) §"Parsing Depth"). |
| SPCR | `"SPCR"` | RISC-V only: `BootInfo.kernel_mmio.uart_base` (from the Generic Address Structure when the address-space identifier is MMIO). `uart_size` is set to the ns16550a conventional 0x100 (SPCR does not carry a region size; the later DTB pass fills `uart_base` / `uart_size` only when ACPI left `uart_base` zero). The pre-Step-1 serial-init path uses the same walk to pick up a UART base for early diagnostics (see [console.md](console.md)). |
| RHCT | `"RHCT"` | RISC-V only, Step 9 (`populate_kernel_mmio`): `BootInfo.kernel_mmio.timebase_freq` from the time-base-frequency field, and the `HART_CAP_*` bits (Sstc, Svpbmt, Svinval, Svnapot) named by every ISA-string node (a per-bit AND; zero when no ISA-string node exists). |
| SSDT | `"SSDT"` | Every architecture where an RSDP is present, Step 9: `BootInfo.vmgenid_paddr`, the non-zero, 4 KiB-aligned `VGIA` named-DWORD value plus the 40-byte GUID offset; an SSDT whose OEM table ID starts with `VMGENID` is preferred, otherwise the first SSDT carrying the pattern. No AML is evaluated. |

Every signature outside this table is ignored by the bootloader. Userspace consumes
the remaining ACPI tree via `BootInfo.acpi_rsdp`; see [firmware-parsing.md](firmware-parsing.md).

---

## Error Handling

Malformed tables are skipped, not fatal:
- A bad XSDT length or a short read yields empty extractor output (for the CPU
  topology, the single-CPU fallback: `cpu_count = 1`, `cpu_ids[0] = bsp_id`).
- An MADT entry with an impossible length byte stops the walk early.
- Unknown MADT entry types are silently skipped; an MCFG allocation entry with a
  zero base address is skipped.

No diagnostic is logged for a malformed or absent table; the walker's
only diagnostics report surplus MADT entries (more than `MAX_CPUS`
enabled CPUs, or on x86-64 more than `MAX_IOAPICS` IOAPICs). The
bootloader proceeds with whatever it successfully extracted. The kernel
falls back to its compile-time defaults
for any zero MMIO base field, but a zero riscv64 `timebase_freq` or a missing `hart_caps`
bit (filled by the RHCT walk; the DTB `/cpus` walk then supplies `timebase_freq` when ACPI
left it zero and ORs in further `hart_caps` bits) halts the kernel at Phase 5 (see
[boot-flow.md](boot-flow.md) §"Step 9").

---

## What Lives Elsewhere

- Aperture merging / sort / cap-at-`MAX_APERTURES` invariants are owned by
  [firmware-parsing.md](firmware-parsing.md) §"`mmio_apertures` construction"; the
  implementation is `derive_mmio_apertures` in
  [`core/boot/src/memory_map.rs`](../src/memory_map.rs).
- The ACPI RSDP physical address is discovered from the UEFI
  configuration table in [`core/boot/src/firmware.rs`](../src/firmware.rs);
  [firmware-parsing.md](firmware-parsing.md) §"Architecture Dispatch"
  covers the dispatch invariants.
- CPU-count / CPU-ID population interacts with the SMP fields in
  `BootInfo`; [boot-flow.md](boot-flow.md) §"Step 9" owns the final
  population invariants.

---

## Summarized By

[Early Console](console.md), [Firmware Parsing](firmware-parsing.md)
