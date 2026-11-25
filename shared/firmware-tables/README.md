# shared/firmware-tables

The formats of the firmware's tables, decoded once for every consumer: the ACPI RSDP, system
description table header, XSDT, MCFG and MADT structures, the DMAR's remapping structures, the
SPCR, and the flattened device tree.

---

## Source Layout

```
firmware-tables/
├── Cargo.toml
├── README.md
├── fuzz/
│   └── firmware-tables/
│       └── seeds/              # Checked-in inputs of the `firmware-tables` fuzz target
└── src/
    ├── lib.rs                  # EcamLocation, and the replay and acceptance tests of the seeds
    ├── bytes.rs                # Fixed-width little- and big-endian field reads
    ├── acpi.rs                 # RSDP, SDT header, XSDT, MCFG entries, MADT structures
    ├── dmar.rs                 # DMAR remapping structures: DRHD units and RMRR regions
    ├── spcr.rs                 # Serial Port Console Redirection table
    ├── fdt.rs                  # Flattened device tree: header, structure events, strings
    └── property/               # The contract of the decoders, as one property (host tests,
        │                       #   proofs and fuzzing only)
        ├── mod.rs              # tables_holds and the reading helpers
        ├── acpi.rs
        ├── dmar.rs
        ├── spcr.rs
        └── fdt.rs
```

`no_std`, no allocation, no dependency. Host-tested (`cargo xtask test`).

---

## Modules

| Module | Decodes |
|---|---|
| `bytes` | A `u8`, and a little- or big-endian `u16`, `u32` and `u64`, read only where it lies wholly inside the buffer, else zero |
| `acpi` | The RSDP's XSDT address, an SDT header's length, signature and OEM table ID, the XSDT's entries, the MCFG's allocation entries as `EcamLocation` windows, and the MADT's interrupt-controller structures as their type, offset and length (ACPI 6.5 § 5.2) |
| `dmar` | The DMAR's remapping structures: each DRHD unit and RMRR region, with the byte range of its device scopes (Intel VT-d 4.1 chapter 8) |
| `spcr` | The console UART's interface type, base address and interrupt |
| `fdt` | A blob's header, the structure block's tokens as an iterator of events (`Fdt::events`, `Fdt::events_at`), a property's value and its offset in the blob, the strings block, the `compatible` list match, and a `reg` property's first pair (Devicetree Specification 0.4 chapter 5) |

The crate reads the layouts and nothing of what they mean. Which interrupt line a MADT routes,
which unit translates a PCI function, which device-tree node is a PCI host bridge, and what a
device scope names are the consumer's. Every decoder reads a caller-mapped byte slice and refuses
what it cannot read whole: a table or structure that runs past its declared length, or past the
slice, ends the walk or yields nothing, never a panic.

The flattened device tree view refuses a blob whose structure block or strings block ends past its
`totalsize`, and a string it reads lies inside the strings block.

---

## Property, Fuzzing and Proofs

The contract of the decoders is one property over any input, `property::tables_holds`
([docs/testing.md](../../docs/testing.md#fuzzing) § Fuzzing, § Bounded verification). The input is
read as every table the crate decodes, and each check judges a decoder against a reading of the
table's layout written apart from the decoder's. Its drivers are the fuzz target
`firmware-tables` (`xtask/fuzz/targets`), which starts from the seeds under
`fuzz/firmware-tables/seeds/`; the replay of those seeds and any
`fuzz/firmware-tables/regressions/` in the crate's tests; and the Kani proofs in each decoder's
module, whose module comment states their bounds and what lies outside them.

---

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [docs/testing.md](../../docs/testing.md) | § Fuzzing, § Bounded verification: the property, the seeds and the proofs |
| [docs/device-management.md](../../docs/device-management.md) | devmgr's use of the tables: ECAM discovery, IOMMU discovery, the MADT's interrupt routing |

---

## Consumers

| Consumer | Use |
|---|---|
| [devmgr](../../services/devmgr/README.md) | `services/devmgr/firmware` interprets the decoded structures: the FADT, the MADT's overrides, I/O APICs and controller windows, the DMAR's device scopes, the device tree's ECAM nodes; it reads the RSDP, XSDT, MCFG and SPCR and the ECAM windows directly |
| [bootloader](../../core/boot/firmware/README.md) | Reads the same decoders to find the tables and the device tree it hands over |

---

## Summarized By

[shared/README.md](../README.md)
