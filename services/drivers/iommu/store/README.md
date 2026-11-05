# iommu/store

The table-page store every IOMMU driver builds its translation structures in (`iommu-store`): the
driver's `iommu_core::TableStore`, used by [`iommu-vtd`](../vtd/README.md) and
[`iommu-riscv`](../riscv/README.md).

- **Pages.** Zeroed 4 KiB pages, taken from memmgr in physically contiguous chunks of
  `CHUNK_PAGES` (`REQUIRE_CONTIGUOUS`), mapped writable into the driver, with each chunk's physical
  base read through `CAP_INFO_MEMORY_PHYS_BASE`, since a unit is programmed with physical
  addresses: the IOMMU driver is the one driver class that reads them
  ([#767](https://github.com/kottlerg/seraph/issues/767)'s named exception).
- **Ordering.** A zeroed page is fenced before it is handed out, and every table store before the
  next one and before the register write that makes a unit read it, so a unit never sees an entry
  before the table it points at.
- **Caches.** A driver whose units read memory past the processor caches gives the store a
  write-back function (`Flush::Writeback`; VT-d's `CLFLUSH` for a unit with `ECAP.C` clear), which
  every zeroed page and table store is written back with; for coherent units
  (`Flush::Coherent`) the fences alone suffice.
- **Lifetime.** No page is ever returned: a unit may walk any of them while translation stays on,
  so they stay with the driver for the boot, and past its death, since devmgr spawns the driver
  `CREATE_DMA_HOLD` and never releases the hold (docs/device-management.md
  [§ IOMMU Discovery and Programming](../../../../docs/device-management.md#iommu-discovery-and-programming)).

The crate calls memmgr and maps pages through the Seraph std runtime, so it builds only for the
Seraph targets, as a dependency of the driver binaries, and has no host tests; the walks over a
`TableStore` are host-tested in each family's library against heap stores.

---

## Source Layout

```
iommu/store/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs           # The Store: memmgr chunks, mapping, ordering, write-back
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | IOMMU discovery and programming |
| [docs/limits.md](../../../../docs/limits.md) | The chunk size |

---

## Summarized By

[services/drivers/README.md](../../README.md)
