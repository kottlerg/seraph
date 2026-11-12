# iommu/store

The table-page store every IOMMU driver builds its translation structures in (`iommu-store`): the
driver's `iommu_core::TableStore`, used by [`iommu-vtd`](../vtd/README.md) and
[`iommu-riscv`](../riscv/README.md).

- **Pages.** Zeroed 4 KiB pages, taken from memmgr in physically contiguous chunks of
  `CHUNK_PAGES` (`REQUIRE_CONTIGUOUS`), mapped writable into the driver, with each chunk's physical
  base read through `CAP_INFO_MEMORY_PHYS_BASE`, since a unit is programmed with physical
  addresses: the IOMMU driver is the one driver class that reads them. devmgr spawns it
  phys-class, so its grants carry the Memory `Phys` right the read needs
  ([docs/device-management.md](../../../../docs/device-management.md#physical-addresses)
  § Physical Addresses). A structure a unit reads whole from its first page's address (VT-d's
  interrupt remapping table) takes a contiguous chunk of its own size (`Store::alloc_contiguous`),
  every page of it handed out at once, so the chunk single pages are drawn from stays the current
  one.
- **Ordering.** A zeroed page is fenced before it is handed out, and every table store before the
  next one, so a unit never sees an entry before the table it points at. The driver's register
  write that makes a unit read them supplies the memory-to-device barrier (`mmio` on riscv64; the
  fence before each VT-d register write on x86-64).
- **Device-written pages.** A page the unit itself writes (the RISC-V IOMMU's fault queue, the
  VT-d invalidation wait's status word) is read only through a raw pointer (`Store::page_ptr`),
  never through a reference.
- **Caches.** A driver whose units read memory past the processor caches gives the store a
  write-back function (`Flush::Writeback`; VT-d's `CLFLUSH` for a unit with `ECAP.C` clear), which
  every zeroed page and table store is written back with; for coherent units
  (`Flush::Coherent`) no write-back is needed, the store's fences and the driver's register
  barriers ordering the writes.
- **Lifetime.** No page is ever returned: a unit may walk any of them while translation stays on,
  so they stay with the driver for the boot, and past its death, since devmgr spawns the driver
  `CREATE_DMA_HOLD` and never releases the hold, deleting its release token at the spawn
  (docs/device-management.md
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
