# iommu/vtd

The VT-d IOMMU driver (`iommu-vtd`): the separate driver process that programs Intel VT-d
remapping units for devmgr. devmgr discovers each unit through the ACPI DMAR, delegates the
unit's register range to this driver, and drives it over `ipc::iommu_labels` from behind its DMA
endpoint, so device drivers keep the `devmgr_dma_labels` contract whichever IOMMU sits behind it
([docs/device-management.md](../../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming).

The driver runs the units in legacy translation mode:

- one root table per unit, one context table per bus a translated function sits on, and one
  domain per function;
- each domain gets second-level page tables 4 levels deep (48-bit IOVAs) where the unit's
  `SAGAW` offers it, and otherwise 3 levels deep (39-bit);
- invalidation goes through the context-command and IOTLB registers and completes before a
  request is answered;
- faults are polled from the fault recording registers.

The library (`iommu_vtd`) holds the register fields and the translation-structure encodings and
the page-table walk. They are host-tested, the walk over a heap-backed page store.

---

## Source Layout

```
iommu/vtd/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs           # Library root (host-tested register and table logic)
    ├── regs.rs          # Register offsets, CAP / ECAP / GCMD fields, invalidation commands,
    │                    #   fault-record decode
    └── tables.rs        # Root and context entries; second-level page tables over a page store
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | DMA safety model, DMA authorisation, IOMMU discovery and programming |

---

## Summarized By

None
