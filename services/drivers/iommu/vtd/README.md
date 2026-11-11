# iommu/vtd

The VT-d IOMMU driver (`iommu-vtd`): the separate driver process that programs Intel VT-d remapping
units for devmgr. devmgr discovers each unit through the ACPI DMAR, moves the unit's register range
to this driver, and drives it over `ipc::iommu_labels` from behind its DMA endpoint, so device
drivers keep the `devmgr_dma_labels` contract whichever IOMMU sits behind it
([docs/device-management.md](../../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming). It is x86-64 only, and ships as a boot module, since it must
confine the root disk before the disk's driver maps a ring; it carries a declaration in the ELF note
section `.note.seraph.driver` (IOMMU family `dmar`), which devmgr matches against the IOMMU family
record in a pass of its own and starts with the IOMMU bootstrap rounds, not the resource list. The
bootstrap, the request checks, and the fault queue are [`iommu-core`](../core/README.md)'s; this
crate is the VT-d `Backend`.

The driver runs the units in legacy translation mode:

- one root table per unit, one context table per bus a translated function sits on, and one
  domain per function;
- each domain gets second-level page tables 4 levels deep (48-bit IOVAs) where the unit's
  `SAGAW` offers it, and otherwise 3 levels deep (39-bit);
- at setup a unit gets an empty root table, a global context-cache and IOTLB invalidation, and
  then translation on, with any translation or queued invalidation the firmware left on turned
  off first and fault events masked;
- `ATTACH` writes the function's context entry, `MAP` and `UNMAP` its second-level entries, and
  `BLOCK` clears its context entry, each followed by the invalidation it needs (an IOTLB
  invalidation after `MAP` only in caching mode), so the reply follows the hardware;
- invalidation goes through the context-command and IOTLB registers (queued invalidation stays
  off) and is polled to completion within `INVALIDATION_TIMEOUT`; batching it is
  [#772](https://github.com/kottlerg/seraph/issues/772);
- a unit whose page walks do not snoop the caches (`ECAP.C` clear, as QEMU's `intel-iommu`
  reports) gets every table write flushed from them before it is used;
- faults are polled from the fault recording registers, since fault events are message-signalled
  ([#325](https://github.com/kottlerg/seraph/issues/325)).

The translation structures live in pages the driver takes from memmgr in physically contiguous
chunks (`REQUIRE_CONTIGUOUS`) and maps into itself, through the page store it shares with the
RISC-V IOMMU driver ([`iommu-store`](../store/README.md)), which writes each table store back from
the caches when a unit does not snoop them. It reads their physical bases, and those of
the frames each `MAP` installs, with `CAP_INFO_MEMORY_PHYS_BASE`: the units are programmed with
physical addresses, which makes the IOMMU driver the one driver class that reads them. devmgr
spawns it phys-class, so its grants carry the Memory `Phys` right, and it reads a driver's frames,
whose caps lack it, presenting a page of its own as the credential (`iommu_core::KernelCaps`; see
[docs/device-management.md](../../../../docs/device-management.md#physical-addresses)
§ Physical Addresses). No table page is
ever returned, and devmgr spawns the driver `CREATE_DMA_HOLD` and never releases it (it deletes the
hold's release token at the spawn), since a unit may walk any of them while translation stays on.

The library (`iommu_vtd`) holds the register fields, the translation-structure encodings, and the
page-table walk. They are host-tested, the walk over a heap-backed `iommu_core::TableStore`.

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
    ├── tables.rs        # Root and context entries; second-level page tables over a page store
    ├── main.rs          # Driver binary: bootstrap, register mapping, setup, the two loops
    ├── backend.rs       # The VT-d Backend: unit setup, attach, map, unmap, block, fault poll
    └── arch/            # Cache-line flushing for a unit that does not snoop (x86_64; a
                         #   documented no-op on riscv64, which builds no VT-d driver)
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | DMA safety model, DMA authorisation, IOMMU discovery and programming |
| [docs/limits.md](../../../../docs/limits.md) | The invalidation bound |

---

## Summarized By

[services/drivers/README.md](../../README.md)
