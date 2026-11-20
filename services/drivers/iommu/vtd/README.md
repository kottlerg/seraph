# iommu/vtd

The VT-d IOMMU driver (`iommu-vtd`): the separate driver process that programs Intel VT-d remapping
units for devmgr. devmgr discovers each unit through the ACPI DMAR, delivers the unit's register
range and its anchor to this driver in its resource list, keeping its own register cap for a
restart, and drives it over `ipc::iommu_labels`
from behind its DMA endpoint, so device drivers keep the `devmgr_dma_labels` contract whichever
IOMMU sits behind it
([docs/device-management.md](../../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming). It is x86-64 only, and ships as a boot module, since it must
confine the root disk before the disk's driver maps a ring; it carries a declaration in the ELF note
section `.note.seraph.driver` (IOMMU family `dmar`), which devmgr matches against the IOMMU family
record in a pass of its own, delivering it the units in its resource list. The delivery decode,
the request checks, and the fault queue are [`iommu-core`](../core/README.md)'s; this crate is the
VT-d `Backend`.

The driver runs the units in legacy translation mode:

- one root table per unit, one context table per bus a translated function sits on, and one
  domain per function;
- each domain gets second-level page tables 4 levels deep (48-bit IOVAs) where the unit's
  `SAGAW` offers it, and otherwise 3 levels deep (39-bit);
- at a boot instance's setup a unit gets queued invalidation on (one page of descriptors), an empty
  root table (its anchor), a global context-cache and IOTLB invalidation, and then translation on,
  with any translation, interrupt remapping, or queued invalidation the firmware left on turned off
  first and fault events masked; a unit without queued invalidation is not set up, since the driver
  invalidates no other way;
- `ATTACH` writes the function's context entry, `MAP` and `UNMAP` its second-level entries, and
  `BLOCK` clears its context entry, each followed by the invalidation it needs (an IOTLB
  invalidation after `MAP` only in caching mode), so the reply follows the hardware;
- every invalidation is a batch of queued descriptors ended by a wait descriptor whose status
  write is polled within `INVALIDATION_TIMEOUT`; a queue error counts as the unit failing; batching
  invalidations across requests is [#772](https://github.com/kottlerg/seraph/issues/772);
- `REMAP_SETUP` takes the one interrupt remapping table devmgr allocates (physically contiguous, in
  `caps[0]`), which the backend keeps and every unit points at, and turns interrupt remapping on
  with compatibility-format interrupts blocked, with 32-bit destinations when asked and every unit
  offers them (`ECAP.EIM`); `REMAP_SET` writes an entry (fixed delivery, physical destination, the
  requester verified by its full source ID) and `REMAP_CLEAR` clears one, each followed by an
  interrupt-entry-cache invalidation of that entry on every unit; an entry that already holds what
  `REMAP_SET` asks for is left untouched, so a repeated set opens no gap in a live source's
  delivery, and a present entry with other contents is cleared and invalidated before it is
  rewritten, so no unit reads one whose two words disagree;
- a unit whose page walks do not snoop the caches (`ECAP.C` clear, as QEMU's `intel-iommu`
  reports) gets every table write flushed from them before it is used;
- faults are polled from the fault recording registers, since fault events are message-signalled;
  an interrupt remapping fault reports the handle the blocked interrupt named in place of an
  address.

Restart. A driver devmgr restarts adopts each unit (`FLAG_ADOPT`): the unit must be translating from
its anchor in legacy mode, and the backend waits for the dead instance's invalidation queue to
drain and replaces it with its own (`QIE` off and on again, translation and interrupt remapping
left on), then builds devmgr's replayed domains under a staging root table. `REMAP_SETUP` requires
each unit to remap from the table given, in the destination width a setup would give, and adopts the
table with its entries as they stand; `REMAP_SET` and `REMAP_CLEAR` record the entry they touch.
`COMMIT` copies each staged root entry into the anchor, one aligned 64-bit store (a legacy root
entry's upper word is reserved zero, and the context table it names holds the same domain IDs and
ranges), runs the context-cache and then the IOTLB global invalidations, draining reads and writes,
and makes not present every remapping entry not set since the adoption. A boot instance builds
directly beneath the anchor.

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
ever returned, and devmgr spawns the driver `CREATE_DMA_HOLD` and releases a dead instance's hold
only once a restarted instance has committed (it keeps each instance's release token), since a unit
may walk any of them while translation stays on.

The library (`iommu_vtd`) holds the register fields, the translation-structure, queued-invalidation,
and interrupt-remapping encodings, and the page-table walk. They are host-tested, the walk over a
heap-backed `iommu_core::TableStore`.

---

## Source Layout

```
iommu/vtd/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs           # Library root (host-tested register and table logic)
    ├── regs.rs          # Register offsets, CAP / ECAP / GCMD fields, fault-record decode
    ├── queue.rs         # Queued-invalidation descriptors and queue register values
    ├── remap.rs         # Interrupt remapping table entries and the IRTA value
    ├── tables.rs        # Root and context entries; second-level page tables over a page store
    ├── main.rs          # Driver binary: bootstrap, register mapping, setup, the two loops
    ├── backend.rs       # The VT-d Backend: unit setup, attach, map, unmap, block, interrupt
    │                    #   remapping, fault poll
    └── arch/            # Cache-line flushing for a unit that does not snoop (x86_64; a
                         #   documented no-op on riscv64, which builds no VT-d driver)
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | DMA safety model, DMA authorisation, IOMMU discovery and programming |
| [docs/limits.md](../../../../docs/limits.md) | The invalidation bound, the queue size, and the remapping table's bound |

---

## Summarized By

[services/drivers/README.md](../../README.md)
