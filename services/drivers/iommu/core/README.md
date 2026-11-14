# iommu/core

The family-independent half of every IOMMU driver (`iommu-core`), a library each family's
driver binary links: what the driver takes from the resource list devmgr delivers it, the
`ipc::iommu_labels` service with its per-domain checks, the polled fault queue, the `TableStore`
the family's translation structures are built in, and the `Backend` trait the family implements.
A family's driver is its `main` and its `Backend`: VT-d's is [`iommu-vtd`](../vtd/README.md)
and the RISC-V IOMMU's is [`iommu-riscv`](../riscv/README.md), both building their tables in the
pages of [`iommu-store`](../store/README.md). The split, and devmgr's side of it, are specified in
[docs/device-management.md](../../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming.

- **Delivery.** The driver receives the resource list of `driver_binding::resources`
  ([docs/driver-binding.md](../../../../docs/driver-binding.md#matching) § Matching): one group
  per remapping unit, in unit-index order, each the unit's round (its PCI segment, whether it
  translates every function of its segment no other unit names, and its scope, each function or
  bridged bus range devmgr resolved from the firmware's description of it), then the unit's
  register `Mmio` range and, when devmgr gives it one, its fault interrupt; then the end round
  with the driver's service endpoint and its devmgr query cap. `Delivery::from_list` refuses any
  other shape: no unit or more than `MAX_IOMMU_UNITS`, a resource before the first unit, a unit
  without exactly one register range of 1 to `MAX_UNIT_REGISTER_PAGES` whole pages, an `IoPort`,
  more than one interrupt per unit, a missing endpoint, or a DMA capability. The driver reads no
  firmware table.
- **Service.** Every request carries `IOMMU_LABELS_VERSION`. Before the backend runs, the service
  checks the unit or domain the request names, that an `ATTACH`'s requester ID is one the unit
  translates (the first unit whose scope names it, else its segment's catch-all unit), that a
  `MAP`'s cap is a Memory cap with the rights its access needs, that a range is page-aligned,
  nonempty, within the unit's width, and clear of the domain's other ranges, and the bounds on
  domains and ranges ([docs/limits.md](../../../../docs/limits.md)). It keeps a mapped cap while its
  range is installed and deletes it at `UNMAP`, at `BLOCK`, or at once on a refusal. A
  `MAP_RESERVED` range, a firmware-reserved range devmgr names by its physical address, is installed
  at that address, read-write, with no cap; `UNMAP` refuses it and `BLOCK` withdraws it. A `MAP_MSI`
  page, an interrupt file devmgr names by its physical address, is installed the same way by the
  family's backend, under a bound of its own; VT-d's backend refuses it. A function attached twice
  keeps its first domain; domain ID 0 is never given. A unit whose backend times out is treated as
  failed and refuses every later request.
- **Interrupt remapping.** `REMAP_SETUP` sets up one remapping table for every unit, of a power of
  two of entries up to `MAX_REMAP_ENTRIES`, once (0 entries turns it off again), and replies whether
  its destinations are 32-bit; it is refused while the units translate more than one PCI segment,
  since an entry names its requester by a source ID with no segment; `REMAP_SET` and `REMAP_CLEAR`
  name an entry below the table's size, and a set's destination, vector (16 and above), trigger,
  and source ID are checked within their widths before the backend runs. The RISC-V IOMMU's
  backend refuses the setup, its MSIs being reached through `MAP_MSI`. A remapping command that
  times out fails the remapping, and every later remapping request is refused.
- **Faults.** A thread of the driver's own polls the units' fault records every `FAULT_POLL_MS`
  into a bounded queue, and `TAKE_FAULTS` polls once more and hands devmgr the oldest, each with
  the unit's reason code in 16 bits (VT-d's 8-bit fault reason, the RISC-V IOMMU's 12-bit
  `CAUSE`) and the faulting address, or the handle a blocked remapped interrupt named.
- **Table pages.** Every family's tables are 4 KiB pages of 64-bit words a unit reads by physical
  address. The family's walks run over a `TableStore`: the driver's is `iommu-store`, the host
  tests' a heap store.
- **Physical bases.** A `MAP` request carries a driver's frames, whose caps lack the Memory `Phys`
  right, so `KernelCaps` reads their physical bases presenting a credential: a page the driver
  takes from memmgr at startup (`KernelCaps::new`), which keeps the right because devmgr spawns
  the driver phys-class
  ([docs/device-management.md](../../../../docs/device-management.md#physical-addresses)
  § Physical Addresses).
- **Setup.** The driver programs every unit empty and turns translation on before it reports
  ready; a unit that fails turns every unit's translation off again (VT-d's translation enable
  cleared, a RISC-V IOMMU returned to Bare), so a driver whose setup fails leaves no device
  blocked. A driver that dies after a unit's translation is on leaves that unit blocking.

The receive loop and the poll loop reach the one service through a lock the driver supplies, held
for one request or one poll. Under it a request that needs table pages the store lacks takes them
from memmgr, a heap allocation may grow the heap (a memmgr call too), and a failure path may log;
the poll waits those calls out, and no call into devmgr is made under the lock. Everything but the
two loops is host-tested over a fake backend.

---

## Source Layout

```
iommu/core/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs           # Crate root: the Backend trait, its errors, Access, a unit's limits,
    │                    #   a remapping entry
    ├── delivery.rs      # What the driver takes from its resource list, the unit lookup
    ├── faults.rs        # The bounded queue of polled faults
    ├── service.rs       # iommu_labels handling, domain records, the receive and poll loops
    └── table.rs         # The TableStore every family's tables are built in
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | DMA safety model, DMA authorisation, IOMMU discovery and programming |
| [docs/limits.md](../../../../docs/limits.md) | The units, scopes, domains, ranges, remapping-table, and fault-queue bounds |

---

## Summarized By

[services/drivers/README.md](../../README.md)
