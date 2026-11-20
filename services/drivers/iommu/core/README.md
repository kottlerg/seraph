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
  translates every function of its segment no other unit names, whether the instance is a restart
  that adopts the unit (`FLAG_ADOPT`), its anchor, one Memory cap, and its scope, each function or
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
  keeps its first domain; domain ID 0 is never given. An `ATTACH` names the handle (`data[3]`) and
  the domain ID (`data[4]`) to take, 0 for either to have the driver pick the handle or the lowest
  free ID, and replies the handle and the domain ID (`data[1]`); a handle or an ID another domain
  holds, or one the unit does not have, is refused. A unit whose backend times out is treated as
  failed and refuses every later request.
- **Interrupt remapping.** `REMAP_SETUP` sets up one remapping table for every unit, of a power of
  two of entries up to `MAX_REMAP_ENTRIES`, once (0 entries turns it off again), in the zeroed,
  physically contiguous memory of the Memory cap devmgr gives in `caps[0]` (at least 16 bytes an
  entry), which the backend keeps, and replies whether
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
  blocked. A driver that dies after a unit's translation is on leaves the unit translating through
  its tables, which devmgr's restarted instance adopts (Restart below).
- **Restart.** A driver devmgr restarts starts with `FLAG_ADOPT` on its units (`Start::Adopt`,
  `Units::adopting`), and each unit must be translating from its anchor, or the backend refuses
  it and the driver does not report ready. The backend leaves translation, and on VT-d interrupt
  remapping, on, replaces only the unit's queues, and builds every attach under a staging root of
  its own, so the unit keeps translating through the dead instance's tables. devmgr replays its
  records in: each `ATTACH` names the handle and domain ID the function held, each `REMAP_SETUP`
  gives the table the units already remap from, which the backend adopts as it stands, and a
  `REMAP_SET` is recorded. `COMMIT` (`Backend::commit`), accepted once from a driver that
  adopted its units, copies each staged root entry into the unit's anchor by the write rule of
  `anchor.rs`, then invalidates each unit's translation caches, draining the device accesses in
  flight; on VT-d it then makes not present each remapping entry not set since the adoption. The
  rule orders each entry's stores so a unit reads the old or the new entry, both holding the same
  ranges under the same domain ID: a differing word alone is one aligned 64-bit store, a valid
  entry made not valid stores its valid word first, a new one its valid word last, and an entry
  that differs in several words is made not valid and invalidated first. From the reply on no unit
  reaches a page of the dead instance's. A boot instance builds directly beneath the anchor.

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
    ├── anchor.rs        # The write rule a restarted driver's commit copies a staged root entry
    │                    #   into an anchor by
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
