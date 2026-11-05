# iommu/core

The family-independent half of every IOMMU driver (`iommu-core`), a library each family's
driver binary links: the bootstrap devmgr serves it, the `ipc::iommu_labels` service with its
per-domain checks, the polled fault queue, and the `Backend` trait the family implements. A
family's driver is its `main` and its `Backend`; VT-d's is
[`iommu-vtd`](../vtd/README.md). The split, and devmgr's side of it, are specified in
[docs/device-management.md](../../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming.

- **Bootstrap.** One round per remapping unit, in unit-index order: the unit's register `Mmio`
  cap, its PCI segment, whether it translates every function of its segment no other unit names,
  the pages its registers span, and its scope, each function or bridged bus range devmgr resolved
  from the firmware's description of it. Then a terminal round with the driver's service endpoint
  and its devmgr query cap. The driver reads no firmware table.
- **Service.** Every request carries `IOMMU_LABELS_VERSION`. Before the backend runs, the service
  checks the unit or domain the request names, that an `ATTACH`'s requester ID is one the unit
  translates (the first unit whose scope names it, else its segment's catch-all unit), that a
  `MAP`'s cap is a Memory cap with the rights its access needs, that a range is page-aligned,
  nonempty, within the unit's width, and clear of the domain's other ranges, and the bounds on
  domains and ranges ([docs/limits.md](../../../../docs/limits.md)). It keeps a mapped cap while
  its range is installed and deletes it at `UNMAP`, at `BLOCK`, or at once on a refusal. A
  function attached twice keeps its first domain; domain ID 0 is never given. A unit whose
  backend times out is treated as failed and refuses every later request.
- **Faults.** A thread of the driver's own polls the units' fault records every `FAULT_POLL_MS`
  into a bounded queue, and `TAKE_FAULTS` polls once more and hands devmgr the oldest.
- **Setup.** The driver programs every unit empty and turns translation on before it reports
  ready; a unit that fails turns every unit off again, so a driver whose setup fails leaves no
  device blocked. A driver that dies after a unit's translation is on leaves that unit blocking.

The receive loop and the poll loop reach the one service through a lock the driver supplies, held
for one request or one poll. A request that needs table pages the store lacks takes them from memmgr
under it, the one IPC made under the lock, which the poll then waits out. Everything but the two
loops is host-tested over a fake backend.

---

## Source Layout

```
iommu/core/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs           # Crate root: the Backend trait, its errors, a unit's limits
    ├── bootstrap.rs     # Unit and endpoint rounds, scope words, the unit lookup
    ├── faults.rs        # The bounded queue of polled faults
    └── service.rs       # iommu_labels handling, domain records, the receive and poll loops
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | DMA safety model, DMA authorisation, IOMMU discovery and programming |
| [docs/limits.md](../../../../docs/limits.md) | The units, scopes, domains, ranges, and fault-queue bounds |

---

## Summarized By

[services/drivers/README.md](../../README.md)
