# iommu/riscv

The RISC-V IOMMU driver (`iommu-riscv`): the separate driver process that programs RISC-V IOMMUs
(RISC-V IOMMU Architecture Specification v1.0) for devmgr. devmgr discovers each IOMMU that is a PCI
function through the ACPI RIMT, turns on the function's memory decode and bus mastering, moves the
first page of its BAR 0, which holds every register, to this driver, and drives it over
`ipc::iommu_labels` from behind its DMA endpoint, so device drivers keep the `devmgr_dma_labels`
contract whichever IOMMU sits behind it
([docs/device-management.md](../../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming). It is riscv64 only, and ships as a boot module, since it must
confine the root disk before the disk's driver maps a ring; it carries a declaration in the ELF note
section `.note.seraph.driver` (IOMMU family `rimt`), which devmgr matches against the IOMMU family
record in a pass of its own and starts with the IOMMU bootstrap rounds, not the resource list. The
bootstrap, the request checks, and the fault queue are [`iommu-core`](../core/README.md)'s, and the
table pages [`iommu-store`](../store/README.md)'s; this crate is the RISC-V IOMMU `Backend`.

The driver runs each IOMMU with first-stage translation only, the second stage Bare, since the
system runs no guests:

- each IOMMU gets a one-page command queue (256 commands) and a one-page fault queue (128 records),
  their interrupts left disabled, and a device directory deep enough for every 16-bit PCI
  requester ID (two levels with 32-byte device contexts, three with the 64-byte ones an IOMMU
  offering `MSI_FLAT` uses), tried in that order and kept at the first depth the IOMMU retains;
- at setup an IOMMU left translating goes Off first, the queues are stopped and reprogrammed, every
  cached directory and translation entry is invalidated, and only then does `ddtp` select the empty
  directory, from which on every device the IOMMU translates reaches nothing until it is attached;
- each domain gets Sv48 page tables where the IOMMU offers them and Sv39 otherwise; a device may
  issue IOVAs one bit narrower than the format (47 or 38 bits), since a zero-extended address with
  the format's top bit set is not a valid virtual address;
- `ATTACH` writes the device's context (`tc.V`, the `iosatp` root, `ta.PSCID` as the domain ID),
  its valid word last, and invalidates its directory entry; `MAP` writes leaf entries readable,
  user-level (every device access without a supervisor process ID is), and accessed, and writable
  and dirty for a write mapping, since the IOMMU's own A/D updating stays off; `UNMAP` invalidates
  the page or the domain, and `BLOCK` clears the context's valid bit and invalidates its directory
  entry and its domain, each ordering the device accesses before it (`IOFENCE.C` with `PR` and
  `PW`); a new valid entry needs no invalidation, since the IOMMU caches no invalid one;
- every command batch ends in an `IOFENCE.C` and is polled to completion within
  `COMMAND_TIMEOUT`, so the reply follows the hardware; a command error stops the queue and fails
  the IOMMU, as a timeout does; batching is [#772](https://github.com/kottlerg/seraph/issues/772);
- each register write is ordered after every structure store before it and before the next
  register write, and the fault records after the tail that publishes them and before the head
  that frees their slots, with the [`mmio`](../../../../shared/mmio/README.md) barriers, since on
  RISC-V a memory fence orders no device access; the fault queue, which the IOMMU writes, is read
  through a raw pointer only;
- faults are polled from the fault queue, since the IOMMU's interrupts are message-signalled
  ([#325](https://github.com/kottlerg/seraph/issues/325)), and reported with their 12-bit `CAUSE`
  and the faulting page;
- a setup that fails, or a driver that cannot report ready, returns every IOMMU to Bare, passing
  DMA through untranslated, so devmgr runs it unconfined.

The IOMMU reads its directory, tables, and queues coherently with the processor caches, as the
platform's PCI host declares (`dma-coherent`) and QEMU's `riscv-iommu-pci` does; the specification
states no coherence rule, and a platform whose IOMMU reads past the caches would need each table
write cleaned from them, which the driver does not do. MSI translation (`msiptp`) stays Off: once
devices signal MSIs ([#325](https://github.com/kottlerg/seraph/issues/325)), their writes to an
IMSIC are DMA through the IOMMU and need a mapping or MSI translation in each domain.

The library (`iommu_riscv`) holds the register fields, the commands, the fault record, the device
context, and the directory and page-table walks. They are host-tested, the walks over a
heap-backed `iommu_core::TableStore`.

---

## Source Layout

```
iommu/riscv/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs           # Library root (host-tested register, command, and table logic)
    ├── regs.rs          # Register offsets and fields, ddtp and queue encodings, commands,
    │                    #   fault-record decode
    ├── tables.rs        # Device directory and context; first-stage tables over a page store
    ├── main.rs          # Driver binary: bootstrap, register mapping, setup, the two loops
    └── backend.rs       # The RISC-V IOMMU Backend: setup, attach, map, unmap, block, fault poll
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../../docs/device-management.md) | DMA safety model, DMA authorisation, IOMMU discovery and programming |
| [docs/limits.md](../../../../docs/limits.md) | The command bound, the queue sizes, and the IOVA width |

---

## Summarized By

[services/drivers/README.md](../../README.md)
