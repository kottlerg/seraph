# shared/driver-binding

Driver declarations and the resource-list bootstrap of driver binding, encoded and decoded once
for the driver and devmgr.

`no_std` with `alloc`, since a driver decodes its resource list onto its heap, and host-tested;
it depends on `shared/ipc`, `shared/syscall`, `abi/process-abi`, and `abi/syscall`. It provides:

- **The declaration** (`decl`): the source form a driver writes (`Declaration`), its compile-time
  encoding into the note descriptor (`encode`), and the decoded form devmgr reads (`DriverDecl`,
  `decode`). The descriptor is a version header and a list of kind, length, and payload fields:
  name, class, match keys (a PCI vendor and device, a PCI class under a mask, an ACPI `_HID` or
  `_CID`, an SPCR interface type, a platform key, an IOMMU family key, `boot-framebuffer`),
  instance limit, interrupt need, DMA, DMA address width, physical access, withdrawal reset, and
  priority tier.
  Every field has a fixed bound, and a descriptor that breaks one, repeats a field, or carries an
  unknown kind is rejected whole (`DeclError`). The wire format is specified in `src/decl.rs`.
- **The note** (`note`): the `driver_declaration!` macro, which places one `seraph`-owned note in
  the `.note.seraph.driver` section (`DRIVER_NOTE_SECTION`) of the driver binary. devmgr locates
  it with `shared/elf`'s `find_note` or `find_note_streaming`.
- **The resource list** (`resources`): the bootstrap devmgr delivers a driver it binds to a
  device. Each non-terminal round carries one resource, its kind in `data[0]`: `Mmio` (the cap,
  its PCI BAR index or none, physical base, bytes, and offset in the BAR), `IoPort` (the cap,
  base, and count), or `Interrupt` (one cap per vector, its kind `Wired`, `Msi`, or `MsiX`, the
  first vector, and the `SYS_IRQ_REGISTER` mode). The terminal end round carries the endpoint
  slots `SLOT_SERVICE`, `SLOT_DEVMGR_QUERY`, and `SLOT_DMA`, packed by
  `ipc::bootstrap::pack_slots`. devmgr builds each round with `Round` (`mmio`, `mmio_at`,
  `io_port`, `interrupts`, `end`); a driver receives the list with `receive`, which decodes
  each round into a `ResourceList` on its heap (`absorb`) and deletes every delivered cap of a
  list it refuses or has no room for. `PlatformDelivery::from_list` reads the list a platform
  record's bind delivers: one register resource (`Mmio` or `IoPort`), an optional wired line,
  and the endpoints.

The crate names standards and the system's own structure only: no driver, device, or device
class appears in it, so it does not grow with the drivers a deployment ships
([docs/driver-binding.md](../../docs/driver-binding.md#principle) § Principle). No stability
obligation; internal code reuse only.

---

## Source Layout

```
shared/driver-binding/
├── Cargo.toml                  # Workspace member; no_std library
├── README.md
└── src/
    ├── lib.rs                  # Crate root; DRIVER_NOTE_SECTION
    ├── decl.rs                 # Declaration source form, encoding, bounds, and decoding
    ├── note.rs                 # The driver note and the driver_declaration! macro
    └── resources.rs            # The resource-list bootstrap: rounds, receive, decode
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/driver-binding.md](../../docs/driver-binding.md) | Declarations, their bounds, matching, binding, and withdrawal |
| [services/devmgr/docs/responsibilities.md](../../services/devmgr/docs/responsibilities.md) | The running bind path and the delivery of the resource list |
| [shared/elf/README.md](../elf/README.md) | `find_note`, which locates the declaration note |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[PCI Enumeration](../../services/devmgr/docs/pci-enumeration.md),
[devmgr Responsibilities and Capabilities](../../services/devmgr/docs/responsibilities.md)
