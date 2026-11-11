# Driver Binding

The data-driven model by which devmgr enumerates devices, matches each to a driver that
declares it, binds the two, and serves the bound driver to consumers by device class.

Implementation status: everything below is design intent; not yet implemented
([#165](https://github.com/kottlerg/seraph/issues/165)). devmgr binds its drivers today through
one hardcoded spawn path per driver and serves them through one query label per class, as
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities specifies; that document stays authoritative for the running system until
the phases of #165 replace it.

---

## Principle

A module declares what it serves; the always-shipped core discovers the declaration. No
resident binary that every deployment ships (init, devmgr, vfsd, svcmgr, procmgr, memmgr) MAY
carry knowledge of one particular driver or filesystem driver: its name, its binary path, its
match keys, its device addresses, or a code path written for it alone. A deployment then ships
only the drivers it needs, and a driver it does not ship costs every resident binary nothing.

What the core keeps is knowledge of standards and of the system's own structure:

- bus and firmware standards: PCI configuration space, the VirtIO PCI transport, the ACPI
  tables devmgr reads, and the IOMMU table formats (DMAR, RIMT);
- the fixed bootstrap set and its order (init, memmgr, procmgr, devmgr, vfsd, svcmgr;
  [process-lifecycle.md](process-lifecycle.md));
- the binding and query mechanism: carving, DMA authorisation, the settle, withdrawal, and
  the class-keyed registry query, in which a device class is an opaque name the core does not
  interpret (§ Device Classes).

No shared crate, no resident binary's source, and no central table grows with the number of
drivers. Adding a driver is adding its binary; adding a device class is adding its protocol
and its class file (§ Device Classes). The build (`xtask`) and the source tree grow with each
module, and MAY list modules by name: they build packages, and a deployment chooses which to
install.

---

## Device Records

devmgr's bus enumerators turn what the platform describes into device records. An enumerator
knows its bus or firmware standard and no driver.

| Enumerator | Source | Identity keys |
|---|---|---|
| PCI | Every ECAM window ([pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md)) | Vendor, device, subsystem vendor and device, class, subclass, programming interface, revision |
| ACPI namespace | Static `Device` objects of the DSDT and SSDTs whose `_HID`, `_CID`, `_UID`, and `_CRS` are `Name` objects | `_HID`, each `_CID` |
| ACPI SPCR | The Serial Port Console Redirection table | The console UART's interface type |
| Boot framebuffer | The bootloader's framebuffer description | One fixed key, `boot-framebuffer` |
| Platform description | A per-machine data table in the boot bundle, chosen by the ACPI OEM table ID | The key each entry names |

devmgr runs no AML: the namespace enumerator reads only `Device` objects whose identifying and
resource objects are static `Name` objects, and skips one that defines any of them as a
`Method`. The platform description covers a device the machine's tables do not describe in
that form; it is data, so a new machine adds a table, not devmgr code.

A record carries the device's resources, typed:

| Resource | Fields |
|---|---|
| `Mmio` | PCI BAR index (PCI only), physical base, size |
| `IoPort` (x86-64) | Base port, count |
| `Interrupt` | Kind and vector count: `Wired` (one line: its GSI or PLIC/APLIC source, its trigger and polarity mode, whether devmgr may share it) or `MessageSignaled` (`Msi` or `MsiX`, the vectors the function supports) |
| `Dma` | The requester ID the IOMMU scope is resolved against |
| `Config` (PCI) | The function's configuration page, which devmgr keeps and delegates to no driver |

The interrupt resource is never one GSI: a record states its kind and a count, so a function
that offers several message-signaled vectors is described as such, and the binding delivers one
capability per vector it grants. The kernel's minting of message-signaled targets is
[#325](https://github.com/kottlerg/seraph/issues/325).

---

## Driver Declarations

Every driver binary carries its declaration in an ELF note section, `.note.seraph.driver`,
located by the same section-header walk `shared/elf` performs for the stack-size note
(`.note.seraph.stack`). One shared `no_std` crate, host-tested, encodes the declaration in
the driver and decodes it in devmgr. The binary is the single carrier: a boot-bundle module
and a driver on the root filesystem are declared the same way, a package is one file that is
installed, updated, and removed by itself, a declaration cannot drift from the binary it
describes, and a signature over the binary would cover its declaration with it.

| Field | Meaning |
|---|---|
| Name | The driver's name in log lines |
| Match entries | One or more keys of § Device Records: a PCI vendor and device, or a PCI class, subclass, and programming interface under a mask; an ACPI `_HID` or `_CID`; an SPCR interface type; a platform key |
| Class | The name of the device class the driver serves (§ Device Classes) |
| Instance limit | The most devices of its match the driver is bound to; absent means every one |
| Interrupt need | None, optional, or required, and for a message-signaled capable driver the vector count it requests |
| DMA | Whether the device performs DMA: the driver is then created `CREATE_PINNED` and `CREATE_DMA_HOLD` and given a DMA capability ([device-management.md](device-management.md#dma-authorisation) § DMA Authorisation) |
| Withdrawal reset | How devmgr stops the device when it withdraws the driver: the VirtIO `device_status` reset, a PCI Express Function Level Reset, or none |
| Priority tier | Boot (`sched_policy::BOOT_DRIVER_PRIORITY`) or auxiliary (`AUX_DRIVER_PRIORITY`) |

A declaration names standards only: the withdrawal reset and the interrupt kind are methods
devmgr implements once, for every driver that declares them.

devmgr collects declarations from two places:

- **Boot modules.** init forwards every boot module outside the bootstrap set to devmgr
  untagged, and devmgr reads each module's note. A module without a valid note is logged and
  released.
- **The drivers directory.** On `SET_DRIVERS_DIR` devmgr lists `/services/drivers/`
  (`NS_READDIR`, so svcmgr sends the subtree cap with `READDIR` beside `LOOKUP | READ`) and
  reads the note of each entry. A binary whose declaration matches no recorded device is not
  loaded.

### Declaration Bounds

A declaration is untrusted input to devmgr, and it is as trusted as the authority that
installed its binary: whoever can write `/services/drivers/` or compose the boot bundle can
already install a driver devmgr hands hardware to. The bounds below make sure a declaration
never claims more than its device and the system's policy give it:

- **Resources.** devmgr carves only from the device record. A declaration selects among the
  record's resources; it cannot name an address, a port, an interrupt, or a DMA right the
  record lacks, so a DMA declaration for a record with no `Dma` resource gets no DMA
  capability.
- **No preemption.** A bind pass binds only unbound records, and the boot pass runs first. A
  drivers-directory declaration cannot take a device a boot driver holds, however specific
  its key.
- **Source.** The boot priority tier, and a class whose class file marks it boot-only
  (§ Device Classes), are accepted only from a boot-bundle declaration. A drivers-directory
  declaration of a boot-only class is logged and ignored, and a drivers-directory driver runs
  at the auxiliary tier.
- **Class.** Declaring a class decides which of that class's consumers talk to the driver; it
  grants no access, since the class's policy is configuration (§ Device Classes). Consumers
  treat a driver's data as untrusted.
- **Form.** Every field has a fixed bound (the match entries, the name's length, the vector
  count). A declaration that exceeds one, carries an unknown field kind, or fails to decode is
  rejected whole and logged. devmgr's reads of a candidate binary are bounded too: the ELF
  header, the section header table, and the one note.

---

## Matching

devmgr builds one match table from the declarations it has collected, and extends it when the
drivers directory arrives. For each unbound device record it takes the most specific match:
an exact PCI vendor and device over a PCI class, an ACPI `_HID` over a `_CID`. Two
declarations equally specific for one device are a conflict: devmgr logs it and binds neither.
A driver's instance limit counts its devices in record order (PCI segment, bus, device,
function; then the firmware's table order). A device no declaration matches stays recorded
and unbound, and a later declaration (a driver installed afterwards, or a hotplug pass) can
still match it.

The IOMMU driver is matched like any other, by its declaration's key for the remapping
hardware devmgr found (the DMAR's units, the RIMT's IOMMUs), and is bound before any device
that declares DMA, as [device-management.md](device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming orders.

---

## Binding

`bind(device, driver)` is the one path that starts a driver, at boot, at `SET_DRIVERS_DIR`,
and for a hot-added device:

1. Carve one capability per resource of the record the declaration needs: each `Mmio` from
   the apertures, each `IoPort` from devmgr's port capability, the interrupt capabilities the
   declaration's need and the record's kind allow, and keep the `Config` page.
2. For a DMA declaration, give the device its DMA grant, confining it where an IOMMU unit
   translates it.
3. Create the driver through procmgr with the flags and priority its declaration implies,
   within § Declaration Bounds, from its boot module or its file.
4. Deliver the capabilities over the bootstrap protocol as a self-describing resource list:
   each capability with its resource kind and its fields, then the service endpoint, the
   devmgr query capability, and the DMA capability. One delivery shape serves every driver,
   in place of today's VirtIO and simple-device round shapes.
5. Record the driver in the pass's settle batch; the settle, the serving of ready drivers, and
   the withdrawal of the rest are unchanged
   ([responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
   § Responsibilities).

Each bind pass (the boot pass over boot-module drivers, the pass at `SET_DRIVERS_DIR`, a
hotplug pass) is one settle batch. Withdrawal applies the reset the declaration names, after
the DMA and Bus Master Enable steps that apply to every DMA-capable device.

---

## Device Classes

A device class is a name (`block`, `serial`, `audio`) shared by the drivers that serve one
service protocol and the consumers that speak it. devmgr does not interpret the name: it
interns each class name a declaration or a class file gives it into a bounded runtime table,
and no source or shared crate lists the classes.

A class's access policy is configuration, set where every other access is set, never by a
driver:

- **Class file.** `/config/devmgr/classes/<name>.class`, in the `.svc` grammar
  ([service-definitions.md](../services/svcmgr/docs/service-definitions.md#grammar)), gives
  the class's name, the client verb mask devmgr stamps on the SEND it hands out, and whether
  the class is boot-only (§ Declaration Bounds).
- **Publication.** For each class file, svcmgr asks devmgr, over a privileged label that only
  svcmgr and init hold, for a registry SEND whose badge carries the class's slot and its verb
  mask, and publishes it seed-only as `devmgr.class.<name>`. A service reaches a class only
  when its `.svc` `seed` line names that publication. init mints the classes the bootstrap set
  needs before svcmgr runs (block for vfsd, serial for logd) the same way, from the boot
  bundle's copies of their class files.
- **Badge.** One generic badge layout, defined once beside the registry protocol, carries the
  slot and the mask. It replaces the per-class authority bits (`BLOCK_DEVICE_AUTHORITY`,
  `DEBUG_PORT_AUTHORITY`, `TEST_LABEL_AUTHORITY`).

Every driver of a class is served under its class file's policy, so no declaration can widen
access to its class, and a deployment that installs no class file for a class serves it to no
one.

One registry label, `QUERY_DEVICE`, replaces the per-class `QUERY_*_DEVICE` labels. It carries
an instance ordinal and takes the class from the caller's badge; devmgr answers as the
per-class queries answer today: the SEND on the served driver at that ordinal, stamped with
the badge's verb mask, `WITHDRAWN` at a withdrawn driver's ordinal, and `NO_DEVICE` past the
last served driver of the class or before the pass that binds it has settled. Ordinals count
the served drivers of the class in record order and are fixed once its pass settles. A
declared class with no class file, and a class file no declaration serves, are logged at
`SET_DRIVERS_DIR`.

The class's protocol (its labels, message layouts, and verb bit positions) is the contract
between its drivers and its consumers, and is the one artefact both compile against. It is
per class, never per driver, and neither devmgr nor svcmgr reads it. The existing protocols
live in `shared/ipc`; a new class's protocol SHOULD be a crate of its own, so adding a class
edits no existing crate.

---

## Hotplug

Hotplug adds no binding path: an enumerator that learns of an added device appends its
record and runs a bind pass over it; one that learns of a removed device withdraws its
driver, which leaves a tombstone at its ordinal. The event sources are specified in
[services/devmgr/docs/hotplug.md](../services/devmgr/docs/hotplug.md).

---

## Test Fixtures

No test-only spawn label survives the binding redesign: a fixture driver is bound through
`bind(device, driver)` against a device the test launch attaches, like any driver, and a test
reaches it through `QUERY_DEVICE` on the test class, whose class file only a test deployment
installs. The fixtures and labels it
retires are listed on [#165](https://github.com/kottlerg/seraph/issues/165).

---

## Summarized By

[Architecture Overview](architecture.md),
[PCI Enumeration](../services/devmgr/docs/pci-enumeration.md)
