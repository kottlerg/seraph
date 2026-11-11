# Driver Binding

The data-driven model by which devmgr enumerates devices, matches each to a driver that
declares it, binds the two, and serves the bound driver to consumers by device class.

Implementation status: partly implemented
([#165](https://github.com/kottlerg/seraph/issues/165)); § Status names what is design intent;
not yet implemented.

---

## Status

Implemented: every driver binary but the test-only `test-fault` and `test-orphan` fixtures
carries its declaration (§ Driver Declarations); init forwards every boot module outside its
bootstrap set to devmgr untagged; devmgr reads the declarations of the boot modules and of the
drivers-directory entries, within § Declaration Bounds; it enumerates every kind of device
record of § Device Records (PCI, the ACPI namespace, the SPCR, the boot framebuffer, a platform
description table, the IOMMU family), matches the declarations against the records (§ Matching),
binds each matched PCI and platform record through one path that delivers the resource list
(§ Binding), and withdraws a bound driver in the order § Binding gives. The rest is design
intent; not yet implemented:

- the IOMMU driver's delivery: devmgr binds it by its family record but gives it its own
  bootstrap rounds rather than the resource list;
- message-signaled vectors: a PCI function's driver is given its wired line only;
- the retirement of the test-only labels and of `TEST_LABEL_AUTHORITY`, and the declarations of
  the `test-fault` and `test-orphan` fixtures, which devmgr still starts on the simple-device
  path only on those labels (§ Test Fixtures,
  [#165](https://github.com/kottlerg/seraph/issues/165)).

Device classes (§ Device Classes) are implemented: class SENDs, `QUERY_DEVICE`,
`MINT_CLASS_SEND`, the class files, and the boot-only mark.

[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities specifies the running system.

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
| IOMMU | The ACPI DMAR's remapping units (x86-64) or the RIMT's IOMMUs (riscv64) | One record per IOMMU family, keyed `dmar` or `rimt`, holding every unit's register range and scope |

devmgr runs no AML: the namespace enumerator reads only `Device` objects whose identifying and
resource objects are static `Name` objects, and skips one that defines any of them as a
`Method`. It does not evaluate `_STA`: a `Device` whose `_STA` is a `Name` with bit 0 clear is
not reported, and one whose `_STA` is a `Method` is reported. The platform description covers a
device the machine's tables do not describe in that form; it is data, so a new machine adds a
table, not devmgr code.

One device has one record. Records are merged by resource identity: a record whose `Mmio` base
or `IoPort` base an earlier record already holds adds its identity keys to that record rather
than standing alone. A record keeps the first key of each single-valued kind it is given (the
`_HID`, the SPCR interface type, the platform key): a later description's key of a kind the
record already carries is dropped, so a declaration matches the merged record by the first
description's key of that kind. A later `_CID` the record lacks is added while the record holds
fewer than four. The console UART that the namespace describes as `PNP0501` and the SPCR
names is therefore one record carrying both keys. A PCI function the RIMT names as an IOMMU
belongs to the IOMMU record and has no record of its own.

A record carries the device's resources, typed:

| Resource | Fields |
|---|---|
| `Mmio` | PCI BAR index (PCI only), physical base, size |
| `IoPort` (x86-64) | Base port, count |
| `Interrupt` | Kind and vector count: `Wired` (one line: its GSI or PLIC/APLIC source, its trigger and polarity mode, whether devmgr may share it, which only a PCI function's line may be) or `MessageSignaled` (`Msi` or `MsiX`, the vectors the function supports) |
| `Dma` | The requester ID the IOMMU scope is resolved against |
| `Config` (PCI) | The function's configuration page, which devmgr keeps and delegates to no driver |

The interrupt resource is never one GSI: a record states its kind and a count, so a function
that offers several message-signaled vectors is described as such, and the binding delivers one
capability per vector it grants. The kernel's minting of message-signaled targets is
[#325](https://github.com/kottlerg/seraph/issues/325).

### Platform Description Tables

A platform description table is a per-machine text file in the `.svc` grammar of the device
class files (line-oriented `key = value`; a line starting `#` is a comment; blank lines are
skipped), parsed by the one grammar parser of
[`shared/svc-grammar`](../shared/svc-grammar/README.md). It carries:

- `oem_table_id = <id>`: at most 8 bytes, compared with the OEM table ID of the XSDT header,
  space padded;
- one `device = <key> <resource>...` line per device, `<key>` being the platform key a driver's
  declaration matches, and each resource one of `mmio <base> <size>`, `io <base> <count>`, or
  `wired <line> <mode>`, with mode `level-high`, `level-low`, `edge-high`, or `edge-low`.

A table holds at most `MAX_TABLE_BYTES` = 8192 bytes, `MAX_PLATFORM_DEVICES` = 16 devices,
`MAX_PLATFORM_KEY_BYTES` = 32 bytes per key, and `MAX_PLATFORM_RESOURCES` = 4 resources per
device; a table past a bound is rejected whole and logged.

Tables live in the tree at `services/devmgr/platform/<machine>.platform`. `xtask/src/bundle.rs`
(`ARCH_TABLES`) bundles them per architecture as boot modules (riscv64:
`platform-qemu-virt`, from `services/devmgr/platform/qemu-virt.platform`; x86-64: none), init
forwards them to devmgr with the driver modules, and devmgr tells one from a driver image by
its content. devmgr uses the table whose `oem_table_id` equals the XSDT's OEM table ID. With no
such table there are no platform-table records, and devmgr logs that once.

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
| Match entries | One or more keys of § Device Records: a PCI vendor and device, or a PCI class, subclass, and programming interface under a mask; an ACPI `_HID` or `_CID`; an SPCR interface type; a platform key; an IOMMU family key; the `boot-framebuffer` key |
| Class | The name of the device class the driver serves (§ Device Classes) |
| Instance limit | The most devices of its match the driver is bound to; absent means every one |
| Interrupt need | None, optional, or required, and for a message-signaled capable driver the vector count it requests |
| DMA | Whether the device performs DMA: the driver is then created `CREATE_PINNED` and `CREATE_DMA_HOLD` and given a DMA capability ([device-management.md](device-management.md#dma-authorisation) § DMA Authorisation) |
| DMA address width | Optional, valid only beside DMA: the address bits the device's DMA reaches, 12 to 64; absent means the device has no limit of its own. devmgr limits the device's IOVA space to the smaller of this and its unit's width (§ Declaration Bounds) |
| Physical access | Whether the driver programs hardware with physical addresses: it is then created `CREATE_PHYS_ACCESS` ([device-management.md](device-management.md#physical-addresses) § Physical Addresses). Accepted only for an IOMMU record (§ Declaration Bounds) |
| Withdrawal reset | How devmgr stops the device when it withdraws the driver: the VirtIO `device_status` reset, a PCI Express Function Level Reset, or none, beside the interrupt disable every PCI function gets (§ Binding) |
| Priority tier | Boot (`sched_policy::BOOT_DRIVER_PRIORITY`) or auxiliary (`AUX_DRIVER_PRIORITY`) |

A declaration names standards only: the withdrawal reset and the interrupt kind are methods
devmgr implements once, for every driver that declares them.

devmgr collects declarations from two places:

- **Boot modules.** init forwards to devmgr, untagged, a copy of every boot module outside the
  bootstrap set (init, procmgr, memmgr, devmgr, vfsd, and `fatfs`, which init delivers to vfsd
  until filesystem drivers declare themselves), and devmgr tells them apart by content: an ELF
  image is a driver, whose `.note.seraph.driver` note devmgr decodes; valid UTF-8 text is a
  platform description table (§ Platform Description Tables). A driver image whose note is
  missing or does not decode, a table that is rejected, and any other module are logged and
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
- **No preemption.** A bind pass binds only unbound records, and the passes over boot-bundle
  declarations run first. A drivers-directory declaration cannot take a device a boot driver
  holds, however specific its key.
- **Source.** The boot priority tier, an IOMMU family key, and a class whose class file marks
  it boot-only (§ Device Classes) are accepted only from a boot-bundle declaration. Physical
  access is accepted only from a boot-bundle declaration that matches an IOMMU record. A
  drivers-directory declaration of any of them is logged and ignored, and a drivers-directory
  driver runs at the auxiliary tier.
- **Withdrawal.** devmgr shares a wired line only among PCI functions; it carves the line of
  any other record exclusive, as it carves the console UART's. Whatever reset a declaration
  names, withdrawing the driver of a PCI function disables the function's wired interrupt
  (§ Binding). A reset of none therefore cannot leave a shared line asserting for the other
  drivers on it.
- **Class.** Declaring a class decides which of that class's consumers talk to the driver; it
  grants no access, since the class's policy is configuration (§ Device Classes). Consumers
  treat a driver's data as untrusted.
- **DMA width.** The width limits the device's IOVA space and never widens it past what its
  remapping unit translates; devmgr knows no device's DMA width, so a driver declares its own.
  A width without DMA, outside 12 to 64 bits, or repeated rejects the declaration whole.
- **Form.** Every field has a fixed bound (the match entries, the name's length, the vector
  count). A declaration that exceeds one, carries an unknown field kind, or fails to decode is
  rejected whole and logged. devmgr's reads of a candidate binary are bounded too: the ELF
  header, the section header table, and the one note.

---

## Matching

devmgr builds one match table from the declarations it has collected, and extends it when the
drivers directory arrives. For each unbound device record it takes the most specific match
over all the record's keys, ranked from most to least specific:

1. an exact PCI vendor and device, an IOMMU family key, or a platform key;
2. an SPCR interface type;
3. an ACPI `_HID`;
4. a PCI class;
5. an ACPI `_CID`;
6. the `boot-framebuffer` key. It is the generic fallback for the framebuffer the firmware set
   up, so a driver that matches the display device by any other key binds in its place.

Two declarations equally specific for one device are a conflict: devmgr logs it and binds
neither.
A driver's instance limit counts its devices in record order (PCI segment, bus, device,
function; then the firmware's table order). A device no declaration matches stays recorded
and unbound, and a later declaration (a driver installed afterwards, or a hotplug pass) can
still match it.

The IOMMU driver is matched by its family key against the IOMMU record (the declaration's
`IommuFamily` match against `dmar` on x86-64 or `rimt` on riscv64), so one driver process
serves every unit of its family. It is spawned with its own IOMMU bootstrap rounds
(`iommu_core::bootstrap`), not the resource list. Its binding keeps what
[device-management.md](device-management.md#iommu-discovery-and-programming) § IOMMU Discovery
and Programming specifies:

- it is bound in a pass and settle batch of its own, before the boot pass over every other
  boot-module driver;
- every unit's register `Mmio` capability moves to it, and devmgr keeps no copy;
- it is created `CREATE_PINNED`, `CREATE_DMA_HOLD`, and `CREATE_PHYS_ACCESS` at the boot tier,
  from its declaration's DMA and physical-access fields;
- it is given no DMA capability;
- devmgr deletes its hold's release token at the spawn.

devmgr is its only consumer, over `ipc::iommu_labels`; it serves no device class.

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
   devmgr query capability, and the DMA capability. One delivery shape serves every driver
   that binds to a PCI or platform record; the IOMMU driver takes its own bootstrap rounds, and
   the test-only fixtures the simple-device rounds.
5. Record the driver in the pass's settle batch; the settle, the serving of ready drivers, and
   the withdrawal of the rest are unchanged
   ([responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
   § Responsibilities).

Each bind pass is one settle batch: the IOMMU pass, the boot pass over boot-module drivers,
the pass at `SET_DRIVERS_DIR`, and a hotplug pass. Withdrawing a driver runs three steps in
order:

1. the DMA and Bus Master Enable steps that apply to every DMA-capable device;
2. for a PCI function, setting the Interrupt Disable bit of its Command register through the
   kept `Config` page, so the function stops asserting its wired line whoever else shares it;
3. the reset the declaration names.

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
- **Publication.** For each class file, svcmgr sends devmgr `MINT_CLASS_SEND`, a label gated on
  `CLASS_AUTHORITY` that only svcmgr and init hold, and receives a class SEND: a SEND on
  devmgr's registry endpoint whose badge carries the class's slot and its verb mask. The
  request carries the verbs, the boot-only flag, and the class name (at most
  `MAX_CLASS_NAME_BYTES` = 32 bytes). svcmgr publishes the class SEND seed-only as
  `devmgr.class.<name>` before it sends `SET_DRIVERS_DIR`, so devmgr knows which classes are
  boot-only before it reads any drivers-directory declaration. A service reaches a class only
  when its `.svc` `seed` line names that publication.
- **Bootstrap.** The one class a bootstrap service needs before svcmgr runs is block, for
  vfsd's root mount. init requests it over the same label, with the block protocol's mount
  verb, as part of the fixed bootstrap structure (§ Principle), and reads no class file for
  it. Every other consumer, logd included, is launched by svcmgr and reaches its classes
  through svcmgr's publications.
- **Badge.** One generic badge layout (`devmgr_labels::class_badge`), defined once beside the
  registry protocol, carries the slot and the mask. No class has an authority bit of its own;
  `TEST_LABEL_AUTHORITY` gates only the test labels.

Every driver of a class is served under its class file's policy, so no declaration can widen
access to its class, and a deployment that installs no class file for a class serves it to no
one.

One registry label, `QUERY_DEVICE`, serves every class. It carries an instance ordinal in
`data[1]` (absent is 0) and takes the class and the verb mask from the caller's class SEND,
never from the message; a registry SEND without a class slot gets `UNAUTHORIZED`. devmgr
answers with the SEND on the served driver at that ordinal, stamped with the badge's verb mask,
`WITHDRAWN` at a withdrawn driver's ordinal, and `NO_DEVICE` past the last served driver of the
class, which a class whose drivers the drivers-directory pass binds is at every ordinal before
`SET_DRIVERS_DIR` arrives. A query received while that pass or its settle runs, whose answer
would name no driver, waits until both are done and is answered from the settled drivers. A class's
ordinals are assigned in the order its drivers are first served: within one pass in record
order, and a later pass appends after every ordinal an earlier pass assigned. An ordinal never
moves once its pass settles, and a withdrawn driver's ordinal stays as a tombstone. A
class configured with no served driver, and a served class no class file configured, are
logged after the drivers-directory settle. A drivers-directory declaration whose class a class
request marked boot-only is logged and not bound; a boot-only mark after the drivers-directory
pass began is refused `INVALID_REQUEST`. devmgr's class table holds at most 64 classes.

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
installs. The fixtures and labels it retires are listed on
[#165](https://github.com/kottlerg/seraph/issues/165).

---

## Summarized By

[Architecture Overview](architecture.md), [Device Management](device-management.md),
[PCI Enumeration](../services/devmgr/docs/pci-enumeration.md),
[devmgr Responsibilities and Capabilities](../services/devmgr/docs/responsibilities.md),
[services/drivers/README.md](../services/drivers/README.md),
[Driver Model](../services/drivers/docs/driver-model.md),
[services/drivers/test-dma/README.md](../services/drivers/test-dma/README.md),
[services/drivers/virtio/blk/README.md](../services/drivers/virtio/blk/README.md),
[shared/driver-binding/README.md](../shared/driver-binding/README.md)
