# Device Management

Device management is a userspace concern. The kernel mints initial capabilities from
boot-provided resource descriptors and enforces hardware access control. All
enumeration, binding, and policy live in `devmgr`.

---

## Boot-Provided Resource Descriptors

The kernel consumes `BootInfo.mmio_apertures` during Phase 7 of
initialization and mints one `Mmio` capability per entry its Phase 6 validates; on RISC-V it
mints one more for the console UART range `BootInfo.kernel_mmio` names, which may also lie
inside an aperture.
These apertures, the arch-specific `BootInfo.kernel_mmio`, and the framebuffer description
are the only device descriptors the bootloader produces. Device-level firmware parsing
(enumerating devices from ACPI / DTB) is a userspace concern, and the kernel contains no
parser.

The kernel mints these capabilities in
[`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md) § Phase 7:
Capability System; the full set it mints is listed in
[`docs/capability-model.md`](capability-model.md) § Initial Capability Distribution; the
bootloader's descriptor production is specified in
[`core/boot/docs/firmware-parsing.md`](../core/boot/docs/firmware-parsing.md).

See [`abi/boot-protocol/src/lib.rs`](../abi/boot-protocol/src/lib.rs) for
the `MmioAperture`, `MmioApertureSlice`, and `KernelMmio` type
definitions.

---

## Raw Firmware Passthrough

The `acpi_rsdp` and `device_tree` fields in `BootInfo` are passed through
to userspace as opaque physical addresses. Device-level discovery —
resolving which aperture covers which device, which GSI goes to which
pin, the PCI bus topology — happens in userspace by re-walking ACPI and
DTB from these passthrough addresses.

The kernel parses neither table: it reads only the DTB header's magic and `totalsize` (to
size the blob's cap and keep its pages out of the buddy pool) and mints read-only Memory
caps over the RSDP page, the DTB blob, and each `AcpiReclaimable` region, which init
forwards to devmgr.

---

## devmgr: Userspace Device Manager

`devmgr` is a privileged userspace process launched during bootstrap (started by init
via procmgr). It is the single point responsible for platform enumeration and driver
binding in a running system.

### What devmgr receives from init

devmgr receives from init a platform capability set sufficient for
enumeration and per-driver delegation (MMIO apertures, firmware-table
Memory caps, the IRQ range, and a full-rights derivation of the root `IoPort` on x86-64 or an
`SbiControl` derivation narrowed to Reset and Suspend on RISC-V, the roots staying with init); its
SchedControl band arrives from procmgr via `ProcessInfo`.
Init exits after bootstrap; devmgr is `restart = never`, `critical = yes`,
so its death triggers a graceful shutdown rather than re-delegation. The
per-round list of what init delivers is specified in
[`services/devmgr/docs/responsibilities.md`](../services/devmgr/docs/responsibilities.md)
§ Capabilities Received; init's side of the transfer is summarized in
[`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md) §
Per-stage authority transfers.

### What devmgr does

devmgr's per-responsibility specification — firmware-table parsing,
PCI enumeration, driver binding, device-registry IPC, and hotplug —
is in [`services/devmgr/docs/responsibilities.md`](../services/devmgr/docs/responsibilities.md)
§ Responsibilities. This document covers only the system-scope
boundary devmgr sits inside.

### Security boundary

devmgr's hardware, platform, and scheduling authority is only what it receives at bootstrap
(the platform set init delegates, plus the SchedControl band procmgr delivers in its
`ProcessInfo`) and the `/services/drivers/` cap svcmgr sends after handover (see Driver
binary sources). Its authority is not re-delegable after bootstrap: init exits, and svcmgr
treats devmgr as `restart = never`, `critical = yes`, so devmgr's death triggers a graceful
shutdown.

---

## DMA Safety Model

DMA access in Seraph operates in one of two modes, distinguished by whether an
IOMMU is present and whether it has been programmed, at devmgr's direction, to scope DMA for a
given device:

**IOMMU-isolated (safe):** When an IOMMU is present and has been configured for
the target device, DMA transactions initiated by that device are
confined by the IOMMU's translation tables to the physical frames devmgr has
explicitly mapped. A driver cannot DMA outside its authorised regions even if
its process is compromised. This is the expected mode on modern x86-64
hardware and on RISC-V platforms that implement the IOMMU extension.

**DMA-unsafe:** When no IOMMU is present, or when devmgr chooses not to have
an available IOMMU configured for a device, unconfined DMA is physically
possible. A driver may still be authorised by devmgr to DMA in this mode,
but no hardware enforcement constrains the device; a compromised driver
can reach any physical address the device can address.

devmgr is responsible for detecting the platform IOMMU situation and deciding per-device policy;
the IOMMU itself is programmed by a separate IOMMU driver devmgr directs (§ IOMMU Discovery and
Programming). The IOMMU is preferred but not required
([platform-requirements.md](platform-requirements.md#iommu-and-dma-confinement)): when none is
present, or the one present cannot be programmed, devmgr logs once that DMA runs unconfined and
spawns every DMA-capable driver in the DMA-unsafe mode, refusing and restricting none. devmgr
programs VT-d on x86-64 through the `iommu-vtd` driver and the RISC-V IOMMU on riscv64 through the
`iommu-riscv` driver; every device a remapping unit translates runs IOMMU-isolated, and a device
no unit translates runs DMA-unsafe.

The kernel is agnostic to DMA mode: it does not read or write IOMMU
registers, does not track per-device DMA state, and does not return a
DMA-safety verdict.

### DMA-Safe Teardown

A device can keep writing the frames its driver posted to it after the driver is gone, until the
device is stopped, and with no IOMMU confining the device to those frames the writes land on
whatever owns them next. A DMA-capable driver's frames therefore return to
memmgr's free pool only after its device's DMA is confirmed stopped, whether the driver died on
its own or devmgr withdrew it:

1. **Bus mastering off.** devmgr clears the function's Bus Master Enable (bit 2 of the Command
   register) through a configuration-page capability it keeps and never delegates, and reads the
   register back. While the bit is clear the function issues no memory or I/O request of its own,
   so it performs no DMA and signals no MSI (PCI Local Bus Specification r3.0 § 6.2.2; PCI Express
   Base Specification r4.0 § 7.5.1.1.3). The driver holds no configuration-space capability, so
   it cannot set the bit again, and devmgr needs neither the driver's cooperation nor a way to
   stop its threads.
   The read-back is also what confirms the DMA already issued has landed. On PCI Express a
   Completion does not pass a Posted Request in the same direction unless its Relaxed Ordering
   or ID-Based Ordering attribute lets it, and neither does here: a Configuration Request carries
   neither attribute (PCI Express Base Specification r4.0 § 2.2.7), its Completion copies its
   Request's attributes (§ 2.2.9), and ID-Based Ordering would let it pass only a Posted Request
   of another Requester, while the function's own writes carry its ID (§ 2.4.1). So the
   read-back's Completion reaches the processor only after every memory write the function
   posted before it. Conventional PCI orders a read's
   completion behind earlier posted writes the same way (PCI Local Bus Specification r3.0
   Appendix E).
2. **Device taken and reset.** devmgr then revokes the driver's BAR capabilities, sets the
   function's Command Interrupt Disable bit through the configuration page it keeps, and runs the
   reset the driver's declaration names (the VirtIO status reset, a PCI Express Function Level
   Reset, or none), waiting for a VirtIO reset to be confirmed for at most `RESET_TIMEOUT` (5 s)
   and for a Function Level Reset `FLR_COMPLETION_MS` (100 ms). A device whose declaration names
   no reset is never confirmed quiet.
3. **Memory freed.** procmgr holds back the `PROCESS_DIED` of a driver devmgr created with
   `CREATE_DMA_HOLD`, however the driver died, so memmgr keeps its frames on the driver's record,
   out of the pool. devmgr releases the hold (`RELEASE_HOLD`) only when the IOMMU blocked the
   device, or when the Bus Master Enable read-back is clear, every BAR copy is revoked and the
   reset is confirmed; a device that meets neither leaves the frames quarantined on that record,
   counted and never handed out again, for the rest of the boot.

Only devmgr can release the hold. procmgr serves `RELEASE_HOLD` only on the release token the
driver's create reply carries, a capability badged with the driver's process badge and a verb bit
no process badge carries, and refuses it on the driver's process handle and on every copy of the
driver's own procmgr capability (procmgr's
[§ Label 3](../services/procmgr/docs/ipc-interface.md#label-3-release_hold)). devmgr keeps the
token with the device and passes it to no one, so a compromised driver that granted its procmgr
capability onward before it died cannot have its frames freed early.

A frame a client lends a driver for one transfer (the memory capability a virtio-blk caller
supplies) is on the client's memmgr record, which no hold covers. memmgr pools it only once no
other process holds a capability to it
([services/memmgr/docs/memory-pool.md](../services/memmgr/docs/memory-pool.md#reclamation)
§ Reclamation), so it stays out of the pool, even after the client releases it or dies, while
devmgr's reference to it lives, and that one lives until the device can no longer write it.
A driver programs its device only with the device address of a DMA mapping of the frame
(§ DMA Authorisation), and devmgr keeps a capability to the frame for each standing mapping:

- **While the driver lives.** The driver maps the frame for the transfer and unmaps it only once
  the transfer completed or the device acknowledged its reset, and it holds the lent capability
  until then too. It moves the capability back in its reply; a reply that fails (the client is
  gone) has it delete the capability, the transfer being over.
- **When the driver is gone.** A driver that dies mid-transfer, or exits after an unacknowledged
  reset, leaves the mapping standing, and its own capability goes with its `CSpace`. When devmgr
  withdraws the device it deletes its mapping capabilities only once the IOMMU blocks the device,
  or once the Bus Master Enable read-back, the BAR revocation and the reset all confirm; otherwise
  it keeps them for the rest of the boot, beside the driver's quarantined record.

Where an IOMMU confines the device, devmgr's first act on taking it from its driver is to withdraw
the device's DMA authorisation (§ DMA Authorisation), which blocks the device in the IOMMU (the
IOMMU driver's `BLOCK`) before Bus Master Enable is cleared. A device the IOMMU blocks can no
longer reach the driver's frames, so devmgr releases the hold once the block is in place, whether
or not the Bus Master Enable read-back, the BAR revocation and the reset confirm; with no IOMMU
confining the device, or a block the IOMMU driver did not complete, the release waits on all three
as step 3 states.

The steps, their owners, and their bounds are specified in
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities (the withdrawal),
[docs/process-lifecycle.md](process-lifecycle.md#process-death) § Process Death (the held
reclaim), and
[services/memmgr/docs/ipc-interface.md](../services/memmgr/docs/ipc-interface.md#label-4-process_died)
§ Label 4 (`PROCESS_DIED`). As an observation, not a guarantee the order relies on, QEMU's
virtio-pci devices also stop processing their queues when Bus Master Enable is cleared.

What the boots exercise of this order is stated in
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities.

---

## DMA Authorisation

A DMA-capable driver programs its device only with device addresses devmgr hands it, never with
a physical address. devmgr gives each PCI-bound driver whose declaration declares DMA
([driver-binding.md](driver-binding.md#driver-declarations) § Driver Declarations) a DMA
capability, and no other driver one: a SEND on devmgr's DMA endpoint badged with the device's
badge, delivered with the driver's other per-device caps at spawn. On it the driver sends
`DMA_MAP` (`ipc::devmgr_dma_labels`) with a Memory cap over the frames the device must reach and
the access it needs (the device reads, or reads and writes); the cap must carry `MAP` rights,
and `MAP|WRITE` for a device that writes. devmgr keeps the cap while the mapping stands and
replies the device address of its first byte, which is what the driver writes into descriptors
and rings. `DMA_UNMAP` withdraws a mapping by that address, and devmgr deletes the cap it kept.
A driver maps its own rings and buffers once at setup; a block driver maps each client-lent
buffer for the duration of the one request that uses it.

devmgr returns every device address; no driver chooses one. With an IOMMU confining the device,
the address is an IOVA in the device's domain, which devmgr allocates first fit from 1 MiB below
the device's limit (the width the device's remapping unit translates, narrowed to the DMA address
width the device's driver declares; [limits.md](limits.md)), outside every firmware-reserved range
the domain maps at its own address and, behind a VT-d unit, outside the interrupt address range
`0xFEE0_0000` to `0xFEEF_FFFF`, whose writes VT-d takes as interrupt requests and never translates
(Intel VT-d specification § 3.14), and the mapping is installed in the IOMMU's tables, through the
IOMMU driver (§ IOMMU Discovery and Programming), before devmgr replies, and withdrawn from them
before devmgr deletes its cap at `DMA_UNMAP`, so the device reaches exactly the frames mapped for
it and its reserved ranges. With none, the device can reach memory only at physical
addresses, so the address devmgr returns is the frames' physical address and the mapping is
bookkeeping alone. The protocol and the driver's code are the same in both modes.

devmgr serves the DMA endpoint on a thread of its own, apart from its control thread, because that
thread makes nested calls (a driver spawn from the root filesystem reads the binary through the
block driver, which maps the read's buffer) and settles batches whose drivers map their rings
before they report ready, and a mapping must never wait on it. The thread runs at the boot
drivers' level (`ipc::sched_policy::BOOT_DRIVER_PRIORITY`, above devmgr's own) because the block
driver blocks on it. The two threads share the table of devices and mappings under one lock, held
only around table operations and never across IPC: a mapping whose IOMMU `MAP` or `UNMAP` is in
flight is pending in the table, so a withdrawal meanwhile neither races its commit nor deletes the
cap the call carries. A device holds at most `MAX_MAPPINGS_PER_DEVICE` mappings
([limits.md](limits.md)). When devmgr withdraws a driver it revokes every copy of the device's DMA
capability, drops the device's mappings, and blocks a confined device in the IOMMU, so a request
still queued is refused and the device reaches nothing.

---

## IOMMU Discovery and Programming

IOMMU topology is a userspace concern. The bootloader emits no IOMMU
descriptor; ACPI and DTB reach userspace only as the opaque
`BootInfo.acpi_rsdp` / `BootInfo.device_tree` physical addresses (see Raw
Firmware Passthrough), over which the kernel mints read-only Memory caps,
and `devmgr` performs the IOMMU-topology walk itself, from the table of its architecture's IOMMU
family. On x86-64 it reads the ACPI DMAR's VT-d remapping units (DRHDs), their device scopes, and
the reserved memory regions (RMRRs). The one boot-side concession is an MMIO aperture the
bootloader seeds over each DRHD's register range, so the kernel mints a cap devmgr can carve the
unit's registers from ([core/boot/docs/acpi.md](../core/boot/docs/acpi.md)). On riscv64 it reads
the ACPI RISC-V IO Mapping Table (RIMT, specification v1.0): each RISC-V IOMMU that is a PCI
function, whose registers are its BAR 0 inside a PCI window the bootloader already seeds, and each
root complex's ID mappings, the requester-ID ranges each IOMMU translates. The firmware the
riscv64 boot targets hands the bootloader ACPI only, so no Device Tree `iommu-map` is read. The
RIMT describes no reserved memory region.

The IOMMU's arch-specific logic (its registers, translation tables, cache invalidation, and fault
reporting) runs in a separate IOMMU driver process, one per IOMMU family, not in devmgr: VT-d's is
`iommu-vtd` ([services/drivers/iommu/vtd/README.md](../services/drivers/iommu/vtd/README.md)) and
the RISC-V IOMMU's is `iommu-riscv`
([services/drivers/iommu/riscv/README.md](../services/drivers/iommu/riscv/README.md)), both over the
family-independent `iommu-core`
([services/drivers/iommu/core/README.md](../services/drivers/iommu/core/README.md)) and the shared
table-page store `iommu-store`
([services/drivers/iommu/store/README.md](../services/drivers/iommu/store/README.md)). For each unit
it discovers, devmgr carves an `Mmio` cap for the unit's register range through the same
aperture-carving flow as any other device (for a RISC-V IOMMU, after turning on the function's
memory decode and bus mastering through its configuration page) and moves it to that family's IOMMU
driver, keeping no copy, with the unit's PCI segment and its scope resolved against the PCI
topology. devmgr keeps the DMA endpoint, its `devmgr_dma_labels` contract, and per-device policy,
and reaches the IOMMU driver over `ipc::iommu_labels` to attach a device to a domain of its own,
install and withdraw mappings, block a device, and take the faults the units recorded, so drivers
see the same protocol whichever IOMMU, or none, sits behind it. The kernel does not read or write
IOMMU registers and holds no per-IOMMU state.

At boot devmgr matches the IOMMU family record against the boot-module declarations and spawns
the matched driver from its boot module (with its own bootstrap rounds, not the resource list)
before any DMA-capable driver, in a settle batch of its own (`CREATE_PROCESS` with
`CREATE_PINNED`, since the units walk its table pages, `CREATE_DMA_HOLD`, and
`CREATE_PHYS_ACCESS`, since the units are programmed with physical
addresses (§ Physical Addresses), at `BOOT_DRIVER_PRIORITY`, since devmgr's DMA thread calls it on
every mapping). The driver programs each unit with empty tables and turns translation on, so from
its ready report every function a unit translates reaches nothing until devmgr attaches it, the
functions no driver binds included. devmgr never releases the driver's hold, and deletes its release
token at the spawn: a unit may walk any of its table pages while translation is on, so they stay
quarantined for the boot. For each DMA-capable device devmgr then decides, before it grants the
device DMA:

- **Confined.** A unit translates the device: devmgr attaches it (`ATTACH`), maps the regions the
  firmware reserves for it (below) in that domain, and grants it DMA there.
- **Refused.** A device whose `ATTACH` fails is refused, since its unit blocks it. So is a device
  whose reserved regions cannot be mapped (below). So is a device whose unit devmgr could not hand
  over: that unit is never programmed, so it does not block the device, but devmgr does not run a
  device unconfined behind an IOMMU it found. So is a device the RIMT gives an IOMMU device ID other
  than its requester ID, since the IOMMU driver addresses each device's context by its requester ID.
- **Unconfined.** No unit translates the device: it runs DMA-unsafe.

Firmware can require a device to keep reaching fixed physical ranges once the IOMMU is on: a VT-d
RMRR names the functions that reach its range (USB controllers with legacy emulation, integrated
graphics, some storage units). Each range firmware reserves for a confined device is mapped in the
device's domain at its own address (an identity mapping), read-write, rounded out to whole pages,
after `ATTACH` and before the DMA grant (`MAP_RESERVED`, which carries no cap, since no Memory cap
covers firmware-reserved memory), and devmgr logs each range against the device. The range stands
for the domain's life: the driver's `DMA_UNMAP` cannot reach it, the IOMMU driver refuses its
`UNMAP`, and the domain's `BLOCK` withdraws it with the rest. devmgr's IOVA allocator gives no
mapping of the device an address inside one (§ DMA Authorisation). devmgr refuses the device, with a
log line, when a range overlaps memory memmgr pools, which the device would then reach (a platform
error: firmware must report its reserved ranges as reserved), when a range passes what its unit
translates, when more than `MAX_RESERVED_RANGES_PER_DEVICE` ranges remain once the ones that touch
are merged ([limits.md](limits.md)), or when a mapping fails, blocking the device again. devmgr
learns what memmgr pools from init at its bootstrap, as the extent of every Memory cap init holds
but the firmware tables', which is everything memmgr pools then or at init's reap
([services/init/docs/bootstrap.md](../services/init/docs/bootstrap.md)); when that set is not known
in full, devmgr refuses every device with a reserved range. The check covers pooled memory only:
RAM the kernel holds for itself is not checked. The RIMT describes no
reserved region, and no Device Tree reserved range is read, so on riscv64 no device has one. A
device reaches its reserved ranges only from its `ATTACH`: from the IOMMU driver's ready report
until then it reaches nothing, as every function a unit translates does, and a device no driver
binds is never attached, so the firmware's own use of its ranges (an SMM handler's USB legacy
emulation) stops when the driver reports ready.

A device's message-signalled interrupt is a write to an interrupt address. On x86-64 VT-d does not
translate a write to the interrupt range through a domain's tables (interrupt remapping governs
it), so `iommu-vtd` refuses `MAP_MSI`, and devmgr gives no mapping of a device a VT-d unit
confines an IOVA in that range, where the device's DMA would never reach it. `iommu-vtd` owns the
interrupt remapping table its units share and programs it through `REMAP_SETUP`, `REMAP_SET` and
`REMAP_CLEAR`, which `iommu-riscv` refuses; devmgr turns remapping on and writes each interrupt
source's entry (§ Interrupt Delivery). On riscv64 the write goes to a hart's IMSIC interrupt file
and the RISC-V IOMMU translates it as any other DMA, so a confined device reaches only the files
its domain maps: `MAP_MSI` maps one file's page at its own address, with no cap, for the domain's
life, as `MAP_RESERVED` does a reserved range. devmgr maps the file of each hart a device's
message-signalled targets sit on before it enables the device's MSI or MSI-X, and keeps the file's
page out of the IOVAs it gives the device's mappings (§ Message-Signaled Interrupts). Why the
RISC-V IOMMU's MSI page tables stay off is specified in
[services/drivers/iommu/riscv/README.md](../services/drivers/iommu/riscv/README.md#msi-confinement)
§ MSI Confinement.

When no unit is found, no IOMMU driver module was delivered, or the driver does not report ready
within the settle bound, devmgr logs once that DMA runs unconfined and every device runs so. A
driver that fails its own setup turns translation off again before it exits, so it leaves no device
blocked. A driver that dies or hangs after it turned a unit's translation on, before it reported
ready, leaves that unit blocking every device behind it, which devmgr cannot undo, since it keeps no
register cap; its log line says so, and those devices' DMA fails. The case that is not an absent
IOMMU is a driver that dies after it reported ready: the units go on translating through the tables
it left, so devmgr cannot fall back to unconfined DMA. It fails closed. A death watch thread of
devmgr's own sees the death at once, independent of the control thread, which may be blocked in a
call to the dead driver. devmgr then logs once, refuses every later `DMA_MAP` of every confined
device, answers any of its own calls still queued on the dead driver's endpoint with an error, and
withdraws the driver of every confined device; it restarts nothing, restartability being
[#262](https://github.com/kottlerg/seraph/issues/262). Invalidation is synchronous, through VT-d's
invalidation queue and through the RISC-V IOMMU's command queue, each polled to completion,
two IPC hops per mapping; batching it is
[#772](https://github.com/kottlerg/seraph/issues/772). Faults are polled, not signalled, because
no IOMMU driver programs a message-signaled interrupt for fault events
([#325](https://github.com/kottlerg/seraph/issues/325)), and devmgr logs each one against its
device.

When devmgr binds a DMA-capable driver, it spawns the driver
with `procmgr_labels::CREATE_PINNED`, so the driver's memory is eager-mapped,
and delivers its resource list (BAR `Mmio` caps and, when the declaration takes an interrupt,
its message-signaled vectors or its wired line, § Message-Signaled Interrupts), endpoint caps, and
DMA
capability (§ DMA Authorisation). With no IOMMU confining the device the physical
isolation is absent, and devmgr runs the device unconfined (§ DMA Safety
Model); the kernel is agnostic to both outcomes.

### Physical Addresses

No DMA-capable driver reads a physical address, and none can: every address it programs comes from
`DMA_MAP` (§ DMA Authorisation), and the only address of its own memory any reply gives it is the
device address `DMA_MAP` returns for an unconfined device, which is the frames' physical address by
necessity. Two processes read physical addresses, devmgr and the IOMMU driver, the phys-class
processes: devmgr turns a driver's cap into a device mapping, reading the frames' physical base for
an unconfined device, and the IOMMU driver programs its units with the physical addresses of its own
table pages and of every frame `MAP` installs. init creates devmgr, and devmgr the IOMMU driver,
with `procmgr_labels::CREATE_PHYS_ACCESS`, so memmgr's grants to them keep the Memory `Phys` right
([capability-model.md](capability-model.md#memory) § Memory); every other process's grants, every
device driver's included, lack it, and memmgr's grant reply names its runs by opaque region ids,
carrying no physical address (see
[`services/memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md#label-1-request_memory_caps)
§ Label 1). A driver's cap lacks `Phys`, so the two read its frames' base by presenting a `Phys`
cap of their own as the credential `SYS_CAP_INFO`'s `CAP_INFO_MEMORY_PHYS_BASE` takes (see
[`core/kernel/docs/cross-boundary-disclosure.md`](../core/kernel/docs/cross-boundary-disclosure.md)
§ Physical-address surfaces, which classifies every surface that still carries a physical
address).

---

## Interrupt Delivery

Implementation status: the kernel's binding mechanism below, its trigger and polarity mode,
devmgr's sharing of a line among the devices on it, the kernel's minting of message-signaled
targets, devmgr's giving of them to drivers (§ Message-Signaled Interrupts), and VT-d interrupt
remapping (§ IOMMU Discovery and Programming) are implemented.

A driver receives a wired interrupt line as a single-line `Interrupt` cap and binds it to a
Notification with `SYS_IRQ_REGISTER`; the line was routed first by `SYS_IRQ_ROUTE`, which devmgr
makes through the cap it carves. The kernel models each wired line as a source with up to
`MAX_IRQ_BINDINGS` (64) bindings, one per bound Interrupt object; a copy or derivation of an
Interrupt cap references a fresh object over the same line, so every capability to a line is a
binding of its own. devmgr splits each PCI device's line once from its range, the first time a
device on it needs it, routes the line through that cap in the line's mode, holds the cap for the
boot, and hands every driver on the line, the first included, a derivation of it, so PCI
functions that share an `INTx` line are all served
([services/devmgr/docs/pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md)
§ Per-Device Capability Creation). The line of a platform record is the exception: devmgr carves
it exclusive, keeps it, and gives the record's driver, the serial driver for the UART's line, a
derivation it revokes when it withdraws the driver (devmgr's
[responsibilities.md § Responsibilities](../services/devmgr/docs/responsibilities.md#responsibilities)).

- **Route.** `SYS_IRQ_ROUTE` through a single-line Interrupt cap carrying `RIGHTS_IRQ_MINT` routes
  the line at its controller in the call's trigger and polarity mode, leaves it masked, and makes
  the cap's object a route holder; a further object routing the line in the same mode becomes
  another holder, and one in another mode is refused with `InvalidArgument`.
- **Bind.** `SYS_IRQ_REGISTER` through an unbound object adds a binding to a routed line, refused
  with `InvalidState` on a line not routed; every new binding masks the line and owes an
  acknowledgement, so the line stays masked until the new receiver's first `SYS_IRQ_ACK`. Every
  binding passes the route's mode, or is refused with `InvalidArgument`. Through a bound object it
  rebinds that binding to the new notification. A binding past the bound is refused with
  `QuotaExceeded`.
- **Deliver.** Each assertion masks the line, marks every binding as owing an acknowledgement,
  signals every bound notification, and completes at the controller; an assertion the controller
  forwarded before the mask took effect is delivered too, so a receiver can be signalled again
  before it acknowledges. A receiver whose device did not assert reads its device's interrupt
  status and finds nothing. Every receiver on a line
  devmgr may share MUST acknowledge each delivery promptly, whether or not it has a request in
  flight: the line stays masked until every binding has acknowledged, so a receiver that
  acknowledges only while it serves a request of its own holds the line masked for the others on
  it while it is idle, and their devices' interrupts are lost (on a line programmed edge-triggered)
  or delayed (on a level-triggered one) until it next does. The VirtIO drivers therefore run an
  interrupt-service thread that acknowledges every delivery
  ([services/drivers/docs/driver-model.md](../services/drivers/docs/driver-model.md)
  rule 5) and also reads its device's interrupt status on a bounded timeout, which recovers an
  edge-triggered line's lost edge (below). A driver that does not acknowledge promptly needs its
  line kept exclusive: the serial driver acknowledges only when its client reads
  ([services/drivers/serial/README.md](../services/drivers/serial/README.md#interrupts)
  § Interrupts), so devmgr keeps the UART line exclusive and shares no other device onto it. The
  UART line is never a PCI `INTx` line on either machine (x86-64 COM1 is ISA IRQ 4; the riscv64
  `virt` NS16550 is APLIC source 10, against `INTx` sources 32 to 35), so the exclusivity costs no
  device a cap in practice.
- **Acknowledge.** `SYS_IRQ_ACK` clears its own binding's debt and unmasks the line only when no
  binding owes one; a repeated acknowledgement changes nothing.
- **Unbind.** A binding goes when its Interrupt object is freed (its capability deleted, revoked,
  or torn down with its holder's CSpace); the line is unmasked when the remaining bindings owe
  nothing, stays routed and masked while a route holder remains with no binding, and is released at
  its controller once neither a holder nor a binding remains. A bound binding holds a reference on
  its Notification, so deleting the Notification's capabilities leaves the binding in place until
  its Interrupt object rebinds or is freed. A driver that
  dies while its device asserts a level-triggered line leaves the device asserting with no
  receiver to clear it, so the line's other receivers are signalled again on each unmask; devmgr
  ends that by setting the function's Interrupt Disable bit, and running its declared reset, when it
  withdraws the device's driver
  ([services/drivers/docs/driver-model.md](../services/drivers/docs/driver-model.md#withdrawal)
  § Withdrawal).

The contract is specified in [core/kernel/docs/syscalls.md](../core/kernel/docs/syscalls.md)
§ `SYS_IRQ_ROUTE`, § `SYS_IRQ_REGISTER` and § `SYS_IRQ_ACK`. On riscv64 the line's APLIC source
mode is programmed with the mode's trigger and polarity, and the unmask of a level-sensitive
source pends it again while it is asserted, so an assertion still held at the unmask is delivered
(core/kernel/src/arch/riscv64/aia.rs). On x86-64 the line's I/O APIC entry is programmed with the
mode's trigger and polarity (core/kernel/src/arch/x86_64/ioapic.rs), and a level-triggered entry
likewise delivers at the unmask an assertion still held. devmgr gives each PCI driver the mode of
its `INTx` line, which every driver on the line then passes: on x86-64 the trigger and polarity
of the MADT Interrupt Source Override that names the line's GSI, field by field, with the PCI
default (level-triggered, active-low) for a field the override leaves conforming to its bus and
for a line no override names; on riscv64 level-triggered, active-high
([services/devmgr/docs/pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md) step 4). On a
line programmed edge-triggered and shared, an assertion while the line is masked or another device
holds it high raises no new edge, and the device stays asserted until its interrupt status is read,
so no later assertion on the line raises one either. The VirtIO interrupt-service thread's timed
read (`ISR_POLL_MS`) clears that assertion and signals the waiting path, so the loss is latency, not
a hang. A device whose driver asks for message-signaled vectors gets them in place of its wired line
(below); a vector is its device's alone, so none of this applies to it.
The kernel delivers each routed line to one CPU, chosen when the line is routed by taking the
CPUs in turn, so the interrupts of several devices spread over the CPUs. On x86-64 with interrupt
remapping off only CPUs whose APIC id an I/O APIC can name (below `0xFF`, the broadcast id) take
part; with it on (`SYS_IRQ_REMAP`) only CPUs whose index is below 302, and under `IRQ_REMAP_ON`
whose APIC id is below `0xFF`. Each x86-64 CPU has its own 217 device vectors, shared by the
routed lines and the message targets on that CPU, and a route or mint fails only when no
eligible CPU has a free vector; on riscv64 a hart's IMSIC identities are shared the same way by
routed APLIC sources and message targets. The mechanism is specified
in [core/kernel/docs/arch-interface.md](../core/kernel/docs/arch-interface.md) § `interrupts`.

### Message-Signaled Interrupts

A PCI function signals a message-signaled interrupt by writing its message, an address and a data
value, to memory as a bus master, and devmgr sets a function's Bus Master Enable only for a
declaration that asks for DMA
([services/devmgr/docs/pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md) step 3).
devmgr therefore gives a driver's function its interrupt by this rule
(`firmware::pci::interrupt_plan`):

- A declaration that asks for message-signaled vectors (an interrupt need with a nonzero vector
  count, [driver-binding.md](driver-binding.md#driver-declarations) § Driver Declarations) and for
  DMA gets MSI-X when the function has the capability, as many vectors as it asks for up to the
  function's table size, table entries 0 onwards; else MSI, one vector; else the function's wired
  line.
- A declaration that asks for no vectors, or does not ask for DMA, gets the function's wired line
  whatever capabilities the function has.
- A function with neither a wired line (its Interrupt Pin is 0, or devmgr finds no line for it)
  nor a message-signaled vector it can be given gets no interrupt: its driver is bound without one
  when its need is optional and not bound when its need is required. A declaration that does not
  ask for DMA is always such a case on a function with no wired line.

MSI is given one vector whatever the function supports: the kernel mints each target on a CPU of
its own choosing, and the several vectors of multi-message MSI need consecutive data values to
one address, which separate targets do not have.

For each vector devmgr mints a target with `SYS_IRQ_MSG_ALLOC`, through a copy of its interrupt
range cap carrying `RIGHTS_IRQ_MINT`, and reads the target's message with `SYS_CAP_INFO`. For MSI it
checks that the message fits the function's capability (an address below 4 GiB for a 32-bit
capability, and 16 bits of data) before any interrupt file is mapped. On riscv64, where the RISC-V
IOMMU translates the device's writes, it then maps the interrupt file each target sits on into the
device's domain (`MAP_MSI`, § IOMMU Discovery and Programming); on x86-64 VT-d does not translate a
write to the interrupt range (below). For MSI devmgr writes the message into the function's MSI
capability, unmasks its vector where the function masks per vector, and enables MSI with one vector.
For MSI-X it carves a cap of its own on the pages holding the function's table, sets Memory Space
Enable (so the table's BAR decodes, whatever the firmware left) and MSI-X Enable under Function
Mask, masks every table entry, writes each vector's message into its entry, entry 0 onwards, reads
it back, and unmasks that entry, then clears Function Mask; every other entry stays masked. An entry
that reads back otherwise fails the step. devmgr
sets the function's Interrupt Disable in both cases. Each vector is one `Interrupt` resource, whose
copy carries `RIGHTS_IRQ_NOTIFY` only and which the driver binds with `SYS_IRQ_REGISTER` in mode 0.
A step that fails at the bind (a mint, a message that does not fit, an interrupt file, the table's
pages, the configuration page) falls back: MSI-X to MSI when the function has it, else to the wired
line, and MSI to the wired line. A step that fails after it
mapped an interrupt file is the exception: the domain keeps the file until it is blocked (`UNMAP`
refuses it), so a fallback would leave the device reaching a hart's file no target of its own sits
on, and devmgr refuses the bind instead, which blocks the domain. When it withdraws the driver
devmgr clears MSI Enable, and MSI-X Enable with Function Mask set, beside Interrupt Disable, before
the declared reset; it deletes its cap on the table's pages, and a target is freed once no cap to it
remains. The table's entries keep their messages until the next bind masks and rewrites them before
it enables MSI-X again.

devmgr is the one writer of every message: no driver of a function devmgr may give MSI-X is
delivered the pages holding that function's MSI-X table or Pending Bit Array. devmgr withholds each
structure's pages, its span rounded out to the 4 KiB a function keeps it apart from other registers
in (PCI Local Bus Specification r3.0 § 6.8.2), from every such driver, and delivers the rest of
each BAR as up to three `Mmio` ranges, each naming its offset in its BAR
([driver-binding.md](driver-binding.md#binding) § Binding). A driver therefore neither retargets
nor masks a vector: it names its vectors in its device's own registers and suppresses its device's
interrupts at the device (VirtIO's `NO_VECTOR` and event suppression; NVMe's and a NIC's per-queue
interrupt enables). A VirtIO function is given MSI-X only when every one of its register regions
lies clear of those pages, since its driver needs them; otherwise devmgr delivers them and the
function falls back to its wired line. A VirtIO function is given no MSI, since VirtIO over PCI
signals by MSI-X vectors or its wired line alone (VirtIO 1.2 § 4.1.4.5, § 4.1.5.1.2;
`firmware::pci::deliverable_messages`). The RISC-V IOMMU driver is delivered the first page of its
unit's BAR 0, the unit's registers (§ IOMMU Discovery and Programming), which hold the unit's MSI
configuration table (`msi_cfg_tbl`, RISC-V IOMMU specification); devmgr gives the unit no vectors,
and the driver keeps the unit's interrupts off and polls its queues, so no message is written
there.

On x86-64 with VT-d interrupt remapping on (§ IOMMU Discovery and Programming), a device's interrupt
write is delivered only through a remapping entry devmgr had the IOMMU driver write for the
device's own requester ID: a remappable message naming an entry written for another requester, or
an entry not present, is blocked, and so is every compatibility-format message. With remapping off
(the DMAR offers none, an I/O APIC has no source ID in the DMAR, or the driver or the kernel refused
the setup, each logged by devmgr), a device whose DMA engine writes to the interrupt range can raise
any vector on any CPU whose APIC id is below `0xFF`, the exception vectors 16 to 31 included, behind
an IOMMU or not; its driver cannot do so through the MSI-X table, which only devmgr writes. On
riscv64 behind the RISC-V IOMMU a device's writes reach only the interrupt files its domain maps.

---

## Relationship to Other Services

```
init
 ├── devmgr  (platform caps + firmware table caps)
 │    ├── driver/iommu-vtd         (VT-d unit MMIO caps; iommu_labels, devmgr only; x86-64)
 │    ├── driver/iommu-riscv       (IOMMU BAR 0 MMIO caps; iommu_labels, devmgr only; riscv64)
 │    ├── driver/virtio-blk        (MMIO + IRQ caps; block class)
 │    ├── driver/virtio-input      (MMIO + opt. IRQ; input class; on-disk)
 │    ├── driver/virtio-console    (MMIO + opt. IRQ; debug-port class; on-disk)
 │    ├── driver/serial            (UART hw + IRQ caps; serial class)
 │    ├── driver/framebuffer       (MMIO cap; framebuffer class)
 │    └── driver/{cmos-rtc,goldfish-rtc} (RTC hw cap; rtc class)
 ├── vfsd  (receives storage endpoint via QUERY_DEVICE on the block class SEND)
 ├── ...
 └── svcmgr
      ├── logd     (serial, framebuffer endpoints via QUERY_DEVICE on class SENDs)
      ├── pwrmgr   (ACPI tables + shutdown hw via QUERY_ACPI_TABLE / QUERY_SHUTDOWN_DEVICE)
      ├── timed    (RTC endpoint via QUERY_DEVICE on the rtc class SEND)
      └── terminal (input, framebuffer, serial endpoints via QUERY_DEVICE on class SENDs)
```

vfsd and the consumers svcmgr launches after handover (logd, pwrmgr, timed, terminal)
query devmgr's registry for their device endpoints and hardware caps, which devmgr serves
only after initial enumeration and binding complete. A device endpoint is queried with one
label, `devmgr_labels::QUERY_DEVICE`, sent on a class SEND: a SEND on devmgr's registry endpoint
whose badge names a class and the verb bits the reply carries. The class and the verbs come from
the badge, never the message, and a registry SEND without a class slot gets `UNAUTHORIZED`.
svcmgr mints each class SEND (`devmgr_labels::MINT_CLASS_SEND`, gated on `CLASS_AUTHORITY`) from
a class file and publishes it seed-only as `devmgr.class.<class>`
([driver-binding.md](driver-binding.md) § Device Classes). The dependency ordering is fixed by
init's bootstrap sequence (devmgr before vfsd) and by svcmgr launching those consumers only
after handover; devmgr and vfsd are `restart = never`, so no restart ordering exists.

devmgr binds each PCI device the most specific driver declaration matches
([driver-binding.md](driver-binding.md) § Matching), each driver with its own service endpoint; a
declaration that requires an interrupt binds only a device devmgr can give a wired line (a device
on a line another device already holds gets a derivation of that line, § Interrupt Delivery).
devmgr serves any driver it spawns, the platform drivers (serial, framebuffer, and RTC) included,
only once it has reported its device set up (`devmgr_labels::DRIVER_READY`). A driver that dies
first, its device setup failed, or that neither reports nor dies within devmgr's settle bound
(`SETTLE_TIMEOUT`, 10 s: twice the VirtIO reset timeout, the longest bounded wait of a driver's
setup) is withdrawn and never served; one still pending at the bound is destroyed. devmgr waits
for every driver of a batch to report, die, or overrun the bound before it serves that batch's
classes (devmgr's
[responsibilities.md § Responsibilities](../services/devmgr/docs/responsibilities.md#responsibilities)
gives the settle, the bound's derivation, and the serving order). `QUERY_DEVICE` selects one of a
class's drivers by an optional instance ordinal in `data[1]` (absent means the first): the
ordinal counts the served drivers of that class in PCI segment, bus, device, function order, is
not stable across boots, and is fixed once the class settles. devmgr
observes every driver's death for the rest of the boot: a served driver that dies is withdrawn, its
service endpoint revoked so callers queued on it return, and a tombstone holds its ordinal, whose
query replies `devmgr_errors::WITHDRAWN` while the ordinals after it keep their drivers; a
withdrawn serial, framebuffer, or RTC driver's query replies `WITHDRAWN` too. Past the last
served driver of a class the reply is `devmgr_errors::NO_DEVICE`. vfsd queries every
block ordinal from 0, passing a `WITHDRAWN` one, until another reply is not `SUCCESS`, and holds
every live disk; the terminal sends none, so it binds the first input instance.

The debug port is a byte transport apart from the console's UART, which a debugger stub, the
[GDB stub](../services/gdbstub/README.md), owns to speak to a host debugger: the first
virtio-console device in PCI order (its declaration's instance limit is 1), driven by the
[virtio-console driver](../services/drivers/virtio/console/README.md), which serves the serial
protocol. devmgr hands it out only on `QUERY_DEVICE` sent on the `debug-port` class SEND, which
svcmgr publishes seed-only as `devmgr.class.debug-port`, so only a service whose definition
seeds that name reaches the port. A machine presents the device only
when a launch asks for it (`--debug-port`); a boot without it has no debug port, and the query
replies `NO_DEVICE`. A further console device is left unbound.

### Driver binary sources

devmgr loads driver binaries from one of two places:

- **Boot bundle** — bootstrap-essentials (virtio-blk, serial,
  framebuffer, and the IOMMU driver of the architecture's family, `iommu-vtd`
  on x86-64 and `iommu-riscv` on riscv64, which must confine the disk before
  its driver maps a ring) ship in the bundle and
  arrive untagged as Memory caps in devmgr's MODULE bootstrap rounds, with any platform
  description table. devmgr tells a module by its content: it reads the declaration of each ELF
  image, parses valid UTF-8 text as a platform description table, and logs and releases anything
  else. It binds the PCI and platform records those declarations match in the boot settle batch
  (the IOMMU family record in a batch of its own before it), and spawns every driver via
  `procmgr_labels::CREATE_PROCESS`.
- **On-disk rootfs** — non-essentials (the per-arch RTC, bound to its platform record, the
  [virtio-input keyboard driver](../services/drivers/virtio/input/README.md), the debug port's
  virtio-console
  driver, and the test-only `test-dma`) live at `/services/drivers/` and are loaded
  via `procmgr_labels::CREATE_FROM_FILE`. The test-only `test-fault` binary lives in
  `/tests/drivers/`, which no boot-time pass reads; devmgr binds it only on
  `devmgr_labels::BIND_DRIVERS` (gated on `BIND_AUTHORITY`, which only svctest's seed-only
  `devmgr.bind` cap carries), so a boot without svctest binds none. Every binary there carries its
  declaration in the ELF note section `.note.seraph.driver`; devmgr reads the declaration of each
  entry once `SET_DRIVERS_DIR` arrives and binds the PCI devices still unbound: virtio-input,
  virtio-console, and test-dma, none of which is on the read-the-disk critical path, ship only
  there and are bound there. A device whose declaration takes its interrupt as optional
  and for which devmgr can give no wired line (for instance, its line lies outside the Interrupt
  range devmgr holds) is delivered a resource list with no `Interrupt` resource, and its driver
  polls its queue.
  Post-handover, svcmgr walks its universal root to `/services/drivers/` and hands devmgr that
  subtree cap via `devmgr_labels::SET_DRIVERS_DIR` (gated by `DRIVERS_DIR_AUTHORITY`, minted from
  the devmgr-registry source init endows svcmgr with; sent at `LOOKUP | READ | READDIR` rights
  only — devmgr lists the directory and cannot reach outside the drivers subtree). The handshake
  is specified in
  [`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md) and
  [`services/svcmgr/docs/ipc-interface.md`](../services/svcmgr/docs/ipc-interface.md). Devmgr
  replies SUCCESS before doing any spawn work so svcmgr never blocks on driver bring-up; the actual
  walk + `CREATE_FROM_FILE` + bootstrap rounds, and the settle of those drivers, run on devmgr's
  control thread after `ipc_reply`, while its registry workers go on serving; a query that would
  find no driver waits until the settle has ended. The spawn is at-most-once per boot;
  on failure (binary missing, ELF corrupt, hardware-carve failure, OOM, a driver that died or did
  not report ready within the settle bound, etc.) devmgr replies `devmgr_errors::NO_DEVICE` on
  subsequent `QUERY_DEVICE` calls on the rtc, input, and debug-port classes and clients
  ([timed](../services/timed/README.md) degrades to its no-RTC path; the terminal, today's only
  input class consumer, logs and exits). Before `SET_DRIVERS_DIR` arrives the reply is the same
  `NO_DEVICE`, so a client that cannot proceed without the device MAY retry a bounded number of
  times (the terminal does), while a client with a no-device path treats the first `NO_DEVICE` as
  terminal; no client retries without a bound (`devmgr_errors::NO_DEVICE` in `shared/ipc` owns the
  rule). Keeping non-essentials out of the boot bundle keeps the ESP-loaded image to what the system
  needs before the rootfs is mounted, so on-disk loading is preferred for anything not on the
  read-the-disk-in-the-first-place critical path.

Storage-side cap delegation downstream of devmgr (whole-disk
endpoint → vfsd → partition-scoped endpoint → fs driver) is
specified in [`docs/storage.md`](storage.md).

---

## Summarized By

[Device Tree Parsing](../core/boot/docs/dtb.md),
[Firmware Parsing](../core/boot/docs/firmware-parsing.md),
[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[Architecture Overview](architecture.md), [Capability Model](capability-model.md),
[Console Model](console-model.md),
[Memory Model](memory-model.md), [Platform Requirements](platform-requirements.md),
[Storage](storage.md), [services/devmgr/README.md](../services/devmgr/README.md),
[devmgr Responsibilities and Capabilities](../services/devmgr/docs/responsibilities.md),
[services/drivers/README.md](../services/drivers/README.md),
[services/drivers/cmos/README.md](../services/drivers/cmos/README.md),
[Driver Model](../services/drivers/docs/driver-model.md),
[services/drivers/goldfish-rtc/README.md](../services/drivers/goldfish-rtc/README.md),
[services/drivers/iommu/core/README.md](../services/drivers/iommu/core/README.md),
[services/drivers/iommu/riscv/README.md](../services/drivers/iommu/riscv/README.md),
[services/drivers/iommu/store/README.md](../services/drivers/iommu/store/README.md),
[services/drivers/iommu/vtd/README.md](../services/drivers/iommu/vtd/README.md),
[services/drivers/test-dma/README.md](../services/drivers/test-dma/README.md),
[services/drivers/test-fault/README.md](../services/drivers/test-fault/README.md),
[services/drivers/virtio/blk/README.md](../services/drivers/virtio/blk/README.md),
[services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md),
[services/drivers/virtio/core/README.md](../services/drivers/virtio/core/README.md),
[services/drivers/virtio/input/README.md](../services/drivers/virtio/input/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[services/vfsd/README.md](../services/vfsd/README.md), [xtask/README.md](../xtask/README.md)
