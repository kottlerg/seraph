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
2. **Device taken and reset.** devmgr then revokes the driver's BAR capabilities and resets the
   device, waiting for the reset to be confirmed for at most `RESET_TIMEOUT` (5 s).
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

What the boots exercise of this order, and why none withdraws a `VirtIO` driver, is stated in
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md#responsibilities)
§ Responsibilities.

---

## DMA Authorisation

A DMA-capable driver programs its device only with device addresses devmgr hands it, never with
a physical address. devmgr gives the driver of each DMA-capable device it binds (a PCI function
with a BAR and an IRQ) a DMA capability: a SEND on devmgr's DMA endpoint badged with the device's
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
the device's limit (the width the device's remapping unit translates, narrowed for a device whose
DMA reaches fewer address bits; [limits.md](limits.md)), and the mapping is installed in the
IOMMU's tables, through the IOMMU driver (§ IOMMU Discovery and Programming), before devmgr
replies, and withdrawn from them before devmgr deletes its cap at `DMA_UNMAP`, so the device
reaches exactly the frames mapped for it. With none, the device can reach memory only at physical
addresses, so the address devmgr returns is the frames' physical address and the mapping is
bookkeeping alone. The protocol and the driver's code are the same in both modes.

devmgr serves the DMA endpoint on a thread of its own, apart from the registry loop, because that
loop makes nested calls (a driver spawn from the root filesystem reads the binary through the
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
reporting) runs in a separate IOMMU driver process, one per IOMMU family, not in devmgr: VT-d's
is `iommu-vtd` ([services/drivers/iommu/vtd/README.md](../services/drivers/iommu/vtd/README.md))
and the RISC-V IOMMU's is `iommu-riscv`
([services/drivers/iommu/riscv/README.md](../services/drivers/iommu/riscv/README.md)), both over
the family-independent `iommu-core`
([services/drivers/iommu/core/README.md](../services/drivers/iommu/core/README.md)) and the shared
table-page store `iommu-store`
([services/drivers/iommu/store/README.md](../services/drivers/iommu/store/README.md)). For each
unit it discovers, devmgr carves an `Mmio` cap for the unit's register range through the same
aperture-carving flow as any other device (for a RISC-V IOMMU, after turning on the function's
memory decode and bus mastering through its configuration page) and moves it to that family's
IOMMU driver, keeping no copy, with the unit's PCI segment and its scope resolved against the PCI
topology. devmgr keeps the DMA endpoint, its
`devmgr_dma_labels` contract, and per-device policy, and reaches the IOMMU driver over
`ipc::iommu_labels` to attach a device to a domain of its own, install and withdraw mappings,
block a device, and take the faults the units recorded, so drivers see the same protocol whichever
IOMMU, or none, sits behind it. The kernel does not read or write IOMMU registers and holds no
per-IOMMU state.

At boot devmgr spawns the IOMMU driver from its boot module before any DMA-capable driver, in a
settle batch of its own (`CREATE_PROCESS` with `CREATE_PINNED`, since the units walk its table
pages, `CREATE_DMA_HOLD`, and `CREATE_PHYS_ACCESS`, since the units are programmed with physical
addresses (§ Physical Addresses), at `BOOT_DRIVER_PRIORITY`, since devmgr's DMA thread calls it on
every mapping). The driver programs each unit with empty tables and turns translation on, so from
its ready report every function a unit translates reaches nothing until devmgr attaches it, the
functions no driver binds included. devmgr never releases the driver's hold, and deletes its
release token at the spawn: a unit may walk any of its table pages while translation is on, so
they stay quarantined for the boot. For each
DMA-capable device devmgr then decides, before it grants the device DMA:

- **Confined.** A unit translates the device: devmgr attaches it (`ATTACH`) and grants it DMA in
  that domain.
- **Refused.** An RMRR names the device, whose firmware expects it to keep reaching a reserved
  region: devmgr refuses it with a log line, since identity-mapping reserved regions is
  [#773](https://github.com/kottlerg/seraph/issues/773). A device whose `ATTACH` fails is
  refused too, since its unit blocks it. So is a device whose unit devmgr could not hand over: that
  unit is never programmed, so it does not block the device, but devmgr does not run a device
  unconfined behind an IOMMU it found. So is a device the RIMT gives an IOMMU device ID other than
  its requester ID, since the IOMMU driver addresses each device's context by its requester ID.
- **Unconfined.** No unit translates the device: it runs DMA-unsafe.

When no unit is found, no IOMMU driver module was delivered, or the driver does not report ready
within the settle bound, devmgr logs once that DMA runs unconfined and every device runs so. A
driver that fails its own setup turns translation off again before it exits, so it leaves no device
blocked. A driver that dies or hangs after it turned a unit's translation on, before it reported
ready, leaves that unit blocking every device behind it, which devmgr cannot undo, since it keeps no
register cap; its log line says so, and those devices' DMA fails. The case that is not an absent
IOMMU is a driver that dies after it reported ready: the units go on translating through the tables
it left, so devmgr cannot fall back to unconfined DMA. It fails closed. A death watch thread of
devmgr's own sees the death at once, independent of the registry loop, which may be blocked in a
call to the dead driver. devmgr then logs once, refuses every later `DMA_MAP` of every confined
device, answers any of its own calls still queued on the dead driver's endpoint with an error, and
withdraws the driver of every confined device; it restarts nothing, restartability being
[#262](https://github.com/kottlerg/seraph/issues/262). Invalidation is synchronous, through VT-d's
invalidation registers and through the RISC-V IOMMU's command queue, each polled to completion,
two IPC hops per mapping; batching it is
[#772](https://github.com/kottlerg/seraph/issues/772). Faults are polled, not signalled, until
message-signalled interrupts exist ([#325](https://github.com/kottlerg/seraph/issues/325)), and
devmgr logs each one against its device.

When devmgr binds a DMA-capable (PCI BAR + IRQ) driver, it spawns the driver
with `procmgr_labels::CREATE_PINNED`, so the driver's memory is eager-mapped,
and delivers its BAR `Mmio` caps, optional IRQ, endpoint caps, and DMA
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

Implementation status: the kernel's binding mechanism below, its trigger and polarity mode, and
devmgr's sharing of a line among the devices on it are implemented; message-signaled interrupts
are design intent (below).

A driver receives a wired interrupt line as a single-line `Interrupt` cap and binds it to a
Notification with `SYS_IRQ_REGISTER`. The kernel models each wired line as a source with up to
`MAX_IRQ_BINDINGS` (64) bindings, one per bound Interrupt object; a copy or derivation of an
Interrupt cap references a fresh object over the same line, so every capability to a line is a
binding of its own. devmgr splits each PCI device's line once from its range, the first time a
device on it needs it, holds that cap for the boot, and hands every driver on the line, the first
included, a derivation of it, so PCI functions that share an `INTx` line are all served
([services/devmgr/docs/pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md)
§ Per-Device Capability Creation). The UART line is the exception: devmgr carves it exclusive,
holds nothing, and moves the cap itself to the serial driver (devmgr's
[responsibilities.md § Responsibilities](../services/devmgr/docs/responsibilities.md#responsibilities)).

- **Bind.** `SYS_IRQ_REGISTER` through an unbound object adds a binding; the line's first binding
  records the call's trigger and polarity mode and routes the line at its controller in it, and
  every new binding masks the line and owes an acknowledgement, so the line stays masked until
  the new receiver's first `SYS_IRQ_ACK`. Every later binding passes the same mode, or is refused
  with `InvalidArgument`. Through a bound object it rebinds that binding to the new notification.
  A binding past the bound is refused with `QuotaExceeded`.
- **Deliver.** Each assertion masks the line, marks every binding as owing an acknowledgement,
  signals every bound notification, and completes at the controller. A receiver whose device did
  not assert reads its device's interrupt status and finds nothing. Every receiver on a line
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
  `virt` NS16550 is PLIC source 10, against `INTx` sources 32 to 35), so the exclusivity costs no
  device a cap in practice.
- **Acknowledge.** `SYS_IRQ_ACK` clears its own binding's debt and unmasks the line only when no
  binding owes one; a repeated acknowledgement changes nothing.
- **Unbind.** A binding goes when its Interrupt object is freed (its capability deleted, revoked,
  or torn down with its holder's CSpace) or its Notification is; the line is unmasked when the
  remaining bindings owe nothing, and released at its controller when none remains. A driver that
  dies while its device asserts a level-triggered line leaves the device asserting with no
  receiver to clear it, so the line's other receivers are signalled again on each unmask; devmgr
  ends that by resetting a `VirtIO` device when it withdraws the device's driver
  ([services/drivers/docs/driver-model.md](../services/drivers/docs/driver-model.md#withdrawal)
  § Withdrawal).

The contract is specified in [core/kernel/docs/syscalls.md](../core/kernel/docs/syscalls.md)
§ `SYS_IRQ_REGISTER` and § `SYS_IRQ_ACK`. On riscv64 the PLIC gateway is level-sensitive, so an
assertion that arrives while the line is masked is delivered at the unmask (QEMU's PLIC model,
though, does not pend a source again that stays asserted across its claim and completion, which the
drivers' timed polls cover); the mode is validated and programs nothing. On x86-64 the line's I/O
APIC entry is programmed with the mode's trigger and polarity
(core/kernel/src/arch/x86_64/ioapic.rs), and a level-triggered entry likewise delivers at the unmask
an assertion still held. devmgr gives each PCI driver the mode of its `INTx` line, which every
driver on the line then passes: on x86-64 the trigger and polarity of the MADT Interrupt Source
Override that names the line's GSI, field by field, with the PCI default (level-triggered,
active-low) for a field the override leaves conforming to its bus and for a line no override names;
on riscv64 level-triggered, active-high
([services/devmgr/docs/pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md) step 4). On a
line programmed edge-triggered and shared, an assertion while the line is masked or another device
holds it high raises no new edge, and the device stays asserted until its interrupt status is read,
so no later assertion on the line raises one either. The VirtIO interrupt-service thread's timed
read (`ISR_POLL_MS`) clears that assertion and signals the waiting path, and the driver's timed poll
finds its completion meanwhile (virtio-blk's `IRQ_WAIT_TIMEOUT_MS`, virtio-input's
`POLL_INTERVAL_MS`), so the loss is latency, not a hang. Devices that need several interrupts are to
get message-signaled ones (design intent, not yet implemented;
[#325](https://github.com/kottlerg/seraph/issues/325)), as further sources beside the wired ones.
The kernel delivers each routed line to one CPU, chosen when the line is first bound by taking the
CPUs in turn, so the interrupts of several devices spread over the CPUs. On x86-64 only CPUs whose
APIC id an I/O APIC can name (below `0xFF`, the broadcast id) take part. The mechanism is specified
in [core/kernel/docs/arch-interface.md](../core/kernel/docs/arch-interface.md) § `interrupts`.

---

## Relationship to Other Services

```
init
 ├── devmgr  (platform caps + firmware table caps)
 │    ├── driver/iommu-vtd         (VT-d unit MMIO caps; iommu_labels, devmgr only; x86-64)
 │    ├── driver/iommu-riscv       (IOMMU BAR 0 MMIO caps; iommu_labels, devmgr only; riscv64)
 │    ├── driver/virtio-blk        (MMIO + IRQ caps; QUERY_BLOCK_DEVICE)
 │    ├── driver/virtio-input      (MMIO + opt. IRQ; QUERY_INPUT_DEVICE; on-disk)
 │    ├── driver/serial            (UART hw + IRQ caps; QUERY_SERIAL_DEVICE)
 │    ├── driver/framebuffer       (MMIO cap; QUERY_FRAMEBUFFER_DEVICE)
 │    └── driver/{cmos-rtc,goldfish-rtc} (RTC hw cap; QUERY_RTC_DEVICE)
 ├── vfsd  (receives storage endpoint via QUERY_BLOCK_DEVICE)
 ├── ...
 └── svcmgr
      ├── logd     (serial, framebuffer endpoints via QUERY_*_DEVICE)
      ├── pwrmgr   (ACPI tables + shutdown hw via QUERY_ACPI_TABLE / QUERY_SHUTDOWN_DEVICE)
      ├── timed    (RTC endpoint via QUERY_RTC_DEVICE)
      └── terminal (input, framebuffer, serial endpoints via QUERY_*_DEVICE)
```

vfsd and the consumers svcmgr launches after handover (logd, pwrmgr, timed, terminal)
query devmgr's registry for their device endpoints and hardware caps, which devmgr serves
only after initial enumeration and binding complete. The dependency ordering is fixed by
init's bootstrap sequence (devmgr before vfsd) and by svcmgr launching those consumers only
after handover; devmgr and vfsd are `restart = never`, so no restart ordering exists.

devmgr spawns one driver for every virtio-input device it enumerates and for every virtio-blk
device it can give an IRQ cap (virtio-blk requires one; a device on a line another device already
holds gets a derivation of that line, § Interrupt Delivery), each with its own service endpoint.
devmgr serves any driver it spawns, those and the serial, framebuffer, and RTC drivers, only once
it has reported its device set up (`devmgr_labels::DRIVER_READY`). A driver that dies first, its
device setup failed, or that neither reports nor dies within devmgr's settle bound
(`SETTLE_TIMEOUT`, 10 s: twice the VirtIO reset timeout, the longest bounded wait of a driver's
setup) is withdrawn and never served; one still pending at the bound is destroyed. devmgr waits
for every driver of a batch to report, die, or overrun the bound before it serves that batch's
classes (devmgr's
[responsibilities.md § Responsibilities](../services/devmgr/docs/responsibilities.md#responsibilities)
gives the settle, the bound's derivation, and the serving order). `QUERY_BLOCK_DEVICE` and
`QUERY_INPUT_DEVICE` select one of those drivers by an optional instance ordinal in `data[1]`
(absent means the first): the ordinal counts the served drivers of that class in PCI segment, bus,
device, function order, is not stable across boots, and is fixed once the class settles. devmgr
observes every driver's death for the rest of the boot: a served driver that dies is withdrawn, its
service endpoint revoked so callers queued on it return, and a tombstone holds its ordinal, whose
query replies `devmgr_errors::WITHDRAWN` while the ordinals after it keep their drivers; a
withdrawn serial, framebuffer, or RTC driver's query replies `WITHDRAWN` too. vfsd queries every
block ordinal from 0, passing a `WITHDRAWN` one, until another reply is not `SUCCESS`, and holds
every live disk; the terminal sends none, so it binds the first input instance.

### Driver binary sources

devmgr loads driver binaries from one of two places:

- **Boot bundle** — bootstrap-essentials (virtio-blk, serial,
  framebuffer, and the IOMMU driver of the architecture's family, `iommu-vtd`
  on x86-64 and `iommu-riscv` on riscv64, which must confine the disk before
  its driver maps a ring) ship in the bundle and
  arrive as Memory caps in devmgr's MODULE bootstrap round. devmgr spawns
  them via `procmgr_labels::CREATE_PROCESS` during initial enumeration.
- **On-disk rootfs** — non-essentials (the per-arch RTC and the [virtio-input keyboard
  driver](../services/drivers/virtio/input/README.md)) live at `/services/drivers/` and are loaded
  via `procmgr_labels::CREATE_FROM_FILE`. The test-only `test-orphan`, `test-fault`, and
  `test-dma` binaries also live there; devmgr spawns them only on
  `devmgr_labels::TEST_SPAWN_ORPHAN`, `TEST_SPAWN_FAULT_DRIVERS`, and `TEST_SPAWN_DMA_DRIVER`
  (gated on `TEST_LABEL_AUTHORITY`, which only svctest's seed-only `devmgr.test` cap carries), so
  a boot without svctest spawns none. virtio-input is
  PCI-enumerated during the initial scan — its BAR/IRQ caps are carved and stashed then — but its
  spawn is deferred to this path, since a keyboard is not on the read-the-disk critical path. A PCI
  device devmgr can give no IRQ cap (for instance, its line lies outside the Interrupt range devmgr
  holds) is delivered a bootstrap that names its IRQ slot absent, and its driver polls its queue.
  Post-handover, svcmgr walks its universal root to `/services/drivers/` and hands devmgr that
  subtree cap via `devmgr_labels::SET_DRIVERS_DIR` (gated by `DRIVERS_DIR_AUTHORITY`, minted from
  the devmgr-registry source init endows svcmgr with; sent at `LOOKUP | READ` rights only — devmgr
  cannot reach outside the drivers subtree). The handshake is specified in
  [`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md) and
  [`services/svcmgr/docs/ipc-interface.md`](../services/svcmgr/docs/ipc-interface.md). Devmgr
  replies SUCCESS before doing any spawn work so svcmgr never blocks on driver bring-up; the actual
  walk + `CREATE_FROM_FILE` + bootstrap rounds, and the settle of those drivers, run after
  `ipc_reply` and before devmgr returns to its next `ipc_recv`. The spawn is at-most-once per boot;
  on failure (binary missing, ELF corrupt, hardware-carve failure, OOM, a driver that died or did
  not report ready within the settle bound, etc.) devmgr replies `devmgr_errors::NO_DEVICE` on
  subsequent `QUERY_RTC_DEVICE` / `QUERY_INPUT_DEVICE` calls and clients
  ([timed](../services/timed/README.md) degrades to its no-RTC path; the terminal, today's only
  `QUERY_INPUT_DEVICE` consumer, logs and exits). Before the spawn has run the reply is the same
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
[services/drivers/test-orphan/README.md](../services/drivers/test-orphan/README.md),
[services/drivers/virtio/blk/README.md](../services/drivers/virtio/blk/README.md),
[services/drivers/virtio/core/README.md](../services/drivers/virtio/core/README.md),
[services/drivers/virtio/input/README.md](../services/drivers/virtio/input/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[services/vfsd/README.md](../services/vfsd/README.md), [xtask/README.md](../xtask/README.md)
