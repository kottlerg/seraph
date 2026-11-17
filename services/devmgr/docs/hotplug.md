# Hotplug

How devmgr learns that a device was added to or removed from a running machine, and how the
device's record and driver follow.

Implementation status: partly implemented
([#939](https://github.com/kottlerg/seraph/issues/939)). PCI Express native hotplug's add path is
implemented. Its removal path (§ Removal) and the ACPI PCI hotplug source (§ Event Sources) are
design intent; not yet implemented.

---

## Event Sources

devmgr learns of a hot-added PCI function from one of two sources, chosen per machine by who
controls the slot:

| Source | Machine | Grant |
|---|---|---|
| PCI Express native hotplug, polled by devmgr (§ Native Hotplug) | riscv64 `virt`; x86-64 q35 with QEMU's ACPI PCI hotplug off | the host bridge's `_OSC` grants native hotplug control, or the machine's platform description table carries `pcie_native_hotplug = yes` |
| ACPI PCI hotplug, through acpid (design intent; not yet implemented, [#1096](https://github.com/kottlerg/seraph/issues/1096)) | x86-64 q35 by default | `_OSC` withholds native control |

A slot is managed natively only under a grant: the `_OSC` result acpid reports for the slot's
host bridge has the native hotplug bit (`OSC_NATIVE_HOTPLUG`, PCI Firmware Specification r3.2
§ 4.5.1), or the platform description table grants it
([docs/driver-binding.md](../../../docs/driver-binding.md#platform-description-tables)
§ Platform Description Tables). Without either, devmgr never touches the slot: a slot that
advertises Hot-Plug Capable while firmware keeps control (QEMU's default q35 root port, `_OSC`
control 0x1E) is driven by firmware's own hotplug, and a second agent on its Slot Control would
contend with it. The platform key exists for a machine whose `_OSC` withholds native control
while it offers no ACPI hotplug either (QEMU's riscv64 `virt`), so no other agent drives the
slot. Both sources feed one add path (§ Add Job).

---

## Native Hotplug

### Slot Discovery

The boot scan finds the slots: each type-1 function whose PCI Express capability is a Root Port
or a switch Downstream Port with Slot Implemented, and whose Slot Capabilities has Hot-Plug
Capable (`firmware::hotplug::read_slot`). A slot carries the port's address, its secondary and
subordinate buses, and the non-prefetchable and prefetchable memory windows firmware programmed
into its type-1 header; a window whose limit lies below its base is off. A port whose secondary
bus is not above its own bus is unconfigured and is no slot.

After the IOMMU driver is bound and before any other pass, devmgr drops two kinds of slot,
logged:

- a slot whose buses hold an IOMMU unit's function (a record the IOMMU pass bound): its removal
  would take the unit;
- a window that lies outside every aperture devmgr was given at boot is closed, since no BAR in
  it could be carved.

### Grant

On each turn of its control loop, after acpid's jobs, devmgr checks every slot still waiting: under
a grant (§ Event Sources) it hands the slot to the poller, logged `managed (native control by _OSC)`
or `by the platform table`; when the host bridge's `_OSC` result has arrived and withholds native
control or reports a failed evaluation, with no platform grant, the slot is never managed, logged
`not managed`. A slot whose `_OSC` result has not arrived waits. The slot's host bridge is the one
whose `_CRS` bus window holds the port's bus, else the one whose root bus it is
(`firmware::hotplug::host_bridge`).

### Poller

The first managed slot starts the poller, a devmgr thread at devmgr's priority. It holds a
derivation of each managed port's configuration page and touches only the port's PCI Express
slot and link registers. At take-over it turns off the slot's event interrupt enables (the
poller reads the latches instead, so the slot needs no message target, no IOMMU domain and no
`_PRT`), clears the latches, and holds the slot occupied when a card is present and a live
record lies behind it, else empty.

Every `HOTPLUG_POLL_MS` (1000) it reads each slot's Slot Status, clears the event latches it
holds (Attention Button Pressed, Power Fault Detected, MRL Sensor Changed, Presence Detect
Changed, Data Link Layer State Changed; all RW1C, so a poll loses no event), and acts
(`firmware::hotplug::next`):

| Slot | Slot Status | Action |
|---|---|---|
| empty | Presence Detect State set | power up, then post the arrival; the slot is occupied, or failed when the link does not come up |
| occupied | presence lost, or Attention Button Pressed | the removal path (§ Removal) |
| failed | presence lost | the slot is empty again |

Power-up writes Slot Control with the slot's power on where it has a Power Controller and its
power indicator on where it has one. Where the slot reports Command Completed, each Slot Control
write clears the latch, writes, and waits up to `SLOT_WAIT_MS` (1000) for it. Where the port
reports Data Link Layer Link Active, the poller waits up to `SLOT_WAIT_MS` for the link and then
`LINK_SETTLE_MS` (100) before any configuration request goes below the port (PCI Express Base
Specification r4.0 § 6.6.1); where it does not report it, it waits `SLOT_WAIT_MS`. A link that
does not come up is logged, the slot powered off, and the slot held failed until the card is
removed. An arrival is posted to the control thread over a channel, with a signal of its job
notification.

### Add Job

The control thread runs each posted arrival (`hotplug::Hotplug::run`). It reads function 0 of
device 0 on the slot's secondary bus, and functions 1 to 7 when function 0 is multi-function: a
downstream port forwards configuration requests to device 0 only. For each function present
(`firmware::hotplug::place`):

1. a type-1 function (a hot-added switch or bridge) is logged and neither descended into nor
   recorded;
2. its MMIO BARs are placed in the slot's windows (`firmware::hotplug::assign`): each BAR
   naturally aligned, the largest first, each at the lowest free base, clear of the BARs of the
   live records on the slot's buses. A 64-bit prefetchable BAR goes in the prefetchable window,
   or in the non-prefetchable window when it does not fit there; every other BAR goes in the
   non-prefetchable window. I/O BARs are not placed;
3. the BARs are written with the function's Memory Space decode off, and the function is read
   again; a BAR that does not read back at its placed base fails the function;
4. its record is appended to the PCI records (`PciRecords::append`), after every earlier record.

A function whose BARs do not fit (a size not a power of two, no open window the BAR may go in, or
no room left in it), or do not read back as written, is logged and not recorded, so no driver is
bound to it. An append the records refuse (a live record already holds the address, or no
memory to grow them) is logged with its reason, and the records are as they were.

Free window space is computed from the live records at each placement and devmgr keeps no
allocator state, so a removed record's BARs free their space by the record's removal.

### Binding

Once an arrival appended a record and the drivers directory is installed (`SET_DRIVERS_DIR`), devmgr
runs a drivers-directory pass over the directory cap it keeps, against the records still unbound,
the appended ones among them, under the bounds of the `SET_DRIVERS_DIR` pass, as its own settle
batch, the hotplug batch ([docs/driver-binding.md](../../../docs/driver-binding.md#hotplug) §
Hotplug). Before `SET_DRIVERS_DIR` the record is only appended, and the directory's pass binds it. A
hot-added function takes the next ordinal of its class, and a bound driver signals the class's
watches.

A hot-added function's `INTx` route is computed through the bridges of the records
(`PciRecords::append`). On x86-64 no firmware programmed its Interrupt Line and devmgr reads no
`_PRT` route for it, so it has no wired line: it is given message-signaled vectors where its
driver's declaration takes them, and a driver that requires an interrupt it cannot be given that
way is refused, logged ([#1096](https://github.com/kottlerg/seraph/issues/1096) adds the
route).

### Removal

Design intent; not yet implemented
([#939](https://github.com/kottlerg/seraph/issues/939)). The poller logs a removal or an
attention-button press on an occupied slot, and devmgr does nothing else: the records and
drivers behind the slot stay. The removal path withdraws every live record on the slot's buses
through the withdrawal order of
[responsibilities.md](responsibilities.md#withdrawing-a-driver) § Withdrawing a Driver, honours
the attention button's 5 s abort window, and powers the slot off only after the withdrawal
returns.

---

## Summarized By

[Driver Binding](../../../docs/driver-binding.md), [acpid and devmgr](../../acpid/docs/devmgr.md),
[services/devmgr/README.md](../README.md), [PCI Enumeration](pci-enumeration.md),
[devmgr Responsibilities and Capabilities](responsibilities.md)
