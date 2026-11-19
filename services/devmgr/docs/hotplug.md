# Hotplug

How devmgr learns that a device was added to or removed from a running machine, and how the
device's record and driver follow.

Implementation status: implemented
([#939](https://github.com/kottlerg/seraph/issues/939),
[#1096](https://github.com/kottlerg/seraph/issues/1096)).

---

## Event Sources

devmgr learns of a hot-added PCI function from one of two sources, chosen per machine by who
controls the slot:

| Source | Machine | Grant |
|---|---|---|
| PCI Express native hotplug, polled by devmgr (§ Native Hotplug) | riscv64 `virt`; x86-64 q35 with QEMU's ACPI PCI hotplug off | the host bridge's `_OSC` grants native hotplug control, or the machine's platform description table carries `pcie_native_hotplug = yes` |
| ACPI PCI hotplug, the firmware's, whose events acpid posts (§ ACPI Hotplug) | x86-64 q35 by default | `_OSC` withholds native control, or fails, and no platform table grants it |

A slot is managed natively only under a grant: the `_OSC` result acpid reports for the slot's
host bridge has the native hotplug bit (`OSC_NATIVE_HOTPLUG`, PCI Firmware Specification r3.2
§ 4.5.1), or the platform description table grants it
([docs/driver-binding.md](../../../docs/driver-binding.md#platform-description-tables)
§ Platform Description Tables). Without either, the firmware drives the slot, and devmgr never
writes its port: a slot that advertises Hot-Plug Capable while firmware keeps control (QEMU's
default q35 root port, `_OSC` control 0x1E) is driven by the firmware's own hotplug, and a second
agent on its Slot Control would contend with it. devmgr then acts on the slot only on the events
acpid posts from the firmware's `Notify` (§ ACPI Hotplug). The platform key exists for a machine
whose `_OSC` withholds native control while it offers no ACPI hotplug either (QEMU's riscv64
`virt`), so no other agent drives the slot. Both sources feed one add path (§ Add Job) and one
removal path (§ Removal).

---

## Slots

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

On each turn of its control loop, after acpid's jobs, and in its drivers-directory job once it
knows its platform description tables, before that job's pass, devmgr checks every slot still
waiting (`firmware::hotplug::slot_grant`): under a grant (§ Event Sources) it hands the slot to
the poller, logged `managed (native control by _OSC)` or `by the platform table`; when the host
bridge's `_OSC` result has arrived and withholds native control or reports a failed evaluation,
it leaves the slot to the firmware, logged `firmware hotplug`, and runs the jobs acpid posts for it
(§ ACPI Hotplug), but only once devmgr knows its platform description tables and they grant none.
devmgr knows them at boot when a boot module's table matches the machine, and otherwise once its
drivers-directory job has read the tables of the root filesystem, or knows there is none
([docs/driver-binding.md](../../../docs/driver-binding.md#platform-description-tables)
§ Platform Description Tables). Until then a slot whose `_OSC` result withholds native control
waits, so that result cannot settle the slot to the firmware, a final grant, ahead of a table's
`pcie_native_hotplug`; a slot whose `_OSC` result grants native control is managed at once,
since a table can only add native control, never withdraw it. A slot whose `_OSC` result has not
arrived waits. The slot's host bridge is the one whose `_CRS` bus window holds
the port's bus, else the one whose root bus it is (`firmware::hotplug::host_bridge`). Once the slot
is handed over, devmgr marks the port's record bound (`firmware::hotplug::hold_port`): the poller
writes the port's Slot Control and Slot Status, past the configuration header, so no pass binds the
port and acpid is refused every configuration write to it ([acpid's
devmgr.md](../../acpid/docs/devmgr.md) § Configuration access).

Before the hand-over, and before it leaves a slot to the firmware, devmgr holds the BAR pages of the
functions behind the slot (`hotplug::hold_behind`): what the apertures still hold of the page span
of each MMIO BAR of each live record on the slot's buses (all of it for an unbound record, what its
bind left for a bound one) moves out of the apertures into devmgr's held BAR pages
(`DevmgrCaps::slot_bars`), from which a bind carves the function's BAR caps. A withdrawal gives
every BAR cap of its driver's device back to the held BAR pages (§ Removal), so the pages a bind
carved come back there too. Placement takes only what the apertures hold (§ Add Job), so no
hot-added BAR lands on them. A slot whose pages cannot be held is neither managed nor left to the
firmware, logged `not managed`: devmgr acts on none of its events, and the pages moved before the
failure go back to the apertures.

---

## Native Hotplug

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
| empty | Presence Detect State set | power up, then post the add job; the slot is occupied, or failed when the link does not come up |
| occupied | presence lost or changed, or the link lost | post the removal job; the slot is removing |
| occupied | Attention Button Pressed | blink the power indicator; the slot is pressed, for the abort window |
| pressed | Attention Button Pressed again | the power indicator on; the removal is cancelled, and the slot is occupied |
| pressed | presence lost or changed, or the link lost | post the removal job; the slot is removing |
| pressed | the abort window ended | post the removal job; the slot is removing |
| removing | Attention Button Pressed, or Presence Detect Changed, with a card present | nothing until the removal job completes; the slot is powered up after it (§ Removal) |
| removing | anything else | nothing, until the removal job completes (§ Removal) |
| off | Attention Button Pressed, or Presence Detect Changed, with a card present | power up, as for an empty slot |
| off, failed | presence lost | the slot is empty |

The link is lost when the port reports Data Link Layer Link Active, Data Link Layer State Changed
is latched, and Link Active reads clear. A Slot Status of all ones, from a port that does not
answer, changes nothing. The abort window is `ABORT_WINDOW_MS` (5000), `ABORT_POLLS` polls (PCI
Express Base Specification r4.0 § 6.7.1.5).

Power-up writes Slot Control with the slot's power on where it has a Power Controller and its
power indicator on where it has one. Where the slot reports Command Completed, each Slot Control
write clears the latch, writes, and waits up to `SLOT_WAIT_MS` (1000) for it. Where the port
reports Data Link Layer Link Active, the poller waits up to `SLOT_WAIT_MS` for the link and then
`LINK_SETTLE_MS` (100) before any configuration request goes below the port (PCI Express Base
Specification r4.0 § 6.6.1); where it does not report it, it waits `SLOT_WAIT_MS`. A link that
does not come up is logged, the slot powered off, and the slot held failed until the card is
removed. A job, add or removal, is posted to the control thread over one channel, with a signal
of its job notification; the control thread runs the jobs in the order they were posted, each to
its end before the next.

---

## ACPI Hotplug

On a slot the firmware drives, QEMU's q35 ACPI PCI hotplug signals a change with GPE 1. acpid runs
`\_GPE._E01`, which reads the firmware's hotplug registers and notifies each slot that changed:
`Notify(slot, 1)` (Device Check) for a card inserted, `Notify(slot, 3)` (Eject Request) for one the
operator asks to remove. acpid turns each into a job it posts to devmgr with `ACPI_HOTPLUG`, a
Device Check or Bus Check as `HOTPLUG_ADDED` and an Eject Request as `HOTPLUG_REMOVED`, naming the
port whose secondary bus the slot is on ([acpid's README](../../acpid/README.md#hotplug) § Hotplug).
devmgr posts the job on the channel the poller posts on (`hotplug::Hotplug::post_acpi`), so the
control thread runs it in order with the others, each to its end before the next:

- a port that is no slot of the boot scan is answered `NO_DEVICE`, and a job for a slot the
  firmware does not drive (managed, waiting for its grant, or not managed) `REFUSED`, each logged;
- an add job runs the add path (§ Add Job), logged `card added (the firmware's device check)`. One
  for a slot behind which live records lie already, a repeat of the firmware's for a card already
  recorded, records nothing, logged;
- a removal job runs the removal path (§ Removal), logged `removing its functions (the firmware's
  eject request)`.

The job's reply carries the number of functions it recorded or removed. Once a removal's reply has
arrived, acpid runs the slot's `_EJ0`, on which the firmware lets the card go (QEMU unplugs it and
emits `DEVICE_DELETED`), so the driver is withdrawn and the records removed before the card leaves.
acpid then runs the slot's `_OST`, where it has one, with the event and its outcome; QEMU's slots
have none. The poller never watches such a slot, and devmgr writes none of its port's registers:
the firmware powers it.

---

## Jobs

### Add Job

The control thread runs each posted add job (`hotplug::Hotplug::run`). It reads function 0 of
device 0 on the slot's secondary bus, and functions 1 to 7 when function 0 is multi-function: a
downstream port forwards configuration requests to device 0 only. For each function present
(`firmware::hotplug::place`):

1. a type-1 function (a hot-added switch or bridge) is logged and neither descended into nor
   recorded;
2. its MMIO BARs are placed in the free ranges of the slot's windows (`firmware::hotplug::assign`):
   the part of each aperture cap devmgr still holds that lies inside a window, in whole pages
   (`firmware::hotplug::free_ranges`). Each BAR lies inside one free range, since its cap is carved
   from one aperture cap, naturally aligned and aligned to a page, the largest first, each at the
   lowest free base. A BAR takes at least a page, which it shares with no other BAR, since devmgr
   carves a BAR's cap in whole pages. A 64-bit
   prefetchable BAR goes in the prefetchable window, or in the non-prefetchable window when it does
   not fit there; every other BAR goes in the non-prefetchable window. I/O BARs are not placed;
3. the BARs are written with the function's Memory Space decode off, and the function is read
   again; a BAR that does not read back at its placed base fails the function;
4. the page span of each placed BAR moves out of the apertures into devmgr's held BAR pages
   (`DevmgrCaps::slot_bars`, `SpanTable::move_all`), all or none;
5. its record is appended to the PCI records (`PciRecords::append`), after every earlier record.

A function whose BARs do not fit (a size not a power of two, no open window the BAR may go in, or
no room left in it), or do not read back as written, is logged and not recorded, so no driver is
bound to it, and the apertures are as they were. Pages that cannot be held, and an append the
records refuse (a live record already holds the address, or no memory to grow them), are logged
with the reason; the held pages go back to the apertures and the records are as they were.

The aperture table is the one record of what is free. A page devmgr granted acpid
([acpid's devmgr.md](../../acpid/docs/devmgr.md) § Region grants), carved for itself or a driver,
or holds for a function behind a managed slot is not in it, so no placement lands on it; a held
page is in no aperture, so no region grant reaches it. A bind carves a hot-added function's BAR
caps from the held pages. The removal job returns a removed function's held pages to the
apertures (§ Removal).

### Binding

Once an arrival appended a record and the drivers directory is installed (`SET_DRIVERS_DIR`), devmgr
runs a drivers-directory pass over the directory cap it keeps, against the records still unbound,
the appended ones among them, under the bounds of the `SET_DRIVERS_DIR` pass, as its own settle
batch, the hotplug batch ([docs/driver-binding.md](../../../docs/driver-binding.md#hotplug) §
Hotplug). Before `SET_DRIVERS_DIR` the record is only appended, and the directory's pass binds it. A
hot-added function therefore binds from `/services/drivers/` at the auxiliary tier whatever its
class, a disk included: a boot-bundle copy of a driver runs only for the bootstrap
([docs/driver-binding.md](../../../docs/driver-binding.md#declaration-bounds) § Declaration Bounds).
It takes the next ordinal of its class, and a bound driver signals the class's watches.

A hot-added function's `INTx` route is computed through the bridges of the records
(`PciRecords::append`). On x86-64 no firmware programmed its Interrupt Line, so devmgr gives
it the line that the PIC-model `_PRT` table of its host bridge (`PRT_PIC_MODE`, which acpid reads
before `_PIC(1)`) routes to the pin and root-bus device number its interrupt reaches the root bus
with (`firmware::acpid::Bridges::line`). A boot function uses the PIC-model line the firmware
programmed, so the hot-added one shares lines as a boot function at its place would. It has no
wired line when devmgr holds no PIC-model table for the bridge or the table does not route the
pin; it is then given message-signaled vectors where its driver's declaration takes them, and a
driver that requires an interrupt it cannot be given that way is refused, logged. On riscv64 the
line is the `virt` swizzle onto the APLIC sources 32 to 35.

### Removal

On a slot the firmware drives, a removal is the firmware's eject request (§ ACPI Hotplug). On a
managed slot it is the card leaving: pulled (presence lost or changed, so a card pulled and
inserted, or swapped, within one poll is removed and then added again, or the link lost), or asked
for with the attention button, whose press blinks the power indicator for the abort window; a second
press within it cancels the removal, and the indicator is on again. The poller posts the slot's
removal job, logged `removing its functions` with the cause, and holds the slot removing until the
job completes, whatever Slot Status reads meanwhile: a card inserted, pressed or pulled then is
acted on only after the completion. The slot keeps whether a card was inserted or the button pressed
while it was removing, so that card is powered up after the completion without a further press, on a
slot with no attention button as on one with it. A removal posted for a card changed in the slot, or
in the poll of a second press within the abort window, which asks to keep the card, starts asked for
the same way; one posted in the poll of a first press does not, since that press asks for the
removal.

The control thread runs the removal job (`firmware::hotplug::remove`), in this order:

1. it withdraws the driver of each live record on the slot's buses
   (`Registry::withdraw_at`): the driver is taken out of its class, its tombstone left and the
   class's watchers signalled, and withdrawn through the order of
   [responsibilities.md](responsibilities.md#withdrawing-a-driver) § Withdrawing a Driver. That
   withdraws its DMA and has the IOMMU block the device, clears Bus Master Enable, revokes the
   driver's copies of the device's BAR caps, disables its message-signaled vectors and clears
   their remapping entries, resets and destroys the driver, and releases its held memory only once
   the device is blocked or confirmed quiet. Each of its device's BAR caps (its `Mmio` resources'
   and its MSI-X table's) is given back to the held BAR pages over the range it covers
   (`PciDeviceCaps::release`), once every copy derived from it is revoked, and merged there with
   each adjacent held span inside its BAR's pages (`bind::return_bar`); a cap whose copies cannot
   be revoked, or that the table cannot record, is deleted, logged, and its pages are lost for the
   boot. A withdrawal asks the driver nothing, so a driver that does not answer cannot
   delay it;
2. it quiesces each of those functions (`firmware::hotplug::quiesce`): memory decode and Bus
   Master Enable off, Interrupt Disable set, so a function with no driver answers at none of its
   BARs either;
3. it moves every held BAR span that lies inside a BAR's page span of one of them back to the
   apertures, whole (`firmware::hotplug::return_bars`), and merges it there with each adjacent
   aperture span: a span moves as the cap it is, so nothing is split, and only out of the held BAR
   pages, so a page is returned once;
4. it marks their records removed (`PciRecords::remove`); the port's own record is on the bus
   above and stays;
5. it returns the instance of each removed record bound to a driver with an instance limit
   (`BoundCounts::release_removed`), so a later pass can bind that driver to the device that
   replaces it ([docs/driver-binding.md](../../../docs/driver-binding.md#matching) § Matching).
   The instance returns only here, once the driver is withdrawn and the record removed, so a
   driver never serves more devices than its limit.

It logs `functions removed` with the number of records removed, drivers withdrawn and held spans
returned. acpid's job then ends with its reply (§ ACPI Hotplug); the poller's posts the slot back to
the poller, which powers it off in two Slot Control writes: the power controller off, then the power
indicator off, logged `powered off`. QEMU unplugs the card on the write that leaves both off. The
slot is then off while the card the removal removed is still present, until a press or a new
insertion asks for it; it is empty when no card is present, or when a card was inserted or the
button pressed while it was removing or by the power-off, so the next poll powers that card up
(`firmware::hotplug::completed`). A slot is powered up again only from empty or off, so no add job
for it runs before its previous occupant's DMA, IOMMU mappings and interrupt routes are gone. A
removal job posted while the slot's add job waits runs after it, and withdraws what the add bound; a
second removal job of a slot finds no live record and returns nothing.

An IOMMU fault is counted for a requester ID only while a DMA grant of a live record tracks it
(`firmware::dma::FaultCounts`): the grant tracks it from zero, the withdrawal stops counting it
once the device is blocked, and a fault of an untracked requester ID is logged, not counted. A
function added at a removed one's address starts with no faults.

A span given back to a table is merged with each adjacent span of it through `SYS_MMIO_MERGE`
(`firmware::resource::SpanTable`), so what a carve split comes back as one span. A BAR cap given
back to the held BAR pages merges only inside its BAR's pages, so no held span reaches past one BAR
and step 3 finds each whole; a span returned to the apertures, by a removal or by an add that
records no function, merges with no bound. A window whose BARs are all removed is then one span
again, as before its first add, and a card added after a removal is placed as in a window never
used, a BAR across the spans the removal returned included. The kernel merges only two caps that
are derivation siblings with no derivation of their own
([syscalls.md](../../../core/kernel/docs/syscalls.md#sys_mmio_merge-70) § `SYS_MMIO_MERGE`). The
pieces of one aperture cap are siblings; two spans it does not merge (pieces of aperture caps with
different derivation parents, or a merge the `CSpace` cannot back) stay apart, each placeable on
its own, and a BAR across them does not fit, logged as `the slot's windows have no room for it`.
Each add at a new place splits a free span into at most three, so the apertures table grows by at
most two spans per BAR placed, and never past one span per page of the windows.

---

## Summarized By

[Driver Binding](../../../docs/driver-binding.md), [acpid and devmgr](../../acpid/docs/devmgr.md),
[services/devmgr/README.md](../README.md), [PCI Enumeration](pci-enumeration.md),
[devmgr Responsibilities and Capabilities](responsibilities.md)
