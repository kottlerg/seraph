# acpid and devmgr

What devmgr gives acpid, what it refuses, and what it keeps of acpid's results.

---

## Capabilities

svcmgr mints acpid's one capability, the `devmgr.acpi` seed: a SEND on devmgr's registry
endpoint badged `REGISTRY_QUERY_AUTHORITY | ACPI_AUTHORITY`, published seed-only, and seeded
by acpid's recipe alone. `ACPI_AUTHORITY` gates every label acpid alone calls; devmgr replies
`UNAUTHORIZED` to them on any other badge. Through the seed acpid acquires:

- the DSDT and the SSDTs, each a read-only `Memory` capability over the reclaimable region that
  holds it (`QUERY_ACPI_TABLE`);
- on x86-64, an `IoPort` over each FADT register block it names: the PM1a event and control
  blocks, GPE0, `SMI_CMD` with the `ACPI_ENABLE` value, and `RESET_REG` when it is in
  `SystemIO` (`QUERY_ACPI_RESOURCES`). RISC-V platforms have none;
- each operation region devmgr grants it (§ Region grants);
- each configuration-space access devmgr makes for it (§ Configuration access).

Every capability is a derivation of one devmgr holds. The wire contract of each label is the
`devmgr_labels` documentation in [shared/ipc/src/lib.rs](../../../shared/ipc/src/lib.rs).

---

## Region grants

acpid asks devmgr (`ACPI_REGION_GRANT`) for a `SystemIO` region's span on its first field
access, and for a `SystemMemory` region the page an access reaches, on the first access to that
page. devmgr refuses, and logs the refusal with the range it collides with:

- a range overlapping a resource of any device record (a PCI BAR, a platform record's `Mmio` or
  `IoPort`), whether or not a driver has been started for it;
- a port of pwrmgr's shutdown actuators;
- the register window of each interrupt controller the MADT describes, which the kernel
  programs (the local APIC, each I/O APIC, the APLIC, each hart's IMSIC interrupt file), and
  on x86-64 the legacy ports the kernel owns: the two 8259s and their edge/level control
  registers (0x20-0x21, 0xA0-0xA1, 0x4D0-0x4D1), the PIT (0x40-0x43) and its gate port 0x61,
  and the COM1 console (0x3F8-0x3FF);
- the configuration-mechanism ports 0xCF8-0xCFF, through which every function's configuration
  space is reachable;
- the FACS, whose Global Lock and waking vector acpid does not own;
- memory that no `Mmio` aperture devmgr still holds covers: RAM, runtime-services memory, ACPI
  NVS, and the ranges devmgr has carved for itself or a driver. The apertures never cover the
  first three ([core/boot/docs/firmware-parsing.md](../../../core/boot/docs/firmware-parsing.md)
  § Firmware exclusion).

A port grant is an `IoPort` over exactly the range. A memory grant is an `Mmio` over one page,
carved from an aperture; a memory request that crosses a page boundary is invalid. devmgr keeps
each carved page's capability and hands acpid a derivation, so a page is granted again to a
restarted acpid, and whether a page is granted does not depend on which of two overlapping
regions reached it first. A refused range fails the field access, and the method that made it
aborts ([startup.md](startup.md) § Failures).

---

## Configuration access

A `PCI_Config` field access is one `ACPI_PCI_CONFIG` call. devmgr allows a read of any
function: one no device record holds, or a removed one, reads all-ones without an access, as an
absent function does. It allows a write only at offset 0x40 and above, past the header whose
BARs, Command register and bus numbers devmgr programs, of a function whose record no driver has
been started for. Any other write is refused and logged. The access runs on devmgr's control
thread (§ Ordering), so no bind of the function interleaves with it.

---

## Pushes

acpid pushes three results per PCI host bridge, named by its segment and bus:

- `OSC_RESULT`: whether `_OSC` was evaluated, its status dword, the control dword it granted,
  and the control acpid asked for. devmgr keeps the first for the boot.
- `BRIDGE_WINDOWS`: the `_CRS` memory, I/O and bus windows, on the bus side of the bridge.
- `PRT_TABLE`: the routes of the bridge's root bus, one word per device of four 16-bit pin
  lanes, of the mode `PRT_ROUTES` (the model acpid selected) or, on x86-64, `PRT_PIC_MODE`
  (read before `_PIC(1)`).

devmgr keeps windows and routes only once they agree with its boot records, checked against
each boot function on the bridge's buses, those of its windows; a `PRT_TABLE` that comes before
the bridge's windows are held is refused, as acpid pushes the windows first:

- **Windows.** The windows hold exactly one bus window, which holds the bridge's bus and ends at
  or below bus 255. Each
  memory BAR lies inside a memory window and inside an aperture devmgr was given at boot; each
  I/O BAR lies inside an I/O window. A BAR at address 0, which the firmware left unassigned, is
  not checked.
- **Routes.** Each function with an interrupt pin is routed at the pin and device its interrupt
  reaches the root bus with. On x86-64 the `PRT_PIC_MODE` table must route it to the line in
  its Interrupt Line register, which the firmware programmed in the PIC model, and the
  `PRT_ROUTES` table is kept only once the `PRT_PIC_MODE` table is held: the same `_PRT`
  read in the APIC model, whose GSIs no register states, so it is checked for being routed. On
  RISC-V the `PRT_ROUTES` table must route each function to the line devmgr gives it, the
  `virt` host's swizzle.

A push that disagrees is refused with `REFUSED` and logged with the check it failed. The
refusal is fail-closed: devmgr holds nothing from it, and the bridge has no windows or routes
from acpid for the boot unless a later push passes. A consumer then finds them not held
(`QUERY_HOST_BRIDGE`). devmgr's own interrupt routing and resource placement read neither. Each
check counts the boot functions it covered.

devmgr keeps the first windows and the first table of each mode that pass, and the first
`_OSC` result, for the boot. A later push equal to the held one is accepted; one that differs
is logged and the held one stays, so a restarted acpid cannot change what devmgr acts on.

`QUERY_HOST_BRIDGE(ordinal)`, under `REGISTRY_QUERY_AUTHORITY`, serves what devmgr holds per
bridge, in segment then bus order: the `_OSC` status and control, whether the routes and the
windows are held, and the functions each check covered. Its production consumer is a service
that drives a PCI Express port feature and must know whether `_OSC` granted it to the OS;
svctest reads it on every boot.

---

## Ordering

`QUERY_ACPI_RESOURCES` is answered on the registry worker that receives it, from the FADT
alone. Every other acpid request runs on devmgr's control thread, which owns the device records,
the apertures and the configuration space: a region check and its carve, a configuration access
and a push are decided against records no bind changes meanwhile. A request waits while the
control thread runs a bind pass and its settle. devmgr never calls acpid, so a dead or stalled
acpid blocks no devmgr work. A request runs to its end whatever happens to acpid: a reply that
cannot be delivered deletes only the capability copy it carried.

---

## Summarized By

[Capability Model](../../../docs/capability-model.md),
[services/acpid/README.md](../README.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md)
