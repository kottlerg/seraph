# acpid Start-up

What acpid does on each start, from loading the tables to the pushes, and how it fails.

---

## Threads

The main thread takes the bootstrap round (the RECV on acpid's service endpoint, the `devmgr.acpi`
seed and the `logd.flush` seed, `caps[2]`, which [README.md](../README.md) § The last line uses),
spawns the evaluation thread, and waits for any of acpid's threads to end. The
evaluation thread runs the whole sequence below and then, for acpid's lifetime, every evaluation the
service needs, so one thread owns the namespace. It blocks only on its work channel, from which it
takes a power request a receiver forwards, a GPE the event thread found, the power button to enable
again, or the end of devmgr's job of a hotplug event ([README.md](../README.md) § Power requests, §
Events and § Hotplug). Two receiver threads serve acpid's endpoint, so one can hold a `WAIT_EVENT`
while the other serves `SLEEP` and `RESET`; on x86-64 an event thread takes the SCI, and a hotplug
thread makes the `ACPI_HOTPLUG` calls, so the evaluation thread does not wait while devmgr runs a
hotplug job. The evaluation thread's stack is the larger of the evaluator's and the parser's stack
bounds plus 256 KiB for acpid's own frames ([docs/limits.md](../../../docs/limits.md)): a spawned
thread's stack is at least the size it asks for, while the main thread's grows past its first pages
only in a demand-paged process. acpid stays alive after the sequence, serving, so that svcmgr does
not restart it into the same start-up and so that it keeps the grants it holds. When the evaluation
thread, a receiver, the event thread or the hotplug thread ends, in a panic too, or the evaluation
thread cannot be spawned, the main thread exits acpid, since a request or an event would wait
unanswered, and svcmgr restarts it. A failed bootstrap round keeps acpid alive instead, since a
restart would fail the same way: a round that delivered the service endpoint without the
`devmgr.acpi` seed has the main thread answer each power request `NO_DEVICE`, and one that delivered
no endpoint parks it.

---

## Sequence

1. **Power registers and events** (x86-64). acpid acquires the `PM1a_CNT` block, or, on a
   hardware-reduced platform, which has none, the sleep control and status registers, writing
   `WAK_STS` to the status register to clear the wake's, and `RESET_REG` (each a port bound to the
   evaluation thread, or a page mapped), then the PM1a event block, the GPE0 block and the SCI, from
   devmgr (`QUERY_ACPI_RESOURCES`), binding the event blocks to the evaluation thread before it asks
   for the SCI; a missing one is logged, and the request or the events that need it go without:
   `NO_DEVICE` for the request, no events without the PM1a event block or the SCI, no GPEs without
   GPE0. devmgr's answer for the SCI says whether an acpid took it earlier in the boot. On any other
   answer, a failed one included (devmgr records the SCI as served even when its reply does not
   reach acpid), acpid then disables every event and clears every status at once, so no later acpid
   of the boot, which devmgr tells it is a restart, takes the press that turned the machine on for a
   new one. It then reads the FADT (`QUERY_ACPI_TABLE`) for its `PWR_BUTTON` flag. RISC-V has none
   of them.
2. **Tables.** acpid asks devmgr for the DSDT (`QUERY_ACPI_TABLE` with the signature
   `DSDT`, which devmgr resolves through the FADT), then for SSDT 0, 1, ... until devmgr
   replies `NO_DEVICE`, at most 64 (`MAX_SSDTS`, [docs/limits.md](../../../docs/limits.md)).
   Each table is mapped read-only, loaded into the namespace, and unmapped. A DSDT that cannot
   be loaded ends the sequence after step 3: no AML runs, and acpid goes on to arm and serve
   (step 10). An SSDT that cannot be loaded is logged and skipped. The method bodies are then
   parsed.
3. **ACPI mode** (x86-64). acpid reads `SCI_EN` in the PM1a control block of step 1. When it
   is clear, acpid writes the FADT's `ACPI_ENABLE` value to `SMI_CMD` and waits up to 3 s for
   `SCI_EN`. `SMI_CMD` comes from devmgr too (`QUERY_ACPI_RESOURCES`). This step needs no AML,
   and runs without a loaded DSDT too, since the fixed power button step 10 arms raises the SCI
   only in ACPI mode. RISC-V has no legacy mode.
4. **Module-level code**, then the **initialization walk**: `\_SB._INI`, then depth-first
   from the root in the order the tables define the objects, each `Device`, `Processor` and
   `ThermalZone`'s `_STA` and, for a present one, its `_INI`. A device absent but
   functioning has its children walked; one absent and not functioning is skipped with its
   children. A `_STA` that faults or returns no integer counts as absent and not functioning.
5. **Host bridges**: each present device whose `_HID` or `_CID` is `PNP0A03` or
   `PNP0A08`, with its `_SEG` and `_BBN` (0 when absent); and each present device below one
   that has a `_PRT` and is reached from it through devices with an `_ADR`, a PCI-to-PCI
   bridge, whose address acpid reads through the Secondary Bus Number of each bridge above it.
6. **Windows**: each host bridge's `_CRS` windows, pushed as `BRIDGE_WINDOWS`. devmgr checks
   a host bridge's `_PRT` against the functions on the buses of the windows it holds, so they
   go first.
7. **PIC-model routes** (x86-64). acpid evaluates each PCI-to-PCI bridge's `_PRT`, the deepest
   first, then each host bridge's, and pushes each as `PRT_PIC_MODE`; it then selects the APIC
   model with `\_PIC(1)` (§ Interrupt model). devmgr checks a table against the functions it
   routes, those no deeper table routes, so the deeper ones go first.
8. **Per bridge**: each PCI-to-PCI bridge's `_PRT`, in the same order, pushed as `PRT_TABLE`
   mode `PRT_ROUTES`; then for each host bridge `_OSC`, pushed as `OSC_RESULT`, and the
   `_PRT`, pushed as `PRT_TABLE` mode `PRT_ROUTES` ([devmgr.md](devmgr.md) § Pushes).
9. acpid logs a `ready:` line with the tables loaded, the devices present, the `_INI` methods
   run, the host bridges found and the PCI-to-PCI bridges with a `_PRT`.
10. **Arm and serve** (§ Threads): on x86-64 the evaluation thread starts the event thread,
    which binds the event blocks and registers the SCI, arms the events and dispatches those a
    restart finds pending ([README.md](../README.md) § Events); without a loaded DSDT no GPE is
    handled. It then starts the receivers, which serve acpid's endpoint
    ([README.md](../README.md) § Power requests); a request sent during the steps above waits in
    the endpoint's queue until then.

`_OSC` asks, with the PCI Host Bridge UUID and revision 1, for every support feature (0x1F)
and for native control of every PCI Express feature (0x1F); the control dword the firmware
returns is what it grants. On QEMU's q35 and `virt` it grants 0x1E: every feature but native
hotplug, which the firmware keeps while ACPI PCI hotplug is on.

A `_PRT` entry whose source is a link device resolves to the line of that device's current
`_CRS` (its `IRQ` or `Extended Interrupt` descriptor); a line of 0, or no interrupt in the
`_CRS`, leaves the pin unrouted. Each device's four pins go into one word of 16-bit lanes.

---

## Interrupt model

The firmware hands an x86-64 machine over in the PIC model. In that model each `_PRT` entry
names a PCI interrupt link device whose `_CRS` reads the PIRQ routing register the firmware
programmed, and the firmware wrote the same line into each function's Interrupt Line register.
acpid reads the `_PRT` in that model first, so that devmgr can check it against those registers
and route a function whose register is unset by it, and only then selects the APIC model, whose
entries name GSIs. RISC-V has one model, and acpid calls no `_PIC` there.

---

## The host

Every hardware access of the evaluator goes through devmgr ([devmgr.md](devmgr.md)):

- An I/O field access asks devmgr for its operation region's whole span on first use, a
  memory field access for the page that holds it. acpid binds the `IoPort` to the evaluation
  thread or maps the `Mmio`, and keeps the grant for acpid's lifetime. A refused span, and a
  page whose map fails, are remembered and not asked for again. A memory write is followed by an
  MMIO ordering barrier.
- A configuration-space access is one `ACPI_PCI_CONFIG` call.
- A `Notify` of a hotplug event is kept, once per object and event, and acted on once the
  evaluation ends: a hotplug event of a slot below a PCI-to-PCI bridge is posted
  to devmgr ([README.md](../README.md) § Hotplug), any other `Notify` logged and dropped. On QEMU
  q35 the ACPI PCI hotplug GPE's method (`\_GPE._E01`) notifies the slots that changed.
- The Global Lock is refused: devmgr refuses acpid the FACS, so a field whose access rule takes
  the lock fails.
- `_OSI` answers false for every string.

On QEMU q35 these refusals follow, each logged and none fatal:

- `\_SB.HPET._STA` reads the HPET's registers through a field that takes the Global Lock, so
  it faults and the HPET reads absent. Its registers at 0xFED0_0000 also lie in no `Mmio`
  aperture, and devmgr would refuse the region. The kernel and the services use no HPET
  ([docs/platform-requirements.md](../../../docs/platform-requirements.md)).
- devmgr refuses the FACS by name; it also lies in memory the memory map reports as reserved,
  outside every `Mmio` aperture.

---

## Failures

Evaluation fails closed: a fault or a value of the wrong shape is logged with the object's path
and the sequence goes on with what it has. A bridge whose `_OSC` fails is pushed as not
evaluated; one whose `_CRS` or `_PRT` fails or is absent has nothing pushed for it, and a
PCI-to-PCI bridge whose `_ADR`, or that of a device above it, fails, or a bridge above which
reads no Secondary Bus Number, has no `_PRT` pushed. A `_CRS`
with more windows than devmgr takes (`MAX_BRIDGE_WINDOWS`) is refused by acpid. A `_PRT`
entry of the wrong shape, or naming a link device that cannot be resolved, is logged and its pin
left unrouted.

---

## Restart

acpid is `restart = on_failure`: svcmgr re-creates it, and it re-acquires its capabilities
from devmgr and runs the sequence again, `_INI` methods included. devmgr keeps the first result
of each push for the boot and logs a later one that differs, so a restart cannot change what
devmgr acts on. A restarted acpid's PIC-model `_PRT` is read after the first instance selected
the APIC model, and so differs from the first. devmgr keeps the memory pages it granted, so a
restarted acpid is granted them again ([devmgr.md](devmgr.md) § Region grants). svcmgr serves
the restarted acpid a fresh RECV on the same service endpoint, so pwrmgr's `acpid.power` SEND
stays valid; a request sent while acpid is down waits in the endpoint's queue. A `WAIT_EVENT`
pending when acpid died fails in the caller, which calls again. devmgr serves the restarted
acpid the SCI again and tells it that it is a restart, so acpid keeps the event status the
hardware latched and dispatches each handled event still set ([README.md](../README.md)
§ Events).

---

## Summarized By

[services/acpid/README.md](../README.md)
