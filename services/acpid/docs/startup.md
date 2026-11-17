# acpid Start-up

What acpid does on each start, from loading the tables to the pushes, and how it fails.

---

## Threads

The main thread takes the bootstrap round (the `devmgr.acpi` seed), spawns the evaluation
thread, waits for it, and then parks. The evaluation thread runs the whole sequence below. Its
stack is the larger of the evaluator's and the parser's stack bounds plus 256 KiB for acpid's
own frames ([docs/limits.md](../../../docs/limits.md)): a spawned thread's stack is at least the
size it asks for, while the main thread's grows past its first pages only in a demand-paged
process. acpid stays alive after the sequence, so that svcmgr does not restart it into the same
start-up and so that it keeps the grants it holds.

---

## Sequence

1. **Tables.** acpid asks devmgr for the DSDT (`QUERY_ACPI_TABLE` with the signature
   `DSDT`, which devmgr resolves through the FADT), then for SSDT 0, 1, ... until devmgr
   replies `NO_DEVICE`, at most 64 (`MAX_SSDTS`, [docs/limits.md](../../../docs/limits.md)).
   Each table is mapped read-only, loaded into the namespace, and unmapped. A DSDT that cannot
   be loaded ends the sequence: no AML runs. An SSDT that cannot be loaded is logged and
   skipped. The method bodies are then parsed.
2. **ACPI mode** (x86-64). acpid reads `SCI_EN` in the PM1a control block. When it is clear,
   acpid writes the FADT's `ACPI_ENABLE` value to `SMI_CMD` and waits up to 3 s for
   `SCI_EN`. Both blocks come from devmgr (`QUERY_ACPI_RESOURCES`). RISC-V has no legacy
   mode.
3. **Module-level code**, then the **initialization walk**: `\_SB._INI`, then depth-first
   from the root in the order the tables define the objects, each `Device`, `Processor` and
   `ThermalZone`'s `_STA` and, for a present one, its `_INI`. A device absent but
   functioning has its children walked; one absent and not functioning is skipped with its
   children. A `_STA` that faults or returns no integer counts as absent and not functioning.
4. **Host bridges**: each present device whose `_HID` or `_CID` is `PNP0A03` or
   `PNP0A08`, with its `_SEG` and `_BBN` (0 when absent).
5. **PIC-model routes** (x86-64). acpid evaluates each bridge's `_PRT` and pushes it as
   `PRT_PIC_MODE`, then selects the APIC model with `\_PIC(1)` (§ Interrupt model).
6. **Per bridge**: `_OSC`, pushed as `OSC_RESULT`; the `_CRS` windows, pushed as
   `BRIDGE_WINDOWS`; the `_PRT`, pushed as `PRT_TABLE` mode `PRT_ROUTES`
   ([devmgr.md](devmgr.md) § Pushes).
7. acpid logs a `ready:` line with the tables loaded, the devices present, the `_INI` methods
   run and the bridges found.

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
acpid reads the `_PRT` in that model first, so that devmgr can check it against those registers,
and only then selects the APIC model, whose entries name GSIs. RISC-V has one model, and acpid
calls no `_PIC` there.

---

## The host

Every hardware access of the evaluator goes through devmgr ([devmgr.md](devmgr.md)):

- An I/O or memory field access asks devmgr for its operation region's whole span on first
  use, binds the `IoPort` to the evaluation thread or maps the `Mmio`, and keeps the grant for
  acpid's lifetime. A refused span is remembered and not asked for again. A memory write is
  followed by an MMIO ordering barrier.
- A configuration-space access is one `ACPI_PCI_CONFIG` call.
- `Notify` is logged and dropped: no consumer of the notifications runs.
- The Global Lock is refused: devmgr refuses acpid the FACS, so a field whose access rule takes
  the lock fails.
- `_OSI` answers false for every string.

On QEMU q35 these refusals follow, each logged and none fatal:

- `\_SB.HPET._STA` reads the HPET's registers through a field that takes the Global Lock, so
  it faults and the HPET reads absent. Its registers at 0xFED0_0000 also lie in no `Mmio`
  aperture, and devmgr would refuse the region. The kernel and the services use no HPET
  ([docs/platform-requirements.md](../../../docs/platform-requirements.md)).
- The CPU hotplug block at ports 0xCD8-0xCE3 is the `IoPort` of a device record, so devmgr
  refuses it, and the processors' `_STA` fault and read absent. acpid does not act on
  processors.
- devmgr refuses the FACS by name; it also lies in memory the memory map reports as reserved,
  outside every `Mmio` aperture.

---

## Failures

Evaluation fails closed: a fault or a value of the wrong shape is logged with the object's path
and the sequence goes on with what it has. A bridge whose `_OSC` fails is pushed as not
evaluated; one whose `_CRS` or `_PRT` fails or is absent has nothing pushed for it. A `_CRS`
with more windows than devmgr takes (`MAX_BRIDGE_WINDOWS`) is refused by acpid. A `_PRT`
entry of the wrong shape, or naming a link device that cannot be resolved, is logged and its pin
left unrouted.

---

## Restart

acpid is `restart = on_failure`: svcmgr re-creates it, and it re-acquires its capabilities
from devmgr and runs the sequence again, `_INI` methods included. devmgr keeps the first result
of each push for the boot and logs a later one that differs, so a restart cannot change what
devmgr acts on. A restarted acpid's PIC-model `_PRT` is read after the first instance selected
the APIC model, and so differs from the first. devmgr keeps the memory regions it granted, so a
restarted acpid is granted them again ([devmgr.md](devmgr.md) § Region grants).

---

## Summarized By

[services/acpid/README.md](../README.md)
