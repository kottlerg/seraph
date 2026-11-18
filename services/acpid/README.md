# acpid

The ACPI service: it runs the firmware's AML and gives devmgr what the AML says about each PCI
host bridge.

---

## Source Layout

```
acpid/
├── Cargo.toml
├── README.md
├── docs/
│   ├── startup.md        # The start-up sequence, the interrupt model, failures, restart
│   └── devmgr.md         # Capabilities, region grants, configuration access, pushes, checks
└── src/
    ├── lib.rs            # Host-tested library: `Failure`, `Why`
    ├── power.rs          # Power requests: decode, `\_S5_`, `\_PTS`, the `PM1a_CNT` values
    ├── events.rs         # The fixed power button and the GPEs: arm, scan, dispatch, re-enable
    ├── hotplug.rs        # PCI hotplug: the `Notify` values, the slot's port, `_EJ0` and `_OST`
    ├── walk.rs           # The `_STA` / `_INI` initialization walk
    ├── bridge.rs         # Host bridges: `_HID`/`_CID`, `_SEG`, `_BBN`, `_OSC`, `_CRS`, `_PRT`
    ├── table.rs          # Where a served table sits in its region's mapping
    ├── sim.rs            # Test host over the captured QEMU tables (tests only)
    ├── main.rs           # Entry, bootstrap, the evaluation thread, the watch on acpid's threads
    ├── caps.rs           # svcmgr bootstrap: the service endpoint, the `devmgr.acpi` seed
    ├── devmgr.rs         # The calls acpid makes on devmgr
    ├── platform.rs       # The evaluator's `Host`: region grants, configuration access
    ├── startup.rs        # The start-up sequence and the pushes
    ├── server.rs         # The work loop, the receivers, the event and hotplug threads,
    │                     # `WAIT_EVENT`
    └── arch/
        ├── mod.rs            # Arch dispatch: `arch::current`
        ├── x86_64/mod.rs     # ACPI mode, port I/O, the APIC model, PM1a_CNT, RESET_REG,
        │                     # the event blocks and the SCI
        └── riscv64/mod.rs    # No I/O space, one interrupt model, no power registers or events
```

The library (`lib.rs`, `walk.rs`, `bridge.rs`, `table.rs`, `power.rs`, `events.rs`, `hotplug.rs`)
holds the evaluation logic and is host-tested over the QEMU tables `shared/aml/fixtures/` holds; the
binary gives it a `Host` that reaches hardware only through devmgr.

---

## Responsibilities

acpid is a svcmgr service, launched on every boot of both architectures from
`rootfs/config/svcmgr/services/acpid.svc` (`restart = on_failure`, `critical = no`). It is the only
process that evaluates AML: devmgr evaluates none
([docs/driver-binding.md](../../docs/driver-binding.md) § Device Records). It loads the DSDT and the
SSDTs devmgr serves, switches an x86-64 platform into ACPI mode, runs the initialization walk, and
evaluates each PCI host bridge's `_OSC`, `_CRS` and `_PRT` ([docs/startup.md](docs/startup.md)). It
pushes the results to devmgr, which keeps those that agree with its boot records and serves them per
bridge with `QUERY_HOST_BRIDGE` ([docs/devmgr.md](docs/devmgr.md) § Pushes). On x86-64 it then takes
the SCI and handles the ACPI events: the fixed power button, which it reports to pwrmgr, and the
general-purpose events (GPEs), whose `\_GPE` methods it runs (§ Events). It posts the firmware's PCI
hotplug events to devmgr and completes each with the slot's `_EJ0` and `_OST` (§ Hotplug).

acpid is a provider: its recipe's `provides = acpid.power:auth acpid.deny:deny` makes svcmgr
create its service endpoint and publish two SENDs on it, the seed-only `acpid.power`, carrying
`POWER_AUTHORITY`, which only pwrmgr seeds, and the public `acpid.deny` without it. Once its
start-up ends, two receiver threads serve the power requests on that endpoint (§ Power
requests); a request sent during start-up waits in the endpoint's queue.

---

## Power requests

acpid serves `ipc::acpid_labels` on its endpoint from two receiver threads, which hand each
`SLEEP` and `RESET` to the evaluation thread and wait for its answer, so every evaluation runs in
turn on the one thread that owns the namespace. A request is checked in order: the label
(`UNKNOWN_OPCODE`), the badge's `POWER_AUTHORITY` (`UNAUTHORIZED`), `ACPID_LABELS_VERSION` in
`data[0]` (`LABEL_VERSION_MISMATCH`), then the argument.

- `SLEEP`, with the state in `data[1]`, of which only S5 (soft-off) is served
  (`INVALID_REQUEST` for another): acpid evaluates `\_S5_` for `SLP_TYPa` (its first element,
  at most 7), runs `\_PTS(5)` when the tables define it (a fault is logged and the sleep goes
  on), then, with the events armed (§ Events), takes and hands on, as the event thread does,
  each event that has fired and that the event thread has not taken yet, disables every GPE and
  every fixed event but the power button, S5's wake event, and clears every PM1 and GPE0 status,
  `WAK_STS` among them, as ACPI 6.5 § 16.1.6 requires before `SLP_EN` is written. It then
  writes `PM1a_CNT` twice, keeping its other bits: `SLP_TYPa` with `SLP_EN` clear, then with
  `SLP_EN` (bit 13) set, and logs `SLEEP(5): PM1a_CNT ...` before the writes. When the writes
  return, acpid keeps the events quiesced for 10 s (`SLEEP_GRACE`), the wait after which ACPICA
  takes an S5 write as not taken; when the platform still runs then, acpid enables the GPEs
  again, logs `SLEEP(5): still running 10 s after the writes; GPEs enabled again`, and
  dispatches each GPE that was enabled before the sleep and latched meanwhile. A GPE that had
  fired before the sleep, or that the quiesce took, is left disabled for its queued method,
  which enables it again, and the power button is left as the quiesce left it: a press taken
  before or during the sleep is delivered once, by the `WAIT_EVENT` it is posted to, which
  enables the button again. So each event is handled once.
- `RESET`: acpid writes the FADT's `RESET_VALUE` to its `RESET_REG` port and logs
  `RESET: RESET_REG ...` before the write.
- `WAIT_EVENT`: the receiver holds the call, with no bound, until an event is pending, and
  replies `SUCCESS` with the pending events in `data[0]` (`EVENT_POWER_BUTTON`) (§ Events). One
  call waits at a time: a later `WAIT_EVENT` takes its place and the earlier one is replied
  `SUPERSEDED`, so the other receiver stays free for `SLEEP` and `RESET`. `NO_DEVICE` when
  acpid has no event to wait for: no SCI, no PM1a event block, or a FADT that declares no fixed
  power button, and always on RISC-V.

On the success path of `SLEEP` and `RESET` the platform powers off or resets and no reply
arrives. A `SUCCESS` reply to `SLEEP` means the platform still runs 10 s after the writes, and
to `RESET` that the write returned and the platform still runs; the caller decides how long to
wait.
`NO_DEVICE` means the platform lacks what the request needs: `PM1a_CNT`, a usable `\_S5_` or
loaded AML for `SLEEP`, an I/O-space `RESET_REG` for `RESET`, and always on RISC-V, whose
platforms power off and reset through SBI. acpid acquires `PM1a_CNT` and `RESET_REG` from
devmgr (`QUERY_ACPI_RESOURCES`) at the start of its start-up and binds them to the evaluation
thread. The endpoint is served even when the DSDT did not load, and, with every request that passes
the checks answered `NO_DEVICE`, when the bootstrap round delivered the endpoint without the
`devmgr.acpi` seed. A receive that keeps failing exits acpid (`ipc::recv_guard`), and svcmgr
restarts it on the same endpoint. pwrmgr bounds each call at 30 s
([pwrmgr](../pwrmgr/README.md#responsibilities)), so a request that acpid, down or blocked, does
not answer fails rather than holding the shutdown.

---

## Events

On x86-64, acpid acquires the PM1a event block, the GPE0 block and the SCI from devmgr
(`QUERY_ACPI_RESOURCES`) at the start of its start-up. devmgr serves the SCI, the FADT's
`SCI_INT` routed through the MADT's interrupt source overrides, as an `Interrupt` capability
derived from the line it holds, and says whether it served the SCI before in the boot, which
tells a restarted acpid from the first one ([docs/devmgr.md](docs/devmgr.md) § Capabilities).
Once the start-up ends, acpid arms the events:

- The fixed power button, when the FADT's `PWR_BUTTON` flag is clear, and each GPE of the GPE0
  block that has a `\_GPE._Lxx` or `_Exx` method. Every other fixed event and GPE is disabled.
  A `_Lxx` or `_Exx` past the GPE0 block, or a second method for the same GPE, is logged and
  not handled.
- acpid binds the event blocks before it asks for the SCI. Unless devmgr's answer says the
  SCI was served before, a failed answer included (devmgr records the SCI as served even when
  its reply does not reach acpid), acpid disables every event and clears every status bit at
  once, before anything else can fail, so the press that turned the machine on is gone before
  devmgr would tell a later acpid that it is a restart. When the events are armed,
  a handled event whose status is set is dispatched: it was latched after that clear, or by a
  dead acpid of the boot that had not handled it, since a status bit is cleared only once its
  event is handled, by a `SLEEP`, or by an acpid that cannot take the SCI. An event latched
  before one of those cleared it is not dispatched by a later acpid, even when the acpid that
  took it died before handling it.
- acpid logs `events armed (...)` with the start, the SCI's GSI, whether the power button is
  on, and the GPEs handled. When the SCI cannot be taken, acpid disables every event and clears
  every status, those a dead acpid of the boot left enabled among them, and handles none.

The event thread blocks on the SCI's notification alone. On each SCI it reads the PM1 and GPE status
and enable registers, disables each event whose status and enable are both set, leaving its status
set, hands it on and acknowledges the interrupt; it runs no AML and makes no IPC. The evaluation
thread runs each GPE's method: for `_Exx` it clears the status first, for `_Lxx` after the method,
and then enables the GPE again. A `Notify` the method makes of a PCI hotplug slot is acted on after
it (§ Hotplug); any other is logged and dropped ([docs/startup.md](docs/startup.md) § The host). A
power-button press is logged as `power button pressed` and posted for `WAIT_EVENT`; its status is
cleared and the button enabled again once a `WAIT_EVENT` reply that carries it is delivered. pwrmgr
waits in `WAIT_EVENT` and powers the platform off on a press
([pwrmgr](../pwrmgr/README.md#responsibilities)). RISC-V platforms have no fixed events: QEMU
`virt`'s FADT is hardware-reduced.

---

## Hotplug

On x86-64 q35 with QEMU's ACPI PCI hotplug on, its default, the firmware drives the hotplug slots
behind its root ports: `_OSC` withholds native hotplug control, and devmgr leaves each such slot to
it ([devmgr's hotplug.md](../devmgr/docs/hotplug.md#acpi-hotplug) § ACPI Hotplug). The firmware's
GPE method (`\_GPE._E01`) notifies the device of each slot that changed. acpid keeps the
`Notify` calls of hotplug events a method makes, once per object and event
([docs/limits.md](../../docs/limits.md)), and after the method acts on each:

- a Bus Check (0) or a Device Check (1) is a device check, an Eject Request (3) an eject request;
  any other value is logged and dropped;
- the slot's port is resolved: the notified device has an `_ADR`, and its parent and each
  device above it up to a host bridge acpid found are PCI-to-PCI bridges, each named by its
  `_ADR`; the port is the parent, on the bus each bridge above it leads to, read from its
  Secondary Bus Number through devmgr. A device on a root bus, or one no such route reaches, is
  logged and dropped;
- an event the slot already holds, the firmware's repeat of it, is dropped; the method notifies an
  eject request again on every GPE until the card is ejected.

acpid logs `hotplug: device check` or `eject request` with the slot's path and port, and posts the
event to devmgr with `ACPI_HOTPLUG`, as `HOTPLUG_ADDED` or `HOTPLUG_REMOVED`. A dedicated hotplug
thread makes the call, one event at a time, so the evaluation thread serves power requests and
GPEs while devmgr runs the job; a slot's next event waits until its previous one ends. devmgr
replies once its job has ended, with the functions it recorded or removed
(`shared/ipc/src/devmgr_labels.rs`, `devmgr_labels::ACPI_HOTPLUG`). The evaluation thread then
completes the event:

- an eject request devmgr ran is ejected: acpid runs the slot's `_EJ0(1)`, on which the firmware
  lets the card go, logged `ejected (_EJ0) once devmgr removed` with the count. devmgr has by then
  withdrawn the driver and removed the records;
- where the slot has an `_OST`, acpid runs it with the `Notify` value and the outcome: success,
  ejection not supported (0x80) for an eject request devmgr refused, or failure. QEMU's slots have
  no `_OST`.

An eject request devmgr refused, or whose call failed, is not ejected: the card stays, and a slot
devmgr does not leave to the firmware is never ejected under it.

---

## Region grants

acpid holds no hardware capability of its own. Beside its service endpoint's `RECV`, its one
capability, the `devmgr.acpi` seed, carries `ACPI_AUTHORITY`, under which devmgr serves it the
FADT's register blocks and grants it, on first use, each `SystemIO` or `SystemMemory` operation
region its AML reaches. devmgr refuses, logged, a range that a device record (a resource container's
aside, [docs/driver-binding.md](../../docs/driver-binding.md) § Device Records), a driver or the
kernel holds (the interrupt controllers and, on x86-64, the legacy ports it drives), the
configuration-mechanism ports 0xCF8-0xCFF, the FACS, and memory outside the `Mmio` apertures it
still holds, which leaves out RAM and ACPI NVS. Memory is granted a page at a time. A field access
in a refused region fails and its method aborts. `PCI_Config` regions are reached one access at a
time through devmgr, which allows reads, and writes only at offset 0x40 and above of a function with
no bound driver. The policy is [docs/devmgr.md](docs/devmgr.md) § Region grants and § Configuration
access.

---

## Checks

devmgr keeps a bridge's `_OSC` result as acpid pushes it, the first one for the boot. It keeps
a bridge's `_CRS` windows and `_PRT` routes only when they agree with its boot records: each
boot function's bus inside the bus window, its memory BARs inside a memory window and an
aperture, its I/O BARs inside an I/O window, and its interrupt pin routed (on x86-64 to the line
the firmware programmed, read in the PIC model; on RISC-V to the `virt` swizzle). A push that
disagrees is refused, fail-closed: the bridge then has no windows or routes from acpid for the
boot. The checks are [docs/devmgr.md](docs/devmgr.md) § Pushes.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/driver-binding.md](../../docs/driver-binding.md) | Device records; devmgr evaluates no AML, acpid does |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability authority; how acpid's capabilities derive from devmgr's |
| [docs/limits.md](../../docs/limits.md) | The evaluator's bounds and acpid's own |
| [shared/aml/README.md](../../shared/aml/README.md) | The parser, namespace and evaluator acpid runs |
| [shared/ipc/src/devmgr_labels.rs](../../shared/ipc/src/devmgr_labels.rs) | The `devmgr_labels` acpid calls and their wire contract |
| [shared/ipc/src/acpid_labels.rs](../../shared/ipc/src/acpid_labels.rs) | The `acpid_labels` it serves and their wire contract |
| [services/pwrmgr/README.md](../pwrmgr/README.md) | The holder of `acpid.power`; powers off and resets x86-64 through acpid, and waits for its power button |
| [services/devmgr/README.md](../devmgr/README.md) | The hardware authority that grants acpid's regions and keeps its results |
| [services/svcmgr/README.md](../svcmgr/README.md) | Launcher and supervisor; mints the `devmgr.acpi` seed and publishes `acpid.power` and `acpid.deny` |
| [services/svctest/README.md](../svctest/README.md) | Services harness; checks what devmgr holds from acpid, the `ACPI_AUTHORITY` gate, and the `POWER_AUTHORITY` gate through `acpid.deny` |

---

## Summarized By

[ACPI Parsing](../../core/boot/docs/acpi.md),
[Firmware Parsing](../../core/boot/docs/firmware-parsing.md),
[Architecture Overview](../../docs/architecture.md),
[Driver Binding](../../docs/driver-binding.md),
[services/pwrmgr/README.md](../pwrmgr/README.md),
[shared/aml/README.md](../../shared/aml/README.md)
