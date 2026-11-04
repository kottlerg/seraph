# devmgr Responsibilities and Capabilities

The responsibilities devmgr carries, the capabilities it receives at bootstrap, and its
authority over driver processes.

---

## Responsibilities

devmgr is launched by init early in the bootstrap sequence. It is a privileged service whose
hardware, platform, and scheduling authority is only what it receives at bootstrap (from init,
plus the SchedControl band procmgr delivers) and the `/services/drivers/` cap svcmgr sends after
handover. Init exits after handover, and devmgr is `restart = never`, `critical = yes`, so its
death triggers a graceful shutdown rather than re-delegation (see
[docs/device-management.md § Security boundary](../../../docs/device-management.md#security-boundary)).
The full design is specified in [docs/device-management.md](../../../docs/device-management.md);
devmgr's responsibilities are:

- **Parse firmware tables** — locate every PCI ECAM window, from read-only
  memory capabilities, through every allocation entry of the ACPI MCFG table
  (RSDP → XSDT → MCFG; preferred on either architecture whenever an RSDP is
  present and it yields a window) or, failing that, every
  `pci-host-ecam-generic` node of the Device Tree blob; and serve ACPI tables
  to pwrmgr (below). When neither yields an ECAM, devmgr on RISC-V falls back to
  the QEMU `virt` platform-default ECAM window (`platform_default_ecam`:
  `0x3000_0000`, 256 MiB, buses 0..=255); on x86-64 the boot halts. devmgr
  derives per-device interrupt lines from PCI configuration space; resolving
  interrupt routing and power domains from firmware tables is design intent;
  not yet implemented.
- **Enumerate PCI devices** — for each ECAM window, reserve VA, fund the AS's
  page-table growth budget via `fund_aspace_pt_budget`, then map the window
  via `mmio_map`, read configuration space, discover every function and its
  BARs, resolve interrupt assignments. See
  [`docs/pci-enumeration.md`](pci-enumeration.md).
- **Bind drivers** — match discovered devices to driver binaries in
  [`drivers/`](../../drivers/README.md), request procmgr to create driver
  processes, and delegate per-device capabilities (MMIO, interrupt, and
  IoPort where applicable). PCI devices spawn through the
  BAR/IRQ-shaped path; fixed-location platform devices (the serial
  UART, the boot framebuffer, the platform RTC chip — `cmos-rtc` on x86-64,
  `goldfish-rtc` on RISC-V) spawn through a simpler path whose first
  bootstrap round delivers a service endpoint and one arch authority cap
  (`IoPort` for COM1 and CMOS, `Mmio` for an NS16550, the framebuffer, or
  the goldfish RTC at `0x101000`), with the UART's interrupt cap after it
  (devmgr carves the UART line exclusive and holds nothing of it: the
  serial driver acknowledges a delivery only when its client reads
  ([services/drivers/serial/README.md](../../drivers/serial/README.md#interrupts)
  § Interrupts), so no other device may share its line; every PCI device's
  line is instead held and shared,
  [docs/pci-enumeration.md](pci-enumeration.md) step 3),
  and whose second, terminal round delivers the driver's devmgr query cap
  (below). The `cmos-rtc` first round also carries one data word: the CMOS
  RAM index of the century register the FADT's `CENTURY` field names, or 0
  when it names none.
  Drivers that need physical-base addresses for device DMA
  programming obtain them from memmgr's `REQUEST_MEMORY_CAPS` reply alongside
  the Memory caps. No IOMMU support exists, so every DMA-capable driver runs
  DMA-unsafe today; DMA isolation programmed by devmgr through IOMMU hardware
  it acquires via the `Mmio` cap flow is design intent; not yet implemented
  (see
  [docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming)).

  devmgr spawns one driver for every virtio-input device and for every
  virtio-blk device it can give an IRQ cap, each with its own service
  endpoint, an `Mmio` cap for every BAR the device's VirtIO register regions
  name, and its own derivation of its line's held `Interrupt` cap, so devices
  that share an `INTx` line are all served (see
  [docs/pci-enumeration.md](pci-enumeration.md) § Per-Device Capability
  Creation).

  devmgr serves a driver's endpoint only once the driver has set its device
  up. It spawns its drivers in two production settle batches: the boot batch
  (every virtio-blk driver, then the serial and framebuffer drivers) and the
  on-disk batch (the RTC driver, then every virtio-input driver). Each
  driver's devmgr query cap is a SEND, badged with its device badge, on its
  batch's private endpoint; the serial and RTC drivers' badges name catalog
  entries that carry no startup info. Once a driver's bootstrap is served,
  devmgr binds a death observer on the driver's thread to its driver death
  queue: one queue for the boot, sized at enumeration to every driver the boot
  can spawn (one per virtio-blk and virtio-input device, the serial,
  framebuffer, and RTC drivers, and the three fixtures of the test-only fault
  batch below), so every bind is funded and no death is dropped. A driver that
  needs startup info (the VirtIO drivers, the framebuffer) calls
  `QUERY_DEVICE_INFO` on its query cap before its device setup, and every
  driver calls `DRIVER_READY` on it after, immediately before its service
  loop. devmgr waits on a wait set over the batch's private endpoint, the
  death queue, and a timer, serving those two labels on the private endpoint
  and taking deaths from the queue, until every driver of the batch has
  reported ready or died or the settle bound elapses, and then takes every
  death still queued. It then revokes the private endpoint, serves each driver
  that reported ready, and withdraws the rest. A `VirtIO` device is reset
  (devmgr maps the BAR cap it keeps that holds the common configuration
  region and writes 0 to `device_status`, which stops the device's DMA and
  drops its pending interrupt; a byte past the span that cap was carved to
  is not written, and the reset is skipped). A driver still running (one
  pending, or one devmgr has no memory to serve) is reset first, then
  destroyed (`DESTROY_PROCESS` on the process handle devmgr keeps until the
  batch settles, which returns once procmgr has torn it down and handed its
  memory back to memmgr), so its device's DMA stops before that memory is
  freed. Then its service endpoint is revoked and deleted, the device reset
  again, so that reset is the last write the device sees, and its BAR and
  IRQ caps released. A driver devmgr's batch cannot record at its spawn is
  withdrawn the same way there. The catalog entry of a withdrawn driver, or of
  one that failed to spawn, stays, so a badge is never reused. No `QUERY_*`
  reply hands out the endpoint of a driver that has not reported its device
  ready.

  The settle bound, `SETTLE_TIMEOUT` (`services/devmgr/src/settle.rs`), is
  twice `virtio_core::pci::RESET_TIMEOUT` (5 s), so 10 s, counted from the
  start of the settle, after the batch's last spawn. The VirtIO reset, which
  a virtio-blk or virtio-input driver polls for once, is the longest bounded
  wait a driver's setup makes, so the settle never ends before a driver's own
  timeout has, and a margin of one further `RESET_TIMEOUT` covers the rest of
  the setup. The serial, framebuffer, and RTC drivers make no bounded wait in
  their setup. The synchronous IPC calls every driver's setup makes (memmgr,
  and devmgr's own `QUERY_DEVICE_INFO`) are not bounded; a driver blocked in
  one past the bound is withdrawn like a hung one. A thread devmgr starts per
  settle sleeps the bound and signals the timer notification; when it cannot
  be started, that settle has no bound.

  A third, test-only batch (TODO(#165)) runs only on
  `devmgr_labels::TEST_SPAWN_FAULT_DRIVERS`, gated on `TEST_LABEL_AUTHORITY`,
  which only svctest's seed-only `devmgr.test` cap carries, and at most once
  per boot: three [`test-fault`](../../drivers/test-fault/README.md) fixtures
  from `/services/drivers/`, two that report ready and one that never does,
  each with a catalog entry that carries no startup info. It settles under
  `TEST_FAULT_SETTLE_TIMEOUT_MS` (1 s) instead of `SETTLE_TIMEOUT`, the
  fixtures making no bounded wait in their setup, and in every other respect
  as the production batches do; its served fixtures form a class of their
  own, queried with `TEST_QUERY_FAULT_DEVICE`.

  The instance ordinals of a class count its served drivers in spawn order
  and are fixed once its batch settles. devmgr observes every driver's death
  for the rest of the boot: its registry loop waits on the registry endpoint
  and the death queue together, and a settle hands the deaths of drivers
  outside its batch back to it. A served driver that dies is withdrawn as
  above, so callers queued on its endpoint return (the endpoint's teardown
  wakes them), and a tombstone holds its ordinal: its query replies
  `devmgr_errors::WITHDRAWN` for the rest of the boot, and the ordinals after
  it keep their drivers, so vfsd's probe of block ordinals, which continues
  past a `WITHDRAWN` reply, skips no live disk.

  The serving order follows from where each batch settles. The boot batch
  settles during initial enumeration, before the registry loop opens. vfsd's
  `QUERY_BLOCK_DEVICE` probes, and every query of the serial and framebuffer
  drivers, wait in the registry endpoint's queue until then. The on-disk
  batch settles in the `SET_DRIVERS_DIR` handler, after its reply and before
  the next receive, so `QUERY_RTC_DEVICE` and `QUERY_INPUT_DEVICE` see the
  settled drivers. While a batch settles, devmgr receives on no registry
  endpoint, and every registry caller waits for the settle, at most the
  settle bound. devmgr cannot serve the settled classes meanwhile: it must
  reply to a received call before its next receive, and it holds no saved
  reply capability, so an input query cannot wait while other labels are
  served.

  The settle does not deadlock against the log path as long as the drivers'
  synchronous log calls reach a receiver that does not wait on devmgr. During
  the boot settle, before handover, that receiver is init-logd, which never
  calls devmgr; the serial and framebuffer drivers do not log at all. During
  the on-disk settle it may be logd. logd calls devmgr only to resolve the
  serial and framebuffer drivers on its first emit. That emit comes before its
  `HANDOVER_PULL`, while init-logd still drains the log endpoint, and logd
  caches both outcomes. The precondition fails only when the serial driver
  cannot be resolved: logd then queries `QUERY_SERIAL_DEVICE` again on later
  emits, and devmgr's own logging in that handler, and the line it logs when
  it withdraws a served driver, already have the same deadlock window.

  Driver binaries are sourced from one of two places:

  - **Boot bundle** — bootstrap-essentials (virtio-blk, serial,
    framebuffer) arrive as `procmgr_labels::CREATE_PROCESS`-ready Memory
    caps in devmgr's MODULE bootstrap round. devmgr spawns these
    during initial enumeration, before the registry loop opens.
  - **On-disk rootfs** — non-essential drivers (the per-arch RTC and
    virtio-input) live at `/services/drivers/<driver>` and are loaded via
    `procmgr_labels::CREATE_FROM_FILE`. virtio-input is PCI-enumerated at
    boot, with its BAR and IRQ caps carved then and its spawn deferred to
    this path. svcmgr delivers a `LOOKUP | READ`-attenuated
    `/services/drivers/` subtree cap via `devmgr_labels::SET_DRIVERS_DIR`
    after handover (gated by `DRIVERS_DIR_AUTHORITY`); devmgr replies
    SUCCESS immediately (so svcmgr never blocks on driver work), then walks
    to each driver's binary and spawns it between `ipc_reply` and the next
    `ipc_recv`, settling the on-disk batch there (above). Each spawn is
    at-most-once per boot; failure, including an on-disk driver's death, or
    its overrun of the settle bound, before it reports ready, is sticky and
    surfaced as `devmgr_errors::NO_DEVICE` on subsequent `QUERY_RTC_DEVICE`
    and `QUERY_INPUT_DEVICE` queries, the same reply as before the spawn has
    run, so a client retries it only a bounded number of times. See
    [docs/device-management.md § Driver binary sources](../../../docs/device-management.md#driver-binary-sources).
- **Expose device registry** — maintain an IPC service that other services
  query to discover device endpoints after drivers are bound: vfsd resolves
  every block device (`QUERY_BLOCK_DEVICE`), logd resolves the serial driver
  (`QUERY_SERIAL_DEVICE`), `programs/terminal` resolves the framebuffer and
  input drivers (`QUERY_FRAMEBUFFER_DEVICE` / `QUERY_INPUT_DEVICE`), timed
  resolves the platform RTC (`QUERY_RTC_DEVICE`), and netd (design intent; not
  yet implemented, #30). devmgr owns each driver's service endpoint and mints a
  badged SEND on query. `QUERY_BLOCK_DEVICE` and `QUERY_INPUT_DEVICE` select
  one driver of their class by an optional instance ordinal in `data[1]`
  (absent means the first), counted over the served drivers (those that
  reported their device ready) in PCI segment, bus, device, function order and
  not stable across boots; a withdrawn driver's ordinal replies `WITHDRAWN`
  (above).
  `QUERY_BLOCK_DEVICE`, whose reply is the `MOUNT_AUTHORITY`-badged whole-disk
  cap, is gated on `BLOCK_DEVICE_AUTHORITY`, which only the registry cap init
  mints for vfsd carries. The serial,
  framebuffer, RTC, and input queries are gated on `REGISTRY_QUERY_AUTHORITY`,
  which every consumer query cap carries: svcmgr's `devmgr.*` publications,
  the cap svcmgr mints for logd at launch, and vfsd's.
- **Broker ACPI and shutdown hardware to pwrmgr** — devmgr is the sole
  owner of the ACPI Memory caps and the only service that walks the ACPI
  table tree (RSDP → XSDT). `QUERY_ACPI_TABLE` locates a table by
  signature or physical address and serves a read-only view of it (devmgr
  reads only the directory and table headers to locate it).
  `QUERY_SHUTDOWN_DEVICE` carves the shutdown-actuator caps pwrmgr
  needs — two narrow `IoPort` caps on x86-64, one over the PM1a control port
  and one over the 8042 reset port, or a Reset-only `SbiControl` derivation
  on RISC-V. pwrmgr names the PM1a port it computed from the FADT, and devmgr
  serves it only when it equals the FADT's `PM1a_CNT_BLK`, which devmgr reads
  itself (with the FADT's `CENTURY` field, the only table-body fields it reads
  beside the MCFG allocation entries it locates the ECAM windows from). On every
  call the caps are re-derived from the
  `IoPort` / `SbiControl` caps devmgr holds, so nothing is consumed and a
  restarted pwrmgr re-acquires them cleanly. devmgr runs no shutdown logic;
  it brokers the hardware, pwrmgr interprets and actuates. `QUERY_ACPI_TABLE`
  is gated on `REGISTRY_QUERY_AUTHORITY`; `QUERY_SHUTDOWN_DEVICE` on
  `SHUTDOWN_DEVICE_AUTHORITY`, which only the `devmgr.shutdown` cap carries:
  a seed-only name pwrmgr alone seeds, which svcmgr's `QUERY_ENDPOINT`
  refuses.
- **Handle hotplug** (design intent; not yet implemented) — on platforms that support it,
  receive hotplug notifications and dynamically spawn or terminate driver processes. See
  [`docs/hotplug.md`](hotplug.md).

---

## Capabilities Received

devmgr receives the following capabilities during bootstrap. Init delivers every one
except SchedControl over the bootstrap protocol in rounds; procmgr delivers SchedControl
in `ProcessInfo`. Round 1 carries the registry endpoint, then whichever of the
Interrupt range, RSDP, and DTB caps are present, with a presence bitmap, the exact
RSDP physical address, the DTB page base, and the DTB's page-rounded size in its data
words. Each later round names its kind in `data[0]`: `APERTURE` rounds carry up to
four Mmio caps and `ACPI_REGION` rounds up to four Memory caps, each round with its
base/size pairs; one `MODULE` round carries the boot-bundle
driver images, each tagged with its module class; a cap-less `FRAMEBUFFER_INFO`
round carries the framebuffer geometry (a zero base means no framebuffer); and the
terminal `SVCMGR_BUNDLE` round carries the svcmgr publish cap and the arch
shutdown-authority cap (a full-rights derivation of init's root `IoPort` on x86-64, a Reset +
Suspend `SbiControl` derivation on RISC-V). Init's
side of the transfer is summarized in
[services/init/docs/bootstrap.md § Per-stage authority transfers](../../init/docs/bootstrap.md#per-stage-authority-transfers).
See [docs/capability-model.md](../../../docs/capability-model.md) for capability type
definitions and [docs/device-management.md](../../../docs/device-management.md) for
how devmgr uses them.

| Capability | Rights | Purpose |
|---|---|---|
| Endpoint (devmgr registry, round 1 `caps[0]`) | `RIGHTS_ALL` (incl. Recv, Send, Grant) | Service endpoint for the device-registry IPC: devmgr serves the client queries (`QUERY_*_DEVICE`, `QUERY_ACPI_TABLE`, `QUERY_SHUTDOWN_DEVICE`), `SET_DRIVERS_DIR`, and the test-only `TEST_SPAWN_ORPHAN` / `TEST_ORPHAN_RESULT` / `TEST_QUERY_DENY_DEVICE` / `TEST_SPAWN_FAULT_DRIVERS` / `TEST_QUERY_FAULT_DEVICE` labels the enumeration redesign removes (#165) on it; every driver's query cap, for `QUERY_DEVICE_INFO` and `DRIVER_READY`, is on its settle batch's private endpoint instead (above). The test labels are gated on `TEST_LABEL_AUTHORITY`, which only the `devmgr.test` cap carries: a seed-only name svctest alone seeds. `TEST_QUERY_DENY_DEVICE` mints a SEND on the serial, input, or framebuffer driver's endpoint badged `TEST_DENY_BADGE`, which carries none of the driver's verb bits, so svctest can assert each driver's `UNAUTHORIZED` reply; every other SEND devmgr mints on those endpoints carries the bits |
| Mmio (one per boot-provided aperture) | Map, Write | Split per device into BAR / register sub-caps for drivers |
| Interrupt (full-rights derivation of init's root IRQ range) | Notify | Split with `SYS_IRQ_SPLIT` into per-line Interrupt caps delegated to drivers |
| IoPort (x86-64, full-rights derivation of init's root) | Use / carve | Carve narrow per-driver port caps (CMOS, COM1) and pwrmgr's PM1a + 8042 reset ports |
| SbiControl (RISC-V, Reset + Suspend) | Reset / Suspend | Steady-state holder of the platform power-state SBI authority (init is reaped); broker a Reset-only derivation to pwrmgr for SBI SRST shutdown / reboot. Suspend held for a future power path |
| Memory (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob; broker read-only ACPI tables to pwrmgr via `QUERY_ACPI_TABLE`. Parsing IOMMU topology (DMAR on x86-64, `iommu` / `iommu-map` on RISC-V) is design intent; not yet implemented |
| Memory (driver modules, MODULE round) | As held by init | Boot-bundle driver images (virtio-blk, serial, framebuffer), one per `module_kind`, spawned via `procmgr_labels::CREATE_PROCESS`; a module of an unknown kind or a second of one kind is logged and released |
| svcmgr publish authority (Endpoint, SVCMGR_BUNDLE round) | Send, Grant (`PUBLISH_AUTHORITY` badge) | Register service caps in svcmgr's registry; held but unused today, reserved for future devmgr publications |
| SchedControl (baseline, via `ProcessInfo`) | band `[1, 26]` (`sched_policy::DEVMGR_BAND_MAX`) | Place spawned drivers at their assigned levels (serial/virtio-blk at 26, framebuffer/RTC/virtio-input at 25 — the `CREATE_PRIORITY` field of each driver spawn) and set devmgr's own threads' priorities. Like every process, devmgr receives this from procmgr (`ProcessInfo.sched_control_cap`); init requests the deliberately-elevated ceiling (above devmgr's own level 24) via the create label's `CREATE_BAND_MAX` field |

IOMMU register regions are not pre-minted as distinct capabilities.
Design intent; not yet implemented: `devmgr` will discover IOMMU units
from the firmware passthrough (DMAR or DTB) and acquire `Mmio` caps for
their register ranges through the same aperture-carving flow as any
other device (see
[docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming)).

---

## Relationship to drivers

devmgr is the sole authority for spawning device drivers; supervising (restarting) them
is design intent; not yet implemented (#17, #262). After discovering a device, devmgr
requests procmgr to create the driver process and then delegates the per-device
capability set via IPC. Drivers MUST NOT be started independently of devmgr. See
[`drivers/README.md`](../../drivers/README.md) for the driver model.

---

## Summarized By

[Device Tree Parsing](../../../core/boot/docs/dtb.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md), [services/devmgr/README.md](../README.md),
[services/drivers/README.md](../../drivers/README.md),
[services/drivers/cmos/README.md](../../drivers/cmos/README.md),
[Driver Model](../../drivers/docs/driver-model.md),
[services/drivers/framebuffer/README.md](../../drivers/framebuffer/README.md),
[services/drivers/goldfish-rtc/README.md](../../drivers/goldfish-rtc/README.md),
[services/drivers/serial/README.md](../../drivers/serial/README.md),
[services/drivers/test-fault/README.md](../../drivers/test-fault/README.md),
[services/drivers/virtio/blk/README.md](../../drivers/virtio/blk/README.md),
[services/drivers/virtio/input/README.md](../../drivers/virtio/input/README.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md)
