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
  [docs/pci-enumeration.md](pci-enumeration.md) step 4),
  and whose second, terminal round delivers the driver's devmgr query cap
  (below). The `cmos-rtc` first round also carries one data word: the CMOS
  RAM index of the century register the FADT's `CENTURY` field names, or 0
  when it names none.
  A DMA-capable driver programs its device only with the device addresses
  devmgr returns from `DMA_MAP` on the driver's DMA capability, never with a
  physical address (below, and
  [docs/device-management.md § DMA Authorisation](../../../docs/device-management.md#dma-authorisation)).
  devmgr confines each DMA-capable device with the IOMMU driver of its
  architecture's family, `iommu-vtd` (VT-d) on x86-64 and `iommu-riscv` (the
  RISC-V IOMMU) on riscv64, which it spawns from its boot module before the
  boot batch, in a settle batch of its own, with each unit's register `Mmio`
  cap moved to it (devmgr keeps no copy), the unit's segment, and its scope
  resolved against the PCI scan. A VT-d unit's cap is carved from the
  apertures and its scope is the DMAR's, resolved against the scan's bridges;
  a RISC-V IOMMU is a PCI function the ACPI RIMT names, whose cap is the first
  page of its BAR 0, carved once devmgr has turned on the function's memory
  decode and bus mastering, and whose scope is the RIMT's ID mappings: each
  bus they cover whole and each scanned function on a bus they cover in part.
  The driver is created `CREATE_PINNED`, `CREATE_DMA_HOLD`, and
  `CREATE_PHYS_ACCESS` at `BOOT_DRIVER_PRIORITY`, and its hold is never
  released: devmgr deletes the release token of its create reply at the
  spawn, so its table pages stay quarantined for the boot; devmgr and it are
  the processes that read physical addresses
  ([docs/device-management.md](../../../docs/device-management.md#physical-addresses)
  § Physical Addresses). Once it is ready devmgr attaches every
  DMA-capable device it binds to a domain of its own (`iommu_labels::ATTACH`)
  before the device's DMA grant and maps there, at their own addresses, the
  ranges an RMRR reserves for it (`iommu_labels::MAP_RESERVED`), logging each.
  It refuses, with a log line, a device whose reserved ranges overlap pooled
  memory, pass its unit's width, number past `MAX_RESERVED_RANGES_PER_DEVICE`,
  or fail to map, one the RIMT gives an IOMMU device ID other than its
  requester ID, one whose unit it could not hand over, and one whose `ATTACH`
  fails; a device no unit translates
  runs DMA-unsafe. With no DMAR or RIMT, no driver module, or a driver not
  ready within the settle bound, devmgr logs once that DMA runs unconfined and
  every DMA-capable driver runs DMA-unsafe (a driver that died or hung after
  it turned a unit's translation on leaves that unit blocking the devices
  behind it, which the log line states). A thread of devmgr's
  takes the driver's recorded faults every second (`TAKE_FAULTS`) and logs
  each against its device. If the driver dies after it reported ready, a death
  watch thread of devmgr's own, which no registry call can delay, fails the
  IOMMU client at once; devmgr logs once, refuses every later `DMA_MAP` of
  every confined device, answers any of its own calls still queued on the
  driver's endpoint from a drain thread, and withdraws every confined device's
  driver; it restarts nothing ([#262](https://github.com/kottlerg/seraph/issues/262)). See
  [docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming).

  devmgr spawns one driver for every virtio-input device, for the first
  virtio-console device (the debug port, below), and for every
  virtio-blk device it can give an IRQ cap, each with its own service
  endpoint, an `Mmio` cap for every BAR the device's VirtIO register regions
  name, its own derivation of its line's held `Interrupt` cap, so devices
  that share an `INTx` line are all served, and the device's DMA capability
  (see [docs/pci-enumeration.md](pci-enumeration.md) § Per-Device Capability
  Creation).

  The DMA capability is a SEND, badged with the device badge, on devmgr's DMA
  endpoint, which devmgr creates before its first spawn and serves on a thread
  of its own for the rest of the boot, placed at `BOOT_DRIVER_PRIORITY` (26,
  above devmgr's 24) since virtio-blk blocks on it twice per transfer: `DMA_MAP`
  records a mapping of the Memory cap a driver sends, which devmgr keeps while
  the mapping stands, and replies its device address, and `DMA_UNMAP` removes
  one (`ipc::devmgr_dma_labels`). For a confined device the address is an IOVA
  devmgr allocates in the device's own IOVA space
  (`devmgr_firmware::dma::iova_limit`), and the thread has the IOMMU driver
  install the mapping (`MAP`, moving it a derivation of the cap) before it
  replies, and remove it (`UNMAP`) before it deletes the cap; a refused or
  failed IOMMU call replies `IOMMU_FAILED`. The thread serves it apart from the registry
  loop because that loop makes nested calls and settles batches during which
  drivers map their buffers: a `CREATE_FROM_FILE` reads a driver binary through
  virtio-blk, which maps the read's buffer, and every `VirtIO` driver maps its
  rings before it reports ready. The two threads share the device and mapping
  table (`devmgr_firmware::dma::DmaTable`) under one lock, taken only around
  table operations and never across IPC: a mapping is pending in the table
  while its IOMMU call is in flight, so a withdrawal meanwhile neither races
  its commit nor deletes the cap the call carries. A device that cannot be given a DMA
  capability is not spawned; devmgr halts when it cannot start the DMA endpoint,
  since no DMA-capable driver could set its device up.

  devmgr serves a driver's endpoint only once the driver has set its device
  up. It spawns its drivers in three production settle batches: the IOMMU
  batch (the IOMMU driver alone, on x86-64, settled first so it is ready
  before any device is attached), the boot batch (every virtio-blk driver,
  then the serial and framebuffer drivers), and the on-disk batch (the RTC
  driver, then every virtio-input driver, then the virtio-console driver).
  Each driver's devmgr query cap is a
  SEND, badged with its device badge, on its batch's private endpoint; the
  IOMMU, serial, and RTC drivers' badges name catalog entries that carry no
  startup info. Once a driver's bootstrap is served,
  devmgr binds a death observer on the driver's thread to its driver death
  queue: one queue for the boot, sized at enumeration to every driver the boot
  can spawn (one per virtio-blk and virtio-input device, one for the debug
  port when a virtio-console device is present, the IOMMU, serial,
  framebuffer, and RTC drivers, and the three fixtures of the test-only fault
  batch and the one of the test-only DMA batch below), so every bind is funded
  and no death is dropped. A driver that
  needs startup info (the VirtIO drivers, the framebuffer) calls
  `QUERY_DEVICE_INFO` on its query cap before its device setup, and every
  driver calls `DRIVER_READY` on it after, immediately before its service
  loop. devmgr waits on a wait set over the batch's private endpoint, the
  death queue, and a timer, serving those two labels on the private endpoint
  and taking deaths from the queue, until every driver of the batch has
  reported ready or died or the settle bound elapses, and then takes every
  death still queued. It then revokes the private endpoint, serves each driver
  that reported ready, and withdraws the rest.

  Withdrawing a `VirtIO` driver, live or dead, takes its device from it in
  this order, so the driver's memory returns to memmgr only once the device's
  DMA is confirmed stopped or blocked
  ([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
  § DMA-Safe Teardown):

  0. devmgr withdraws the device's DMA capability: it revokes every copy of
     it, the driver's included, drops the device's mappings, and blocks a
     confined device in the IOMMU (`iommu_labels::BLOCK`, which withdraws every
     range of its domain), so the driver maps nothing more and a confined
     device reaches nothing. It keeps the Memory caps it kept for the mappings,
     each a reference that keeps its frame out of memmgr's pool, and deletes
     them only after steps 1 to 3 have run, when the block is in place or all
     three confirm; a device that meets neither leaves them kept for the rest
     of the boot.
  1. devmgr clears the function's Bus Master Enable through the `Mmio` cap of
     the function's configuration page, which it carves at enumeration and
     delegates to no driver ([`docs/pci-enumeration.md`](pci-enumeration.md)
     § Per-Device Capability Creation), and reads the Command register back.
     While the bit is clear the function issues no memory request of its own,
     so it performs no DMA, whatever its driver does; the driver holds only
     BAR caps, so it cannot set the bit again.
  2. devmgr revokes every cap derived from the BAR caps it keeps, which
     removes the driver's mappings of the device before the revocation
     returns. A live driver's next register access faults; its death is held
     at step 4 like any other.
  3. devmgr maps the BAR cap holding the common configuration region, writes
     0 to `device_status`, and waits, bounded by `RESET_TIMEOUT`
     (`virtio_core::pci::RESET_TIMEOUT`, 5 s), for the status to read 0, which
     completes the reset: the device has then dropped its pending interrupt,
     so a line it shares is left no assertion to loop on.
  4. devmgr sends `DESTROY_PROCESS` on the driver's process handle, which it
     keeps for the rest of the boot; procmgr tears a live driver down, and a
     dead one it has reaped already is a no-op. Every `VirtIO` driver is
     created `CREATE_DMA_HOLD`, so procmgr holds the driver's memory on its
     memmgr record, out of the free pool, whether the driver died on its own
     or was destroyed. Only when the IOMMU blocked the device at step 0, or
     Bus Master Enable read back clear, every BAR copy was revoked, and the
     reset confirmed, does devmgr send `RELEASE_HOLD` on the driver's release
     token, the third cap of the driver's create reply, which devmgr keeps
     with the device's caps and hands to no one; procmgr then sends memmgr
     `PROCESS_DIED`, and the memory returns to the pool
     ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md#label-3-release_hold)
     § Label 3). Otherwise the device may still be writing that memory:
     devmgr logs the device, deletes the token, and never releases the hold,
     so the memory stays quarantined on the dead driver's memmgr record,
     counted and never handed out again, for the rest of the boot. The frames
     a client lends a virtio-blk driver for a transfer are on the client's
     memmgr record, which no hold covers; memmgr keeps them out of the pool
     while the driver, or devmgr's DMA mapping, still holds a capability to
     them
     ([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#reclamation)
     § Reclamation). A dead driver's go with its `CSpace`, but the device
     reaches such a frame only through a standing mapping, whose cap devmgr
     deletes only as step 0 says, so such a frame too returns only once the
     device is confirmed stopped or blocked. A status byte past the span its
     BAR cap was carved to is not written, and a BAR copy whose revocation
     fails leaves the driver its mapping; either counts as an unconfirmed
     reset.

  Each withdrawal resets once, and the wait for the confirmation holds
  devmgr's thread (the settle, or the registry loop) for up to `RESET_TIMEOUT`
  per withdrawn device, all of it for one whose status does not read 0 within
  the bound. A driver still running (one pending, one devmgr has no memory to
  serve, one devmgr's batch cannot record at its spawn, or one whose bootstrap
  failed after its start) is withdrawn the same way, its Bus Master Enable
  cleared before its BAR caps are taken. A driver that dies on its own is
  withdrawn when devmgr takes its death from the death queue; procmgr may reap
  it first, and holds its memory until devmgr's release. devmgr spawns no
  driver for a `VirtIO` device whose configuration page it holds no cap for,
  since it could not clear that function's Bus Master Enable. Then the
  driver's service endpoint is revoked and deleted and its BAR, DMA,
  configuration-page, and IRQ caps released. A withdrawn driver of any other
  class is destroyed through its process handle while devmgr still keeps it
  (until its batch settles); none of them drives a DMA-capable device, and none
  is created `CREATE_DMA_HOLD`.

  No boot withdraws a `VirtIO` driver, so none runs this order. A boot serves
  every `VirtIO` driver that reports ready, and devmgr withdraws one only on
  its death or a failed settle. A test boot cannot cause either without a
  test-only label to kill a `VirtIO` driver, which the enumeration redesign
  removes ([#165](https://github.com/kottlerg/seraph/issues/165)): only devmgr
  holds a `VirtIO` driver's process handle, and the only virtio-blk driver of a
  test boot serves its root filesystem. Nor could a boot place a late device
  write after a free, since the emulated devices complete a request on their
  own event loop, with nothing a guest can hold in flight. What every boot does
  run is the carve of each `VirtIO` function's configuration page and the
  mapping helper (`with_mmio_mapped`), through which the ECAM scan maps each
  window; the configuration page itself is mapped only on a withdrawal. The
  Command register arithmetic is host-tested in the devmgr firmware crate, and
  svctest's `procmgr_dma_hold` phase checks the held reclaim the order rests
  on: a started held child's pages stay out of memmgr's pool after its
  teardown until the release on its token, which its process handle cannot
  send. The order in which devmgr deletes its mapping caps at a withdrawal has
  no boot, for the same reasons. Nor has the deletion of a lent cap in a
  virtio-blk reply that fails: it needs the driver's client to die, or run out
  of slots, mid-request, and no test process can call the driver, since only
  vfsd and fatfs hold a SEND on it (svctest's devmgr phase checks that svctest
  holds no `BLOCK_DEVICE_AUTHORITY`).

  The catalog entry of a withdrawn driver, or of one that failed to spawn,
  stays, so a badge is never reused. No `QUERY_*` reply hands out the endpoint
  of a driver that has not reported its device ready.

  The settle bound, `SETTLE_TIMEOUT` (`services/devmgr/src/settle.rs`), is
  twice `virtio_core::pci::RESET_TIMEOUT` (5 s), so 10 s, counted from the
  start of the settle, after the batch's last spawn. The VirtIO reset, which
  a virtio-blk, virtio-input, or virtio-console driver polls for once, is the
  longest bounded wait a driver's setup makes, so the settle never ends before
  a driver's own timeout has, and a margin of one further `RESET_TIMEOUT`
  covers the rest of the setup. The serial, framebuffer, and RTC drivers make
  no bounded wait in their setup. The synchronous IPC calls every driver's setup makes (memmgr,
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

  A fourth, test-only batch (TODO(#165)) runs only on
  `devmgr_labels::TEST_SPAWN_DMA_DRIVER`, under the same gate, at most once per
  boot: devmgr binds QEMU's `edu` device (PCI `1234:11e8`, which xtask attaches
  on both architectures) to the [`test-dma`](../../drivers/test-dma/README.md)
  fixture. It carves the first page of the device's BAR 0 and its
  configuration page, gives the device its DMA grant, attaching it to its IOMMU
  domain where a unit translates it, turns its memory decode and bus mastering
  on, and spawns the fixture from `/services/drivers/` through the PCI spawn
  path, settled under `SETTLE_TIMEOUT`; it is queried with
  `TEST_QUERY_DMA_DEVICE`, and `TEST_DMA_FAULTS` takes and logs the IOMMU
  driver's faults and reports those taken for the device.

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
  the next receive, so `QUERY_RTC_DEVICE`, `QUERY_INPUT_DEVICE`, and
  `QUERY_DEBUG_PORT_DEVICE` see the settled drivers. While a batch settles,
  devmgr receives on no registry endpoint, and every registry caller waits for
  the settle, at most the settle
  bound plus up to `RESET_TIMEOUT` for each withdrawn `VirtIO` device (all of
  it for one whose status does not read 0 within the bound, above). devmgr
  cannot serve the settled classes meanwhile: it must reply to a received call
  before its next receive, and it holds no saved reply capability, so an input
  query cannot wait while other labels are served.

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

  - **Boot bundle** — bootstrap-essentials (virtio-blk, serial, framebuffer, and
    the IOMMU driver, `iommu-vtd` on x86-64 and `iommu-riscv` on riscv64) arrive as
    `procmgr_labels::CREATE_PROCESS`-ready Memory caps in devmgr's MODULE
    bootstrap round. devmgr spawns these during initial enumeration, before the
    registry loop opens.
  - **On-disk rootfs** — non-essential drivers (the per-arch RTC,
    virtio-input, and virtio-console) live at `/services/drivers/<driver>` and
    are loaded via `procmgr_labels::CREATE_FROM_FILE`. virtio-input and
    virtio-console are PCI-enumerated at boot, with their BAR and IRQ caps
    carved then and their spawns deferred to this path. svcmgr delivers a `LOOKUP | READ`-attenuated
    `/services/drivers/` subtree cap via `devmgr_labels::SET_DRIVERS_DIR`
    after handover (gated by `DRIVERS_DIR_AUTHORITY`); devmgr replies
    SUCCESS immediately (so svcmgr never blocks on driver work), then walks
    to each driver's binary and spawns it between `ipc_reply` and the next
    `ipc_recv`, settling the on-disk batch there (above). Each spawn is
    at-most-once per boot; failure, including an on-disk driver's death, or
    its overrun of the settle bound, before it reports ready, is sticky and
    surfaced as `devmgr_errors::NO_DEVICE` on subsequent `QUERY_RTC_DEVICE`,
    `QUERY_INPUT_DEVICE`, and `QUERY_DEBUG_PORT_DEVICE` queries, the same reply
    as before the spawn has run, so a client retries it only a bounded number of times. See
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
  `QUERY_DEBUG_PORT_DEVICE` answers with the debug port: the first
  virtio-console device's driver, which serves the serial protocol
  ([services/drivers/virtio/console/README.md](../../drivers/virtio/console/README.md)),
  a byte transport apart from the console's UART that a debugger stub owns. Its
  reply reads and writes the port, so it is gated on `DEBUG_PORT_AUTHORITY`,
  which svcmgr mints only onto the seed-only `devmgr.debug` name; a further
  console device is left unbound, and a boot with none has no debug port.
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
base/size pairs; cap-less `RAM_EXTENT` rounds carry the base/size pair of every
extent of RAM memmgr pools, against which devmgr checks the regions firmware reserves
for a device
([docs/device-management.md](../../../docs/device-management.md#iommu-discovery-and-programming)
§ IOMMU Discovery and Programming); one `MODULE` round carries the boot-bundle
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
| Endpoint (devmgr registry, round 1 `caps[0]`) | `RIGHTS_ALL` (incl. Recv, Send, Grant) | Service endpoint for the device-registry IPC: devmgr serves the client queries (`QUERY_*_DEVICE`, `QUERY_ACPI_TABLE`, `QUERY_SHUTDOWN_DEVICE`), `SET_DRIVERS_DIR`, and the test-only `TEST_SPAWN_ORPHAN` / `TEST_ORPHAN_RESULT` / `TEST_QUERY_DENY_DEVICE` / `TEST_SPAWN_FAULT_DRIVERS` / `TEST_QUERY_FAULT_DEVICE` / `TEST_SPAWN_DMA_DRIVER` / `TEST_QUERY_DMA_DEVICE` / `TEST_DMA_FAULTS` labels the enumeration redesign removes (#165) on it; every driver's query cap, for `QUERY_DEVICE_INFO` and `DRIVER_READY`, is on its settle batch's private endpoint instead (above). The test labels are gated on `TEST_LABEL_AUTHORITY`, which only the `devmgr.test` cap carries: a seed-only name svctest alone seeds. `TEST_QUERY_DENY_DEVICE` mints a SEND on the serial, input, or framebuffer driver's endpoint badged `TEST_DENY_BADGE`, which carries none of the driver's verb bits, so svctest can assert each driver's `UNAUTHORIZED` reply; every other SEND devmgr mints on those endpoints carries the bits |
| Mmio (one per boot-provided aperture) | Map, Write | Split per device into BAR / register sub-caps for drivers, and into each IOMMU unit's register cap (a VT-d unit's register page, a RISC-V IOMMU's BAR 0 page), which devmgr moves to the IOMMU driver; the ECAM windows carved from them stay devmgr's, split into the configuration page of each `VirtIO` function, which devmgr keeps to clear its Bus Master Enable (above) |
| Interrupt (full-rights derivation of init's root IRQ range) | Notify | Split with `SYS_IRQ_SPLIT` into per-line Interrupt caps delegated to drivers |
| IoPort (x86-64, full-rights derivation of init's root) | Use / carve | Carve narrow per-driver port caps (CMOS, COM1) and pwrmgr's PM1a + 8042 reset ports |
| SbiControl (RISC-V, Reset + Suspend) | Reset / Suspend | Steady-state holder of the platform power-state SBI authority (init is reaped); broker a Reset-only derivation to pwrmgr for SBI SRST shutdown / reboot. Suspend held for a future power path |
| Memory (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob; broker read-only ACPI tables to pwrmgr via `QUERY_ACPI_TABLE`; read the DMAR's VT-d units, scopes, and RMRRs on x86-64, and the RIMT's PCI IOMMUs and ID mappings on riscv64 |
| Memory (driver modules, MODULE round) | As held by init | Boot-bundle driver images (virtio-blk, serial, framebuffer, and the IOMMU driver, `iommu-vtd` on x86-64 and `iommu-riscv` on riscv64), one per `module_kind`, spawned via `procmgr_labels::CREATE_PROCESS`; a module of an unknown kind or a second of one kind is logged and released |
| svcmgr publish authority (Endpoint, SVCMGR_BUNDLE round) | Send, Grant (`PUBLISH_AUTHORITY` badge) | Register service caps in svcmgr's registry; held but unused today, reserved for future devmgr publications |
| SchedControl (baseline, via `ProcessInfo`) | band `[1, 26]` (`sched_policy::DEVMGR_BAND_MAX`) | Place spawned drivers at their assigned levels (serial/virtio-blk/the IOMMU driver at 26, framebuffer/RTC/virtio-input/virtio-console at 25 — the `CREATE_PRIORITY` field of each driver spawn) and set devmgr's own threads' priorities (the DMA thread at 26, the IOMMU fault-log thread at 24, through `std::os::seraph::thread::BuilderExt::spawn_at_priority`). Like every process, devmgr receives this from procmgr (`ProcessInfo.sched_control_cap`); init requests the deliberately-elevated ceiling (above devmgr's own level 24) via the create label's `CREATE_BAND_MAX` field |

devmgr's own `AddressSpace` cap, which procmgr installs, carries no `RIGHTS_AS_READ`: procmgr
mints every child's address space without it, a phys-class child's included
([services/procmgr/docs/ipc-interface.md](../../procmgr/docs/ipc-interface.md) § Label 1:
`CREATE_PROCESS`). devmgr reads that cap's rights at startup, before its bootstrap rounds, and
halts, logged, when the right is present or the rights cannot be read: it is the phys-class child
every boot creates, so a mint that kept the right fails the boot instead of passing unseen.

IOMMU register regions are not pre-minted as distinct capabilities.
`devmgr` discovers VT-d units from the DMAR, carves an `Mmio` cap for each
unit's register range through the same aperture-carving flow as any other
device (the bootloader seeds an aperture over each, since no other table
names those pages), and moves each to the VT-d IOMMU driver. It discovers
the RISC-V IOMMUs from the RIMT, carves the first page of each one's BAR 0,
which lies in a PCI window the bootloader seeds already, and moves each to the
RISC-V IOMMU driver (see
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
[services/drivers/test-dma/README.md](../../drivers/test-dma/README.md),
[services/drivers/test-fault/README.md](../../drivers/test-fault/README.md),
[services/drivers/virtio/blk/README.md](../../drivers/virtio/blk/README.md),
[services/drivers/virtio/console/README.md](../../drivers/virtio/console/README.md),
[services/drivers/virtio/input/README.md](../../drivers/virtio/input/README.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md),
[services/pwrmgr/README.md](../../pwrmgr/README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md)
