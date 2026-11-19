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
  to acpid (below). When neither yields an ECAM, devmgr on RISC-V falls back to
  the QEMU `virt` platform-default ECAM window (`platform_default_ecam`:
  `0x3000_0000`, 256 MiB, buses 0..=255); on x86-64 the boot halts. devmgr
  derives per-device interrupt lines from PCI configuration space; resolving
  interrupt routing and power domains from firmware tables is design intent;
  not yet implemented.
- **Enumerate PCI devices** — for each ECAM window, reserve VA, map the
  window via `std::os::seraph::mmio_map_funded`, which funds the AS's
  page-table growth budget the map needs, read configuration space, discover
  every function and its BARs, resolve interrupt assignments. See
  [`docs/pci-enumeration.md`](pci-enumeration.md).
- **Bind drivers** — match discovered devices to driver binaries in
  [`drivers/`](../../drivers/README.md) by the declaration each binary
  carries, request procmgr to create driver processes, and delegate
  per-device capabilities (MMIO, interrupt, and IoPort where applicable)
  ([docs/driver-binding.md](../../../docs/driver-binding.md), whose § Status
  names what of it runs). Each PCI device is bound by declaration through
  one bind path (below), and so is each platform device record
  ([docs/driver-binding.md](../../../docs/driver-binding.md#device-records)
  § Device Records), in record order: the boot framebuffer; the static
  `Device` objects of the DSDT and every SSDT; the SPCR's console UART; and
  the devices of the platform description table whose `oem_table_id` equals
  the XSDT's OEM table ID (§ Platform Description Tables there). devmgr merges
  the records by resource identity and delivers each driver the record's
  resource list: each `Mmio` carved as
  [docs/driver-binding.md](../../../docs/driver-binding.md#binding) § Binding
  step 1 says, each `IoPort` from its
  port capability, and the wired line carved exclusive, shared with no other
  device (the serial driver acknowledges a delivery only when its client reads
  ([services/drivers/serial/README.md](../../drivers/serial/README.md#interrupts)
  § Interrupts), so no other device may share its line; every PCI device's
  line is instead held and shared,
  [docs/pci-enumeration.md](pci-enumeration.md) step 4), then the service
  endpoint and the driver's devmgr query cap (below). The serial driver
  matches an SPCR interface type 0x00 or 0x12 or `_HID` `PNP0501`, the
  framebuffer driver the `boot-framebuffer` key, `cmos-rtc` `_HID` or `_CID`
  `PNP0B00`, `PNP0B01` or `PNP0B02`, `tpm` `_HID` `MSFT0101`,
  and `goldfish-rtc` the platform key `google,goldfish-rtc`. devmgr attaches
  the FADT's `CENTURY` index to the record carrying `PNP0B00`, `PNP0B01`, or
  `PNP0B02` as device info (`ipc::device_info_kind::RTC_CENTURY`, a one-byte
  payload), which `cmos-rtc` reads with `QUERY_DEVICE_INFO`; with none it
  takes the century 20. The IOMMU driver, matched against the IOMMU family
  record (below), takes the same resource list, with one unit round opening
  each unit's resources.
  A DMA-capable driver programs its device only with the device addresses
  devmgr returns from `DMA_MAP` on the driver's DMA capability, never with a
  physical address (below, and
  [docs/device-management.md § DMA Authorisation](../../../docs/device-management.md#dma-authorisation)).
  devmgr confines each DMA-capable device with the IOMMU driver of its
  architecture's family, `iommu-vtd` (VT-d) on x86-64 and `iommu-riscv` (the
  RISC-V IOMMU) on riscv64, which it spawns from its boot module before the
  boot batch, in a settle batch of its own, delivering it in its resource
  list each unit's segment, its scope resolved against the PCI scan, and its
  register `Mmio` cap, whose original devmgr deletes once the spawn returns
  (devmgr keeps no copy). A VT-d unit's cap is carved from the
  apertures and its scope is the DMAR's, resolved against the scan's bridges;
  a RISC-V IOMMU is a PCI function the ACPI RIMT names, whose cap is the first
  page of its BAR 0, carved before devmgr turns on the function's memory
  decode and bus mastering, the hand-over's last step, so an IOMMU not
  handed over is left as the firmware left it, and whose scope is the RIMT's
  ID mappings: each bus they cover whole and each scanned function on a bus
  they cover in part.
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
  watch thread of devmgr's own, which no call of its control thread can delay, fails the
  IOMMU client at once; devmgr logs once, refuses every later `DMA_MAP` of
  every confined device, answers any of its own calls still queued on the
  driver's endpoint from a drain thread, and withdraws every confined device's
  driver; it restarts none of them, nor the IOMMU driver (§ Driver Restart). See
  [docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming).

  devmgr binds PCI devices in two passes
  ([docs/driver-binding.md](../../../docs/driver-binding.md#matching)
  § Matching): the boot pass, over the declarations of the boot modules it
  holds, and the
  drivers-directory pass at `SET_DRIVERS_DIR`, over the declarations of the
  `/services/drivers/` entries (below). Each pass gathers the declarations
  that match an unbound device, walks the unbound devices in PCI
  segment, bus, device, function order, and binds each to its most specific
  match: an exact vendor and device key outranks a class key, two equally
  specific matches are a conflict that devmgr logs and binds neither of, and a
  declaration's instance limit counts the devices bound to a driver of its
  name in that order.
  A pass binds a device at most once a boot, so a drivers-directory declaration
  never takes a device a boot module's driver holds. The bind
  (`services/devmgr/src/bind.rs`) gives the driver its own service endpoint
  and, from the device's record only
  ([docs/pci-enumeration.md](pci-enumeration.md) § Per-Device Capability
  Creation):

  - an `Mmio` cap per MMIO BAR: for a driver that declares the VirtIO
    status reset, and so is given the VirtIO register layout, each BAR the
    layout names, clipped to the pages its regions reach, and for any other
    driver every MMIO BAR, whole. For a
    function devmgr may give MSI-X the pages holding its MSI-X table and
    Pending Bit Array are cut out, so a BAR may be up to three caps, each
    naming its offset in its BAR; devmgr keeps the table's pages and writes
    every table entry itself. I/O BARs are not delivered;
  - for a declaration that takes an interrupt, its own derivation of its
    line's held `Interrupt` cap with `RIGHTS_IRQ_NOTIFY` only, so devices that
    share an `INTx` line are all served and no driver holds Mint (devmgr routed
    the line when it carved it); a device with no line is not bound when its
    declaration requires one. A declaration that
    asks for vectors (nonzero `msi_vectors`) and for DMA gets message-signaled
    vectors in place of the line: MSI-X (`min(requested, table size)` vectors,
    table entries 0 onwards, each entry's message written and unmasked by
    devmgr), else MSI (one vector), else the line. Each vector is one
    `Interrupt` resource (kind `Msi` or `MsiX`, mode 0) devmgr mints with
    `SYS_IRQ_MSG_ALLOC`; a bind delivers at most 72 resources
    (`MAX_BOUND_RESOURCES`, 8 BAR ranges and 64 vectors). On riscv64
    behind the RISC-V IOMMU devmgr maps each target's IMSIC interrupt file
    into the device's domain with `MAP_MSI` before it enables the vectors;
    VT-d refuses `MAP_MSI`, and its interrupt remapping governs the write instead.
    [docs/device-management.md](../../../docs/device-management.md#message-signaled-interrupts)
    § Message-Signaled Interrupts owns the rule;
  - for a DMA declaration, the device's DMA capability, after its grant
    attaches it to its IOMMU domain where a unit translates it (above); the
    driver is then created `CREATE_PINNED` and `CREATE_DMA_HOLD`;
  - a catalog entry carrying the VirtIO startup info for a driver given the
    VirtIO register layout, and no startup info otherwise.

  devmgr keeps the function's configuration page, which it carves at the bind
  and delegates to no driver, and writes the Command register through it:
  Memory Space Enable on, Bus Master Enable on only for a DMA declaration, and
  Interrupt Disable clear only for a driver given the line (MSI Enable or
  MSI-X Enable set for one given vectors). It creates the
  driver at `BOOT_DRIVER_PRIORITY` for a declaration of the boot tier from a
  boot module and at `AUX_DRIVER_PRIORITY` otherwise, a drivers-directory
  declaration's boot tier logged and ignored, and grants no PCI-bound driver
  physical access. It delivers the caps as the resource list of
  `driver_binding::resources`: one round per resource naming its kind and
  fields, then a terminal round carrying the service endpoint, the driver's
  devmgr query cap, and the DMA capability
  ([shared/driver-binding/README.md](../../../shared/driver-binding/README.md)).
  A device none of these can be had for is logged and not bound.

  The DMA capability is a SEND, badged with the device badge, on devmgr's DMA
  endpoint, which devmgr creates before its first spawn and serves on a thread
  of its own for the rest of the boot, placed at `BOOT_DRIVER_PRIORITY` (26,
  above devmgr's 24) since virtio-blk blocks on it twice per transfer: `DMA_MAP`
  records a mapping of the Memory cap a driver sends, which devmgr keeps while
  the mapping stands, and replies its device address, and `DMA_UNMAP` removes
  one (`ipc::devmgr_dma_labels`). For a confined device the address is an IOVA
  devmgr allocates in the device's own IOVA space, below the smaller of the
  unit's translated width and the DMA address width the bound declaration
  states (`devmgr_firmware::dma::iova_limit`), and the thread has the IOMMU
  driver install the mapping (`MAP`, moving it a derivation of the cap) before it
  replies, and remove it (`UNMAP`) before it deletes the cap; a refused or
  failed IOMMU call replies `IOMMU_FAILED`. The thread serves it apart from the registry
  and the control thread (below) because the control thread makes nested calls and settles
  batches during which drivers map their buffers: a `CREATE_FROM_FILE` reads a driver binary through
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
  batch (the IOMMU driver alone, settled first so it is ready before any
  device is attached), the boot batch (the boot pass, over the PCI and platform records the boot
  modules' declarations match), and the on-disk batch (the drivers-directory
  pass, which binds the RTC driver to its platform record). Each hotplug arrival that appends a
  record after `SET_DRIVERS_DIR` runs one more drivers-directory pass, in a batch of its own,
  the hotplug batch ([hotplug.md](hotplug.md#binding) § Binding).
  Each driver's devmgr query cap is a
  SEND, badged with its device badge, on its batch's private endpoint; the
  IOMMU driver's badge, and those of PCI-bound drivers given no VirtIO
  register layout (any that declares no VirtIO status reset), name catalog
  entries that carry no startup info;
  a platform record's badge names an entry too, the framebuffer's carrying its
  geometry and the CMOS RTC's its century index. Once a driver's bootstrap is
  served,
  devmgr binds two death observers on the driver to its driver death queues
  (§ Relationship to drivers): a counted death set (`shared/death-set`)
  whose first queue is sized at enumeration to both observers of every
  driver the boot's records can be given (one per PCI device, one per
  platform device record, the IOMMU driver), and which adds a further queue
  of twice the last when the queues' binds are spent. Each queue's ring has
  an entry per observer it takes and each observer posts at most once, so
  every bind is funded and no death is dropped. A driver that
  needs startup info (the VirtIO drivers, the framebuffer) calls
  `QUERY_DEVICE_INFO` on its query cap before its device setup, and every
  driver calls `DRIVER_READY` on it after, immediately before its service
  loop. devmgr waits on a wait set over the batch's private endpoint, the
  death queues, and a timer, serving those two labels on the private endpoint
  and taking deaths from the queue, until every driver of the batch has
  reported ready or died or the settle bound elapses, and then takes every
  death still queued. It then revokes the private endpoint, serves each driver
  that reported ready, and withdraws the rest.

  Withdrawing a driver devmgr bound to a PCI device, live or dead, takes the
  device from it in this order, so the driver's memory returns to memmgr only
  once the device's DMA is confirmed stopped or blocked
  ([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
  § DMA-Safe Teardown):

  0. devmgr withdraws the device's DMA capability: it revokes every copy of
     it, the driver's included, drops the device's mappings, and blocks a
     confined device in the IOMMU (`iommu_labels::BLOCK`, which withdraws every
     range of its domain), so the driver maps nothing more and a confined
     device reaches nothing. It keeps the Memory caps it kept for the mappings,
     each a reference that keeps its frame out of memmgr's pool, and deletes
     them only after steps 1 to 4 have run, when the block is in place or
     steps 1, 2, and 4 all confirm; a device that meets neither leaves them
     kept for the rest of the boot. A driver with no DMA capability skips
     this step.
  1. devmgr clears the function's Bus Master Enable through the `Mmio` cap of
     the function's configuration page, which it carves at the bind and
     delegates to no driver ([`docs/pci-enumeration.md`](pci-enumeration.md)
     § Per-Device Capability Creation), and reads the Command register back.
     While the bit is clear the function issues no memory request of its own,
     so it performs no DMA, whatever its driver does; the driver holds only
     BAR caps, so it cannot set the bit again.
  2. devmgr revokes every cap derived from the BAR caps it keeps, which
     removes the driver's mappings of the device before the revocation
     returns. A live driver's next register access faults; its death is held
     at step 5 like any other.
  3. devmgr clears the function's MSI Enable and MSI-X Enable bits and sets its
     Interrupt Disable bit through the same page and reads the latter back, so
     the function no longer signals a message or asserts its wired line,
     whoever else shares it; a bit that does not read back set is logged, and
     does not decide whether the device is quiet, which concerns its DMA
     alone.
  4. devmgr runs the reset the driver's declaration names. The VirtIO status
     reset maps the BAR cap holding the common configuration region, writes 0
     to `device_status`, and waits, bounded by `RESET_TIMEOUT`
     (`virtio_core::pci::RESET_TIMEOUT`, 5 s), for the status to read 0, which
     completes the reset: the device has then dropped its pending interrupt.
     A PCI Express Function Level Reset finds the function's PCI Express
     capability, checks that Device Capabilities offers the reset, sets
     Initiate Function Level Reset in Device Control, sleeps
     `FLR_COMPLETION_MS` (`devmgr_firmware::pci`, 100 ms), and confirms the
     reset when the Vendor ID answers. A declaration of no reset, or of a
     VirtIO reset for a device whose status byte no delivered BAR holds, is
     never confirmed.
  5. devmgr sends `DESTROY_PROCESS` on the driver's process handle, which it
     keeps for the rest of the boot; procmgr tears a live driver down, and a
     dead one it has reaped already is a no-op. Every driver of a DMA
     declaration is created `CREATE_DMA_HOLD`, so procmgr holds the driver's
     memory on its memmgr record, out of the free pool, whether the driver
     died on its own or was destroyed. Only when the IOMMU blocked the device
     at step 0, or Bus Master Enable read back clear, every BAR copy was
     revoked, and the reset confirmed, does devmgr send `RELEASE_HOLD` on the
     driver's release
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
  devmgr's control thread (the settle, or a death's withdrawal) per withdrawn device for
  up to the bound of its reset: `RESET_TIMEOUT` for the VirtIO status reset,
  all of it for a device whose status does not read 0 within the bound, and
  `FLR_COMPLETION_MS` for a Function Level Reset. A driver still running (one
  pending, one devmgr has no memory to serve, one devmgr's batch cannot record
  at its spawn, or one whose bootstrap failed after its start) is withdrawn
  the same way, its Bus Master Enable cleared before its BAR caps are taken.
  A driver that dies on its own is withdrawn when devmgr takes its death from
  the death queues; procmgr may reap it first, and holds its memory until
  devmgr's release. devmgr binds no driver to a PCI device whose
  configuration page it cannot carve or map, since it could not clear that
  function's Bus Master Enable. Then the driver's service endpoint is revoked
  and deleted and its BAR, DMA, configuration-page, and IRQ caps released: each
  BAR cap (an `Mmio` resource's, and the MSI-X table's) goes back to devmgr's
  held BAR pages over the range it covers, from which a later bind carves it
  again, and is deleted, logged, only when a copy of it cannot be revoked or
  the table cannot record it ([`docs/hotplug.md`](hotplug.md#removal)
  § Removal). A
  withdrawn driver of a platform record has its copies of the record's caps
  revoked, the `Mmio`, `IoPort`, and wired-line caps devmgr carved and keeps,
  and is destroyed through its process handle while devmgr still keeps it (until
  its batch settles); none of them drives a DMA-capable device, and none is
  created `CREATE_DMA_HOLD`.

  Every svctest boot runs this order on PCI functions without DMA: its
  `devmgr_on_demand_bind` phase has devmgr withdraw three `test-fault`
  fixtures bound to QEMU `pci-testdev` functions, one on its death after
  `FAULT_EXIT`, one still pending at its settle's bound, and one whose
  bootstrap fails, so the Bus Master Enable and Interrupt Disable writes, the
  endpoint revocation, and the BAR and configuration-page releases run; the
  fixture declares no reset and no DMA, so neither a reset nor a DMA release
  runs there. Every `--test-devices` boot runs it on one DMA-capable
  PCI-bound driver: svctest's `devmgr_msi_release` phase has the `test-dma`
  fixture, bound to QEMU's `edu` device and declaring no reset, exit
  (`ipc::test_dma_labels::FIXTURE_EXIT`), and devmgr withdraws it on its
  death, so step 0 and the hold of step 5 run: behind an IOMMU the block lets
  `RELEASE_HOLD` return the fixture's memory, and without one its reset is
  never confirmed, so the memory stays quarantined. No boot withdraws any
  other DMA-capable driver. A boot serves every such driver that reports
  ready, and devmgr withdraws one only on its death or a failed settle, which
  a test boot causes for no other: only devmgr holds a PCI-bound driver's
  process handle, and the only virtio-blk driver of a test boot serves its
  root filesystem. Nor could a boot place a late device
  write after a free, since the emulated devices complete a request on their
  own event loop, with nothing a guest can hold in flight. What every boot does
  run is the carve of each bound function's configuration page, the bind's
  Command register write through it, and the mapping helper
  (`with_mmio_mapped`), through which the ECAM scan maps each window. The
  Command register arithmetic, the Interrupt Disable read-back, and the
  Function Level Reset's capability walk and completion check are host-tested
  in the devmgr firmware crate, and
  svctest's `procmgr_dma_hold` phase checks the held reclaim the order rests
  on: a started held child's pages stay out of memmgr's pool after its
  teardown until the release on its token, which its process handle cannot
  send. The order in which devmgr deletes its mapping caps at a withdrawal has
  no boot, for the same reasons. Nor has the deletion of a lent cap in a
  virtio-blk reply that fails: it needs the driver's client to die, or run out
  of slots, mid-request, and no test process can call the driver, since only
  vfsd and fatfs hold a SEND on it (svctest's devmgr phase checks that
  `QUERY_DEVICE` on a registry SEND without a class slot replies `UNAUTHORIZED`).

  The catalog entry of a withdrawn driver, or of one that failed to spawn,
  stays, so a badge is never reused. No `QUERY_DEVICE` reply hands out the endpoint
  of a driver that has not reported its device ready.

  The settle bound, `SETTLE_TIMEOUT` (`services/devmgr/src/settle.rs`), is
  twice `virtio_core::pci::RESET_TIMEOUT` (5 s), so 10 s, counted from the
  start of the settle, after the batch's last spawn. The VirtIO reset, which
  a virtio-blk, virtio-input, virtio-rng, or virtio-console driver polls for once, is the
  longest bounded wait a driver's setup makes, so the settle never ends before
  a driver's own timeout has, and a margin of one further `RESET_TIMEOUT`
  covers the rest of the setup. The platform drivers (serial, framebuffer, and RTC) make
  no bounded wait in their setup. The synchronous IPC calls every driver's setup makes (memmgr,
  and devmgr's own `QUERY_DEVICE_INFO`) are not bounded; a driver blocked in
  one past the bound is withdrawn like a hung one. A thread devmgr starts per
  settle sleeps the bound and signals the timer notification; when it cannot
  be started, that settle has no bound.

  A further batch runs for each `devmgr_labels::BIND_DRIVERS`, gated on
  `BIND_AUTHORITY`, which only svctest's seed-only `devmgr.bind` cap carries
  (seeded as `SEND|GRANT`, as only it and each `:grant` name are, since the
  request moves a directory cap to devmgr). devmgr replies `SUCCESS` at once; its
  control thread then runs a drivers-directory pass over the directory cap,
  named by the directory's absolute path the request carries as a name block
  from data word `DRIVERS_DIR_PATH_WORD`, under the same declaration bounds as
  the `SET_DRIVERS_DIR` pass (auxiliary tier, no physical access, no IOMMU
  family key) against the device records still unbound,
  starts the drivers it binds in a settle batch of its own, and serves them once
  it settles, within `SETTLE_TIMEOUT`. A pass binds a record at most once a boot, and none binds
  it again once its driver is withdrawn, so a second request over the same directory binds
  nothing; a limited driver's bound devices are counted across passes by driver name
  (`BoundCounts`), so each pass binds it only to the devices its limit leaves, and a device's
  hotplug removal returns its instance. A request with no directory cap or no
  path, before `SET_DRIVERS_DIR`, or while an earlier one is not done gets
  `INVALID_REQUEST`. A `QUERY_DEVICE` whose answer would name no driver waits
  until the pass and its settle end.

  The [`test-dma`](../../drivers/test-dma/README.md) fixture is bound like any
  driver: its declaration matches QEMU's `edu` device (PCI `1234:11e8`, which
  only `--test-devices` launches attach), so the drivers-directory pass binds
  it whenever the device is present, delivering BAR 0 whole and the device's
  DMA capability. The DMA endpoint's `devmgr_dma_labels::DMA_FAULTS` answers a
  device's own caller: devmgr takes and logs the IOMMU driver's recorded faults
  (`iommu_labels::TAKE_FAULTS`), and replies `data[0]` = `DMA_CONFINED` (1)
  when an IOMMU confines the device, else 0, `data[1]` = DMA translation
  faults taken for the device since its DMA grant, `data[2]` = the latest's IOVA,
  page aligned, 0 with none (a VT-d interrupt-remapping fault, whose
  recorded address is a remapping table handle, is logged only);
  `UNAUTHORIZED` when the device is withdrawn or was never given DMA.

  The [`test-fault`](../../drivers/test-fault/README.md) fixture lives in
  `/tests/drivers/`, which no boot-time pass reads: it binds the QEMU
  `pci-testdev` functions (PCI `1b36:0005`) only through `BIND_DRIVERS`, its
  role taken from its resource list (no BAR 2 serves, a 4 KiB BAR 2 never
  reports ready, an 8 KiB BAR 2 fails its bootstrap's terminal round so devmgr
  withdraws the device and destroys the fixture mid-bootstrap).

  The instance ordinals of a class count its served drivers in spawn order
  and are fixed once its batch settles. devmgr observes the death of every
  driver for the rest of the boot (an exit of its main thread, or a terminal
  fault of any of its threads; § Relationship to drivers): its control thread
  waits on the death queues and its job notification together, and a settle
  hands the deaths of drivers outside its batch back to it. A served driver
  that dies is withdrawn as above, so callers queued on its endpoint return
  (the endpoint's teardown wakes them), and a tombstone holds its ordinal:
  its query replies `devmgr_errors::WITHDRAWN` for the rest of the boot, and
  the ordinals after it keep their drivers, so vfsd's probe of block
  ordinals, which continues past a `WITHDRAWN` reply, skips no live disk.

  The serving order follows from where each batch settles. devmgr's main
  thread is its control thread: it enumerates, spawns and settles every
  batch, and withdraws every driver whose death it takes. Four registry
  worker threads (`REGISTRY_WORKERS`, a concurrency setting that bounds no
  capacity) receive on the registry endpoint once the boot batch has
  settled, each on its own IPC buffer page
  ([shared/recv-pool](../../../shared/recv-pool/README.md)); vfsd's block
  class probes, and every query of the serial and framebuffer drivers, wait
  in the registry endpoint's queue until then. A request that leaves work
  for the control thread (`SET_DRIVERS_DIR`'s drivers-directory pass and
  on-disk settle, and `BIND_DRIVERS`'s pass and settle) posts it
  as a job and replies; the control thread runs it. A query whose answer
  names no driver (an ordinal past the class's last served driver, so
  `NO_DEVICE`) waits while a posted job is not done, and is answered once it
  is, so a query received after `SET_DRIVERS_DIR`'s reply sees the on-disk
  batch's drivers, at most the settle bound plus the bound of each withdrawn
  device's reset (above) after its pass. A query whose answer names a
  driver, live or withdrawn, is answered at once, during a settle too: a
  class's ordinals only grow, so that answer is final. The workers and the
  control thread share the served drivers under one lock, under which no
  thread makes an IPC call or logs; a reply carrying a SEND derived from a
  driver's endpoint is sent while the lock is held, so a withdrawal, which
  takes the driver out under the lock and revokes its endpoint after, cannot
  delete that SEND before the reply.

  The settle does not deadlock against the log path as long as the drivers'
  synchronous log calls reach a receiver that does not wait on devmgr. During
  the boot settle, before handover, that receiver is init-logd, which never
  calls devmgr; the serial and framebuffer drivers do not log at all. During
  the on-disk settle it may be logd. logd calls devmgr only from its main thread, to
  register a `WATCH_CLASS` watch on the serial and the framebuffer class and resolve both
  drivers. It does so before its `HANDOVER_PULL`, while init-logd still drains the log endpoint,
  and resolves a driver again only when devmgr signals that class's watch; its emit path never
  calls devmgr, so no receive worker waits on a query that names no driver while the control
  thread's own log lines during the on-disk job wait on logd.

  Driver binaries are sourced from one of two places:

  - **Boot bundle** — bootstrap-essentials (virtio-blk and the IOMMU driver, `iommu-vtd` on x86-64
    and `iommu-riscv` on riscv64, and any platform description table a root mount needs) arrive
    untagged as `procmgr_labels::CREATE_PROCESS`-ready Memory caps in devmgr's MODULE bootstrap
    rounds. devmgr tells a module by its content, after taking the body of each through the
    parse-only `objsig::split` (`decls::classify`; a module whose trailer does not parse is logged
    and released): an ELF image is a driver, read for its declaration (one without a declaration is
    logged and released); valid UTF-8 text is a platform description table, parsed by
    `firmware::platform::parse_module` (one rejected is logged and released); anything else is
    logged and released. devmgr spawns the drivers during initial enumeration, before the registry
    loop opens: the IOMMU driver, matched against the IOMMU family record in a pass of its own, and
    every other module by the declaration it carries, read from the module mapped read-only and
    bound in the boot pass (above). Every module cap is released once its pass ends.
  - **On-disk rootfs** — the drivers at `/services/drivers/<driver>` (among
    them the per-arch RTC, virtio-input, virtio-console, virtio-rng, test-dma, and a copy
    of virtio-blk), loaded via `procmgr_labels::CREATE_FROM_FILE`. svcmgr
    delivers a `LOOKUP | READ | READDIR`-attenuated `/services/drivers/`
    subtree cap via `devmgr_labels::SET_DRIVERS_DIR` after handover (gated by
    `DRIVERS_DIR_AUTHORITY`), with the directory's absolute path as a name block from data word
    `DRIVERS_DIR_PATH_WORD`, so devmgr names each driver `<path>/<entry>` to procmgr (a request
    with no path is refused `INVALID_REQUEST`), and, when its walk finds it, the directory of the
    platform description tables (`devmgr_labels::PLATFORM_TABLES_PATH`) as an optional `caps[1]`
    at the same rights; devmgr replies SUCCESS immediately (so svcmgr
    never blocks on driver work), and its control thread runs the
    drivers-directory pass, settling the on-disk batch (above). Before the pass, unless a boot
    module's table matched, the job reads the platform description tables as
    [docs/driver-binding.md](../../../docs/driver-binding.md#platform-description-tables)
    § Platform Description Tables describes, and deletes the directory cap. The pass
    lists the directory (`NS_READDIR`, at most 4096 entries) and reads each
    entry's declaration through `FS_READ` on its file cap, bounded as
    [docs/driver-binding.md](../../../docs/driver-binding.md#declaration-bounds)
    § Declaration Bounds requires: the ELF header page, the section header
    table, the section name table, and the note section up to 1 KiB. A
    binary with no declaration note is passed over unlogged, one whose
    declaration matches no unbound device is not loaded, and the pass is
    skipped when every device is bound. Each spawn is
    at-most-once per boot; failure, including an on-disk driver's death, or
    its overrun of the settle bound, before it reports ready, is sticky and
    surfaced as `devmgr_errors::NO_DEVICE` on subsequent `QUERY_DEVICE` queries of
    the rtc, input, hwrng, and debug-port classes, the same reply
    as before `SET_DRIVERS_DIR` arrives, so a client that needs the class waits on a `WATCH_CLASS`
    watch. See
    [docs/device-management.md § Driver binary sources](../../../docs/device-management.md#driver-binary-sources).
- **Expose device registry** — maintain an IPC service that other services
  query to discover device endpoints after drivers are bound: vfsd resolves
  every block device, logd the serial and framebuffer drivers,
  `programs/terminal` the framebuffer, input, and serial drivers, timed the
  platform RTC, and netd (design intent; not yet implemented, #30). devmgr
  owns each driver's service endpoint and mints a badged SEND on query. One
  label, `QUERY_DEVICE`, serves every class, sent on a *class SEND*: a SEND on
  the registry endpoint whose badge names a class slot and the verb bits the
  reply carries (`devmgr_labels::class_badge`). The class and the verbs come
  from the badge, never the message; `data[1]` is the instance ordinal
  (absent means the first), counted over the class's served drivers (those
  that reported their device ready) in PCI segment, bus, device, function
  order and not stable across boots. A registry SEND without a class slot
  (`devmgr.registry`, `devmgr.bind`) gets `UNAUTHORIZED`. A withdrawn driver's
  ordinal replies `WITHDRAWN` (above) and an ordinal past the last served
  driver of the class `NO_DEVICE`. The query logs nothing.

  A second label on a class SEND, `WATCH_CLASS`, registers a watch on the
  class ([driver-binding.md § Device
  Classes](../../../docs/driver-binding.md#device-classes)), refused
  `UNAUTHORIZED` to a SEND without a class slot. A class SEND carries no grant
  right, so devmgr creates the watch's Notification from its own object slab,
  before it takes the registry lock, and replies with a wait-only copy and the
  class's ordinal count, read in the hold that adds the watch to the class's
  watcher list (`firmware::watchers`). devmgr signals every watch of a class
  (`WATCH_CLASS_CHANGED`), without blocking, in the hold that serves a new
  driver of the class and in each that withdraws one, so the signal and the
  ordinal it reports are ordered with every query. Before it signals a watch,
  and when a registration finds the class at `MAX_CLASS_WATCHERS` (8), devmgr
  asks whether its own copy is the only reference left to the Notification
  (`CAP_INFO_SOLE_REFERENCE`); a watch whose consumer deleted its copy or
  exited is deleted and dropped. A registration past the bound with no watch
  gone is refused `WATCHERS_FULL`. A class therefore holds at most 8
  Notifications of 64 B each. The handler logs nothing, as the query does
  not.

  devmgr mints class SENDs on `MINT_CLASS_SEND`, gated on `CLASS_AUTHORITY`
  (badge bit 59), which svcmgr and init each derive from their badge-0
  registry source and no published name carries. The request carries the verbs
  and the class name (at most `MAX_CLASS_NAME_BYTES`, 32, bytes); devmgr
  interns the class into its class table and replies a SEND whose badge
  carries the class's slot and the verbs. svcmgr sends one per
  class file before `SET_DRIVERS_DIR` ([service-definitions.md § Device class
  files](../../svcmgr/docs/service-definitions.md#device-class-files)); init requests the
  `block` class SEND for vfsd. The class table holds at most
  `MAX_CLASSES` (64) classes: a new class's request past it is refused, and a
  ready driver of a new class is withdrawn, logged. After the drivers-directory
  settle devmgr logs
  each class configured with no served driver and each served class no class
  file configured.

  The `block` class's reply is the `MOUNT_AUTHORITY`-badged whole-disk cap,
  and it reaches only vfsd, through the
  class SEND init requests for it, and a service whose definition seeds
  `devmgr.class.block`, which no shipped definition does. The `debug-port`
  class answers with the debug port: the driver served under that class,
  which virtio-console declares with an
  instance limit of 1, so it is bound to the first virtio-console device in
  PCI order. It serves the serial protocol
  ([services/drivers/virtio/console/README.md](../../drivers/virtio/console/README.md)),
  a byte transport apart from the console's UART that a debugger stub owns. Its
  reply reads and writes the port, so only a service whose definition seeds
  `devmgr.class.debug-port` reaches it; a further console device is left
  unbound, and a boot with none has no debug port. Each query looks its class
  up by slot in the class table devmgr interns the class names into
  (`devmgr_firmware::classes::Classes`).
- **Broker ACPI tables to acpid and the shutdown cap to pwrmgr** — devmgr is the
  sole owner of the ACPI Memory caps and the only service that walks the ACPI
  table tree (RSDP → XSDT). `QUERY_ACPI_TABLE` locates a table by
  signature or physical address and serves a read-only view of it (devmgr
  reads only the directory and table headers to locate it).
  `QUERY_SHUTDOWN_DEVICE` serves the shutdown-actuator cap pwrmgr needs on
  RISC-V, a Reset-only `SbiControl` derivation; on x86-64 it replies
  `NO_DEVICE`, since pwrmgr powers off and resets through acpid and holds no
  port. On every call the cap is re-derived from the `SbiControl` cap devmgr
  holds, so nothing is consumed and a restarted pwrmgr re-acquires it cleanly.
  devmgr runs no shutdown logic; it brokers the cap, pwrmgr actuates.
  `QUERY_ACPI_TABLE` is gated on `REGISTRY_QUERY_AUTHORITY`; `QUERY_SHUTDOWN_DEVICE` on
  `SHUTDOWN_DEVICE_AUTHORITY`, which only the `devmgr.shutdown` cap carries:
  a seed-only name pwrmgr alone seeds, which svcmgr's `QUERY_ENDPOINT`
  refuses.
- **Serve acpid** — acpid, the service that evaluates AML, calls devmgr and devmgr never calls
  acpid. Labels 24 to 29 and 31 (`QUERY_ACPI_RESOURCES`, `ACPI_REGION_GRANT`,
  `ACPI_PCI_CONFIG`, `OSC_RESULT`, `BRIDGE_WINDOWS`, `PRT_TABLE`, `ACPI_HOTPLUG`) are gated on
  `ACPI_AUTHORITY`, which only the seed-only `devmgr.acpi` cap carries, seeded by acpid's
  recipe alone ([acpid and devmgr](../../acpid/docs/devmgr.md) § Capabilities).
  - devmgr grants each operation region acpid's AML reaches against its policy, and makes
    each configuration-space access for it
    ([acpid and devmgr](../../acpid/docs/devmgr.md) § Region grants and § Configuration access).
  - devmgr keeps acpid's first `_OSC` result for the boot, and the windows and routes that agree
    with its boot records, and serves them per bridge with `QUERY_HOST_BRIDGE`
    ([acpid and devmgr](../../acpid/docs/devmgr.md) § Pushes).
  - devmgr serves acpid the FADT's register blocks and, on x86-64, the SCI's `Interrupt`, a
    derivation of the line it holds for the boot
    ([acpid and devmgr](../../acpid/docs/devmgr.md) § Capabilities).
  - Every acpid request but `QUERY_ACPI_RESOURCES` for a register block runs on the control
    thread ([acpid and devmgr](../../acpid/docs/devmgr.md) § Ordering).
- **Handle hotplug** — devmgr finds the PCI Express hotplug slots in the boot scan and manages
  each under a native-control grant (its host bridge's `_OSC`, or the platform description
  table's `pcie_native_hotplug`). A poller thread reads each managed slot's Slot Status every
  second, powers up a slot a card arrives in, and posts the arrival; the control thread places
  and programs the new functions' BARs in the slot's windows, appends their records, and binds
  them in a hotplug batch (above). When a card leaves, or its removal is asked for with the
  attention button, the poller posts the removal; the control thread withdraws each driver behind
  the slot as below, quiesces the functions, returns their BAR pages to the apertures and removes
  their records, and the poller then powers the slot off. A slot whose firmware drives hotplug
  (its `_OSC` withholds native control) is left to the firmware: devmgr holds the BAR pages
  behind it, and runs the add or removal job for each `ACPI_HOTPLUG` event acpid posts. See
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
§ IOMMU Discovery and Programming); `MODULE` rounds of one Memory cap each (round data
`[MODULE, 1, size, name (32 words)]`, the module's size in bytes, since a module's cap covers
whole pages and devmgr reads no byte past the module's end, then the module's bundle entry
name, its install path: `BOOT_MODULE_NAME_LEN` (256) bytes, little-endian, NUL-padded, which
devmgr gives procmgr to verify the module's signature under) carry every boot module outside
init's bootstrap set (init, procmgr, memmgr, devmgr, vfsd, fatfs, the log-level configuration,
trust-store),
untagged: the driver images and any platform description table; a cap-less
`FRAMEBUFFER_INFO` round carries the framebuffer geometry (a zero base means no framebuffer); and
the terminal `SVCMGR_BUNDLE` round carries the svcmgr publish cap and the arch shutdown-authority
cap (a full-rights derivation of init's root `IoPort` on x86-64, a Reset + Suspend `SbiControl`
derivation on RISC-V). Init's side of the transfer is summarized in [services/init/docs/bootstrap.md
§ Per-stage authority transfers](../../init/docs/bootstrap.md#per-stage-authority-transfers). See
[docs/capability-model.md](../../../docs/capability-model.md) for capability type definitions and
[docs/device-management.md](../../../docs/device-management.md) for how devmgr uses them.

| Capability | Rights | Purpose |
|---|---|---|
| Endpoint (devmgr registry, round 1 `caps[0]`) | `RIGHTS_ALL` (incl. Recv, Send, Grant) | Service endpoint for the device-registry IPC: devmgr serves the client queries (`QUERY_DEVICE`, `MINT_CLASS_SEND`, `QUERY_ACPI_TABLE`, `QUERY_SHUTDOWN_DEVICE`, `QUERY_HOST_BRIDGE`), acpid's labels (`QUERY_ACPI_RESOURCES`, `ACPI_REGION_GRANT`, `ACPI_PCI_CONFIG`, `OSC_RESULT`, `BRIDGE_WINDOWS`, `PRT_TABLE`, `ACPI_HOTPLUG`), `SET_DRIVERS_DIR`, and `BIND_DRIVERS` on it; every driver's query cap, for `QUERY_DEVICE_INFO` and `DRIVER_READY`, is on its settle batch's private endpoint instead (above). `BIND_DRIVERS` is gated on `BIND_AUTHORITY`, which only the `devmgr.bind` cap carries: a seed-only name svctest alone seeds. |
| Mmio (one per boot-provided aperture) | Map, Write | Split per device into BAR / register sub-caps for drivers, and into each IOMMU unit's register cap (a VT-d unit's register page, a RISC-V IOMMU's BAR 0 page), which devmgr delivers to the IOMMU driver, keeping no copy; the ECAM windows carved from them stay devmgr's, split into the configuration page of each function devmgr binds a driver to, which devmgr keeps to write its Command register (above) |
| Interrupt (full-rights derivation of init's root IRQ range) | Notify, Mint | Split with `SYS_IRQ_SPLIT` into per-line Interrupt caps, each routed with `SYS_IRQ_ROUTE` when carved and kept for the boot, whose derivations are delegated to drivers; mint message-signaled targets with `SYS_IRQ_MSG_ALLOC` through a copy carrying `RIGHTS_IRQ_MINT` alone, derived at startup ([docs/device-management.md](../../../docs/device-management.md#message-signaled-interrupts) § Message-Signaled Interrupts) |
| IoPort (x86-64, full-rights derivation of init's root) | Use / carve | Carve narrow per-driver port caps (a platform record's `IoPort` resource, such as CMOS or COM1) and acpid's FADT register-block ports |
| SbiControl (RISC-V, Reset + Suspend) | Reset / Suspend | Steady-state holder of the platform power-state SBI authority (init is reaped); broker a Reset-only derivation to pwrmgr for SBI SRST shutdown / reboot. Suspend held for a future power path |
| Memory (firmware tables) | Map (read-only) | Parse ACPI RSDP / Device Tree blob; broker read-only ACPI tables via `QUERY_ACPI_TABLE`; read the DMAR's VT-d units, scopes, and RMRRs on x86-64, and the RIMT's PCI IOMMUs and ID mappings on riscv64 |
| Memory (boot modules, MODULE rounds) | As held by init | Boot-bundle driver images (virtio-blk and the IOMMU driver, `iommu-vtd` on x86-64 and `iommu-riscv` on riscv64) and any platform description table a root mount needs, untagged and held in `DevmgrCaps.modules`; a driver is spawned via `procmgr_labels::CREATE_PROCESS` by the declaration devmgr reads from it (above), a table is parsed; a module that is neither, or that fails to read, is logged and released |
| svcmgr publish authority (Endpoint, SVCMGR_BUNDLE round) | Send, Grant (`PUBLISH_AUTHORITY` badge) | Register service caps in svcmgr's registry; held but unused today, reserved for future devmgr publications |
| SchedControl (baseline, via `ProcessInfo`) | band `[1, 26]` (`sched_policy::DEVMGR_BAND_MAX`) | Place spawned drivers at their assigned levels (each driver of the boot tier from a boot module, the IOMMU driver and each PCI-bound one, at 26; every other driver, the serial, framebuffer and RTC drivers included, at 25 — the `CREATE_PRIORITY` field of each driver spawn) and set devmgr's own threads' priorities (the DMA thread at 26, the IOMMU fault-log thread at 24, through `std::os::seraph::thread::BuilderExt::spawn_at_priority`). Like every process, devmgr receives this from procmgr (`ProcessInfo.sched_control_cap`); init requests the deliberately-elevated ceiling (above devmgr's own level 24) via the create label's `CREATE_BAND_MAX` field |

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
names those pages), and delivers each to the VT-d IOMMU driver. It discovers
the RISC-V IOMMUs from the RIMT, carves the first page of each one's BAR 0,
which lies in a PCI window the bootloader seeds already, and delivers each to
the RISC-V IOMMU driver, keeping no copy of either (see
[docs/device-management.md § IOMMU Discovery and Programming](../../../docs/device-management.md#iommu-discovery-and-programming)).

---

## CSpace headroom

devmgr runs on the `CSpace` procmgr seeds every child with, and holds a few capabilities for each
driver it binds, each device record's carves, each class watch, and each DMA mapping, so its
slots grow with the drivers and classes it serves. The `CSpace`'s body arena, which holds the
body of each `Mmio`, `IoPort`, and `Interrupt` split and copy, draws whole pages from the same
growth budget the slot pages come from, and each page it takes lowers the capacity by a page's
slots. devmgr holds its headroom above a low-water mark through `std::os::seraph::CSpaceHeadroom`,
whose rule [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § CSpace slot headroom
states: below `CSPACE_LOW_WATER` plus a page's slots, or a growth budget below a page, it funds
the slot-page pool from memmgr for `CSPACE_TOPUP_SLOTS`, twice the mark (`src/headroom.rs`).

The mark is the most one record's bind takes, at the declaration bound of resources
(`spawn::MAX_BOUND_RESOURCES`): devmgr's carved cap and the driver's copy of each resource, the
spawn's other copies (the end round's endpoints, the badged creator, the argv and env, procmgr's
create reply, the death observer's copy), and the arena pages the bodies of those caps take,
counted as the slots of those pages, with the requests the registry's workers and the DMA thread
serve meanwhile: about 450 slots. The page `CSpaceHeadroom` holds beyond the mark keeps the first
of those arena pages funded.

devmgr holds it before each turn of the control thread's loop (acpid's requests, hotplug jobs,
withdrawals, and the bind passes they start), before each record's carves (PCI and platform),
before each driver spawn (the IOMMU driver's included), before each registry request a worker
serves, and before each DMA request. A failed top-up is retried at the next hold; the control
thread logs a run of them once, since a registry worker or the DMA thread may be serving logd, or
a driver logd writes through, and must not log.

While the headroom is short of the mark and its top-up was refused, devmgr takes no capability
it would keep, so the slots left and the IPC receive reserve the next top-up's reply needs stay
free: a record's carves and a driver spawn fail, logged, and the record is not bound; the
registry refuses `WATCH_CLASS`, whose watch keeps a Notification, with `OUT_OF_RESOURCES`; and
the DMA thread refuses `DMA_MAP`, which keeps the mapped Memory cap, with `OUT_OF_RESOURCES`
(`firmware::headroom`). Every other request keeps nothing past its reply, or one directory cap
(`SET_DRIVERS_DIR`, `BIND_DRIVERS`), and is served.

---

## Relationship to drivers

devmgr is the sole authority for spawning device drivers. It observes each driver's death and
withdraws the driver. It binds two death observers on each driver, with the driver's device badge as
the correlator: one on the driver's main thread, which an exit or a fault of that thread posts, and
one procmgr binds on the driver's address space at devmgr's request ([procmgr IPC
Interface](../../procmgr/docs/ipc-interface.md) § Label 25: `BIND_DEATH_OBSERVER`), which the first
terminal fault of any of the driver's threads posts, once. A fault of a worker thread drives
procmgr's teardown of the driver, whose stop of the main thread posts nothing, so only the
address-space observer reports that death. A fault of the main thread that is the driver's first
terminal fault posts to both observers; devmgr takes the first post and drops the second, which
names a driver already dead or withdrawn. An
exit of the main thread posts only the thread observer, since the kernel fires an address space's
observers on a terminal fault alone, so neither observer covers the other. A served driver that dies
is restarted as § Driver Restart describes (the supervision hierarchy is in
[docs/supervision.md](../../../docs/supervision.md)). After
discovering a device, devmgr requests procmgr to create the driver process and then delegates
the per-device capability set via IPC. Drivers MUST NOT be started independently of devmgr. See
[`drivers/README.md`](../../drivers/README.md) for the driver model.

---

## Driver Restart

devmgr restarts a served driver that dies: it starts the same driver again on the same device
record, from the driver's installed path, and serves the new instance at its class's next ordinal
([docs/supervision.md](../../../docs/supervision.md) § Restart Shapes). The policy's decisions are
pure functions of `services/devmgr/firmware/src/restart.rs`, host-tested there; the restart itself
is `bind::restart` (`services/devmgr/src/bind.rs`), run by the control thread.

### Restart shape

Every driver bound to a device record serves on an endpoint devmgr creates at the bind; the driver
is delivered its receive copy, and a client holds a SEND devmgr derives from it at
`QUERY_DEVICE`, badged with the verbs the client may use
([`devmgr_labels`](../../../shared/ipc/src/devmgr_labels.rs)). No driver creates an endpoint of
its own. What a badge names differs:

| Driver | A client's badge names | A client registers |
|---|---|---|
| `virtio-blk` | its verbs (`MOUNT_AUTHORITY`); on a partition's SEND, the partition | a partition range, whose badged SEND the driver derives (vfsd) |
| `virtio-input` | its verbs (`READ_AUTHORITY`) | nothing |
| `virtio-console` | its verbs | the receive notification (`SERIAL_REGISTER_RX_NOTIFY`) |
| `virtio-rng` | its verbs (`READ_AUTHORITY`) | nothing |
| `tpm` | its verbs (`READ_AUTHORITY`) | nothing |
| `serial` | its verbs | the receive notification (`SERIAL_REGISTER_RX_NOTIFY`) |
| `framebuffer` | its verbs (`WRITE_AUTHORITY`) | nothing |
| `cmos`, `goldfish-rtc` | its verbs (`READ_AUTHORITY`) | nothing |
| `test-dma`, `test-fault` | nothing | nothing |

Every driver restarts by revoke and re-resolve. The withdrawal of the dead instance revokes its
endpoint, so every call queued on it and every later call through a client's SEND fails at once,
whether a restart follows or not; the class's watchers are signalled; and a client resolves the new
instance at the class's next ordinal (Clients below). A persistent endpoint, kept across instances,
is used for no driver, the stateless ones included: a caller of such an endpoint whose restart was
refused or failed would wait on an endpoint no instance receives on, state a client registered
with the dead instance would be lost without a sign to the client, and the registry's answers would
stop being final (an ordinal's driver once answered could change).

### When a driver restarts

A restart is considered for the death of a served driver of a class, which devmgr's death watch
takes (§ Relationship to drivers). No other withdrawal restarts its driver: a hotplug removal's,
the IOMMU driver's death's (`fail_iommu`), or a settle's withdrawal of a driver that died or did
not report ready before its batch settled, which was never served. The IOMMU driver itself is never
restarted ([#1079](https://github.com/kottlerg/seraph/issues/1079)).

The death is restarted when every check passes, in this order:

1. **A fault or a kill.** The exit reason is `EXIT_FAULT_BASE` or above. A driver that exits with
   a code of its own has decided to stop serving, and is not restarted.
2. **Not declined.** The driver's consumer has not declined its restart (§ Root disk below).
3. **Installed.** `SET_DRIVERS_DIR` has installed the drivers directory, and the driver's install
   path is an entry of it. A boot module is named by its install path
   ([docs/boot-media.md](../../../docs/boot-media.md)), so a driver of the boot pass restarts from
   its entry under `/services/drivers/`, never from a boot module or an image kept from boot. A
   driver started through `BIND_DRIVERS` from another directory is never restarted.
4. **Quiet.** The withdrawal confirmed the device quiet: Bus Master Enable read back clear, every
   copy of its BAR caps revoked, and the reset its driver declares confirmed
   ([docs/device-management.md](../../../docs/device-management.md) § DMA-Safe Teardown). An
   IOMMU's block of the device does not suffice: it releases the dead driver's memory, but the
   new instance's bind enables the device's bus mastering again, under a new domain. A platform
   device has no DMA and is quiet once its caps are taken. The withdrawal also released the
   driver's DMA hold, or it held none.
5. **Within the budget.** The record's restart budget has room: `restart_budget::RestartBudget`
   ([shared/restart-budget](../../../shared/restart-budget/README.md)), `RESTART_BURST` restarts in
   a `RESTART_WINDOW_NS` window, the bound svcmgr applies to a service, carried from each instance
   of the record's driver to the next. It stops a driver that dies at once on its device from
   restarting in a loop; a rarer death always restarts. Only a restart that passes every other
   check is charged.

The first three are read in the hold of the registry lock that takes the dead driver out, which
also posts the restart as a registry job, so a `QUERY_DEVICE` from then on that would find no
driver waits until the restart's settle ends. The last two are read once the withdrawal is done.
A refused restart is logged with its reason, and the record stays bound with no driver, as a
withdrawal leaves it.

### How a driver restarts

The control thread runs each restart in a settle batch of its own. It reads the declaration of the
drivers-directory entry at the dead driver's install path, and starts it only when it declares the
dead driver's name and interrupt and matches the record under the drivers-directory declaration
bounds (the auxiliary tier, no physical access, no IOMMU family key): an entry replaced by another
driver, or by a version that declares another interrupt, is not started in its place. It binds the
record to the driver as a pass does, which delivers the new instance the device's caps again: a PCI
device's BARs, carved again from the held BAR pages its withdrawal gave them back to, its interrupt,
and its DMA grant and IOMMU domain; a platform record's resources, which devmgr cannot carve again
once released, kept from the dead instance's withdrawal, every copy derived from them revoked, and
delivered again. Each instance gets a new catalog entry, and so a new device badge, so a late death
post of the dead instance names no live driver.

The record stays bound throughout, so no drivers-directory, `BIND_DRIVERS` or hotplug pass takes
it, and the new instance replaces the dead one in its driver's instance count. A restart whose entry
is missing or unreadable, whose declaration differs, or whose bind fails is logged, and the record
stays bound with no driver. A new instance that dies or does not report ready before its batch
settles is withdrawn and not served, as any batch's driver is, and its death is not restarted.

### Clients

A client recovers from a restart the same way every time. Its calls on the dead instance fail once
the withdrawal revokes the endpoint, `QUERY_DEVICE` answers `WITHDRAWN` at the dead instance's
ordinal, and its `WATCH_CLASS` watch is signalled at the withdrawal and again when the new
instance is served. A `QUERY_DEVICE` at the next ordinal (`first_device_from`) then waits for the
restart's settle and names the new instance, or answers `NO_DEVICE` when the restart was refused or
failed. A client re-registers with the new instance whatever it registered with the dead one. logd's
sinks, entropyd and the terminal re-resolve this way on their class watches; `ipc::refresh_device`
is the look a client makes at its class on a signal.

### Root disk

The driver of the disk the root filesystem sits on is not restarted: its loss is fatal
([docs/boot-media.md](../../../docs/boot-media.md); vfsd ends on the loss of the root's disk,
[services/vfsd/docs/namespace-composition.md](../../vfsd/docs/namespace-composition.md) § Driver
death and device loss). vfsd declines that driver's restart with `DECLINE_RESTART` on its `block`
class SEND once it has mounted the root, before it serves anything. devmgr marks the served driver,
and its death is then withdrawn and not restarted. devmgr refuses the request once
`SET_DRIVERS_DIR` has arrived: from then a restart can happen and reads the mark, so the marks are
sealed, and no class SEND holder can switch off a driver's restart once restarts are possible.

---

## Summarized By

[Device Tree Parsing](../../../core/boot/docs/dtb.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Supervision](../../../docs/supervision.md), [services/devmgr/README.md](../README.md),
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
[services/pwrmgr/README.md](../../pwrmgr/README.md)
