# init Bootstrap Stages

Authoritative enumeration of the work init performs between kernel
handoff (`_start`) and `sys_thread_exit`, organised into three
stages: **Raw bootstrap**, **Root acquisition**, **Handover**. The
names used in source `log()` strings — `"phase 1 bootstrap complete"`,
`"phase 2: acquiring system-root cap"`, `"phase 2 bootstrap complete"`,
`"phase 3: ..."` — are the searchable equivalents and remain stable.

---

## Stages

### Raw bootstrap

Init reaches `run()` (`../src/main.rs`) with the kernel-supplied
`InitInfo` populated and the initial CSpace seeded (see
[Capability flow](#capability-flow)). It performs the work required to
stand memmgr and procmgr up via raw syscalls, then delegates further
process creation to procmgr IPC.

- Version-check `InitInfo` against `INIT_PROTOCOL_VERSION` and exit
  on mismatch (`INIT_PROTOCOL_VERSION` check in `run()`, `../src/main.rs`).
- Initialise the per-arch serial path used for FATAL pre-IPC errors
  (`arch::current::serial_init`, `../src/main.rs`).
- Build the `MemoryAlloc` bump allocator over the kernel-provided
  memory pool (`MemoryAlloc::new`, `../src/main.rs`).
- Reserve a Memory cap to back kernel-object retypes (the endpoint slab;
  one page suffices for the eight endpoints init creates)
  (`../src/main.rs`).
- Map a fresh IPC buffer page at `INIT_IPC_BUF_VA` and register it
  with the kernel (`syscall::ipc_buffer_set`, `../src/main.rs`).
- Mint endpoint objects: init's bootstrap endpoint, procmgr's
  service endpoint, memmgr's service endpoint, svcmgr's service
  endpoint (`syscall::cap_create_endpoint`, `../src/main.rs`; minted here so procmgr can receive
  an un-badged SEND on it during procmgr's bootstrap round), and
  the master log endpoint (`../src/main.rs`).
- Spawn the init-logd thread — a second thread of the init process
  that drains the master log endpoint and writes lines to the serial
  UART directly (`logging::spawn_log_thread`, `../src/main.rs`, with the receive loop in
  `../src/logging.rs`). After this point init's own `log()` lines
  ride IPC through init-logd to the serial UART. init-logd outlives
  init's main thread: it covers the console across the init→svcmgr
  handover and svcmgr's reconcile, until the svcmgr-launched
  real-logd pulls its captured history via `HANDOVER_PULL` and
  init-logd self-terminates (see [Handover](#handover) and the
  [logd handover protocol](../../logd/docs/handover-protocol.md)).
- Bootstrap memmgr via raw `cap_create_aspace` / `cap_create_cspace`
  / `cap_create_thread`, ELF-load it from the `memmgr` bundle
  entry, prepare its `ProcessInfo` page, and configure its main
  thread but defer `thread_start`
  (`bootstrap::bootstrap_memmgr` in `../src/bootstrap.rs`,
  called from `run()` in `../src/main.rs`).
- Bootstrap procmgr the same way; procmgr's `ProcessInfo` receives
  the memmgr SEND cap so its std heap reaches memmgr on the first
  allocation (`bootstrap::bootstrap_procmgr` in
  `../src/bootstrap.rs`, called from `run()` in `../src/main.rs`).
- Delegate all remaining RAM Memory caps to memmgr's CSpace via
  `finalize_memmgr` and serve a single bootstrap-IPC round carrying
  the pool's memory-cap range + a read-only phys-table cap (so memmgr can
  ingest its pool) (`finalize_memmgr`, served via `ipc::bootstrap::serve_round`; `../src/main.rs`).
  Init retains every boot-module Memory cap (its self-loaded
  memmgr/procmgr ELFs plus the devmgr/vfsd/driver modules) as sole
  owner; those donate to memmgr's pool on the reap-handoff route, not
  here (`../src/main.rs`).
- Start procmgr's thread and serve procmgr's bootstrap IPC, handing
  it the log endpoint SEND and svcmgr's service endpoint SEND
  (`bootstrap::start_procmgr`, `../src/main.rs`).
- Request procmgr to create devmgr via boot-module
  `CREATE_PROCESS` and serve devmgr's multi-round bootstrap
  (hardware caps: MMIO apertures, Interrupt range, ACPI Memory caps,
  DTB Memory cap on riscv64, and a `FRAMEBUFFER_INFO` round carrying
  the bootloader-discovered `boot_protocol::FramebufferInfo` so devmgr
  can spawn the userspace framebuffer driver)
  (`run()` in `../src/main.rs` + `service::create_devmgr_with_caps` in
  `../src/service.rs`).
- Request procmgr to create vfsd the same way and serve its
  bootstrap (`run()` in `../src/main.rs` +
  `service::create_vfsd_with_caps` in `../src/service.rs`).
- Closing marker: `"phase 1 bootstrap complete"`
  (`../src/main.rs`).

### Root acquisition

vfsd self-mounts the root partition at `/` on its own startup, then
mounts the ESP at `/esp` and the data partition at `/data` (both
best-effort), identifying partitions by GPT type-GUID
(`boot_protocol::role_guids::SERAPH_ROOT_<arch>`; see
[Storage](../../../docs/storage.md)). Init issues no `MOUNT`; its only
contribution is the seed-cap pull, which doubles as init's
wait-for-root barrier.

- Pull the seed system-root cap via `GET_SYSTEM_ROOT_CAP`
  (`mount::request_system_root`; protocol in the
  [vfsd service interface](../../vfsd/docs/vfs-ipc-interface.md)).
  vfsd self-mounts root before any service thread serves its endpoint,
  so the call blocks until the root filesystem is up. vfsd replies
  `NO_MOUNT` only when the self-mount failed; init treats the resulting
  zero cap as FATAL. The success reply is a badged SEND on vfsd's
  namespace endpoint at the synthetic root with full namespace rights
  — every later child receives a `cap_copy` of it via
  `procmgr_labels::CONFIGURE_NAMESPACE`, and init derives the
  `rootfs.root` SEND from it for svcmgr's endowment, which svcmgr
  publishes as-is.
- real-logd is a svcmgr-launched service, not an init responsibility.
  init-logd continues to serve the master log endpoint and write
  serial directly; svcmgr brings up real-logd post-handover from the
  reserved log-sink sources init endows in the Handover stage (the
  `LOGD_SOURCES` round below), and real-logd then pulls init-logd's
  captured state via `HANDOVER_PULL`. See
  [`../../logd/docs/handover-protocol.md`](../../logd/docs/handover-protocol.md).
- Closing marker: `"phase 2 bootstrap complete"`
  (`../src/main.rs`).

### Handover

`service::phase3_svcmgr_handover` (in `../src/service.rs`, called
from `../src/main.rs`) loads svcmgr, serves it the handover endowment,
moves init's kernel-object caps to procmgr (the first
`REGISTER_INIT_TEARDOWN` round, which binds procmgr's death observers),
signals `HANDOVER_COMPLETE`, streams init's reclaimable Memory caps to
procmgr in later `REGISTER_INIT_TEARDOWN` rounds, sends
`INIT_TEARDOWN_DONE`, and exits. svcmgr — not init — publishes the
well-known caps, registers services, and talks to devmgr, all from the
endowment (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)).

- Spawn svcmgr from `/services/svcmgr` with the `Universal` namespace
  policy (`create_svcmgr_from_file`), then serve it the handover
  endowment over the bootstrap-round protocol (`endow_svcmgr`):
  - **Round 1 (`CAPS`)** — svcmgr's service + bootstrap endpoints
    (full rights), plus the publish-role source caps: a `SEND` on the
    root filesystem's namespace endpoint (svcmgr publishes it as
    `rootfs.root`) and a badge-0 `SEND|GRANT` source on
    `devmgr_registry_ep` (svcmgr mints the `REGISTRY_QUERY_AUTHORITY`
    `devmgr.registry` publish cap and the `DRIVERS_DIR_AUTHORITY`
    `SET_DRIVERS_DIR` cap from it; see
    [Publish authority](../../svcmgr/docs/ipc-interface.md#publish-authority)). `data[1]` carries
    `SVCMGR_LABELS_VERSION`. An absent source rides as a zero slot.
  - **Rounds 2..N (`SUBSTRATE`)** — one `(name, thread_cap)` per
    init-bootstrapped substrate service: `memmgr`, `procmgr`, `devmgr`,
    `vfsd`. svcmgr parks them and binds death-notification on
    each at reconciliation, pairing against the matching `<name>.svc`
    recipe in `/config/svcmgr/services/` — see
    [`../../svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)
    and [Death notification](../../svcmgr/docs/ipc-interface.md#death-notification).
    logd is not among them: it is a svcmgr-launched service (from the
    `LOGD_SOURCES` round below), not a parked substrate.
  - **Terminal round (`LOGD_SOURCES`)** — the two reserved log-sink
    source caps svcmgr holds for the system's lifetime so it can
    launch and supervise real-logd (restart: design intent; not yet
    implemented (#262)): `master_log_source`, a `RIGHTS_ALL` derive of init's master log
    endpoint (svcmgr mints real-logd's master-log RECV from it on every
    (re)launch, plus the one-shot `HANDOVER_PULL` SEND on the first
    launch; see [`log_sink`](../../svcmgr/docs/service-definitions.md#log_sink)), and
    `procmgr_death_auth_source`, a badge-0
    `RIGHTS_EP_SEND_GRANT` derive of procmgr's service endpoint (svcmgr
    mints real-logd's `DEATH_EQ_AUTHORITY` SEND from it for per-sender
    death-EQ registration). Holding `master_log_source` keeps the log
    endpoint object alive across a logd crash, so log senders are
    agnostic to which process holds the RECV (per
    [`log_sink`](../../svcmgr/docs/service-definitions.md#log_sink)). An absent source rides as
    a zero slot.
- After draining the endowment, **svcmgr** (not init) publishes the
  well-known names it owns into its own registry and installs devmgr's
  drivers dir (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)):
  - `rootfs.root` — the endowed `SEND` on the root filesystem's
    namespace endpoint (FS-driver-agnostic by design).
  - `svcmgr` — un-badged SEND on svcmgr's own service endpoint.
  - `devmgr.registry` — `REGISTRY_QUERY_AUTHORITY`-badged SEND minted
    from the endowed devmgr-registry source. Consumers needing to
    resolve a device driver themselves (`programs/terminal` →
    `QUERY_FRAMEBUFFER_DEVICE` / `QUERY_INPUT_DEVICE` / `QUERY_SERIAL_DEVICE`;
    timed and pwrmgr → their devmgr queries; future: any non-init caller of
    devmgr's discovery surface) seed this name. The badge bit survives
    svcmgr's plain `cap_derive` in
    `registry_lookup_derived`.
  - `SET_DRIVERS_DIR` — svcmgr walks its universal root to
    `/services/drivers/` at `LOOKUP | READ` and hands devmgr the subtree
    cap on a `DRIVERS_DIR_AUTHORITY`-badged copy of the
    devmgr-registry source. Devmgr replies SUCCESS *before* any spawn
    work, then walks the per-arch RTC name and spawns the driver between
    its `ipc_reply` and next `ipc_recv` (procmgr `CREATE_FROM_FILE` —
    the binary lives on the rootfs, not in the boot bundle; see
    [Driver binary sources](../../../docs/device-management.md#driver-binary-sources)). Best-effort:
    a failure leaves the system without a wallclock — timed degrades to
    `WALL_CLOCK_UNAVAILABLE` (see [timed](../../timed/README.md)).

  `pwrmgr.shutdown`, `pwrmgr.deny`, and `timed` are published by
  svcmgr's provider path on each provider's launch (see
  [`provides`](../../svcmgr/docs/service-definitions.md#provides)). Name constants are
  centralised in `ipc::published_names`.
- The wallclock chain and pwrmgr are **not** spawned by init. `timed`
  and `pwrmgr` are svcmgr-launched providers (`timed.svc` / `pwrmgr.svc`),
  brought up post-handover; each resolves its authority from devmgr at
  startup (`QUERY_RTC_DEVICE` for [timed](../../timed/README.md);
  `QUERY_ACPI_TABLE` + `QUERY_SHUTDOWN_DEVICE` for
  [pwrmgr](../../pwrmgr/README.md)). The RTC chip driver (cmos-rtc on
  x86-64, goldfish-rtc on RISC-V) is spawned by devmgr from
  `/services/drivers/<chip>` after svcmgr's `SET_DRIVERS_DIR` handshake
  (see [Driver binary sources](../../../docs/device-management.md#driver-binary-sources)).
- Move init's kernel-object caps (`AddressSpace`, `CSpace`, main
  `Thread`, init-logd `Thread`) to procmgr in the first
  `REGISTER_INIT_TEARDOWN` round (`register_init_reap_objects` in
  `../src/service.rs`). IPC cap-transfer MOVES the caps, so they leave
  init's CSpace while the objects keep backing init's running threads.
  This round runs before `HANDOVER_COMPLETE` so procmgr's death
  observers are bound before real-logd can release init-logd.
- Notification `HANDOVER_COMPLETE`. svcmgr scans `/config/svcmgr/services/`,
  reconciles the parked substrate against the recipes, and launches the
  defined-but-unparked services (`logd`, `timed`, `pwrmgr`, `terminal`,
  staged harnesses) from disk (see
  [Reconciliation](../../svcmgr/docs/service-definitions.md#reconciliation)).
- Stream every reclaimable Memory cap init solely owns (ELF segments,
  user stack pages, `InitInfo` pages, the bootloader/bundle reclaim
  ranges, the AP-trampoline memory cap, the boot-module ELF sources, the
  usable-RAM caps that did not fit the bootstrap round, and
  `MemoryAlloc`'s orphaned remainders) to procmgr in further
  `REGISTER_INIT_TEARDOWN` rounds, then send `INIT_TEARDOWN_DONE`
  (`finish_init_reap_handoff` in `../src/service.rs`). The usable-RAM
  prefix already forwarded to memmgr (below the reap floor), the
  firmware read-only caps, and init's own bootstrap backing
  (arena-forwarded to memmgr at `finalize_memmgr`) are excluded.
- Call `sys_thread_exit`. Procmgr's `INIT_REAP_CORRELATOR` death
  observers are bound on both init threads by the first
  `REGISTER_INIT_TEARDOWN` round (see the
  [procmgr IPC interface](../../procmgr/docs/ipc-interface.md)). Each
  init-thread death runs
  [`init_reap::run_reap`](../../procmgr/src/init_reap.rs), which counts
  deaths down and tears init down on the second, once
  `INIT_TEARDOWN_DONE` has armed the reap (normally init-logd's death,
  after real-logd's `HANDOVER_RELEASE`): both Thread caps are deleted, init's `AddressSpace` is
  revoked + deleted (its pool donations `retype_free`'d, user-page
  mappings vanish), the accumulated Memory caps are `DONATE_MEMORY_CAPS`'d to
  memmgr's pool, init's `CSpace` is revoked + deleted (cascading
  dec_ref through init's remaining caps — endpoint SENDs and the
  retype-pinned endpoint-slab arena already forwarded to memmgr).
  Every reclaimable Memory cap was donated, so no `owns_memory` cap
  reaches its last reference and nothing frees to the sealed buddy.
  Procmgr logs a summary line; no init-related kernel object
  remains; svcmgr is the resident supervisor from this point on.

memmgr and procmgr are the only two processes init creates via
raw syscalls. Every later service spawn goes through procmgr IPC.
After the raw bootstrap completes, the only `no_std` userspace
services in the running system are init and
[memmgr](../../memmgr/README.md); everything else is std-built.

---

## Capability flow

### Initial CSpace at `_start`

The kernel populates init's CSpace before transferring control (see
[Capability Model](../../../docs/capability-model.md)). Init holds:

| Class | Content |
|---|---|
| Self-objects | `Thread`, `AddressSpace`, `CSpace` caps for init itself |
| Memory | `Memory` caps covering every usable physical memory page |
| MMIO | One `Mmio` cap per coarse MMIO aperture |
| Interrupts | One root `Interrupt` range cap (narrowed per-device in userspace via `sys_irq_split`) |
| I/O ports (x86-64) | `IoPort` cap covering the full 64 KiB port space |
| SBI (RISC-V) | `SbiControl` cap |
| Firmware tables | Read-only `Memory` caps covering the ACPI RSDP page, each `AcpiReclaimable` region, and the DTB blob |
| Scheduler | `SchedControl` cap |
| Boot modules | `Memory` caps for each boot-module image inside `bootstrap.bundle` (procmgr, memmgr, devmgr, vfsd, …) — resolved by name via the `init_protocol` module-name table |

Init derives and transfers these to services using the
**derive-twice** pattern documented in
[`../../../docs/capability-model.md`](../../../docs/capability-model.md):
init retains intermediary derivations (revocable) rather than the
roots, so it can revoke a child's authority before the handover to
svcmgr if needed (derivation-tree mechanics in
[capability internals](../../../core/kernel/docs/capability-internals.md)).

### Per-stage authority transfers

The system-wide capability flow across these stages is owned by
[Process Lifecycle](../../../docs/process-lifecycle.md); the table below
enumerates init's side of it.

| Stage | Recipient | Authority transferred |
|---|---|---|
| Raw bootstrap | memmgr | RAM `Memory` cap pool (every Memory cap not consumed by init/procmgr setup) |
| Raw bootstrap | procmgr | memmgr SEND cap, log endpoint SEND, svcmgr service endpoint SEND, boot-module `Memory` caps for downstream `CREATE_PROCESS` |
| Raw bootstrap | devmgr | MMIO apertures, Interrupt range, ACPI/DTB Memory caps; root `IoPort` (x86-64) / `SbiControl` (RISC-V) via the terminal `SVCMGR_BUNDLE` round — the hardware + shutdown authority [devmgr](../../devmgr/docs/responsibilities.md#capabilities-received) brokers to drivers and to pwrmgr |
| Raw bootstrap | vfsd | `SEED_AUTHORITY`-badged SEND on vfsd's own service endpoint (gates `GET_SYSTEM_ROOT_CAP`). vfsd self-mounts root, so init issues no `MOUNT` and keeps no FS access of its own. |
| Handover | svcmgr | `Universal` namespace seed (full `system_root_cap`) installed via `procmgr_labels::CONFIGURE_NAMESPACE` before `START_PROCESS`; then the handover endowment over the bootstrap protocol — round 1 (`CAPS`): full-rights (`RIGHTS_ALL`, incl. RECV) caps on its own service + bootstrap endpoints, a `SEND` on the root filesystem namespace endpoint (svcmgr publishes as `rootfs.root`) and a badge-0 `SEND\|GRANT` source on `devmgr_registry_ep` (svcmgr mints the `devmgr.registry` publish cap and the `SET_DRIVERS_DIR` cap); rounds 2..N (`SUBSTRATE`): one `(name, thread_cap)` per substrate service for death-supervision binding; terminal round (`LOGD_SOURCES`): a `RIGHTS_ALL` master-log endpoint source and a badge-0 `SEND\|GRANT` procmgr source, both reserved for the system's lifetime so svcmgr can launch and supervise real-logd, minting its master-log RECV, first-launch `HANDOVER_PULL` SEND, and `DEATH_EQ_AUTHORITY` SEND per launch (restart: design intent; not yet implemented, #262). svcmgr publishes all well-known names itself, sends `SET_DRIVERS_DIR` from these sources, and launches real-logd; init publishes nothing and does not talk to devmgr (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)). |
| Reap | procmgr | Init's `AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`, every reclaimable Memory cap it solely owns (ELF segments, user stack, `InitInfo` pages, bootloader/bundle reclaim ranges, AP-trampoline memory cap, boot-module ELF sources) |

---

## Summarized By

[ELF Loading](../../../core/boot/docs/elf-loading.md),
[System Bootstrap](../../../docs/bootstrap.md),
[Device Management](../../../docs/device-management.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md),
[services/init/README.md](../README.md), [logd IPC interface](../../logd/docs/ipc-interface.md),
[memmgr Memory Pool](../../memmgr/docs/memory-pool.md),
[services/procmgr/README.md](../../procmgr/README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md),
[svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md),
[vfsd Service Interface](../../vfsd/docs/vfs-ipc-interface.md)
