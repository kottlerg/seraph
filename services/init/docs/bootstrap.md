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

Init reaches `run()` (`../src/main.rs:350`) with the kernel-supplied
`InitInfo` populated and the initial CSpace seeded (see
[Capability flow](#capability-flow)). It performs the work required to
stand memmgr and procmgr up via raw syscalls, then delegates further
process creation to procmgr IPC.

- Version-check `InitInfo` against `INIT_PROTOCOL_VERSION` and exit
  on mismatch (`../src/main.rs:357`).
- Initialise the per-arch serial path used for FATAL pre-IPC errors
  (`../src/main.rs:364`).
- Build the `FrameAlloc` bump allocator over the kernel-provided
  memory pool (`../src/main.rs:366`).
- Reserve a Frame to back kernel-object retypes (the endpoint slab;
  one page suffices for the eight endpoints init creates)
  (`../src/main.rs:377`).
- Map a fresh IPC buffer page at `INIT_IPC_BUF_VA` and register it
  with the kernel (`../src/main.rs:393`–`../src/main.rs:405`).
- Mint endpoint objects: init's bootstrap endpoint, procmgr's
  service endpoint, memmgr's service endpoint, svcmgr's service
  endpoint (`../src/main.rs:439`; minted here so procmgr can receive
  an un-badged SEND on it during procmgr's bootstrap round), and
  the master log endpoint (`../src/main.rs:460`).
- Spawn the init-logd thread — a second thread of the init process
  that drains the master log endpoint and writes lines to the serial
  UART directly (`../src/main.rs:472`, with the receive loop in
  `../src/logging.rs`). After this point init's own `log()` lines
  ride IPC through init-logd to the serial UART. init-logd outlives
  init's main thread: it covers the console across the init→svcmgr
  handover and svcmgr's reconcile, until the svcmgr-launched
  real-logd pulls its captured history via `HANDOVER_PULL` and
  init-logd self-terminates (see [Handover](#handover)).
- Bootstrap memmgr via raw `cap_create_aspace` / `cap_create_cspace`
  / `cap_create_thread`, ELF-load it from the `memmgr` bundle
  entry, prepare its `ProcessInfo` page, and configure its main
  thread but defer `thread_start`
  (`bootstrap::bootstrap_memmgr` at `../src/bootstrap.rs:521`,
  called from `../src/main.rs:506`).
- Bootstrap procmgr the same way; procmgr's `ProcessInfo` receives
  the memmgr SEND cap so its std heap reaches memmgr on the first
  allocation (`bootstrap::bootstrap_procmgr` at
  `../src/bootstrap.rs:1119`, called from `../src/main.rs:515`).
- Delegate all remaining RAM Frame caps to memmgr's CSpace via
  `finalize_memmgr` and serve a single bootstrap-IPC round carrying
  the pool's frame range + a read-only phys-table cap (so memmgr can
  ingest its pool) (`../src/main.rs:543`, serve at `../src/main.rs:574`).
  Init retains every boot-module Frame cap (its self-loaded
  memmgr/procmgr ELFs plus the devmgr/vfsd/driver modules) as sole
  owner; those donate to memmgr's pool on the reap-handoff route, not
  here (`../src/main.rs:628`).
- Start procmgr's thread and serve procmgr's bootstrap IPC, handing
  it the log endpoint SEND and svcmgr's service endpoint SEND
  (`../src/main.rs:634`).
- Request procmgr to create devmgr via boot-module
  `CREATE_PROCESS` and serve devmgr's multi-round bootstrap
  (hardware caps: MMIO apertures, Interrupt range, ACPI Frame caps,
  DTB Frame cap on riscv64, and a `FRAMEBUFFER_INFO` round carrying
  the bootloader-discovered `boot_protocol::FramebufferInfo` so devmgr
  can spawn the userspace framebuffer driver)
  (`../src/main.rs:720` + `service::create_devmgr_with_caps` at
  `../src/service.rs:341`).
- Request procmgr to create vfsd the same way and serve its
  bootstrap (`../src/main.rs:738` +
  `service::create_vfsd_with_caps` at `../src/service.rs:738`).
- Closing marker: `"phase 1 bootstrap complete"`
  (`../src/main.rs:755`).

### Root acquisition

vfsd self-mounts the root partition at `/` (and the ESP at `/esp`) on
its own startup, identifying partitions by GPT type-GUID
(`boot_protocol::role_guids::SERAPH_ROOT_<arch>`). Init issues no
`MOUNT`; its only contribution is the seed-cap pull, which doubles as
init's wait-for-root barrier.

- Pull the seed system-root cap via `GET_SYSTEM_ROOT_CAP`
  (`mount::request_system_root`). vfsd replies `NO_MOUNT` until it has
  mounted root, so the call blocks until the root filesystem is up; a
  zero return is FATAL. The success reply is a badged SEND on vfsd's
  namespace endpoint at the synthetic root with full namespace rights
  — every later child receives a `cap_copy` of it via
  `procmgr_labels::CONFIGURE_NAMESPACE`, and svcmgr derives the
  published `rootfs.root` SEND from it.
- real-logd is a svcmgr-launched service, not an init responsibility.
  init-logd continues to serve the master log endpoint and write
  serial directly; svcmgr brings up real-logd post-handover from the
  reserved log-sink sources init endows in the Handover stage (the
  `LOGD_SOURCES` round below), and real-logd then pulls init-logd's
  captured state via `HANDOVER_PULL`. See
  [`../../logd/docs/handover-protocol.md`](../../logd/docs/handover-protocol.md).
- Closing marker: `"phase 2 bootstrap complete"`
  (`../src/main.rs:783`).

### Handover

`service::phase3_svcmgr_handover` (in `../src/service.rs`, called
from `../src/main.rs`) loads svcmgr, serves it the handover endowment,
signals handover, and hands init's own kernel objects to procmgr for
reaping. svcmgr — not init — publishes the well-known caps, registers
services, and talks to devmgr, all from the endowment.

- Spawn svcmgr from `/services/svcmgr` with the `Universal` namespace
  policy (`create_svcmgr_from_file`), then serve it the handover
  endowment over the bootstrap-round protocol (`endow_svcmgr`):
  - **Round 1 (`CAPS`)** — svcmgr's service + bootstrap endpoints
    (full rights), plus the publish-role source caps: a `SEND` on the
    root filesystem's namespace endpoint (svcmgr publishes it as
    `rootfs.root`) and a badge-0 `SEND|GRANT` source on
    `devmgr_registry_ep` (svcmgr mints the `REGISTRY_QUERY_AUTHORITY`
    `devmgr.registry` publish cap and the `DRIVERS_DIR_AUTHORITY`
    `SET_DRIVERS_DIR` cap from it). `data[1]` carries
    `SVCMGR_LABELS_VERSION`. An absent source rides as a zero slot.
  - **Rounds 2..N (`SUBSTRATE`)** — one `(name, thread_cap)` per
    init-bootstrapped substrate service: `memmgr`, `procmgr`, `devmgr`,
    `vfsd`. svcmgr parks them and binds death-notification on
    each at reconciliation, pairing against the matching `<name>.svc`
    recipe in `/config/svcmgr/services/` — see
    [`../../svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md).
    logd is not among them: it is a svcmgr-launched service (from the
    `LOGD_SOURCES` round below), not a parked substrate.
  - **Terminal round (`LOGD_SOURCES`)** — the two reserved log-sink
    source caps svcmgr holds for the system's lifetime so it can
    launch + supervise + restart real-logd any number of times:
    `master_log_source`, a `RIGHTS_ALL` derive of init's master log
    endpoint (svcmgr mints real-logd's master-log RECV from it on every
    (re)launch, plus the one-shot `HANDOVER_PULL` SEND on the first
    launch), and `procmgr_death_auth_source`, a badge-0
    `RIGHTS_SEND_GRANT` derive of procmgr's service endpoint (svcmgr
    mints real-logd's `DEATH_EQ_AUTHORITY` SEND from it for per-sender
    death-EQ registration). Holding `master_log_source` keeps the log
    endpoint object alive across a logd crash, so log senders are
    agnostic to which process holds the RECV. An absent source rides as
    a zero slot.
- After draining the endowment, **svcmgr** (not init) publishes the
  well-known names it owns into its own registry and installs devmgr's
  drivers dir:
  - `rootfs.root` — the endowed `SEND` on the root filesystem's
    namespace endpoint (FS-driver-agnostic by design).
  - `svcmgr` — un-badged SEND on svcmgr's own service endpoint.
  - `devmgr.registry` — `REGISTRY_QUERY_AUTHORITY`-badged SEND minted
    from the endowed devmgr-registry source. Consumers needing to
    resolve a device driver themselves (`programs/fb-charset` →
    `QUERY_FRAMEBUFFER_DEVICE`; timed and pwrmgr → their devmgr queries;
    future: any non-init caller of devmgr's discovery surface) seed this
    name. The badge bit survives svcmgr's plain `cap_derive` in
    `registry_lookup_derived`.
  - `SET_DRIVERS_DIR` — svcmgr walks its universal root to
    `/services/drivers/` at `LOOKUP | READ` and hands devmgr the subtree
    cap on a `DRIVERS_DIR_AUTHORITY`-badged copy of the
    devmgr-registry source. Devmgr replies SUCCESS *before* any spawn
    work, then walks the per-arch RTC name and spawns the driver between
    its `ipc_reply` and next `ipc_recv` (procmgr `CREATE_FROM_FILE` —
    the binary lives on the rootfs, not in the boot bundle). Best-effort:
    a failure leaves the system without a wallclock — timed degrades to
    `WALL_CLOCK_UNAVAILABLE`.

  `pwrmgr.shutdown`, `pwrmgr.deny`, and `timed` are published by
  svcmgr's provider path on each provider's launch. Name constants are
  centralised in `ipc::published_names`.
- The wallclock chain and pwrmgr are **not** spawned by init. `timed`
  and `pwrmgr` are svcmgr-launched providers (`timed.svc` / `pwrmgr.svc`),
  brought up post-handover; each resolves its authority from devmgr at
  startup (`QUERY_RTC_DEVICE` for timed; `QUERY_ACPI_TABLE` +
  `QUERY_SHUTDOWN_DEVICE` for pwrmgr). The RTC chip driver (cmos-rtc on
  x86-64, goldfish-rtc on RISC-V) is spawned by devmgr from
  `/services/drivers/<chip>` after svcmgr's `SET_DRIVERS_DIR` handshake.
- Signal `HANDOVER_COMPLETE`. svcmgr scans `/config/svcmgr/services/`,
  reconciles the parked substrate against the recipes, and launches any
  defined-but-unparked services (`timed`, `pwrmgr`, staged harnesses)
  from disk.
- Hand init's kernel-object caps (`AddressSpace`, `CSpace`, main
  `Thread`, init-logd `Thread`) and every reclaimable Frame cap it
  solely owns (ELF segments, user stack pages, `InitInfo` pages, the
  bootloader/bundle reclaim ranges, the AP-trampoline frame, and the
  boot-module ELF sources) to procmgr via
  `REGISTER_INIT_TEARDOWN` (`handoff_to_procmgr_reap` in
  `../src/service.rs`). IPC
  cap-transfer MOVES the caps, so they leave init's CSpace. The
  usable-RAM range (already memmgr's), the firmware read-only caps,
  and init's own bootstrap backing (arena-forwarded to memmgr at
  `finalize_memmgr`) are excluded.
- Call `sys_thread_exit`. Procmgr's
  death-EQ observer (bound on init's main thread with
  `INIT_REAP_CORRELATOR`) fires and runs
  [`init_reap::run_reap`](../../procmgr/src/init_reap.rs): both
  Thread caps are deleted, init's `AddressSpace` is revoked +
  deleted (PT chunks `retype_free`'d, user-page mappings
  vanish), the accumulated Frame caps are `DONATE_FRAMES`'d to
  memmgr's pool, init's `CSpace` is revoked + deleted (cascading
  dec_ref through init's remaining caps — endpoint SENDs and the
  retype-pinned endpoint-slab arena already forwarded to memmgr).
  Every reclaimable Frame was donated, so no `owns_memory` cap
  reaches its last reference and nothing frees to the sealed buddy.
  Procmgr logs a summary line; no init-related kernel object
  remains; svcmgr is the resident supervisor from this point on.

memmgr and procmgr are the only two processes init creates via
raw syscalls. Every later service spawn goes through procmgr IPC.
After the raw bootstrap completes, the only `no_std` userspace
services in the running system are init and memmgr; everything
else is std-built.

---

## Capability flow

### Initial CSpace at `_start`

The kernel populates init's CSpace before transferring control. Init
holds:

| Class | Content |
|---|---|
| Self-objects | `Thread`, `AddressSpace`, `CSpace` caps for init itself |
| Memory | `Frame` caps covering every usable physical memory page |
| MMIO | One `MmioRegion` cap per coarse MMIO aperture |
| Interrupts | One root `Interrupt` range cap (narrowed per-device in userspace via `sys_irq_split`) |
| I/O ports (x86-64) | `IoPortRange` cap covering the full 64 KiB port space |
| SBI (RISC-V) | `SbiControl` cap |
| Firmware tables | Read-only `Frame` caps covering the ACPI RSDP page, each `AcpiReclaimable` region, and the DTB blob |
| Scheduler | `SchedControl` cap |
| Boot modules | `Frame` caps for each boot-module image inside `bootstrap.bundle` (procmgr, memmgr, devmgr, vfsd, …) — resolved by name via the `init_protocol` module-name table |

Init derives and transfers these to services using the
**derive-twice** pattern documented in
[`../../../docs/capability-model.md`](../../../docs/capability-model.md):
init retains intermediary derivations (revocable) rather than the
roots, so it can revoke a child's authority before the handover to
svcmgr if needed.

### Per-stage authority transfers

| Stage | Recipient | Authority transferred |
|---|---|---|
| Raw bootstrap | memmgr | RAM `Frame` pool (every Frame cap not consumed by init/procmgr setup) |
| Raw bootstrap | procmgr | memmgr SEND cap, log endpoint SEND, svcmgr service endpoint SEND, boot-module `Frame` caps for downstream `CREATE_PROCESS` |
| Raw bootstrap | devmgr | MMIO apertures, Interrupt range, ACPI/DTB Frame caps; root `IoPortRange` (x86-64) / `SbiControl` (RISC-V) via the terminal `SVCMGR_BUNDLE` round — the hardware + shutdown authority devmgr brokers to drivers and to pwrmgr |
| Raw bootstrap | vfsd | `SEED_AUTHORITY`-badged SEND on vfsd's own service endpoint (gates `GET_SYSTEM_ROOT_CAP`). vfsd self-mounts root, so init issues no `MOUNT` and keeps no FS access of its own. |
| Handover | svcmgr | `Universal` namespace seed (full `system_root_cap`) installed via `procmgr_labels::CONFIGURE_NAMESPACE` before `START_PROCESS`; then the handover endowment over the bootstrap protocol — round 1 (`CAPS`): full-rights SEND on its own service + bootstrap endpoints, a `SEND` on the root filesystem namespace endpoint (svcmgr publishes as `rootfs.root`) and a badge-0 `SEND\|GRANT` source on `devmgr_registry_ep` (svcmgr mints the `devmgr.registry` publish cap and the `SET_DRIVERS_DIR` cap); rounds 2..N (`SUBSTRATE`): one `(name, thread_cap)` per substrate service for death-supervision binding; terminal round (`LOGD_SOURCES`): a `RIGHTS_ALL` master-log endpoint source and a badge-0 `SEND\|GRANT` procmgr source, both reserved for the system's lifetime so svcmgr can launch + supervise + restart real-logd (minting its master-log RECV, first-launch `HANDOVER_PULL` SEND, and `DEATH_EQ_AUTHORITY` SEND per launch). svcmgr publishes all well-known names itself, sends `SET_DRIVERS_DIR` from these sources, and launches real-logd; init publishes nothing and does not talk to devmgr. |
| Reap | procmgr | Init's `AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`, every reclaimable Frame cap it solely owns (ELF segments, user stack, `InitInfo` pages, bootloader/bundle reclaim ranges, AP-trampoline frame, boot-module ELF sources) |

---

## Summarized By

[init/README.md](../README.md), [docs/bootstrap.md](../../../docs/bootstrap.md), [docs/process-lifecycle.md](../../../docs/process-lifecycle.md)
