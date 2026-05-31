# init Bootstrap Stages

Authoritative enumeration of the work init performs between kernel
handoff (`_start`) and `sys_thread_exit`, organised into three
stages: **Raw bootstrap**, **Root acquisition**, **Handover**. The
names used in source `log()` strings — `"phase 1 bootstrap complete"`,
`"phase 2: acquiring system-root cap"`, `"phase 2 epilogue"`,
`"phase 3: ..."` — are the searchable equivalents and remain stable.

---

## Stages

### Raw bootstrap

Init reaches `run()` (`../src/main.rs:375`) with the kernel-supplied
`InitInfo` populated and the initial CSpace seeded (see
[Capability flow](#capability-flow)). It performs the work required to
stand memmgr and procmgr up via raw syscalls, then delegates further
process creation to procmgr IPC.

- Version-check `InitInfo` against `INIT_PROTOCOL_VERSION` and exit
  on mismatch (`../src/main.rs:382`).
- Initialise the per-arch serial path used for FATAL pre-IPC errors
  (`../src/main.rs:389`).
- Build the `FrameAlloc` bump allocator over the kernel-provided
  memory pool (`../src/main.rs:391`).
- Reserve a Frame to back kernel-object retypes (the endpoint slab;
  one page suffices for the eight endpoints init creates)
  (`../src/main.rs:396`).
- Map a fresh IPC buffer page at `INIT_IPC_BUF_VA` and register it
  with the kernel (`../src/main.rs:404`–`../src/main.rs:427`).
- Mint endpoint objects: init's bootstrap endpoint, procmgr's
  service endpoint, memmgr's service endpoint, svcmgr's service
  endpoint (`../src/main.rs:461`; minted here so procmgr can receive
  an un-tokened SEND on it during procmgr's bootstrap round), and
  the master log endpoint (`../src/main.rs:483`).
- Spawn the init-logd thread, which serves the log endpoint until
  real-logd takes over via `HANDOVER_PULL`
  (`../src/main.rs:494`, with the receive loop in
  `../src/logging.rs`). After this point init's own `log()` lines
  ride IPC through init-logd to the serial UART.
- Bootstrap memmgr via raw `cap_create_aspace` / `cap_create_cspace`
  / `cap_create_thread`, ELF-load it from the `memmgr` bundle
  entry, prepare its `ProcessInfo` page, and configure its main
  thread but defer `thread_start`
  (`bootstrap::bootstrap_memmgr` at `../src/bootstrap.rs:429`,
  called from `../src/main.rs:527`).
- Bootstrap procmgr the same way; procmgr's `ProcessInfo` receives
  the memmgr SEND cap so its std heap reaches memmgr on the first
  allocation (`bootstrap::bootstrap_procmgr` at
  `../src/bootstrap.rs:796`, called from `../src/main.rs:537`).
- Donate the remaining RAM Frame caps to memmgr's CSpace, serve a
  single bootstrap-IPC round carrying the donated slot range
  (so memmgr knows where its pool lives), then donate the
  boot-module Frame caps that backed procmgr/devmgr/vfsd
  (`../src/main.rs:630`, `../src/main.rs:652`).
- Start procmgr's thread and serve procmgr's bootstrap IPC, handing
  it the log endpoint SEND and svcmgr's service endpoint SEND
  (`../src/main.rs:696`).
- Request procmgr to create devmgr via boot-module
  `CREATE_PROCESS` and serve devmgr's multi-round bootstrap
  (hardware caps: MMIO apertures, Interrupt range, ACPI Frame caps,
  DTB Frame cap on riscv64, and a `FRAMEBUFFER_INFO` round carrying
  the bootloader-discovered `boot_protocol::FramebufferInfo` so devmgr
  can spawn the userspace framebuffer driver)
  (`../src/main.rs:782` + `service::create_devmgr_with_caps` at
  `../src/service.rs:371`).
- Request procmgr to create vfsd the same way and serve its
  bootstrap (`../src/main.rs:800` +
  `service::create_vfsd_with_caps` at `../src/service.rs:950`).
- Closing marker: `"phase 1 bootstrap complete"`
  (`../src/main.rs:821`).

### Root acquisition

vfsd self-mounts the root partition at `/` (and the ESP at `/esp`) on
its own startup, identifying partitions by GPT type-GUID
(`boot_protocol::role_guids::SERAPH_ROOT_<arch>`). Init issues no
`MOUNT`; its only contribution is the seed-cap pull, which doubles as
init's wait-for-root barrier.

- Pull the seed system-root cap via `GET_SYSTEM_ROOT_CAP`
  (`mount::request_system_root`). vfsd replies `NO_MOUNT` until it has
  mounted root, so the call blocks until the root filesystem is up; a
  zero return is FATAL. The success reply is a tokened SEND on vfsd's
  namespace endpoint at the synthetic root with full namespace rights
  — every later child receives a `cap_copy` of it via
  `procmgr_labels::CONFIGURE_NAMESPACE`, and svcmgr derives the
  published `rootfs.root` SEND from it.
- **Phase 2 epilogue** — walk `/services/logd`, request procmgr to
  create real-logd via `CREATE_FROM_FILE`, and serve its bootstrap
  round (RECV cap on the master log endpoint, one-shot SEND for
  `HANDOVER_PULL`, `DEATH_EQ_AUTHORITY`-tokened SEND on procmgr,
  arch serial authority). Real-logd pulls init-logd's captured
  state via `HANDOVER_PULL`; init-logd self-terminates on the
  final reply. See
  [`../../logd/docs/handover-protocol.md`](../../logd/docs/handover-protocol.md)
  (`../src/main.rs:866` → `service::create_and_start_logd` in
  `../src/service.rs`).
- Closing marker: `"phase 2 bootstrap complete"`
  (`../src/main.rs:881`).

### Handover

`service::phase3_svcmgr_handover` (in `../src/service.rs`, called
from `../src/main.rs`) loads svcmgr, serves it the handover endowment,
signals handover, and hands init's own kernel objects to procmgr for
reaping. init no longer publishes well-known caps, registers services,
or talks to devmgr — svcmgr does all of that from the endowment.

- Spawn svcmgr from `/services/svcmgr` with the `Universal` namespace
  policy (`create_svcmgr_from_file`), then serve it the handover
  endowment over the bootstrap-round protocol (`endow_svcmgr`):
  - **Round 1 (`CAPS`)** — svcmgr's service + bootstrap endpoints
    (full rights), plus the publish-role source caps: a `SEND` on the
    root filesystem's namespace endpoint (svcmgr publishes it as
    `rootfs.root`) and a token-0 `SEND|GRANT` source on
    `devmgr_registry_ep` (svcmgr mints the `REGISTRY_QUERY_AUTHORITY`
    `devmgr.registry` publish cap and the `DRIVERS_DIR_AUTHORITY`
    `SET_DRIVERS_DIR` cap from it). `data[1]` carries
    `SVCMGR_LABELS_VERSION`. An absent source rides as a zero slot.
  - **Rounds 2..N (`SUBSTRATE`)** — one `(name, thread_cap)` per
    init-bootstrapped substrate service: `memmgr`, `procmgr`, `devmgr`,
    `vfsd`, `logd`. svcmgr parks them and binds death-notification on
    each at reconciliation, pairing against the matching `<name>.svc`
    recipe in `/config/svcmgr/services/` — see
    [`../../svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md).
- After draining the endowment, **svcmgr** (not init) publishes the
  well-known names it owns into its own registry and installs devmgr's
  drivers dir:
  - `rootfs.root` — the endowed `SEND` on the root filesystem's
    namespace endpoint (FS-driver-agnostic by design).
  - `svcmgr` — un-tokened SEND on svcmgr's own service endpoint.
  - `devmgr.registry` — `REGISTRY_QUERY_AUTHORITY`-tokened SEND minted
    from the endowed devmgr-registry source. Consumers needing to
    resolve a device driver themselves (`programs/fb-charset` →
    `QUERY_FRAMEBUFFER_DEVICE`; timed and pwrmgr → their devmgr queries;
    future: any non-init caller of devmgr's discovery surface) seed this
    name. The token bit survives svcmgr's plain `cap_derive` in
    `registry_lookup_derived`.
  - `SET_DRIVERS_DIR` — svcmgr walks its universal root to
    `/services/drivers/` at `LOOKUP | READ` and hands devmgr the subtree
    cap on a `DRIVERS_DIR_AUTHORITY`-tokened copy of the
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
| Raw bootstrap | vfsd | `SEED_AUTHORITY`-tokened SEND on vfsd's own service endpoint (gates `GET_SYSTEM_ROOT_CAP`). vfsd self-mounts root, so init issues no `MOUNT` and keeps no FS access of its own. |
| Root acquisition | logd | RECV on the master log endpoint, one-shot SEND for `HANDOVER_PULL`, `DEATH_EQ_AUTHORITY`-tokened SEND on procmgr, arch serial authority (`IoPortRange` on x86-64, `SbiControl` on RISC-V) |
| Handover | svcmgr | `Universal` namespace seed (full `system_root_cap`) installed via `procmgr_labels::CONFIGURE_NAMESPACE` before `START_PROCESS`; then the handover endowment over the bootstrap protocol — round 1 (`CAPS`): full-rights SEND on its own service + bootstrap endpoints, a `SEND` on the root filesystem namespace endpoint (svcmgr publishes as `rootfs.root`) and a token-0 `SEND\|GRANT` source on `devmgr_registry_ep` (svcmgr mints the `devmgr.registry` publish cap and the `SET_DRIVERS_DIR` cap); rounds 2..N (`SUBSTRATE`): one `(name, thread_cap)` per substrate service for death-supervision binding. svcmgr publishes all well-known names itself and sends `SET_DRIVERS_DIR` from these sources; init no longer publishes or talks to devmgr. |
| Reap | procmgr | Init's `AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`, every reclaimable Frame cap it solely owns (ELF segments, user stack, `InitInfo` pages, bootloader/bundle reclaim ranges, AP-trampoline frame, boot-module ELF sources) |

---

## Summarized By

[init/README.md](../README.md), [docs/bootstrap.md](../../../docs/bootstrap.md), [docs/process-lifecycle.md](../../../docs/process-lifecycle.md)
