# init Bootstrap Stages

Authoritative enumeration of the work init performs between kernel
handoff (`_start`) and `sys_thread_exit`, organised into three
stages: **Raw bootstrap**, **Root mount**, **Handover**. The names
used in source `log()` strings — `"phase 1 bootstrap complete"`,
`"phase 2: mounting root filesystem"`, `"phase 2 epilogue"`,
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

### Root mount

vfsd identifies the root partition by GPT type-GUID
(`boot_protocol::role_guids::SERAPH_ROOT_<arch>`), so init names
only the *role* and vfsd performs the partition lookup. Init's
contribution is the MOUNT exchange and the seed-cap pull; the ESP
and any further partitions are discovered and mounted by vfsd
directly without init involvement.

- Send `MOUNT(MountRole::Root, "/")` to vfsd
  (`../src/main.rs:830` → `mount::send_mount` at
  `../src/mount.rs:63`). The wire payload is the `MountRole`
  discriminant byte (`../src/mount.rs:30`, currently a single
  variant `Root = 0`) plus the mount-point path.
- Pull the seed system-root cap via `GET_SYSTEM_ROOT_CAP`
  (`../src/main.rs:846` → `mount::request_system_root` at
  `../src/mount.rs:100`). The reply is a tokened SEND on vfsd's
  namespace endpoint at the synthetic root with full namespace
  rights — every later child receives a `cap_copy` of it via
  `procmgr_labels::CONFIGURE_NAMESPACE`.
- **Phase 2 epilogue** — walk `/services/logd`, request procmgr to
  create real-logd via `CREATE_FROM_FILE`, and serve its bootstrap
  round (RECV cap on the master log endpoint, one-shot SEND for
  `HANDOVER_PULL`, `DEATH_EQ_AUTHORITY`-tokened SEND on procmgr,
  arch serial authority). Real-logd pulls init-logd's captured
  state via `HANDOVER_PULL`; init-logd self-terminates on the
  final reply. See
  [`../../logd/docs/handover-protocol.md`](../../logd/docs/handover-protocol.md)
  (`../src/main.rs:866` → `service::create_and_start_logd` at
  `../src/service.rs:1595`).
- Closing marker: `"phase 2 bootstrap complete"`
  (`../src/main.rs:881`).

### Handover

`service::phase3_svcmgr_handover` (`../src/service.rs:1231`, called
from `../src/main.rs:886`) brings up the remaining bootstrap
services, transfers the system-wide service registry to svcmgr,
publishes the well-known caps, registers init-bootstrapped
services with svcmgr, and hands init's own kernel objects to
procmgr for reaping.

- Spawn svcmgr from `/services/svcmgr` with the `Universal` namespace
  policy and serve its bootstrap round
  (`../src/service.rs:1341` → `create_svcmgr_from_file` at
  `../src/service.rs:1135`; `setup_and_start_svcmgr` at
  `../src/service.rs:1213`).
- Walk `system_root_cap` to `/services/drivers/` at `LOOKUP | READ`
  rights and hand devmgr the resulting subtree cap via
  `devmgr_labels::SET_DRIVERS_DIR`, on an
  `INIT_BIND_AUTHORITY`-tokened copy of `devmgr_registry_ep`. Devmgr
  replies SUCCESS *before* doing any spawn work, then walks the
  per-arch RTC name from that subtree and spawns the driver between
  its `ipc_reply` and next `ipc_recv` (procmgr `CREATE_FROM_FILE` —
  the binary lives on the rootfs, not in the boot bundle).
  Best-effort: the handshake is non-fatal, and any failure
  (walk fails, devmgr replies non-SUCCESS) leaves the system without
  a wallclock — timed degrades to `WALL_CLOCK_UNAVAILABLE`.
  (`set_drivers_dir_on_devmgr` in `../src/service.rs`.)
- Bring up the wallclock chain: spawn timed and resolve the per-arch
  RTC driver through devmgr. The RTC chip driver (cmos-rtc on x86-64,
  goldfish-rtc on RISC-V) is spawned by devmgr from the on-disk
  rootfs (`/services/drivers/<chip>`) after the
  `SET_DRIVERS_DIR` handshake above, not by init; timed resolves the
  SEND at startup via `devmgr_labels::QUERY_RTC_DEVICE` on the
  `REGISTRY_QUERY_AUTHORITY`-tokened copy of devmgr's registry
  endpoint delivered in its bootstrap round
  (`../src/service.rs:1372` → `bring_up_timed` at
  `../src/service.rs:2077`, with `create_and_start_timed` at
  `../src/service.rs:1980`).
- Spawn pwrmgr with the arch authority cap
  (`IoPortRange` on x86-64, `SbiControl` on RISC-V) and the
  ACPI Frame caps; capture pwrmgr's service endpoint and main
  thread cap (`../src/service.rs:1383` →
  `create_and_start_pwrmgr` at `../src/service.rs:796`).
- Derive a `PUBLISH_AUTHORITY`-tokened `RIGHTS_SEND_GRANT` cap on
  svcmgr's service endpoint (`../src/service.rs:1409`) and
  publish five well-known names via `PUBLISH_ENDPOINT`:
  - `rootfs.root` — tokened SEND on the root filesystem's
    namespace endpoint at its root directory (FS-driver-agnostic
    by design) (`../src/service.rs:1422`).
  - `pwrmgr.shutdown` — `SHUTDOWN_AUTHORITY`-tokened SEND on
    pwrmgr's service endpoint (`../src/service.rs:1443`).
  - `pwrmgr.deny` — non-AUTHORITY SEND on pwrmgr's service
    endpoint (negative-test twin) (`../src/service.rs:1455`).
  - `svcmgr` — un-tokened SEND on svcmgr's own service endpoint
    (`../src/service.rs:1475`).
  - `devmgr.registry` — `REGISTRY_QUERY_AUTHORITY`-tokened SEND
    on devmgr's registry endpoint. Consumers needing to resolve a
    device driver themselves (today: `programs/fb-charset` →
    `QUERY_FRAMEBUFFER_DEVICE`; future: any non-init caller of
    devmgr's discovery surface) seed this name. The token bit
    survives svcmgr's plain `cap_derive` in
    `registry_lookup_derived`.

  Name constants are centralised in `ipc::published_names`.
- Register each init-bootstrapped service with svcmgr via the v3
  `REGISTER_SERVICE` wire (name + thread cap)
  (`../src/service.rs:1521`–`../src/service.rs:1543`;
  `register_service` helper at `../src/service.rs:1273`).
  Registration set: `memmgr`, `procmgr`, `devmgr`, `vfsd`,
  `logd`, `timed`, `pwrmgr`. svcmgr reconciles each against the
  matching `<name>.svc` recipe in `/config/svcmgr/services/` and
  binds death-notification — see
  [`../../svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md).
- Signal `HANDOVER_COMPLETE` (`../src/service.rs:1545`). svcmgr
  scans `/config/svcmgr/services/` and launches any
  defined-but-unregistered services from disk.
- Hand init's kernel-object caps (`AddressSpace`, `CSpace`, main
  `Thread`, init-logd `Thread`) and every reclaimable Frame cap
  (segments, stack, `InitInfo` region, IPC buffer) to procmgr via
  `REGISTER_INIT_TEARDOWN` (`../src/service.rs:1558` →
  `handoff_to_procmgr_reap` at `../src/service.rs:1579`). IPC
  cap-transfer MOVES the caps, so they leave init's CSpace.
- Call `sys_thread_exit` (`../src/service.rs:1567`). Procmgr's
  death-EQ observer (bound on init's main thread with
  `INIT_REAP_CORRELATOR`) fires and runs
  [`init_reap::run_reap`](../../procmgr/src/init_reap.rs): both
  Thread caps are deleted, init's `AddressSpace` is revoked +
  deleted (PT chunks `retype_free`'d, user-page mappings
  vanish), the accumulated Frame caps are `DONATE_FRAMES`'d to
  memmgr's pool, init's `CSpace` is revoked + deleted (cascading
  dec_ref through every remaining cap; `owns_memory=true` caps
  return their pages to the kernel buddy via `dealloc_object`),
  and procmgr logs a summary line. No init-related kernel object
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
| Raw bootstrap | devmgr | MMIO apertures, Interrupt range, ACPI/DTB Frame caps |
| Raw bootstrap | vfsd | `SEED_AUTHORITY`-tokened SEND on vfsd's own service endpoint (gates `GET_SYSTEM_ROOT_CAP`); the un-tokened service-endpoint SEND init holds is used for the un-gated MOUNT call. Init keeps no FS access of its own. |
| Root mount | logd | RECV on the master log endpoint, one-shot SEND for `HANDOVER_PULL`, `DEATH_EQ_AUTHORITY`-tokened SEND on procmgr, arch serial authority (`IoPortRange` on x86-64, `SbiControl` on RISC-V) |
| Handover | svcmgr | `Universal` namespace seed (full `system_root_cap`) installed via `procmgr_labels::CONFIGURE_NAMESPACE` before `START_PROCESS`; in the bootstrap round, full-rights SEND on its own service endpoint and on the local svcmgr-bootstrap endpoint |
| Handover | pwrmgr | Remaining arch authority (`IoPortRange` / `SbiControl`) + ACPI region Frame caps |
| Handover (publish) | svcmgr registry | `rootfs.root`, `pwrmgr.shutdown`, `pwrmgr.deny`, `svcmgr`, `devmgr.registry` named caps |
| Reap | procmgr | Init's `AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`, every reclaimable Frame cap (segments, stack, `InitInfo` region, IPC buffer) |

---

## Summarized By

[init/README.md](../README.md), [docs/bootstrap.md](../../../docs/bootstrap.md), [docs/process-lifecycle.md](../../../docs/process-lifecycle.md)
