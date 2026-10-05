# init

Bootstrap service and first userspace process. The kernel starts init at the end
of its initialization sequence. Init runs a three-stage
[bootstrap](docs/bootstrap.md) — raw memmgr / procmgr creation, root
acquisition, then handover to svcmgr — and exits. It is not a long-lived
service manager.

---

## Source Layout

```
init/
├── Cargo.toml                  # Workspace member; no_std binary
├── README.md
├── docs/
│   └── bootstrap.md            # Authoritative stage enumeration + capability flow
└── src/
    ├── main.rs                 # _start, run() orchestration across the three stages
    ├── bootstrap.rs            # Raw memmgr / procmgr ELF-load + kernel-object setup
    ├── service.rs              # IPC-driven spawns (devmgr, vfsd, svcmgr)
    │                             and phase3_svcmgr_handover
    ├── mount.rs                # GET_SYSTEM_ROOT_CAP pull (vfsd self-mounts root)
    ├── logging.rs              # init-logd thread
    │                             (serves the log endpoint until real-logd takes over)
    ├── walk.rs                 # /services/<name> path walker over the seed system-root cap
    └── arch/                   # Per-arch serial init (x86-64, riscv64)
```

Init depends on `shared/elf` for ELF parsing (used to load memmgr and procmgr
from their bundle entries) and `shared/syscall` for raw syscall wrappers (used
to create memmgr and procmgr without IPC).

---

## Bootstrap

Init runs three stages between `_start` and `sys_thread_exit`:

1. **Raw bootstrap** — version-check `InitInfo`, set up the IPC buffer, mint
   endpoints, spawn init-logd, bring up memmgr and procmgr via raw syscalls,
   then drive procmgr IPC to create devmgr and vfsd.
2. **Root acquisition** — vfsd self-mounts the Seraph root partition at `/`
   on its own startup; init issues no `MOUNT` (see
   [vfsd service interface](../vfsd/docs/vfs-ipc-interface.md)). Pull the seed
   `system_root_cap` via `GET_SYSTEM_ROOT_CAP` (which vfsd serves only once
   root is mounted, so the call blocks until root is up). The init-logd
   thread keeps serving the master log endpoint and writing serial directly;
   the svcmgr-launched real-logd takes over the endpoint and pulls init-logd's
   captured history via `HANDOVER_PULL` post-handover (see
   [logd handover protocol](../logd/docs/handover-protocol.md)).
3. **Handover** — load svcmgr and serve it the handover endowment over
   the bootstrap-round protocol: its own endpoints, the publish-role
   source caps (`rootfs.root` SEND, devmgr-registry `SEND|GRANT` source),
   one `(name, thread_cap)` round per init-bootstrapped substrate
   service, and a terminal round carrying the reserved log-sink sources
   (master-log endpoint + procmgr `SEND|GRANT`) svcmgr keeps to launch and
   supervise real-logd. Move init's own kernel objects to procmgr in the
   first `REGISTER_INIT_TEARDOWN` round, which binds
   [procmgr](../procmgr/README.md)'s death-EQ on both init threads (main +
   init-logd) before real-logd can release init-logd; notify
   `HANDOVER_COMPLETE`; stream init's reclaimable Memory caps to procmgr in
   later `REGISTER_INIT_TEARDOWN` rounds; send `INIT_TEARDOWN_DONE`; call
   `sys_thread_exit`. Procmgr runs the reap path once both threads have
   exited — purely death-driven, with no force-stop; a handover that never
   completes leaves init-logd serving and init's memory caps held until
   shutdown (a benign hold, not a wedge).
   svcmgr publishes the well-known names it now owns (`rootfs.root`,
   `svcmgr`, `devmgr.registry`) and installs devmgr's `/services/drivers/`
   cap via `SET_DRIVERS_DIR` from the endowment (see
   [svcmgr IPC interface](../svcmgr/docs/ipc-interface.md)); it then
   launches the non-bootstrap services itself — `timed` and `pwrmgr`
   (providers), `terminal`, the staged test harnesses — and publishes their
   names (see [svcmgr](../svcmgr/README.md)). The per-arch RTC chip driver is
   [devmgr](../devmgr/README.md)-spawned lazily after `SET_DRIVERS_DIR` and
   resolved by [timed](../timed/README.md) via `QUERY_RTC_DEVICE`.

See [docs/bootstrap.md](docs/bootstrap.md) for the authoritative
stage-by-stage enumeration, source citations, and per-stage capability
transfer table.

---

## What init does NOT do

- Does not supervise services or restart them on crash (svcmgr's
  responsibility).
- Does not retain raw process-creation capabilities — the kernel-object
  retypes (`cap_create_aspace` / `cap_create_cspace` / `cap_create_thread`)
  used to bring up memmgr and procmgr happen only in init's
  [Raw bootstrap stage](docs/bootstrap.md#raw-bootstrap); after that, every
  process is created via procmgr IPC.
- Does not read a service dependency graph file at runtime (bootstrap order
  is compiled in).
- Does not remain resident after bootstrap completes —
  [procmgr](../procmgr/README.md) reaps init's address space, CSpace, and
  threads after `sys_thread_exit`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, init/memmgr/procmgr/svcmgr roles |
| [docs/bootstrap.md](../../docs/bootstrap.md) | System-scope end-to-end boot lifecycle |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, ProcessInfo/InitInfo handover, authority transfer |
| [docs/capability-model.md](../../docs/capability-model.md) | Initial capability distribution, derive-twice pattern |
| [docs/namespace-model.md](../../docs/namespace-model.md) | Namespace-cap distribution invariants |
| [abi/boot-protocol/](../../abi/boot-protocol/) | `BootInfo`, `bootstrap.bundle`, initial CSpace |
| [abi/init-protocol/](../../abi/init-protocol/) | Kernel-to-init handover (`InitInfo`, module-name table) |
| [services/memmgr/README.md](../memmgr/README.md) | First service init creates; receives the RAM Memory cap pool |
| [services/procmgr/README.md](../procmgr/README.md) | Owns process creation post-bootstrap; runs init's reap path |
| [services/svcmgr/README.md](../svcmgr/README.md) | Takes over as resident supervisor after `HANDOVER_COMPLETE` |
| [services/logd/README.md](../logd/README.md) | Master log endpoint owner; svcmgr-launched, pulls init-logd's history at handover |
| [services/pwrmgr/README.md](../pwrmgr/README.md) | svcmgr-launched post-handover; acquires its shutdown caps from devmgr, not from init |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/documentation-standards.md](../../docs/documentation-standards.md) | Document hierarchy, authority, backlinks |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md)
