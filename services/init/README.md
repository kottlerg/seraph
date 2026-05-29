# init

Bootstrap service and first userspace process. The kernel starts init at the end
of its initialization sequence. Init runs a three-stage bootstrap — raw memmgr /
procmgr creation, root mount, then handover to svcmgr — and exits. It is not a
long-lived service manager.

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
    ├── service.rs              # IPC-driven spawns (devmgr, vfsd, svcmgr, logd, timed, pwrmgr) and phase3_svcmgr_handover
    ├── mount.rs                # Root MOUNT exchange + GET_SYSTEM_ROOT_CAP pull
    ├── logging.rs              # init-logd thread (serves the log endpoint until real-logd takes over)
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
2. **Root mount** — issue `MOUNT(MountRole::Root, "/")` to vfsd (vfsd resolves
   the role to the arch-specific Seraph root GPT type-GUID), pull the seed
   `system_root_cap` via `GET_SYSTEM_ROOT_CAP`, then launch real-logd from
   `/services/logd` and hand off the master log endpoint via `HANDOVER_PULL`.
3. **Handover** — spawn svcmgr, timed, and pwrmgr (the per-arch RTC
   chip driver is devmgr-spawned during devmgr's enumeration sweep
   and resolved by timed via `QUERY_RTC_DEVICE`); publish the
   well-known caps (`rootfs.root`, `pwrmgr.shutdown`, `pwrmgr.deny`,
   `svcmgr`, `timed`); register every init-bootstrapped service with svcmgr via
   `REGISTER_SERVICE`; signal `HANDOVER_COMPLETE`; hand init's own
   kernel objects + reclaimable Frame caps to procmgr via
   `REGISTER_INIT_TEARDOWN`; call `sys_thread_exit`. Procmgr's death-EQ
   observer then runs the reap path.

See [docs/bootstrap.md](docs/bootstrap.md) for the authoritative
stage-by-stage enumeration, source citations, and per-stage capability
transfer table.

---

## What init does NOT do

- Does not supervise services or restart them on crash (svcmgr's
  responsibility).
- Does not retain raw process-creation capabilities — the kernel-object
  retypes (`cap_create_aspace` / `cap_create_cspace` / `cap_create_thread`)
  used to bring up memmgr and procmgr happen only in init's Raw bootstrap
  stage; after that, every process is created via procmgr IPC.
- Does not read a service dependency graph file at runtime (bootstrap order
  is compiled in).
- Does not remain resident after bootstrap completes — procmgr reaps init's
  address space, CSpace, and threads after `sys_thread_exit`.

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
| [services/memmgr/README.md](../memmgr/README.md) | First service init creates; receives the RAM Frame pool |
| [services/procmgr/README.md](../procmgr/README.md) | Owns process creation post-bootstrap; runs init's reap path |
| [services/svcmgr/README.md](../svcmgr/README.md) | Takes over as resident supervisor after `HANDOVER_COMPLETE` |
| [services/logd/README.md](../logd/README.md) | Master log endpoint owner post-Phase-2-epilogue |
| [services/pwrmgr/README.md](../pwrmgr/README.md) | Receives arch authority + ACPI Frame caps during handover |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/documentation-standards.md](../../docs/documentation-standards.md) | Document hierarchy, authority, backlinks |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md), [Process Lifecycle](../../docs/process-lifecycle.md), [logd](../logd/README.md), [memmgr](../memmgr/README.md), [pwrmgr](../pwrmgr/README.md)
